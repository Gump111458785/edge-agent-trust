"""Transactional trusted state and current-release verification."""

from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Iterator, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import sha256_hex, verify_bytes
from .payloads import validate_content
from .protocol import ReleaseRef, SignedStatement, TrustError, is_identifier, validate_identity


@dataclass(frozen=True)
class TrustedKey:
    public_key: Ed25519PublicKey
    publish: frozenset[str] = frozenset()
    revoke: frozenset[str] = frozenset()


@dataclass(frozen=True)
class VerifiedRelease:
    ref: ReleaseRef
    content: bytes


@dataclass(frozen=True)
class _Head:
    release: VerifiedRelease
    revoked: bool


class ReleaseStore:
    """Open persisted state. Only the publisher process needs write access to the file."""

    def __init__(self, path: Path, scope: str, keys: Mapping[str, TrustedKey]):
        if not is_identifier(scope):
            raise TrustError("INVALID_STATEMENT")
        self.path = Path(path).absolute()
        self.scope = scope
        self._keys = MappingProxyType(dict(keys))

    @classmethod
    def initialize(cls, path: Path, scope: str, keys: Mapping[str, TrustedKey]) -> "ReleaseStore":
        store = cls(path, scope, keys)
        try:
            with closing(sqlite3.connect(store.path)) as connection, connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS release_heads (
                        scope TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        artifact_id TEXT NOT NULL,
                        version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2147483647),
                        manifest BLOB NOT NULL,
                        content BLOB NOT NULL,
                        revocation BLOB,
                        PRIMARY KEY (scope, kind, artifact_id)
                    ) WITHOUT ROWID
                """)
        except sqlite3.Error as exc:
            raise TrustError("STATE_UNAVAILABLE") from exc
        return store

    @contextmanager
    def _transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        mode = "rw" if write else "ro"
        uri = self.path.as_uri() + "?mode=" + mode
        try:
            with closing(sqlite3.connect(uri, uri=True)) as connection, connection:
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield connection
        except sqlite3.Error as exc:
            raise TrustError("STATE_UNAVAILABLE") from exc

    def _authenticate(self, signed: SignedStatement, action: str) -> None:
        if signed.action != action:
            raise TrustError("INVALID_STATEMENT")
        message = signed.signing_bytes()
        payload = signed.payload
        if payload.scope != self.scope:
            raise TrustError("SCOPE_MISMATCH")
        key = self._keys.get(payload.key_id)
        if key is None or payload.kind not in (key.publish if action == "publish" else key.revoke):
            raise TrustError("UNAUTHORIZED_KEY")
        if not verify_bytes(key.public_key, message, signed.signature):
            raise TrustError("BAD_SIGNATURE")

    def _head(self, connection: sqlite3.Connection, kind: str, artifact_id: str) -> _Head | None:
        validate_identity(self.scope, kind, artifact_id)
        row = connection.execute(
            "SELECT version, manifest, content, revocation FROM release_heads "
            "WHERE scope = ? AND kind = ? AND artifact_id = ?", (self.scope, kind, artifact_id),
        ).fetchone()
        if row is None:
            return None
        version, manifest, content, revocation = row
        signed = SignedStatement.from_json(manifest)
        self._authenticate(signed, "publish")
        ref = signed.release_ref()
        if (ref.kind, ref.artifact_id, ref.version) != (kind, artifact_id, version):
            raise TrustError("STATE_INVALID")
        if not isinstance(content, bytes) or sha256_hex(content) != signed.payload.digest:
            raise TrustError("DIGEST_MISMATCH")
        if revocation is not None:
            signed_revoke = SignedStatement.from_json(revocation)
            self._authenticate(signed_revoke, "revoke")
            target = signed_revoke.payload
            if (target.kind, target.artifact_id, target.version, target.digest) != (
                    kind, artifact_id, ref.version, ref.manifest_sha256):
                raise TrustError("STATE_INVALID")
        return _Head(VerifiedRelease(ref, content), revoked=revocation is not None)

    def publish(self, signed: SignedStatement, content: bytes) -> ReleaseRef:
        self._authenticate(signed, "publish")
        if not isinstance(content, bytes) or sha256_hex(content) != signed.payload.digest:
            raise TrustError("DIGEST_MISMATCH")
        ref = signed.release_ref()
        validate_content(ref.kind, content)
        identity = ref.scope, ref.kind, ref.artifact_id
        with self._transaction(write=True) as connection:
            # The protected floor survives removing a compromised publisher from the keyring.
            row = connection.execute(
                "SELECT version FROM release_heads WHERE scope = ? AND kind = ? AND artifact_id = ?",
                identity,
            ).fetchone()
            if row is not None:
                if ref.version < row[0]:
                    raise TrustError("ROLLBACK")
                if ref.version == row[0]:
                    head = self._head(connection, ref.kind, ref.artifact_id)
                    if ref != head.release.ref:
                        raise TrustError("VERSION_CONFLICT")
                    if head.revoked:
                        raise TrustError("REVOKED")
                    return ref
            connection.execute("""
                INSERT INTO release_heads (scope, kind, artifact_id, version, manifest, content)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope, kind, artifact_id) DO UPDATE SET
                    version = excluded.version, manifest = excluded.manifest,
                    content = excluded.content, revocation = NULL
            """, (*identity, ref.version, signed.to_json(), content))
        return ref

    def revoke(self, signed: SignedStatement) -> None:
        self._authenticate(signed, "revoke")
        target = signed.payload
        with self._transaction(write=True) as connection:
            head = self._head(connection, target.kind, target.artifact_id)
            if head is None:
                raise TrustError("UNKNOWN_RELEASE")
            current = head.release.ref
            if target.version < current.version:
                raise TrustError("ROLLBACK")
            if (target.version, target.digest) != (current.version, current.manifest_sha256):
                raise TrustError("VERSION_CONFLICT")
            if not head.revoked:
                connection.execute(
                    "UPDATE release_heads SET revocation = ? WHERE scope = ? AND kind = ? AND artifact_id = ?",
                    (signed.to_json(), target.scope, target.kind, target.artifact_id),
                )

    @contextmanager
    def snapshot(self) -> Iterator["ReleaseSnapshot"]:
        with self._transaction() as connection:
            yield ReleaseSnapshot(self, connection)

    def load(self, kind: str, artifact_id: str, *,
             expected_version: str | None = None) -> VerifiedRelease:
        with self.snapshot() as snapshot:
            return snapshot.load(kind, artifact_id, expected_version=expected_version)

    def verify(self, kind: str, artifact_id: str, content: bytes, *,
               expected_version: str | None = None) -> ReleaseRef:
        release = self.load(kind, artifact_id, expected_version=expected_version)
        if not isinstance(content, bytes) or sha256_hex(content) != sha256_hex(release.content):
            raise TrustError("DIGEST_MISMATCH")
        return release.ref


class ReleaseSnapshot:
    """One SQLite read snapshot for a single authorization or retrieval decision."""

    def __init__(self, store: ReleaseStore, connection: sqlite3.Connection):
        self._store = store
        self._connection = connection

    def load(self, kind: str, artifact_id: str, *,
             expected_version: str | None = None) -> VerifiedRelease:
        head = self._store._head(self._connection, kind, artifact_id)
        if head is None:
            raise TrustError("UNKNOWN_RELEASE")
        if head.revoked:
            raise TrustError("REVOKED")
        if expected_version is not None and head.release.ref.tag != expected_version:
            raise TrustError("VERSION_MISMATCH")
        return head.release
