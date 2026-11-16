"""Wire format for signed releases and exact-release revocations."""

from dataclasses import asdict, dataclass
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import canonical_json, sha256_hex, sign_bytes


KINDS = frozenset({"agent_config", "prompt", "policy", "tool_manifest", "knowledge"})
MAX_VERSION = 2**31 - 1


class TrustError(Exception):
    """A stable, fail-closed rejection code for integration or experiment logs."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def is_identifier(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) is not None


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def validate_identity(scope: str, kind: str, artifact_id: str) -> None:
    if not (is_identifier(scope) and isinstance(kind, str) and kind in KINDS
            and is_identifier(artifact_id)):
        raise TrustError("INVALID_STATEMENT")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def decode_json(data: bytes | str) -> object:
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


@dataclass(frozen=True, kw_only=True)
class Statement:
    scope: str
    kind: str
    artifact_id: str
    version: int
    key_id: str
    digest: str

    def validate(self) -> None:
        validate_identity(self.scope, self.kind, self.artifact_id)
        if (type(self.version) is not int or not 1 <= self.version <= MAX_VERSION
                or not is_identifier(self.key_id) or not _is_digest(self.digest)):
            raise TrustError("INVALID_STATEMENT")

    def signing_bytes(self, action: str) -> bytes:
        self.validate()
        prefix = f"edge-agent-trust:{action}:v1\n".encode("ascii")
        return prefix + canonical_json(asdict(self))


@dataclass(frozen=True)
class ReleaseRef:
    scope: str
    kind: str
    artifact_id: str
    version: int
    manifest_sha256: str

    @property
    def tag(self) -> str:
        return f"v{self.version}-{self.manifest_sha256}"


@dataclass(frozen=True)
class SignedStatement:
    action: str
    payload: Statement
    signature: str

    def signing_bytes(self) -> bytes:
        if self.action not in ("publish", "revoke") or type(self.payload) is not Statement:
            raise TrustError("INVALID_STATEMENT")
        return self.payload.signing_bytes(self.action)

    def release_ref(self) -> ReleaseRef:
        if self.action != "publish":
            raise TrustError("INVALID_STATEMENT")
        manifest = self.payload
        return ReleaseRef(manifest.scope, manifest.kind, manifest.artifact_id, manifest.version,
                          sha256_hex(self.signing_bytes()))

    def to_json(self) -> bytes:
        return canonical_json(asdict(self))

    @classmethod
    def from_json(cls, data: bytes | str) -> "SignedStatement":
        try:
            wire = decode_json(data)
            if not isinstance(wire, dict) or set(wire) != {"action", "payload", "signature"}:
                raise ValueError("Invalid envelope")
            result = cls(wire["action"], Statement(**wire["payload"]), wire["signature"])
            if not isinstance(result.signature, str):
                raise ValueError("Invalid signature field")
            result.signing_bytes()
        except (ValueError, TypeError, RecursionError) as exc:
            raise TrustError("INVALID_STATEMENT") from exc
        return result


def _sign(key: Ed25519PrivateKey, action: str, payload: Statement) -> SignedStatement:
    return SignedStatement(action, payload, sign_bytes(key, payload.signing_bytes(action)))


def sign_release(key: Ed25519PrivateKey, *, scope: str, kind: str, artifact_id: str,
                 version: int, content: bytes, key_id: str) -> SignedStatement:
    return _sign(key, "publish", Statement(
        scope=scope, kind=kind, artifact_id=artifact_id, version=version,
        key_id=key_id, digest=sha256_hex(content),
    ))


def sign_revocation(key: Ed25519PrivateKey, ref: ReleaseRef, *, key_id: str) -> SignedStatement:
    return _sign(key, "revoke", Statement(
        scope=ref.scope, kind=ref.kind, artifact_id=ref.artifact_id, version=ref.version,
        key_id=key_id, digest=ref.manifest_sha256,
    ))
