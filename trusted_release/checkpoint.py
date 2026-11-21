"""Independent, committed release-state reads through B's existing Fabric client."""

from dataclasses import asdict
from math import isfinite
from pathlib import Path
import re
from threading import Lock
from time import monotonic
from typing import Callable, Protocol

from .protocol import KINDS, MAX_VERSION, ReleaseRef, TrustError, decode_json, is_identifier
from .crypto import canonical_json


class ReleaseCheckpoint(Protocol):
    def verify_current(self, ref: ReleaseRef) -> None:
        """Reject unless the independently committed, unrevoked head equals ref."""


class CommittedClient(Protocol):
    def submit(self, transaction: str, *args: str) -> dict:
        """Return B's receipt after both configured organizations confirm the read."""


class FabricReleaseCheckpoint:
    def __init__(self, client: CommittedClient, *, max_read_seconds: int = 15,
                 clock: Callable[[], float] = monotonic):
        if type(max_read_seconds) is not int or not 1 <= max_read_seconds <= 15:
            raise ValueError("Checkpoint read budget must be an integer from 1 to 15 seconds")
        self.client = client
        self.max_read_seconds = max_read_seconds
        self._clock = clock
        self._highest_block = -1
        self._lock = Lock()

    @classmethod
    def from_config(cls, path: Path, *, max_read_seconds: int = 15) -> "FabricReleaseCheckpoint":
        from role_b.approval import FabricClient

        path = Path(path).resolve()
        config = decode_json(path.read_bytes())
        if (not isinstance(config, dict)
                or not {"channel", "chaincode", "identity", "peers"} <= config.keys()
                or not all(isinstance(config[name], str) and config[name].strip()
                           for name in ("channel", "chaincode"))
                or not isinstance(config["identity"], dict)
                or not isinstance(config["peers"], list) or len(config["peers"]) != 2
                or not all(isinstance(peer, dict) for peer in config["peers"])):
            raise ValueError("Invalid Fabric release checkpoint connection configuration")
        # B owns TLS, identity, endorsement and dual-organization commit verification.
        return cls(FabricClient(path), max_read_seconds=max_read_seconds)

    def verify_current(self, ref: ReleaseRef) -> None:
        value = self._committed_value(lambda: self.client.submit("ReadRelease", ref.scope, ref.kind, ref.artifact_id))
        if value != {**asdict(ref), "revoked": False}:
            raise TrustError("CHECKPOINT_MISMATCH")

    def _committed_value(self, submit: Callable[[], dict]) -> dict | None:
        # Serialize each instance's commits so a legitimate older response cannot arrive
        # after a newer one and trigger a false regression. Bound queueing separately.
        if not self._lock.acquire(timeout=self.max_read_seconds):
            raise TrustError("STATE_UNAVAILABLE")
        try:
            started = self._clock()
            receipt = submit()
            elapsed = self._clock() - started
            if (not isfinite(elapsed) or not 0 <= elapsed <= self.max_read_seconds
                    or not isinstance(receipt, dict)
                    or set(receipt) != {"transaction_id", "block", "value"}
                    or not _matches(receipt["transaction_id"], r"[0-9a-f]{64}")
                    or not _matches(receipt["block"], r"0|[1-9][0-9]{0,19}")):
                raise ValueError("Invalid or late release checkpoint receipt")
            block = int(receipt["block"])
            if block >= 2**64:
                raise ValueError("Invalid checkpoint block")
            if block < self._highest_block:
                raise ValueError("Checkpoint block regressed")
            value = receipt["value"]
            if value is not None and not _valid_record(value):
                raise ValueError("Invalid checkpoint release record")
            self._highest_block = block
            return value
        except Exception as exc:
            # No stale affirmative cache or local-only fallback on transport/parser failure.
            raise TrustError("STATE_UNAVAILABLE") from exc
        finally:
            self._lock.release()


def _matches(value: object, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _valid_record(value: object) -> bool:
    return (isinstance(value, dict)
            and set(value) == {"scope", "kind", "artifact_id", "version", "manifest_sha256", "revoked"}
            and is_identifier(value["scope"]) and is_identifier(value["artifact_id"])
            and isinstance(value["kind"], str) and value["kind"] in KINDS
            and type(value["version"]) is int and 1 <= value["version"] <= MAX_VERSION
            and type(value["revoked"]) is bool
            and _matches(value["manifest_sha256"], r"[0-9a-f]{64}"))


def anchor_release(config_path: Path, ref: ReleaseRef, *, revoked: bool = False) -> None:
    """Admin-only publication step; never give this identity to a consumer service."""
    from role_b.anchors import publish_release, revoke_release

    source = FabricReleaseCheckpoint.from_config(config_path)
    try:
        value = source._committed_value(lambda: (revoke_release if revoked else publish_release)(source.client, ref))
        expected = {**asdict(ref), "revoked": revoked}
        if canonical_json(value) != canonical_json(expected):
            raise ValueError("Unexpected committed release anchor")
    except TrustError:
        raise
    except Exception as exc:
        raise TrustError("STATE_UNAVAILABLE") from exc
