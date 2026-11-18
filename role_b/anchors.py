"""Commit and verify C's release references and ordered off-chain audit batches."""

from dataclasses import asdict
import re
from typing import Iterable

from trusted_release.crypto import canonical_json, sha256_hex
from trusted_release.protocol import ReleaseRef

from .approval import FabricClient


def release_current(client: FabricClient, ref: ReleaseRef) -> bool:
    value = client.submit("ReadRelease", ref.scope, ref.kind, ref.artifact_id)["value"]
    return value == {**asdict(ref), "revoked": False}


def publish_release(client: FabricClient, ref: ReleaseRef) -> dict:
    return client.submit("PublishRelease", canonical_json(asdict(ref)).decode("ascii"))


def revoke_release(client: FabricClient, ref: ReleaseRef) -> dict:
    return client.submit("RevokeRelease", canonical_json(asdict(ref)).decode("ascii"))


def audit_batch(stream: str, first_seq: int, events: Iterable[dict]) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", stream):
        raise ValueError("INVALID_STREAM")
    if type(first_seq) is not int or not 1 <= first_seq < 2**53 - 1:
        raise ValueError("INVALID_SEQUENCE")
    level = []
    for seq, event in enumerate(events, first_seq):
        if not isinstance(event, dict) or type(event.get("seq")) is not int or event["seq"] != seq:
            raise ValueError("AUDIT_RANGE_INVALID")
        leaf = canonical_json({"stream": stream, "event": event})
        level.append(bytes.fromhex(sha256_hex(b"\x00" + leaf)))
    last_seq = first_seq + len(level) - 1
    if not level or last_seq >= 2**53 - 1:
        raise ValueError("AUDIT_RANGE_INVALID")
    while len(level) > 1:
        pairs = zip(level[::2], level[1::2])
        parents = [bytes.fromhex(sha256_hex(b"\x01" + left + right)) for left, right in pairs]
        level = parents + (level[-1:] if len(level) % 2 else [])
    return {"stream": stream, "first_seq": first_seq, "last_seq": last_seq, "root": level[0].hex()}


def anchor_audit(client: FabricClient, stream: str, first_seq: int, events: Iterable[dict]) -> dict:
    batch = audit_batch(stream, first_seq, events)
    return client.submit("AnchorAudit", canonical_json(batch).decode("ascii"))


def verify_audit(client: FabricClient, stream: str, first_seq: int, events: Iterable[dict]) -> bool:
    anchored = client.submit("ReadAudit", stream, str(first_seq))["value"]
    try:
        batch = audit_batch(stream, first_seq, events)
    except ValueError:
        return False
    return anchored == batch


def audit_head(client: FabricClient, stream: str) -> int | None:
    head = client.submit("ReadAuditHead", stream)["value"]
    return head["last_seq"] if head is not None else None
