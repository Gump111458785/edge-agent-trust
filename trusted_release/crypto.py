"""Shared byte-level primitives for release, token and approval protocols."""

import base64
from hashlib import sha256
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def sha256_hex(content: bytes) -> str:
    return sha256(content).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def sign_bytes(key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(key.sign(payload)).decode("ascii").rstrip("=")


def verify_bytes(key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
        return False
    raw = base64.urlsafe_b64decode(signature + "==")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != signature:
        return False
    try:
        key.verify(raw, payload)
    except InvalidSignature:
        return False
    return True
