"""Open C's release database using deployment-owned public keys."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .protocol import KINDS, decode_json, is_identifier
from .store import ReleaseStore, TrustedKey


def open_store(config_path: Path, *, initialize: bool = False) -> ReleaseStore:
    config_path = Path(config_path).resolve()
    config = decode_json(config_path.read_bytes())
    if (not isinstance(config, dict) or set(config) != {"scope", "database", "keys"}
            or not is_identifier(config["scope"]) or not _path_string(config["database"])
            or not isinstance(config["keys"], dict) or not config["keys"]):
        raise ValueError("Invalid release trust configuration")
    keys = {}
    for key_id, entry in config["keys"].items():
        if (not is_identifier(key_id) or not isinstance(entry, dict)
                or set(entry) != {"public_key", "publish", "revoke"}
                or not _path_string(entry["public_key"])):
            raise ValueError("Invalid release key configuration")
        public_key = load_pem_public_key((config_path.parent / entry["public_key"]).read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Release signing keys must be Ed25519 public keys")
        keys[key_id] = TrustedKey(public_key, _kinds(entry["publish"]), _kinds(entry["revoke"]))
    factory = ReleaseStore.initialize if initialize else ReleaseStore
    return factory(config_path.parent / config["database"], config["scope"], keys)


def _path_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _kinds(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(kind, str) and kind in KINDS for kind in value):
        raise ValueError("Invalid artifact kinds in release trust configuration")
    return frozenset(value)
