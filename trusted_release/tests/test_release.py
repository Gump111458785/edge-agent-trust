from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import sqlite3
from threading import Barrier

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from trusted_release.crypto import canonical_json, sha256_hex, sign_bytes, verify_bytes
from trusted_release.protocol import SignedStatement, sign_release, sign_revocation
from trusted_release.store import ReleaseStore, TrustError, TrustedKey


@pytest.fixture
def context(tmp_path):
    publisher = Ed25519PrivateKey.generate()
    revoker = Ed25519PrivateKey.generate()
    keys = {
        "publisher": TrustedKey(
            publisher.public_key(),
            publish=frozenset({"agent_config", "prompt", "policy", "tool_manifest", "knowledge"}),
        ),
        "revoker": TrustedKey(revoker.public_key(), revoke=frozenset({"prompt"})),
    }
    db = tmp_path / "state.sqlite"
    return ReleaseStore.initialize(db, "campus", keys), publisher, revoker, keys


def release(key, revision=1, data=b"campus prompt", *, scope="campus", kind="prompt",
            artifact_id="system", key_id="publisher"):
    return sign_release(key, scope=scope, kind=kind, artifact_id=artifact_id,
                        version=revision, content=data, key_id=key_id)


def test_crypto_known_vectors_and_encoding():
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert canonical_json({"z": 1, "a": "门"}) == '{"a":"门","z":1}'.encode()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60"))
    expected = (
        "5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr"
        "0lv18FlbviRlUUFDjnoQCw"
    )
    assert sign_bytes(key, b"") == expected
    assert verify_bytes(key.public_key(), b"", expected)
    assert not verify_bytes(key.public_key(), b"changed", expected)
    assert not verify_bytes(key.public_key(), b"", expected + "=")
    assert not verify_bytes(key.public_key(), b"", expected[:-1] + "x")


def test_publish_verify_and_retry(context):
    store, key, _, _ = context
    signed = release(key)
    parsed = SignedStatement.from_json(signed.to_json())
    ref = store.publish(parsed, b"campus prompt")
    assert ref == store.publish(signed, b"campus prompt")
    assert store.load("prompt", "system").content == b"campus prompt"
    assert store.verify("prompt", "system", b"campus prompt", expected_version=ref.tag) == ref
    assert len(ref.tag) <= 80
    with pytest.raises(TrustError, match="DIGEST_MISMATCH"):
        store.verify("prompt", "system", b"changed")


@pytest.mark.parametrize(("kind", "data"), [
    ("agent_config", b'{"temperature":0,"model":"fixture"}'),
    ("policy", b'{"max_minutes":120}'),
])
def test_raw_configuration_tampering_fails_at_use_time(context, kind, data):
    store, key, _, _ = context
    ref = store.publish(release(key, data=data, kind=kind), data)
    assert store.load(kind, "system", expected_version=ref.tag).content == data
    with pytest.raises(TrustError, match="DIGEST_MISMATCH"):
        store.verify(kind, "system", data + b"\n", expected_version=ref.tag)


@pytest.mark.parametrize(("case", "code"), [
    ("wrong bytes", "DIGEST_MISMATCH"), ("forged signature", "BAD_SIGNATURE"),
    ("unknown key", "UNAUTHORIZED_KEY"), ("wrong scope", "SCOPE_MISMATCH"),
    ("wrong role", "UNAUTHORIZED_KEY"), ("edited manifest", "BAD_SIGNATURE"),
])
def test_publish_rejects_invalid_envelope_without_advancing(context, case, code):
    store, publisher, revoker, _ = context
    first = store.publish(release(publisher), b"campus prompt")
    signed = release(publisher, 2)
    content = b"campus prompt"
    if case == "wrong bytes":
        content = b"unverified"
    elif case == "forged signature":
        signed = replace(signed, signature=release(revoker, 2).signature)
    elif case == "unknown key":
        signed = release(publisher, 2, key_id="unknown")
    elif case == "wrong scope":
        signed = release(publisher, 2, scope="other")
    elif case == "wrong role":
        signed = release(revoker, 2, key_id="revoker")
    else:
        signed = replace(signed, payload=replace(signed.payload, version=3))
    with pytest.raises(TrustError, match=code):
        store.publish(signed, content)
    assert store.load("prompt", "system").ref == first


def test_conflicting_and_old_versions_fail_after_reopen(context):
    store, key, _, keys = context
    first = store.publish(release(key, 1), b"campus prompt")
    latest = store.publish(release(key, 2), b"campus prompt")
    restarted = ReleaseStore(store.path, "campus", keys)
    with pytest.raises(TrustError, match="ROLLBACK"):
        restarted.publish(release(key, 1), b"campus prompt")
    with pytest.raises(TrustError, match="VERSION_CONFLICT"):
        restarted.publish(release(key, 2, b"conflict"), b"conflict")
    with pytest.raises(TrustError, match="VERSION_MISMATCH"):
        restarted.load("prompt", "system", expected_version=first.tag)
    assert restarted.load("prompt", "system").ref == latest


def test_revocation_survives_restart_cannot_be_replayed_or_reactivated(context):
    store, publisher, revoker, keys = context
    signed = release(publisher)
    first = store.publish(signed, b"campus prompt")
    with pytest.raises(TrustError, match="UNAUTHORIZED_KEY"):
        store.revoke(sign_revocation(publisher, first, key_id="publisher"))
    with pytest.raises(TrustError, match="VERSION_CONFLICT"):
        store.revoke(sign_revocation(revoker, replace(first, manifest_sha256="0" * 64),
                                     key_id="revoker"))
    revocation = sign_revocation(revoker, first, key_id="revoker")
    store.revoke(SignedStatement.from_json(revocation.to_json()))
    restarted = ReleaseStore(store.path, "campus", keys)
    restarted.revoke(revocation)
    with pytest.raises(TrustError, match="REVOKED"):
        restarted.load("prompt", "system")
    with pytest.raises(TrustError, match="REVOKED"):
        restarted.publish(signed, b"campus prompt")
    latest = restarted.publish(release(publisher, 2), b"campus prompt")
    with pytest.raises(TrustError, match="ROLLBACK"):
        restarted.revoke(revocation)
    assert restarted.load("prompt", "system").ref == latest


def test_concurrent_same_version_conflict_is_serialized(context):
    store, key, _, _ = context
    gate = Barrier(2, timeout=5)

    def submit(data):
        signed = release(key, data=data)
        gate.wait()
        try:
            store.publish(signed, data)
        except TrustError as exc:
            return exc.code
        return "ok"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, [b"alpha", b"beta"])) == ["VERSION_CONFLICT", "ok"]
    assert store.load("prompt", "system").content in {b"alpha", b"beta"}


def test_corrupt_content_is_rejected_at_point_of_use(context):
    store, key, _, _ = context
    store.publish(release(key), b"campus prompt")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE release_heads SET content = ?", (b"modified",))
    with pytest.raises(TrustError, match="DIGEST_MISMATCH"):
        store.load("prompt", "system")


def test_misconfigured_or_missing_state_fails_closed(context, tmp_path):
    store, key, _, _ = context
    store.publish(release(key), b"campus prompt")
    with pytest.raises(TrustError, match="UNAUTHORIZED_KEY"):
        ReleaseStore(store.path, "campus", {}).load("prompt", "system")
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(TrustError, match="STATE_UNAVAILABLE"):
        ReleaseStore(missing, "campus", {}).load("prompt", "system")
    assert not missing.exists()


def test_new_key_can_replace_head_after_compromised_key_is_removed(context):
    store, old_key, _, _ = context
    store.publish(release(old_key, 2), b"campus prompt")
    new_key = Ed25519PrivateKey.generate()
    rotated = ReleaseStore(
        store.path, "campus", {"new": TrustedKey(new_key.public_key(), publish=frozenset({"prompt"}))},
    )
    with pytest.raises(TrustError, match="UNAUTHORIZED_KEY"):
        rotated.load("prompt", "system")
    with pytest.raises(TrustError, match="ROLLBACK"):
        rotated.publish(release(new_key, 1, key_id="new"), b"campus prompt")
    replacement = rotated.publish(release(new_key, 3, key_id="new"), b"campus prompt")
    assert rotated.load("prompt", "system").ref == replacement


def test_head_cannot_reuse_a_different_signed_version(context):
    store, key, _, _ = context
    old = release(key)
    store.publish(old, b"campus prompt")
    store.publish(release(key, 2), b"campus prompt")
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE release_heads SET manifest = ?", (old.to_json(),))
    with pytest.raises(TrustError, match="STATE_INVALID"):
        store.load("prompt", "system")


@pytest.mark.parametrize("value", [True, 0, -1, 2**31, 1.0])
def test_wire_rejects_invalid_versions(context, value):
    _, key, _, _ = context
    envelope = json.loads(release(key).to_json())
    envelope["payload"]["version"] = value
    with pytest.raises(TrustError, match="INVALID_STATEMENT"):
        SignedStatement.from_json(json.dumps(envelope))


def test_wire_rejects_duplicate_members_and_unrecognized_fields(context):
    _, key, _, _ = context
    encoded = release(key).to_json()
    with pytest.raises(TrustError, match="INVALID_STATEMENT"):
        SignedStatement.from_json(encoded.replace(b'"version":1', b'"version":1,"version":2'))
    value = json.loads(encoded)
    value["payload"]["unknown"] = True
    with pytest.raises(TrustError, match="INVALID_STATEMENT"):
        SignedStatement.from_json(json.dumps(value))
