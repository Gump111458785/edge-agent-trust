"""Use independently held release state at C's actual point of use."""

from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
from threading import Event, Lock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from trusted_release.crypto import canonical_json
from trusted_release.protocol import TrustError, sign_release
from trusted_release.store import ReleaseStore, TrustedKey


class CommittedClient:
    def __init__(self):
        self.value = None
        self.block = 10
        self.calls = []
        self.error = None

    def submit(self, name, *arguments):
        self.calls.append((name, arguments))
        if self.error:
            raise self.error
        return {"transaction_id": "a" * 64, "block": str(self.block), "value": self.value}


def checkpoint(client, **kwargs):
    from trusted_release.checkpoint import FabricReleaseCheckpoint
    return FabricReleaseCheckpoint(client, **kwargs)


@pytest.fixture
def releases(tmp_path):
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({"knowledge", "policy", "tool_manifest", "prompt", "agent_config"})
    keys = {"c": TrustedKey(key.public_key(), kinds, kinds)}
    store = ReleaseStore.initialize(tmp_path / "releases.sqlite", "campus", keys)

    def publish(version=1, text="当前校园规章", kind="knowledge", artifact="handbook"):
        value = {"source": "official", "chunks": [{"chunk_id": "entrance", "text": text}]}
        if kind != "knowledge":
            value = {"text": text} if kind != "tool_manifest" else {"tools": []}
        content = canonical_json(value)
        signed = sign_release(key, scope="campus", kind=kind, artifact_id=artifact,
                              version=version, content=content, key_id="c")
        return store.publish(signed, content)

    return store, keys, publish


def test_consumer_load_queries_checkpoint_each_time(releases):
    store, keys, publish = releases
    ref = publish()
    client = CommittedClient()
    client.value = {**asdict(ref), "revoked": False}
    consumer = ReleaseStore(store.path, store.scope, keys, checkpoint=checkpoint(client))
    assert consumer.load("knowledge", "handbook").ref == ref
    assert consumer.load("knowledge", "handbook").ref == ref
    assert client.calls == [("ReadRelease", ("campus", "knowledge", "handbook"))] * 2
    client.value["revoked"] = True
    with pytest.raises(TrustError, match="^CHECKPOINT_MISMATCH$"):
        consumer.load("knowledge", "handbook")


def test_old_whole_database_snapshot_is_rejected(releases, tmp_path):
    store, keys, publish = releases
    old = publish()
    backup = tmp_path / "old.sqlite"
    shutil.copy2(store.path, backup)
    current = publish(2, "新规章")
    client = CommittedClient()
    client.value = {**asdict(current), "revoked": False}
    consumer = ReleaseStore(store.path, store.scope, keys, checkpoint=checkpoint(client))
    assert consumer.load("knowledge", "handbook").ref == current
    shutil.copy2(backup, store.path)
    assert store.load("knowledge", "handbook").ref == old  # valid signatures alone miss rollback
    with pytest.raises(TrustError, match="^CHECKPOINT_MISMATCH$"):
        consumer.load("knowledge", "handbook")


@pytest.mark.parametrize("change", [
    None, {"revoked": True}, {"version": 2}, {"manifest_sha256": "b" * 64},
    {"scope": "other"}, {"artifact_id": "other"}, {"kind": "policy"},
])
def test_non_current_independent_record_is_rejected(releases, change):
    _, _, publish = releases
    ref = publish()
    client = CommittedClient()
    client.value = None if change is None else {**asdict(ref), "revoked": False, **change}
    with pytest.raises(TrustError, match="^CHECKPOINT_MISMATCH$"):
        checkpoint(client).verify_current(ref)


@pytest.mark.parametrize("change", [
    {"version": True}, {"revoked": 0}, {"manifest_sha256": "not-a-digest"},
    {"extra": "untrusted"}, {"version": "1"}, {"version": -1},
])
def test_malformed_independent_state_is_unavailable(releases, change):
    _, _, publish = releases
    ref = publish()
    client = CommittedClient()
    client.value = {**asdict(ref), "revoked": False, **change}
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        checkpoint(client).verify_current(ref)


@pytest.mark.parametrize("receipt", [
    None, {}, {"transaction_id": "a" * 64, "block": "01", "value": None},
    {"transaction_id": "a" * 64, "block": -1, "value": None},
    {"transaction_id": "bad", "block": "10", "value": None},
    {"transaction_id": "a" * 64, "block": "10"},
])
def test_malformed_commit_receipts_fail_closed(releases, receipt):
    _, _, publish = releases
    ref = publish()
    class BadReceipt:
        def submit(self, *args):
            return receipt
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        checkpoint(BadReceipt()).verify_current(ref)


def test_network_failures_and_slow_reads_are_unavailable(releases):
    _, _, publish = releases
    ref = publish()
    client = CommittedClient()
    client.error = OSError("network unavailable")
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        checkpoint(client).verify_current(ref)
    client.error = None
    client.value = {**asdict(ref), "revoked": False}
    ticks = iter([100, 116])
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        checkpoint(client, clock=lambda: next(ticks)).verify_current(ref)


def test_old_committed_block_is_not_accepted_after_newer_read(releases):
    _, _, publish = releases
    ref = publish()
    client = CommittedClient()
    client.value = {**asdict(ref), "revoked": False}
    guard = checkpoint(client)
    guard.verify_current(ref)
    client.block -= 1
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        guard.verify_current(ref)


@pytest.mark.parametrize("value", [0, -1, True, 16, float("nan"), "15"])
def test_invalid_read_time_budget_is_rejected(value):
    with pytest.raises(ValueError):
        checkpoint(CommittedClient(), max_read_seconds=value)


def test_concurrent_commit_reads_do_not_false_alarm_on_response_reordering(releases):
    _, _, publish = releases
    ref = publish()
    first_started, second_started, finish_first = Event(), Event(), Event()
    class OrderedClient:
        def __init__(self):
            self.count = 0
            self.lock = Lock()
        def submit(self, *args):
            with self.lock:
                self.count += 1
                count = self.count
            if count == 1:
                first_started.set()
                assert finish_first.wait(3)
            else:
                second_started.set()
            return {"transaction_id": "a" * 64, "block": str(10 + count),
                    "value": {**asdict(ref), "revoked": False}}
    guard = checkpoint(OrderedClient())
    with ThreadPoolExecutor(max_workers=2) as pool:
        older = pool.submit(guard.verify_current, ref)
        assert first_started.wait(2)
        newer = pool.submit(guard.verify_current, ref)
        try:
            assert not second_started.wait(0.15), "concurrent reads could return out of commit order"
        finally:
            finish_first.set()
        older.result(timeout=3)
        newer.result(timeout=3)


@pytest.mark.parametrize("change", [
    {"block": str(2**64)}, {"block": "01"}, {"unexpected": "field"}, {"transaction_id": "bad"},
])
def test_admin_anchor_uses_the_same_strict_commit_receipt_checks(releases, monkeypatch, change):
    from trusted_release.checkpoint import anchor_release, FabricReleaseCheckpoint
    _, _, publish = releases
    ref = publish()
    class ReceiptClient:
        def submit(self, *args):
            return {"transaction_id": "a" * 64, "block": "10", "value": {**asdict(ref), "revoked": False}, **change}
    guard = checkpoint(ReceiptClient())
    monkeypatch.setattr(FabricReleaseCheckpoint, "from_config", classmethod(lambda cls, path: guard))
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        anchor_release(Path("fixture.json"), ref)


def test_admin_anchor_rejects_confirmation_past_its_read_budget(releases, monkeypatch):
    from trusted_release.checkpoint import anchor_release, FabricReleaseCheckpoint
    _, _, publish = releases
    ref = publish()
    client = CommittedClient()
    client.value = {**asdict(ref), "revoked": False}
    ticks = iter([0.0, 16.0])
    guard = checkpoint(client, clock=lambda: next(ticks))
    monkeypatch.setattr(FabricReleaseCheckpoint, "from_config", classmethod(lambda cls, path: guard))
    with pytest.raises(TrustError, match="^STATE_UNAVAILABLE$"):
        anchor_release(Path("fixture.json"), ref)
