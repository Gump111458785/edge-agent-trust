"""Reproduce C's database rollback protection; optionally use B's deployed Fabric profiles."""

import argparse
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .checkpoint import FabricReleaseCheckpoint
from .crypto import canonical_json
from .protocol import TrustError, sign_release
from .rag import ChunkCandidate, retrieve
from .store import ReleaseStore, TrustedKey


class ChaincodeMemoryClient:
    """Replay test commands through the original B ledger, not through a live network."""

    def __init__(self, node: str):
        self.node = node
        self.history = []

    def submit(self, transaction: str, *args: str) -> dict:
        commands = self.history + [{"transaction": transaction, "args": args}]
        script = Path(__file__).with_name("experiments") / "checkpoint_ledger.cjs"
        result = subprocess.run([self.node, str(script)], input=json.dumps(commands), capture_output=True,
                                text=True, encoding="utf-8", timeout=12, check=True)
        receipt = json.loads(result.stdout)
        self.history = commands
        return receipt


def run_demo(*, node: str = "node", fabric_reader: Path | None = None,
             fabric_publisher: Path | None = None) -> dict:
    if (fabric_reader is None) != (fabric_publisher is None):
        raise ValueError("Provide both --fabric-reader and --fabric-publisher")
    live = fabric_reader is not None
    if live:
        guard = FabricReleaseCheckpoint.from_config(fabric_reader)
        publisher = FabricReleaseCheckpoint.from_config(fabric_publisher).client
    else:
        publisher = ChaincodeMemoryClient(node)
        guard = FabricReleaseCheckpoint(publisher)
    cases = []
    artifact = "checkpoint-demo-" + uuid4().hex[:16]
    text = "校园访客请先预约后从东门登记。"
    with TemporaryDirectory(prefix="c-checkpoint-demo-") as temporary:
        folder = Path(temporary)
        key = Ed25519PrivateKey.generate()
        kinds = frozenset({"knowledge"})
        keys = {"c": TrustedKey(key.public_key(), kinds, kinds)}
        store = ReleaseStore.initialize(folder / "releases.sqlite", "campus", keys)
        consumer = ReleaseStore(store.path, store.scope, keys, checkpoint=guard)

        def publish(version):
            content = canonical_json({"source": "课堂合成规章", "chunks": [{"chunk_id": "entrance", "text": text}]})
            signed = sign_release(key, scope="campus", kind="knowledge", artifact_id=artifact,
                                  version=version, content=content, key_id="c")
            return store.publish(signed, content)

        def anchor(ref, revoked=False):
            # This is B's existing transaction, with the explicit publisher transport.
            publisher.submit("RevokeRelease" if revoked else "PublishRelease", canonical_json(asdict(ref)).decode())

        def observe(name, action, expected="accepted", **evidence):
            try:
                action()
                actual = "accepted"
            except TrustError as error:
                actual = error.code
            cases.append({"case": name, "expected": expected, "actual": actual,
                          "pass": actual == expected, **evidence})

        load = lambda: consumer.load("knowledge", artifact)
        first = publish(1)
        backup = folder / "old.sqlite"
        shutil.copy2(store.path, backup)
        anchor(first)
        observe("checkpoint_current", load)
        second = publish(2)
        observe("update_not_yet_anchored", load, "CHECKPOINT_MISMATCH")
        anchor(second)
        observe("higher_version_anchored", load)
        fresh = folder / "current.sqlite"
        shutil.copy2(store.path, fresh)
        shutil.copy2(backup, store.path)
        local_valid = store.load("knowledge", artifact).ref == first
        observe("whole_database_rollback", load, "CHECKPOINT_MISMATCH", local_signature_valid=local_valid)
        shutil.copy2(fresh, store.path)
        anchor(second, revoked=True)
        observe("independent_revocation", load, "CHECKPOINT_MISMATCH")
        third = publish(3)
        anchor(third)
        observe("recovery_with_new_version", load)

        class Offline:
            def submit(self, *args):
                raise OSError("experiment offline checkpoint")
        offline = ReleaseStore(store.path, store.scope, keys, checkpoint=FabricReleaseCheckpoint(Offline()))
        observe("checkpoint_unavailable", lambda: offline.load("knowledge", artifact), "STATE_UNAVAILABLE")

        class Index:
            def search(self, query, limit):
                return [ChunkCandidate("campus", artifact, third.tag, "entrance", text, 0.9)]
        result = retrieve(Index(), consumer, "访客入口", limit=1)
        cases.append({"case": "rag_current", "actual": len(result.hits), "expected": 1,
                      "pass": len(result.hits) == 1 and result.hits[0].ref == third})
        anchor(third, revoked=True)
        result = retrieve(Index(), consumer, "访客入口", limit=1)
        codes = [row.code for row in result.rejections]
        cases.append({"case": "rag_independent_revocation", "actual": codes, "expected": ["CHECKPOINT_MISMATCH"],
                      "pass": not result.hits and codes == ["CHECKPOINT_MISMATCH"]})
        with closing(sqlite3.connect(store.path)) as database, database:
            database.execute("UPDATE release_heads SET content = ?", (b"changed bytes",))
        observe("local_content_tamper", load, "DIGEST_MISMATCH")
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "backend": "fabric-committed" if live else "b-chaincode-memory", "live_fabric": live,
            "artifact_id": artifact, "cases": cases, "pass": all(row["pass"] for row in cases),
            "scope": "C release checkpoints; no cloud LLM, fixed retrieval candidates"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="node")
    parser.add_argument("--fabric-reader", type=Path)
    parser.add_argument("--fabric-publisher", type=Path)
    args = parser.parse_args()
    if (args.fabric_reader is None) != (args.fabric_publisher is None):
        parser.error("Provide both --fabric-reader and --fabric-publisher")
    try:
        report = run_demo(node=args.node, fabric_reader=args.fabric_reader, fabric_publisher=args.fabric_publisher)
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 0 if report["pass"] else 1
    except (OSError, ValueError, TrustError, subprocess.SubprocessError) as error:
        # Avoid leaking identity/profile contents or subprocess credentials in reports.
        print(json.dumps({"pass": False, "error": type(error).__name__, "live_fabric": args.fabric_reader is not None}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
