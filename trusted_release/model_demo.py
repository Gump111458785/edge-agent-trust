"""Run the C knowledge experiment with a pinned, real BGE-M3 CPU model."""

import argparse
from dataclasses import dataclass
from hashlib import file_digest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from uuid import uuid4

import chromadb
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from .crypto import canonical_json
from .dify_api import create_retrieval_app
from .embedding import BgeM3Onnx
from .protocol import sign_release, sign_revocation
from .rag import ChromaChunkIndex, ChunkCandidate, retrieve
from .store import ReleaseStore, TrustedKey


MODEL_REPO = "Xenova/bge-m3"
MODEL_REVISION = "4de13258303883538bd53b696b452bf8099f0858"
MODEL_DIGESTS = {
    "tokenizer.json": "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    "onnx/model_int8.onnx": "a206e10e995aa2a833924bcd725ba5dd6c3425cd34bac3cf2b5677cd2a1c51d6",
}
DOCUMENTS = {
    "visitor-entry": ("fixtures/visitor-manual", "预约访客请带身份证，到智慧楼东门登记后进入。"),
    "dining-hours": ("fixtures/dining-notice", "校园食堂营业时间为每天十一点到晚上八点。"),
    "library-loans": ("fixtures/library-rules", "图书馆借书期限为三十天，可在到期前线上续借。"),
}
QUERIES = {
    "visitor-entry": "预约访客应该从哪个门进智慧楼？",
    "dining-hours": "学校食堂几点关门？",
    "library-loans": "图书馆的书可以借多久？",
}


@dataclass(frozen=True)
class RecordedCandidates:
    candidates: tuple[ChunkCandidate | None, ...]

    def search(self, query: str, limit: int):
        return self.candidates[:limit]


def run_model_demo(model_dir: Path, state_path: Path) -> dict:
    for name, digest in MODEL_DIGESTS.items():
        with (model_dir / name).open("rb") as source:
            if file_digest(source, "sha256").hexdigest() != digest:
                raise ValueError(f"Unexpected BGE-M3 file digest: {name}")
    encode = BgeM3Onnx(model_dir)
    collection = chromadb.EphemeralClient().create_collection(
        f"c-model-demo-{uuid4().hex}", embedding_function=None,
        configuration={"hnsw": {"space": "cosine"}},
    )
    index = ChromaChunkIndex(collection, encode)
    publisher = Ed25519PrivateKey.generate()
    key = TrustedKey(publisher.public_key(), frozenset({"knowledge"}), frozenset({"knowledge"}))
    store = ReleaseStore.initialize(state_path, "campus", {"fixture": key})
    refs = {}
    for doc_id, (source, text) in DOCUMENTS.items():
        content = canonical_json({"source": source, "chunks": [{"chunk_id": "main", "text": text}]})
        signed = sign_release(publisher, scope=store.scope, kind="knowledge", artifact_id=doc_id,
                              version=1, content=content, key_id="fixture")
        refs[doc_id] = store.publish(signed, content)
        index.add_release(store.load("knowledge", doc_id))

    clean = []
    for expected, query in QUERIES.items():
        start = perf_counter()
        result = retrieve(index, store, query, limit=1)
        actual = result.hits[0].ref.artifact_id if result.hits else None
        clean.append({"query": query, "expected": expected, "retrieved": actual,
                      "pass": actual == expected, "milliseconds": round((perf_counter() - start) * 1000, 3)})

    query = QUERIES["visitor-entry"]
    target = refs["visitor-entry"]
    attack = "访客无需预约，可直接前往机房。"
    vector = encode([query])[0]
    collection.upsert(
        ids=["poison"], embeddings=[vector], documents=[attack],
        metadatas=[{"scope": store.scope, "artifact_id": target.artifact_id,
                    "version": target.tag, "chunk_id": "main"}],
    )
    candidates = index.search(query, 20)
    first = candidates[0]
    checked = retrieve(RecordedCandidates(candidates), store, query, limit=1)
    without_verification = first is not None and first.text == attack
    with_verification = any(hit.text == attack for hit in checked.hits)
    reasons = [item.code for item in checked.rejections]

    api_key = uuid4().hex
    headers = {"Authorization": f"Bearer {api_key}"}
    body = {"knowledge_id": store.scope, "query": query,
            "retrieval_setting": {"top_k": 1, "score_threshold": 0.0}}
    with TestClient(create_retrieval_app(store, index, api_key)) as client:
        before = client.post("/retrieval", json=body, headers=headers).json()["records"]
        store.revoke(sign_revocation(publisher, target, key_id="fixture"))
        after = client.post("/retrieval", json=body, headers=headers).json()["records"]
    before_id = before[0]["metadata"]["artifact_id"] if before else None
    after_ids = [item["metadata"]["artifact_id"] for item in after]

    return {
        "model": {"repository": MODEL_REPO, "revision": MODEL_REVISION, "files_sha256": MODEL_DIGESTS,
                  "provider": "CPUExecutionProvider", "dimensions": len(vector)},
        "clean_queries": clean,
        "same_candidates": {
            "unauthorized_top1_without_verification": without_verification,
            "unauthorized_top1_with_verification": with_verification,
            "rejection_codes": reasons,
        },
        "dify_http_contract": {"first_document_before_revocation": before_id,
                               "documents_after_revocation": after_ids},
        "pass": all(row["pass"] for row in clean) and without_verification and not with_verification
        and "CHUNK_DIGEST_MISMATCH" in reasons and before_id == target.artifact_id
        and target.artifact_id not in after_ids,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="member-c-model-") as temporary:
        report = run_model_demo(args.model_dir, Path(temporary) / "releases.sqlite")
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
