"""Integrity checks on untrusted vector-search candidates."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Protocol

from .crypto import canonical_json, sha256_hex
from .payloads import KnowledgeDocument, parse_knowledge
from .protocol import ReleaseRef, TrustError, is_identifier
from .store import ReleaseStore, VerifiedRelease

if TYPE_CHECKING:
    from chromadb import Collection


@dataclass(frozen=True)
class ChunkCandidate:
    scope: str
    artifact_id: str
    version: str
    chunk_id: str
    text: str
    score: float | None = None


class ChunkIndex(Protocol):
    def search(self, query: str, limit: int) -> Iterable[ChunkCandidate | None]:
        """Return ranked candidates. None represents a malformed index record."""


@dataclass(frozen=True)
class VerifiedChunk:
    ref: ReleaseRef
    chunk_id: str
    source: str
    text: str
    chunk_sha256: str
    score: float | None = None


@dataclass(frozen=True)
class RejectedCandidate:
    rank: int
    code: str


@dataclass(frozen=True)
class SearchResult:
    hits: tuple[VerifiedChunk, ...]
    rejections: tuple[RejectedCandidate, ...]


def retrieve(index: ChunkIndex, store: ReleaseStore, query: str, *, limit: int = 5,
             candidate_limit: int = 20, score_threshold: float = 0.0) -> SearchResult:
    if (not isinstance(query, str) or not query.strip()
            or type(limit) is not int or type(candidate_limit) is not int
            or not 1 <= limit <= candidate_limit <= 1000 or not _valid_score(score_threshold)):
        raise TrustError("INVALID_QUERY")
    candidates = tuple(islice(index.search(query, candidate_limit), candidate_limit))
    hits = []
    rejections = []
    seen = set()
    documents: dict[str, tuple[ReleaseRef, KnowledgeDocument]] = {}
    with store.snapshot() as snapshot:
        for rank, candidate in enumerate(candidates, start=1):
            try:
                if (not isinstance(candidate, ChunkCandidate)
                        or not all(is_identifier(value) for value in (
                            candidate.scope, candidate.artifact_id, candidate.version, candidate.chunk_id))
                        or not isinstance(candidate.text, str)):
                    raise TrustError("INVALID_CANDIDATE")
                if candidate.scope != store.scope:
                    raise TrustError("SCOPE_MISMATCH")
                if candidate.artifact_id not in documents:
                    release = snapshot.load("knowledge", candidate.artifact_id)
                    documents[candidate.artifact_id] = release.ref, parse_knowledge(release.content)
                ref, document = documents[candidate.artifact_id]
                hit = _verify_chunk(candidate, ref, document)
                identity = candidate.artifact_id, candidate.chunk_id
                if identity not in seen and (hit.score or 0.0) >= score_threshold:
                    hits.append(hit)
                    seen.add(identity)
            except TrustError as exc:
                if exc.code in {"STATE_UNAVAILABLE", "STATE_INVALID"}:
                    # A shared trust dependency failed: discard partial results and report 503.
                    raise
                rejections.append(RejectedCandidate(rank, exc.code))
            if len(hits) == limit:
                break
    return SearchResult(tuple(hits), tuple(rejections))


def _verify_chunk(candidate: ChunkCandidate, ref: ReleaseRef,
                  document: KnowledgeDocument) -> VerifiedChunk:
    if candidate.version != ref.tag:
        raise TrustError("VERSION_MISMATCH")
    text = document.chunks.get(candidate.chunk_id)
    if text is None:
        raise TrustError("UNKNOWN_CHUNK")
    try:
        digest = sha256_hex(candidate.text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise TrustError("INVALID_CANDIDATE") from exc
    if digest != sha256_hex(text.encode("utf-8")):
        raise TrustError("CHUNK_DIGEST_MISMATCH")
    if candidate.score is not None and not _valid_score(candidate.score):
        raise TrustError("INVALID_CANDIDATE")
    return VerifiedChunk(ref, candidate.chunk_id, document.source, text, digest, candidate.score)


def _valid_score(value: object) -> bool:
    return type(value) in (int, float) and 0 <= value <= 1


class ChromaChunkIndex:
    """Store search candidates in Chroma with a caller-provided dense embedder."""

    def __init__(self, collection: Collection, embed: Callable[[list[str]], list[list[float]]]):
        self._collection = collection
        self._embed = embed
        self.supports_scores = (collection.configuration.get("hnsw") or {}).get("space") == "cosine"

    def add_release(self, release: VerifiedRelease) -> None:
        ref = release.ref
        if ref.kind != "knowledge":
            raise TrustError("INVALID_CONTENT")
        document = parse_knowledge(release.content)
        texts = list(document.chunks.values())
        try:
            self._collection.upsert(
                ids=[sha256_hex(canonical_json([ref.scope, ref.artifact_id, ref.tag, chunk_id]))
                     for chunk_id in document.chunks],
                documents=texts,
                embeddings=self._embed(texts),
                metadatas=[
                    {"scope": ref.scope, "artifact_id": ref.artifact_id, "revision": ref.version,
                     "version": ref.tag, "chunk_id": chunk_id}
                    for chunk_id in document.chunks
                ],
            )
            self._collection.delete(where={"$and": [
                {"scope": ref.scope}, {"artifact_id": ref.artifact_id},
                {"revision": {"$lt": ref.version}},
            ]})
        except Exception as exc:
            raise TrustError("INDEX_UNAVAILABLE") from exc

    def search(self, query: str, limit: int) -> tuple[ChunkCandidate | None, ...]:
        try:
            result = self._collection.query(
                query_embeddings=self._embed([query]), n_results=limit,
                include=["documents", "metadatas", "distances"],
            )
            rows = zip(result["documents"][0], result["metadatas"][0], result["distances"][0], strict=True)
            return tuple(_candidate(text, metadata, distance, self.supports_scores)
                         for text, metadata, distance in rows)
        except Exception as exc:
            # A vector service or embedding failure cannot authorize raw candidates.
            raise TrustError("INDEX_UNAVAILABLE") from exc


def _candidate(text: object, metadata: object, distance: float, cosine: bool) -> ChunkCandidate | None:
    fields = ("scope", "artifact_id", "version", "chunk_id")
    if (not isinstance(text, str) or not isinstance(metadata, dict)
            or not all(isinstance(metadata.get(field), str) for field in fields)):
        return None
    if cosine and (type(distance) not in (float, int) or not isfinite(distance)):
        return None
    score = max(0.0, min(1.0, 1.0 - distance)) if cosine else None
    return ChunkCandidate(*(metadata[field] for field in fields), text, score)


def open_bge_m3_index(path: Path, collection_name: str, *, model_name: str = "BAAI/bge-m3",
                      revision: str | None = None) -> ChromaChunkIndex:
    """Open persistent Chroma with the CPU dense encoder from BAAI/BGE-M3."""
    import chromadb
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_name, revision=revision, device="cpu", trust_remote_code=False)
    collection = chromadb.PersistentClient(path=str(path)).get_or_create_collection(
        collection_name, embedding_function=None,
    )

    def embed(texts: list[str]) -> list[list[float]]:
        return model.encode(texts, normalize_embeddings=True).tolist()

    return ChromaChunkIndex(collection, embed)
