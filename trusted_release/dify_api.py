"""Dify External Knowledge API with a read-only release trust configuration."""

from hmac import compare_digest
import logging
import os
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .handoff import open_store
from .protocol import TrustError
from .rag import ChromaChunkIndex, retrieve
from .store import ReleaseStore


logger = logging.getLogger(__name__)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RetrievalSetting(StrictModel):
    top_k: Annotated[int, Field(ge=1, le=100)]
    score_threshold: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class MetadataCondition(StrictModel):
    logical_operator: Literal["and", "or"] = "and"
    conditions: list[dict] = Field(default_factory=list)


class RetrievalRequest(StrictModel):
    knowledge_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
    retrieval_setting: RetrievalSetting
    metadata_condition: MetadataCondition | None = None


def _reply(body: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def _error(status: int, number: int, message: str) -> JSONResponse:
    return _reply({"error_code": number, "error_msg": message}, status)


def create_retrieval_app(store: ReleaseStore, index: ChromaChunkIndex, api_key: str) -> FastAPI:
    if len(api_key) < 24 or not api_key.isascii() or any(c.isspace() for c in api_key):
        raise ValueError("ROLE_C_DIFY_KEY must be an ASCII secret of at least 24 characters")
    if not index.supports_scores:
        raise ValueError("Dify retrieval requires a cosine-distance collection")
    app = FastAPI(title="Trusted campus knowledge", docs_url=None, redoc_url=None, openapi_url=None)
    secret = api_key.encode("ascii")

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if request.method == "POST":
            scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not credentials:
                return _error(401, 1001, "BEARER_REQUIRED")
            if not compare_digest(credentials.encode("utf-8"), secret):
                return _error(401, 1002, "AUTHORIZATION_FAILED")
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request, exc):
        return _error(422, 2002, "INVALID_REQUEST")

    @app.post("/retrieval")
    def get_knowledge(request: RetrievalRequest):
        if request.knowledge_id != store.scope:
            return _error(404, 2001, "KNOWLEDGE_NOT_FOUND")
        if request.metadata_condition and request.metadata_condition.conditions:
            return _error(422, 2002, "METADATA_FILTER_UNSUPPORTED")
        setting = request.retrieval_setting
        try:
            result = retrieve(
                index, store, request.query, limit=setting.top_k,
                candidate_limit=max(20, setting.top_k * 4), score_threshold=setting.score_threshold,
            )
        except TrustError as exc:
            return _error(503, 2003, exc.code)
        for rejected in result.rejections:
            logger.info("Rejected knowledge candidate rank=%d code=%s", rejected.rank, rejected.code)
        return _reply({"records": [
            {"content": hit.text, "score": hit.score, "title": hit.source,
             "metadata": {"scope": hit.ref.scope, "artifact_id": hit.ref.artifact_id,
                          "release_version": hit.ref.tag, "chunk_id": hit.chunk_id,
                          "chunk_sha256": hit.chunk_sha256}}
            for hit in result.hits
        ]})

    return app


def create_app() -> FastAPI:
    from .embedding import open_onnx_index

    api_key = os.environ["ROLE_C_DIFY_KEY"]
    store = open_store(Path(os.environ["ROLE_C_TRUST_CONFIG"]))
    index = open_onnx_index(
        Path(os.environ["ROLE_C_INDEX_PATH"]), Path(os.environ["ROLE_C_BGE_MODEL_DIR"]),
        create=False,
    )
    return create_retrieval_app(store, index, api_key)
