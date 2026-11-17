"""CPU dense BGE-M3 embeddings using the local INT8 ONNX export."""

from pathlib import Path

import chromadb
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from .rag import ChromaChunkIndex


COLLECTION = "campus-bge-m3-int8-v1"


class BgeM3Onnx:
    def __init__(self, model_dir: Path):
        self._tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self._tokenizer.enable_truncation(max_length=512)
        self._tokenizer.enable_padding(pad_id=self._tokenizer.token_to_id("<pad>"))
        options = ort.SessionOptions()
        options.intra_op_num_threads = 4
        self._model = ort.InferenceSession(
            str(model_dir / "onnx" / "model_int8.onnx"),
            sess_options=options, providers=["CPUExecutionProvider"],
        )

    def __call__(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        batches = []
        for offset in range(0, len(texts), 16):
            tokens = self._tokenizer.encode_batch(texts[offset:offset + 16])
            inputs = {
                "input_ids": np.asarray([row.ids for row in tokens], dtype=np.int64),
                "attention_mask": np.asarray([row.attention_mask for row in tokens], dtype=np.int64),
            }
            (hidden,) = self._model.run(["last_hidden_state"], inputs)
            vectors = hidden[:, 0, :]
            norms = np.linalg.norm(vectors, axis=1, keepdims=True)
            if not np.all(np.isfinite(norms) & (norms > 0)):
                raise ValueError("Embedding model produced invalid vectors")
            batches.extend((vectors / norms).tolist())
        return batches


def open_onnx_index(path: Path, model_dir: Path, *, create: bool = True) -> ChromaChunkIndex:
    client = chromadb.PersistentClient(path=str(path))
    if create:
        collection = client.get_or_create_collection(
            COLLECTION, embedding_function=None, configuration={"hnsw": {"space": "cosine"}},
        )
    else:
        collection = client.get_collection(COLLECTION, embedding_function=None)
    return ChromaChunkIndex(collection, BgeM3Onnx(model_dir))
