"""RAG vector store for threat intelligence.

Backends:
  * Milvus server (MILVUS_URI=http://host:19530) - used by Docker Compose / Helm
  * Milvus Lite   (MILVUS_URI unset, Linux/macOS) - embedded, a single local file
  * Built-in      (Windows, or if Milvus is not installed) - NumPy cosine search

Embeddings:
  * fastembed (BAAI/bge-small-en-v1.5, 384-d, CPU friendly) if installed
  * hash     - zero-download feature hashing, works everywhere (default fallback)
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sys
from pathlib import Path

import numpy as np

log = logging.getLogger("soc.rag")
DIM = 384
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._:/-]*")


class HashEmbedder:
    name = "hash"

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), DIM), dtype=np.float32)
        for row, text in enumerate(texts):
            tokens = _TOKEN.findall(text.lower())
            feats = tokens + [f"{a} {b}" for a, b in zip(tokens, tokens[1:])]
            for tok in tokens:  # char trigrams give fuzzy matching on IOCs and words
                padded = f"#{tok}#"
                feats.extend(padded[i : i + 3] for i in range(max(1, len(padded) - 2)))
            for feat in feats:
                h = int.from_bytes(hashlib.blake2b(feat.encode(), digest_size=8).digest(), "little")
                out[row, h % DIM] += 1.0 if (h >> 63) & 1 else -1.0
            norm = np.linalg.norm(out[row])
            if norm:
                out[row] /= norm
        return out


class FastEmbedder:
    name = "fastembed"

    def __init__(self):
        from fastembed import TextEmbedding  # type: ignore

        self._model = TextEmbedding("BAAI/bge-small-en-v1.5")

    def embed(self, texts: list[str]) -> np.ndarray:
        return np.array(list(self._model.embed(texts)), dtype=np.float32)


def make_embedder(backend: str):
    if backend in ("auto", "fastembed"):
        try:
            return FastEmbedder()
        except Exception as exc:  # not installed / model download failed
            if backend == "fastembed":
                log.warning("fastembed unavailable (%s); using hash embeddings", exc)
    return HashEmbedder()


def _int_id(key: str) -> int:
    return int.from_bytes(hashlib.sha1(key.encode()).digest()[:8], "big") & 0x7FFFFFFFFFFFFFFF


class LocalVectorStore:
    """Persistent NumPy store - fine for tens of thousands of records on a laptop."""

    backend = "builtin"

    def __init__(self, path: Path):
        self.path = path
        self.ids: list[str] = []
        self.vectors = np.zeros((0, DIM), dtype=np.float32)
        if path.exists():
            try:
                blob = np.load(path, allow_pickle=False)
                self.vectors = blob["vectors"].astype(np.float32)
                self.ids = json.loads(str(blob["ids"]))
            except Exception as exc:
                log.warning("could not load %s (%s); starting empty", path, exc)

    def upsert(self, ids: list[str], vectors: np.ndarray) -> None:
        index = {k: i for i, k in enumerate(self.ids)}
        new_rows = []
        for key, vec in zip(ids, vectors):
            if key in index:
                self.vectors[index[key]] = vec
            else:
                index[key] = len(self.ids) + len(new_rows)
                new_rows.append(vec)
                self.ids.append(key)
        if new_rows:
            self.vectors = np.vstack([self.vectors, np.array(new_rows, dtype=np.float32)])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        np.savez(self.path, vectors=self.vectors, ids=np.array(json.dumps(self.ids)))

    def search(self, vector: np.ndarray, k: int) -> list[tuple[str, float]]:
        if not self.ids:
            return []
        scores = self.vectors @ vector
        top = np.argsort(-scores)[:k]
        return [(self.ids[i], float(scores[i])) for i in top]

    def count(self) -> int:
        return len(self.ids)


class MilvusVectorStore:
    backend = "milvus"

    def __init__(self, uri: str, token: str, collection: str):
        from pymilvus import MilvusClient  # type: ignore

        self.client = MilvusClient(uri=uri, token=token) if token else MilvusClient(uri=uri)
        self.collection = collection
        self.backend = "milvus-lite" if uri.endswith(".db") else "milvus"
        if not self.client.has_collection(collection):
            self.client.create_collection(collection_name=collection, dimension=DIM, metric_type="COSINE")

    def upsert(self, ids: list[str], vectors: np.ndarray) -> None:
        rows = [{"id": _int_id(k), "vector": v.tolist(), "key": k} for k, v in zip(ids, vectors)]
        for i in range(0, len(rows), 500):
            self.client.upsert(collection_name=self.collection, data=rows[i : i + 500])

    def search(self, vector: np.ndarray, k: int) -> list[tuple[str, float]]:
        self.client.load_collection(collection_name=self.collection)  # Milvus must load before search
        res = self.client.search(collection_name=self.collection, data=[vector.tolist()], limit=k,
                                 output_fields=["key"])
        hits = res[0] if res else []
        return [(h["entity"]["key"], float(h["distance"])) for h in hits]

    def count(self) -> int:
        try:
            stats = self.client.get_collection_stats(self.collection)
            return int(stats.get("row_count", 0))
        except Exception:
            return -1


class ThreatIntelRAG:
    """Embeds intel records, stores vectors, and answers semantic queries."""

    def __init__(self, settings, db):
        self.db = db
        self.embedder = make_embedder(settings.embedding_backend)
        collection = f"threat_intel_{self.embedder.name}"
        self.store = None
        uri = settings.milvus_uri
        if not uri and sys.platform != "win32":
            uri = str(settings.data_dir / "milvus_lite.db")
        if uri and settings.vector_store != "builtin":
            try:
                self.store = MilvusVectorStore(uri, settings.milvus_token, collection)
            except Exception as exc:
                log.warning("Milvus unavailable at %s (%s); using built-in vector store", uri, exc)
        if self.store is None:
            self.store = LocalVectorStore(settings.data_dir / f"{collection}.npz")

    @property
    def backend(self) -> str:
        return f"{self.store.backend} · {self.embedder.name} embeddings"

    def index(self, records: list[dict]) -> int:
        if not records:
            return 0
        for i in range(0, len(records), 256):
            batch = records[i : i + 256]
            vectors = self.embedder.embed([f"{r['title']}\n{r['text']}" for r in batch])
            self.store.upsert([r["id"] for r in batch], vectors)
        return len(records)

    def search(self, query: str, k: int = 5, min_score: float = 0.05) -> list[dict]:
        if not query.strip():
            return []
        vector = self.embedder.embed([query])[0]
        try:
            raw = self.store.search(vector, k)
        except Exception as exc:  # a vector-store hiccup must never stop triage
            log.warning("vector search failed (%s); continuing without intel matches", exc)
            return []
        hits = [(key, score) for key, score in raw if not math.isnan(score)]
        rows = self.db.get_intel([key for key, _ in hits])
        results = []
        for key, score in hits:
            if key in rows and score >= min_score:
                results.append({**rows[key], "score": round(score, 3)})
        return results

    def count(self) -> int:
        return self.store.count()
