"""Vector store interface.

Wraps the embedding model and the vector database: upsert chunks, similarity
search, delete by source. The rest of the app talks to this module rather than
to the Chroma client directly.

Backend is Chroma in embedded/persistent mode (data/chroma_db/); keep the
surface small enough that swapping it stays a one-file change.

One collection per access tier, not one collection with a tier filter. Both
enforce the same rule, but they fail in opposite directions: a forgotten
metadata filter returns every tier, whereas a forgotten collection returns
nothing. `query()` takes the caller's allowed tiers as a required argument and
there is no code path that searches without them.

Note the embedded chunk text is stored alongside the vectors, so this directory
holds restricted content in the clear. Filesystem access to data/chroma_db/
bypasses auth entirely — that is a property of the design, not a bug to fix
here, and it belongs in the phase 2 writeup.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any, Iterable

import chromadb

from app.secrets import CHROMA_DIR

# Cosine keeps distances in a comparable 0..2 range across collections, which
# matters because query() merges results from several of them.
_COLLECTION_METADATA = {"hnsw:space": "cosine"}

_client: chromadb.ClientAPI | None = None

# One lock over the shared Chroma client. It is a module global touched from two
# threads — the event loop thread running /query and /chat, and the connector
# sync worker thread (asyncio.to_thread) — and PersistentClient is not safe for
# concurrent cross-thread use: an overlapping read/write wedges the client and
# every later retrieval then AttributeErrors until restart. Every public
# function below holds this for its whole Chroma interaction.
# ponytail: single global lock; split per-collection only if it ever bottlenecks
# (it won't on a single-process laptop deployment).
_CLIENT_LOCK = threading.RLock()


def _get_client() -> chromadb.ClientAPI:
    global _client
    if _client is None:
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return _client


def _collection(tier: str) -> chromadb.Collection:
    """One collection per tier. Chroma's default embedder runs locally."""
    return _get_client().get_or_create_collection(
        name=f"docs_{tier}", metadata=_COLLECTION_METADATA
    )


def chunk_id(source: str, index: int) -> str:
    """Stable id so re-ingesting a document updates rather than duplicates."""
    return hashlib.sha256(f"{source}:{index}".encode("utf-8")).hexdigest()[:32]


def add_chunks(tier: str, chunks: Iterable[tuple[str, str, dict[str, Any]]]) -> int:
    """Upsert (id, text, metadata) triples into `tier`'s collection.

    The tier is written into metadata as well as deciding the collection —
    redundant on purpose, so a result can be attributed after retrieval.
    """
    ids, documents, metadatas = [], [], []
    for chunk_key, text, metadata in chunks:
        ids.append(chunk_key)
        documents.append(text)
        metadatas.append({**metadata, "tier": tier})
    if not ids:
        return 0
    with _CLIENT_LOCK:
        _collection(tier).upsert(ids=ids, documents=documents, metadatas=metadatas)
    return len(ids)


def query(
    allowed_tiers: tuple[str, ...], text: str, k: int = 4
) -> list[dict[str, Any]]:
    """Search only the tiers the caller may read, nearest first.

    An empty `allowed_tiers` returns nothing. That is the fail-closed case and
    callers must not special-case it into an unfiltered search.
    """
    if not allowed_tiers:
        return []

    hits: list[dict[str, Any]] = []
    with _CLIENT_LOCK:
        for tier in allowed_tiers:
            collection = _collection(tier)
            if collection.count() == 0:
                continue
            result = collection.query(
                query_texts=[text],
                n_results=min(k, collection.count()),
                include=["documents", "metadatas", "distances"],
            )
            for document, metadata, distance in zip(
                result["documents"][0], result["metadatas"][0], result["distances"][0]
            ):
                hits.append({"text": document, "metadata": metadata, "distance": distance})

    hits.sort(key=lambda hit: hit["distance"])
    return hits[:k]


def delete_source(tier: str, source: str) -> None:
    with _CLIENT_LOCK:
        _collection(tier).delete(where={"source": source})


def indexed_state(tier: str, origin: str) -> dict[str, str]:
    """Map source id -> content_hash for everything in `tier` from `origin`.

    Lets a connector diff upstream against what is already indexed, so a sync
    can skip unchanged records instead of re-embedding the whole corpus.
    """
    with _CLIENT_LOCK:
        result = _collection(tier).get(where={"origin": origin}, include=["metadatas"])
    return {
        metadata["source"]: metadata.get("content_hash", "")
        for metadata in result["metadatas"]
        if metadata.get("source")
    }


def stats() -> dict[str, int]:
    """Chunk count per tier. Metadata only — safe to expose to an admin."""
    with _CLIENT_LOCK:
        return {tier: _collection(tier).count() for tier in ("public", "internal", "restricted")}
