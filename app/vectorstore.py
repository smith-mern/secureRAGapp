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
from pathlib import Path
from typing import Any, Iterable

import chromadb

from app import audit_log
from app.secrets import CHROMA_DIR

# Cosine keeps distances in a comparable 0..2 range across collections, which
# matters because query() merges results from several of them.
_COLLECTION_METADATA = {"hnsw:space": "cosine"}

_client: chromadb.ClientAPI | None = None
_embedder: Any = None

# One lock over the shared Chroma client. It is a module global touched from two
# threads — the event loop thread running /query and /chat, and the connector
# sync worker thread (asyncio.to_thread) — and PersistentClient is not safe for
# concurrent cross-thread use: an overlapping read/write wedges the client and
# every later retrieval then AttributeErrors until restart. Every public
# function below holds this for its whole Chroma interaction.
# ponytail: single global lock; split per-collection only if it ever bottlenecks
# (it won't on a single-process laptop deployment).
_CLIENT_LOCK = threading.RLock()


class ModelIntegrityError(RuntimeError):
    """The on-disk embedding model does not match its pin. Fail closed.

    Never carries file contents — only which file failed, which is safe to log.
    """


# SHA256 of each extracted file of the default embedding model. Derived from the
# `onnx.tar.gz` archive that chromadb itself pins by SHA256 (`_MODEL_SHA256` in
# chromadb/utils/embedding_functions/onnx_mini_lm_l6_v2.py), *not* from whatever
# happened to be in the local cache — a pin taken from the disk you are trying to
# distrust proves nothing.
#
# Regenerate after a chromadb upgrade that moves the model (the mismatch error
# will tell you), by hashing the members of that verified archive:
#
#   python - <<'EOF'
#   import hashlib, os, tarfile
#   from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2 as E
#   arch = os.path.join(E.DOWNLOAD_PATH, E.ARCHIVE_FILENAME)
#   assert hashlib.sha256(open(arch,"rb").read()).hexdigest() == E._MODEL_SHA256
#   with tarfile.open(arch, "r:gz") as tar:
#       for m in sorted(tar.getmembers(), key=lambda m: m.name):
#           if m.isfile():
#               print(os.path.basename(m.name), hashlib.sha256(tar.extractfile(m).read()).hexdigest())
#   EOF
_MODEL_FILE_SHA256 = {
    "config.json": "b567c7d5a55b636c95186aaf993f9a8920842b7e05a9e703e68b23cab2c3a670",
    "model.onnx": "4f148ba8ae9c2c7fbee4af2b132db8d06c6a6545b47fc83bbb98c3d22b8393e6",
    "special_tokens_map.json": "b6d346be366a7d1d48332dbc9fdf3bf8960b5d879522b7799ddba59e76237ee3",
    "tokenizer.json": "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0",
    "tokenizer_config.json": "7702051bbc4953b94d47fa1d61b42ed4cbb3c71b501a8dd7183a823f8bea1f20",
    "vocab.txt": "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
}

# Re-hashed only when size/mtime changes — 90 MB per query is not payable, and
# everything else here is small enough to read every time.
_LARGE_FILES = frozenset({"model.onnx"})

_model_verified = False
_seen_metadata: dict[str, tuple[int, int]] = {}


def _extracted_model_dir() -> Path:
    """Where chromadb keeps the extracted model. Read from chromadb, not hardcoded.

    Taking the path from the library means a version that relocates its cache
    fails the check loudly instead of verifying an empty directory and passing.
    """
    from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

    return Path(ONNXMiniLM_L6_V2.DOWNLOAD_PATH) / ONNXMiniLM_L6_V2.EXTRACTED_FOLDER_NAME


def _fingerprint(path: Path) -> tuple[int, int, int, int]:
    """Cheap "has this file changed?" key for the one file too big to re-hash.

    `st_ctime_ns` and `st_ino` are here because mtime and size are *forgeable*:
    `touch -r` copies a timestamp across and a crafted file can be padded to the
    original length, which is exactly how this check was bypassed in testing.
    Neither of those touches ctime — the kernel sets it on any inode change and
    offers no API to backdate it — and replacing a file in place almost always
    lands on a new inode. Defeating this now needs raw device writes or control
    of the system clock, which is a different class of access to `touch -r`.
    """
    stat = path.stat()
    return (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino)


def verify_embedding_model() -> None:
    """Hash the extracted model files before using them. Raises on mismatch.

    chromadb verifies the download archive and then, on every later start, checks
    only that the six extracted files *exist* — so the model that decides what
    every tier retrieves is a mutable file that is never re-read for integrity.
    Anyone who can write that cache silently steers retrieval for all three
    tiers, with no upload, no query payload, and no log line.

    Fails closed: an unverified embedder is worse than a broken app, because a
    wrong answer built from attacker-chosen chunks looks exactly like a right one.

    A missing cache is not a failure — chromadb has not downloaded it yet, and it
    fetches under its own SHA-pinned archive. Verification is simply not marked
    done, so the next call through here checks the files once they exist.

    Runs on every call rather than once per process, because "verified at boot"
    says nothing about the file being read now. The cost is kept sane by what
    gets re-read: the five small files (~1 MB total) are re-hashed every time,
    and `model.onnx` (90 MB) is re-hashed only when its size or mtime moves.
    That closes replace-after-verification for anything that does not also
    forge the metadata; an attacker who copies mtime and size across (`touch
    -r`) still gets one round. Nothing here replaces mounting the cache
    read-only, which is the control that makes the question moot.
    """
    global _model_verified
    folder = _extracted_model_dir()
    for name, expected in _MODEL_FILE_SHA256.items():
        path = folder / name
        if not path.is_file():
            _model_verified = False
            return  # not downloaded yet; chromadb fetches under its archive pin

        # Skip re-hashing the large file when its metadata is unchanged since the
        # last check. Small files are cheap enough to read every time.
        if name in _LARGE_FILES and _seen_metadata.get(name) == _fingerprint(path):
            continue

        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        _seen_metadata[name] = _fingerprint(path)
        if actual != expected:
            audit_log.log(
                "model.integrity", decision="deny", artifact=name,
                path=str(folder), reason="sha256_mismatch",
            )
            raise ModelIntegrityError(
                f"Embedding model file '{name}' does not match its pinned SHA256. "
                "Retrieval is disabled. If you upgraded chromadb, regenerate the "
                "pin in app/vectorstore.py from its verified archive; otherwise "
                "treat the model cache as compromised and delete it."
            )

    # Log the pass once; a line per query would bury the deny that matters.
    if not _model_verified:
        _model_verified = True
        audit_log.log(
            "model.integrity", decision="allow", files=len(_MODEL_FILE_SHA256),
            path=str(folder),
        )


def _get_client() -> chromadb.ClientAPI:
    # PersistentClient — embedded, in-process, no HTTP surface. Not only a
    # deployment convenience: chromadb 1.5.9 carries a pre-auth code-injection
    # advisory (CVE-2026-45829) in its FastAPI *server*, with no patched release.
    # Embedded means that module is never imported, so the advisory is present
    # and unreachable. Switching this to HttpClient makes it reachable — see
    # redteam/findings/supply-chain-vulnerabilities.md, sub-finding D.
    global _client
    if _client is None:
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return _client


def _collection(tier: str) -> chromadb.Collection:
    """One collection per tier. Chroma's default embedder runs locally.

    Every upsert and every query reaches the embedder through here, which is why
    the integrity check hangs off this function rather than off startup: a model
    swapped while the process is running is caught, and a deployment that never
    embeds never pays for the hashing.
    """
    verify_embedding_model()
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


CURATED_ORIGIN = "curated"


def query_by_trust(
    allowed_tiers: tuple[str, ...], text: str, k: int = 4
) -> list[dict[str, Any]]:
    """Search curated and password-writable content separately, then merge.

    One search over everything gives every document the same shot at a finite
    number of slots, which makes retrieval a popularity contest an uploader can
    win by volume: enough near-duplicate poison documents push the curated
    document out of the candidate set, and a provenance rule downstream can only
    prefer a curated chunk that was actually retrieved. Widening the window does
    not fix that — it just names a number of copies the attacker has to exceed.

    Giving each trust class its own budget removes the contest. Curated content
    competes only against other curated content, so no quantity of uploads can
    evict it; uploads compete only against each other. Whether the unverified
    half is then used at all is `retriever.prefer_trusted`'s decision.
    """
    curated = query(allowed_tiers, text, k=k, where={"origin": CURATED_ORIGIN})
    unverified = query(
        allowed_tiers, text, k=k, where={"origin": {"$ne": CURATED_ORIGIN}}
    )
    return curated + unverified


def query(
    allowed_tiers: tuple[str, ...],
    text: str,
    k: int = 4,
    where: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Search only the tiers the caller may read, nearest first.

    An empty `allowed_tiers` returns nothing. That is the fail-closed case and
    callers must not special-case it into an unfiltered search.

    `where` is a Chroma metadata filter, used by `query_by_trust` to give each
    trust class its own slots. It narrows a search that is already tier-scoped;
    it can never widen one.
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
                where=where,
                include=["documents", "metadatas", "distances"],
            )
            for document, metadata, distance in zip(
                result["documents"][0], result["metadatas"][0], result["distances"][0]
            ):
                hits.append({"text": document, "metadata": metadata, "distance": distance})

    hits.sort(key=lambda hit: hit["distance"])
    return hits[:k]


def embed(texts: list[str]) -> list[list[float]]:
    """Embed arbitrary text with the same local model the collections use.

    For comparing two pieces of text to each other — not for storage. The caller
    that needs this is the agent's relevance gate, which has to ask "is the query
    the model chose related to what the user asked?" and cannot answer that from
    a distance to a document. Runs on this machine like every other embedding.
    """
    global _embedder
    verify_embedding_model()
    with _CLIENT_LOCK:
        if _embedder is None:
            from chromadb.utils import embedding_functions

            _embedder = embedding_functions.DefaultEmbeddingFunction()
        return [list(vector) for vector in _embedder(texts)]


def mark_reviewed(tier: str, source: str, reviewer: str) -> int:
    """Flip every chunk of `source` to reviewed. Returns how many changed.

    Review is recorded on the chunks rather than in a side table because
    retrieval reads chunks and nothing else — a trust decision kept anywhere the
    retrieval path does not look is a trust decision that does not apply.

    Returns 0 for an unknown source, which the caller reports as a 404 rather
    than pretending to have approved something.
    """
    with _CLIENT_LOCK:
        collection = _collection(tier)
        found = collection.get(where={"source": source}, include=["metadatas"])
        ids = found["ids"]
        if not ids:
            return 0
        collection.update(
            ids=ids,
            metadatas=[
                {**metadata, "reviewed": True, "reviewed_by": reviewer}
                for metadata in found["metadatas"]
            ],
        )
    return len(ids)


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
