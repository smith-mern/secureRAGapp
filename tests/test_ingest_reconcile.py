"""Ingestion replaces and retracts — it is not add-only.

Chunk ids are `source:index`, so writing a shorter version of a document only
overwrites the ids it reuses. Without an explicit delete the old tail stays
embedded under the higher ids, and a document deleted from disk stays in the
index for good. Both leave the vector store answering from content the corpus
no longer contains, which no downstream trust or clearance rule can catch — the
chunk is curated and in-tier, it is just stale.

Stubs the vector store: this is about which sources get written and retracted,
not about embedding.
"""

from __future__ import annotations

from app import ingest


class FakeStore:
    """Records upserts and deletes, keyed by source."""

    def __init__(self) -> None:
        self.chunks: dict[str, list[str]] = {}

    def delete_source(self, tier: str, source: str) -> None:
        self.chunks.pop(source, None)

    def add_chunks(self, tier, chunks) -> int:
        written = list(chunks)
        for _id, text, metadata in written:
            self.chunks.setdefault(metadata["source"], []).append(text)
        return len(written)

    def indexed_state(self, tier: str, origin: str) -> dict[str, str]:
        return {source: "" for source in self.chunks}


def _patch(monkeypatch, store: FakeStore) -> None:
    for name in ("delete_source", "add_chunks", "indexed_state"):
        monkeypatch.setattr(ingest.vectorstore, name, getattr(store, name))


def _write(base, name: str, text: str):
    path = base / "internal" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_shrinking_a_document_removes_its_old_tail(monkeypatch, tmp_path):
    store = FakeStore()
    _patch(monkeypatch, store)

    secret = "the merger codename is BLUEJAY"
    path = _write(tmp_path, "policy.md", "a" * ingest.CHUNK_CHARS + secret)
    ingest.ingest_tier("internal", base=tmp_path)
    assert len(store.chunks["internal/policy.md"]) > 1

    path.write_text("short public summary")
    ingest.ingest_tier("internal", base=tmp_path)

    assert store.chunks["internal/policy.md"] == ["short public summary"]


def test_deleting_a_document_retracts_it_from_the_index(monkeypatch, tmp_path):
    store = FakeStore()
    _patch(monkeypatch, store)

    path = _write(tmp_path, "gone.md", "internal salary bands")
    _write(tmp_path, "stays.md", "the office opens at nine")
    ingest.ingest_tier("internal", base=tmp_path)

    path.unlink()
    ingest.ingest_tier("internal", base=tmp_path)

    assert set(store.chunks) == {"internal/stays.md"}


def test_the_sweep_does_not_retract_another_origin(monkeypatch, tmp_path):
    """An uploads run must not retract curated content, or vice versa.

    Both roots feed the same collection, so a sweep scoped to the tier alone
    would let a `/ingest` of an empty uploads directory delete the whole
    curated corpus for that tier.
    """
    store = FakeStore()
    _patch(monkeypatch, store)
    store.chunks["internal/handbook.md"] = ["curated text"]
    # Only curated sources are indexed under the curated origin.
    monkeypatch.setattr(
        ingest.vectorstore,
        "indexed_state",
        lambda tier, origin: {} if origin == ingest.UPLOAD_ORIGIN else store.chunks,
    )

    ingest.ingest_tier("internal", base=tmp_path, origin=ingest.UPLOAD_ORIGIN)

    assert "internal/handbook.md" in store.chunks
