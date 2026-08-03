"""Document ingestion pipeline.

Takes source documents from data/documents/<tier>/, extracts text, chunks it,
and hands chunks to the vectorstore for embedding and indexing. Attaches
per-chunk metadata — source, tier — that authorization depends on at query time.

The tier comes from the directory a document was loaded from
(data/documents/{public,internal,restricted}) and is written into chunk metadata
here. After chunking, the directory is gone: if the tier isn't recorded at
ingest, the vector store has no way to enforce it and every tier becomes
readable by every caller.

Ingested content is untrusted. Anything read here may later be retrieved into
the model's context, so this is the first place to record provenance and the
last place that should treat document text as instructions. Injection screening
happens at retrieval rather than here — a document that is malicious for one
caller is still evidence for a red-team writeup, so it gets indexed and
filtered on the way out, not silently dropped on the way in.

Validates file type, size, and path at the boundary; never executes or
evaluates document content.
"""

from __future__ import annotations

from pathlib import Path

from app import audit_log, vectorstore
from app.auth import TIERS
from app.filters.input_validation import ValidationError, safe_document_path
from app.secrets import DOCUMENTS_DIR, optional

ALLOWED_SUFFIXES = {".txt", ".md"}
MAX_FILE_BYTES = 2 * 1024 * 1024

CHUNK_CHARS = int(optional("CHUNK_CHARS", "1000"))
CHUNK_OVERLAP = int(optional("CHUNK_OVERLAP", "150"))


def chunk_text(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Fixed-width overlapping chunks.

    ponytail: character windows, not sentence- or token-aware splitting. Good
    enough to retrieve against; swap in a real splitter if recall disappoints.
    """
    if overlap >= size:
        raise ValueError("overlap must be smaller than size")
    text = text.strip()
    if not text:
        return []
    step = size - overlap
    return [text[i : i + size] for i in range(0, len(text), step) if text[i : i + size].strip()]


def _read_document(path: Path) -> str | None:
    """Read one file, or return None with the reason logged."""
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        audit_log.log("ingest.skip", decision="deny", file=path.name, reason="suffix")
        return None
    if path.stat().st_size > MAX_FILE_BYTES:
        audit_log.log("ingest.skip", decision="deny", file=path.name, reason="too_large")
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        audit_log.log("ingest.skip", decision="deny", file=path.name, reason="not_utf8")
        return None


def ingest_tier(tier: str) -> int:
    """Index every document in one tier's directory. Returns chunks written."""
    if tier not in TIERS:
        raise ValidationError("unknown tier")

    # Resolve the root once and compare resolved-against-resolved throughout.
    # Mixing the two silently breaks wherever the root has a symlink in its
    # ancestry (/var -> /private/var on macOS, for one).
    root = DOCUMENTS_DIR.resolve()
    tier_dir = root / tier
    if not tier_dir.is_dir():
        return 0

    written = 0
    for path in sorted(tier_dir.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        # Guards against a symlink in the tier directory pointing somewhere else.
        try:
            resolved = safe_document_path(root, path)
        except ValidationError:
            audit_log.log("ingest.skip", decision="deny", file=path.name, reason="path_escape")
            continue

        text = _read_document(resolved)
        if text is None:
            continue

        source = str(resolved.relative_to(root))
        chunks = chunk_text(text)
        written += vectorstore.add_chunks(
            tier,
            (
                (vectorstore.chunk_id(source, i), chunk, {"source": source})
                for i, chunk in enumerate(chunks)
            ),
        )
        audit_log.log("ingest.file", decision="allow", tier=tier, source=source, chunks=len(chunks))

    return written


def ingest_all() -> dict[str, int]:
    """Index every tier. Returns chunks written per tier."""
    result = {tier: ingest_tier(tier) for tier in TIERS}
    audit_log.log("ingest.run", decision="allow", **result)
    return result
