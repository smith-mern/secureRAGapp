"""Document ingestion pipeline.

Two sources feed the index, and the distinction between them is the security
boundary:

- **Curated** — files under `data/documents/<tier>/`, placed by whoever
  administers the deployment. Tier comes from the directory. Trusted in the
  sense that writing here already requires host access.
- **Upload** — files under `data/uploads/<tier>/`, submitted over the API by an
  account holding the `uploader` role. No host access required, so this is the
  lowest-trust of the three writable paths and the one an attacker reaches with
  nothing but a password.
- **Connector** — records pulled from the upstream source system by
  `app.connectors`. Tier is inherited from the source record's ACL. Anyone who
  can file a ticket can put text here, with no account on this application.

Both end up in the same collections and are retrieved identically. Every chunk
carries `origin` so a later mitigation can treat them differently — the whole
point of recording provenance is that "where did this text come from" is
answerable at query time.

Ingested content is untrusted regardless of source. Anything read here may
later be retrieved into a model's context, so this is the first place to record
provenance and the last place that should treat document text as instructions.
Injection screening happens at retrieval rather than here — a document that is
malicious for one caller is still evidence for a red-team writeup, so it gets
indexed and filtered on the way out, not silently dropped on the way in.

Validates file type, size, and path at the boundary; never executes or
evaluates document content.
"""

from __future__ import annotations

from pathlib import Path

from app import audit_log, vectorstore
from app.auth import TIERS
from app.connectors import tickets
from app.filters.input_validation import (
    ValidationError,
    safe_document_path,
    validate_filename,
    validate_tier,
)
from app.secrets import DOCUMENTS_DIR, UPLOADS_DIR, optional

ALLOWED_SUFFIXES = {".txt", ".md"}
MAX_FILE_BYTES = 2 * 1024 * 1024

CHUNK_CHARS = int(optional("CHUNK_CHARS", "1000"))
CHUNK_OVERLAP = int(optional("CHUNK_OVERLAP", "150"))

CURATED_ORIGIN = "curated"
UPLOAD_ORIGIN = "upload"


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


def _index(tier: str, source: str, text: str, metadata: dict) -> int:
    chunks = chunk_text(text)
    return vectorstore.add_chunks(
        tier,
        (
            (vectorstore.chunk_id(source, i), chunk, {**metadata, "source": source})
            for i, chunk in enumerate(chunks)
        ),
    )


# --------------------------------------------------------------------------
# Curated documents on disk
# --------------------------------------------------------------------------


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


def ingest_tier(
    tier: str,
    actor: str = "system",
    base: Path = DOCUMENTS_DIR,
    origin: str = CURATED_ORIGIN,
) -> int:
    """Index every document in one tier's directory under `base`."""
    if tier not in TIERS:
        raise ValidationError("unknown tier")

    # Resolve the root once and compare resolved-against-resolved throughout.
    # Mixing the two silently breaks wherever the root has a symlink in its
    # ancestry (/var -> /private/var on macOS, for one).
    root = base.resolve()
    tier_dir = root / tier
    if not tier_dir.is_dir():
        return 0

    # `source` is what chunk ids hash, so the two roots must not produce the
    # same string for the same relative path — otherwise an upload named
    # public/policy.md would silently overwrite the curated document of that
    # name. Curated keeps its bare path so existing chunk ids stay stable.
    prefix = "" if origin == CURATED_ORIGIN else f"{origin}/"

    written = 0
    for path in sorted(tier_dir.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        try:
            resolved = safe_document_path(root, path)
        except ValidationError:
            audit_log.log(
                "ingest.skip", actor=actor, decision="deny",
                file=path.name, reason="path_escape",
            )
            continue

        text = _read_document(resolved)
        if text is None:
            continue

        source = prefix + str(resolved.relative_to(root))
        count = _index(tier, source, text, {"origin": origin})
        written += count
        audit_log.log(
            "ingest.file", actor=actor, decision="allow",
            origin=origin, tier=tier, source=source, chunks=count,
        )

    return written


def ingest_curated(actor: str = "system") -> dict[str, int]:
    """Index every tier's curated documents."""
    result = {tier: ingest_tier(tier, actor) for tier in TIERS}
    audit_log.log("ingest.run", actor=actor, decision="allow", origin=CURATED_ORIGIN, **result)
    return result


# --------------------------------------------------------------------------
# Uploaded documents
# --------------------------------------------------------------------------


def ingest_uploads(actor: str = "system") -> dict[str, int]:
    """Re-index every tier's uploaded documents from disk."""
    result = {
        tier: ingest_tier(tier, actor, UPLOADS_DIR, UPLOAD_ORIGIN) for tier in TIERS
    }
    audit_log.log("ingest.run", actor=actor, decision="allow", origin=UPLOAD_ORIGIN, **result)
    return result


def store_upload(
    filename: str, tier: str, content: str, actor: str, allowed_tiers: tuple[str, ...]
) -> dict[str, object]:
    """Validate, persist, and index one uploaded document.

    Every value here arrived over the network, so each is checked before it is
    used for anything: the tier against what this uploader may write, the name
    against the path rules, and the joined path against the root a second time
    in case the name check ever loosens. The body is never inspected for
    intent — uploaded text is data, and screening it for injection happens at
    retrieval where the caller asking for it is known.
    """
    tier = validate_tier(tier, allowed_tiers)
    filename = validate_filename(filename, ALLOWED_SUFFIXES)

    if not isinstance(content, str) or not content.strip():
        raise ValidationError("document is empty")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_FILE_BYTES:
        raise ValidationError(f"document must be at most {MAX_FILE_BYTES} bytes")

    root = UPLOADS_DIR.resolve()
    tier_dir = root / tier
    tier_dir.mkdir(parents=True, exist_ok=True)
    destination = safe_document_path(root, tier_dir / filename)

    replaced = destination.exists()
    destination.write_bytes(encoded)

    source = f"{UPLOAD_ORIGIN}/{tier}/{filename}"
    if replaced:
        # Chunk ids are source:index, so a shorter replacement would leave the
        # tail of the previous version retrievable. Drop the old chunks first.
        vectorstore.delete_source(tier, source)
    # reviewed=False: an upload is the one write path reachable with nothing but
    # a password, so it is indexed as unreviewed and cannot answer anyone until
    # an `approver` account signs it off. See app/retriever.py:is_trusted.
    chunks = _index(
        tier, source, content,
        {"origin": UPLOAD_ORIGIN, "uploaded_by": actor, "reviewed": False},
    )
    audit_log.log(
        "ingest.upload", actor=actor, decision="allow", origin=UPLOAD_ORIGIN,
        tier=tier, source=source, chunks=chunks, bytes=len(encoded), replaced=replaced,
    )
    return {"source": source, "tier": tier, "chunks": chunks, "replaced": replaced}


# --------------------------------------------------------------------------
# Connector-sourced records
# --------------------------------------------------------------------------


def sync_connector(actor: str = "system") -> dict[str, int]:
    """Reconcile the index against the upstream source.

    Incremental, not a full rebuild. Each run diffs upstream records against
    what is already indexed and touches only what changed:

    - **added**    — present upstream, absent from the index
    - **updated**  — content hash differs from the indexed copy
    - **deleted**  — indexed but gone upstream, or its ACL moved it to another
                     tier (removed from the old tier, added to the new one)
    - **unchanged** — skipped entirely, no re-embedding

    Re-embedding an unchanged corpus on every cycle is the naive version and
    the expensive one; embedding is the slow step in this pipeline.

    `actor` defaults to "system" because a scheduled sync has no user behind it
    — that is the honest value, not a placeholder. A manually triggered sync
    passes the requesting user instead.
    """
    try:
        records = tickets.fetch_records()
    except tickets.SourceUnavailable as exc:
        audit_log.log(
            "connector.sync", actor=actor, decision="error",
            connector=tickets.ORIGIN, reason=type(exc).__name__,
        )
        raise

    # What upstream says should exist, keyed by tier.
    desired: dict[str, dict[str, tuple[str, dict]]] = {tier: {} for tier in TIERS}
    skipped = 0
    for record in records:
        mapped = tickets.to_document(record)
        if mapped is None:
            skipped += 1
            audit_log.log(
                "connector.skip", actor=actor, decision="deny",
                connector=tickets.ORIGIN, record=str(record.get("id")),
                reason="unmappable_or_unknown_acl",
            )
            continue
        source, text, metadata = mapped
        # Tier is inherited from upstream. The RAG does not get a vote.
        desired[record["acl"]][source] = (text, metadata)

    added = updated = deleted = unchanged = 0

    for tier in TIERS:
        indexed = vectorstore.indexed_state(tier, tickets.ORIGIN)
        wanted = desired[tier]

        # Gone upstream, or moved to a different tier.
        for source in set(indexed) - set(wanted):
            vectorstore.delete_source(tier, source)
            deleted += 1
            audit_log.log(
                "connector.delete", actor=actor, decision="allow",
                connector=tickets.ORIGIN, tier=tier, source=source,
            )

        for source, (text, metadata) in wanted.items():
            if indexed.get(source) == metadata["content_hash"]:
                unchanged += 1
                continue
            is_new = source not in indexed
            # Same rule as uploads: "anyone can file a ticket" upstream, and a
            # scheduled sync has no human in it at all, so connector records are
            # indexed unreviewed and answer nobody until signed off.
            _index(tier, source, text, {**metadata, "reviewed": False})
            if is_new:
                added += 1
            else:
                updated += 1

    audit_log.log(
        "connector.sync", actor=actor, decision="allow", connector=tickets.ORIGIN,
        records=len(records), skipped=skipped,
        added=added, updated=updated, deleted=deleted, unchanged=unchanged,
    )
    return {"added": added, "updated": updated, "deleted": deleted, "unchanged": unchanged}


def ingest_all(actor: str = "system") -> dict[str, dict[str, int]]:
    """Index every source. Connector failure does not block on-disk content."""
    curated = ingest_curated(actor)
    uploads = ingest_uploads(actor)
    try:
        connector = sync_connector(actor)
    except tickets.SourceUnavailable:
        connector = {"error": "source_unavailable"}
    return {"curated": curated, "uploads": uploads, "connector": connector}
