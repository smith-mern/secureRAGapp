"""Connector for the upstream ticket/wiki source.

Pulls records over HTTP and maps them to indexable documents. This is how
production RAG acquires most of its corpus — a scheduled sync against a system
of record, not a user uploading files.

Two properties matter for security:

1. **The tier comes from the source record's ACL**, not from anything the RAG
   controls. The connector inherits the upstream classification. If the source
   system's ACLs are wrong, the RAG's access control is wrong, and nothing here
   would notice.

2. **Record bodies are attacker-influenced.** Anyone can file a ticket, so
   `body` is untrusted text that will later be placed in a prompt — for a user
   who may hold far higher clearance than whoever wrote it. Provenance is
   recorded per chunk (`origin`, `author`) so a later mitigation can treat
   connector content differently from curated content.

The connector does not screen content. Screening belongs at retrieval, where
the caller and their clearance are known.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx

from app.secrets import optional

SOURCE_URL = optional("SOURCE_URL", "http://localhost:8001")
SYNC_TIMEOUT = float(optional("CONNECTOR_TIMEOUT", "15"))

ORIGIN = "connector:tickets"
VALID_ACLS = ("public", "internal", "restricted")


class SourceUnavailable(RuntimeError):
    """The upstream source could not be reached."""


def fetch_records() -> list[dict[str, Any]]:
    try:
        response = httpx.get(f"{SOURCE_URL}/records", timeout=SYNC_TIMEOUT)
    except httpx.HTTPError as exc:
        raise SourceUnavailable(f"cannot reach source at {SOURCE_URL}: {exc}") from exc
    response.raise_for_status()
    return response.json().get("records", [])


def to_document(record: dict[str, Any]) -> tuple[str, str, dict[str, Any]] | None:
    """Map one source record to (source_id, text, metadata).

    Returns None for records the connector refuses to index. An unrecognised ACL
    is dropped rather than defaulted — guessing a classification for a record
    whose permissions we do not understand is how content ends up one tier too
    low.
    """
    acl = record.get("acl")
    if acl not in VALID_ACLS:
        return None

    record_id = record.get("id")
    title = (record.get("title") or "").strip()
    body = (record.get("body") or "").strip()
    if record_id is None or not body:
        return None

    source_id = f"tickets/{record_id}"
    text = f"{title}\n\n{body}" if title else body
    metadata = {
        "source": source_id,
        "origin": ORIGIN,
        # Claimed by the submitter, never verified — useful for tracing, not
        # for trusting.
        "author": str(record.get("author", "unknown")),
        "title": title,
        "updated_at": str(record.get("updated_at", "")),
        # Lets the next sync tell "unchanged" from "edited" without re-embedding.
        "content_hash": content_hash(text),
    }
    return source_id, text, metadata


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
