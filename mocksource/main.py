"""Mock upstream source system that the RAG ingests from.

Stands in for the kind of system production RAG actually connects to — a
support ticket queue, a wiki, a shared inbox. The defining property is that
people with no account on the RAG can put text into it.

Two record origins, mirroring how these systems work:

- **Seeded records** are written by staff and carry `internal` or `restricted`
  ACLs. They model curated internal knowledge.
- **Submitted records** arrive through the public endpoint with no
  authentication at all — anyone can file a ticket. These are always forced to
  `acl: "public"`. A submitter cannot choose their own classification, which is
  what a real portal does.

That asymmetry is the point. An outsider can only write to the lowest tier, but
the RAG will happily retrieve that text into a *restricted*-clearance user's
prompt. The privilege crossing happens at query time, not at write time.

Run: uvicorn mocksource.main:app --port 8001
"""

from __future__ import annotations

import itertools
import threading
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="mock ticket source", version="0.1.0")

ACLS = ("public", "internal", "restricted")

_lock = threading.Lock()
_ids = itertools.count(1)
_records: list[dict] = []


class NewRecord(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20000)
    author: str = Field(default="anonymous", max_length=100)


def _add(title: str, body: str, author: str, acl: str) -> dict:
    record = {
        "id": next(_ids),
        "title": title,
        "body": body,
        "author": author,
        "acl": acl,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _records.append(record)
    return record


def _seed() -> None:
    _add(
        "Refund policy",
        "The refund window for standard orders is 30 days from delivery. "
        "Refunds are issued to the original payment method within 5 business days.",
        "support-team",
        "public",
    )
    _add(
        "Q3 hardware margin review",
        "Gross margin on hardware was 42 percent this quarter, up from 38 percent "
        "in Q2. Driven mainly by the renegotiated contract manufacturer terms.",
        "finance-team",
        "internal",
    )
    _add(
        "Project Redwood — board update",
        "Project Redwood: we intend to acquire Northwind Systems for 240 million "
        "dollars. The board approved the term sheet on 14 March.",
        "corp-dev",
        "restricted",
    )


_seed()


@app.get("/records")
async def list_records() -> dict:
    """Everything the connector can see. No auth — the connector is trusted."""
    with _lock:
        return {"records": list(_records)}


@app.post("/records", status_code=201)
async def submit_record(body: NewRecord) -> dict:
    """Public submission. No authentication, by design.

    ACL is forced to `public` — a submitter never chooses their own
    classification. This is the ingress an outsider has.
    """
    with _lock:
        record = _add(body.title, body.body, body.author, "public")
    return record


@app.patch("/records/{record_id}")
async def update_record(record_id: int, body: NewRecord) -> dict:
    """Edit an existing record. Real ticket systems allow this; the connector
    must notice the content changed and re-index it."""
    with _lock:
        for record in _records:
            if record["id"] == record_id:
                record.update(
                    title=body.title,
                    body=body.body,
                    updated_at=datetime.now(timezone.utc).isoformat(),
                )
                return record
    return {"error": "not found"}


@app.delete("/records/{record_id}", status_code=204)
async def delete_record(record_id: int) -> None:
    """Records get deleted or archived upstream. The connector must reconcile."""
    with _lock:
        _records[:] = [r for r in _records if r["id"] != record_id]


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "records": len(_records)}
