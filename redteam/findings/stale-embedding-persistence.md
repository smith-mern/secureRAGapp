# Stale embedding persistence — redacted content keeps answering

**Severity:** High — confidentiality breach that survives correcting the corpus, and it inverts the review control.
**Category:** OWASP LLM08 — Vector and Embedding Weaknesses (data lifecycle in the index).
**Attack:** [`redteam/attacks/stale_embedding_persistence.py`](../attacks/stale_embedding_persistence.py)
**Component:** `app/ingest.py` (`_index`, `ingest_tier`), `app/vectorstore.py` (`chunk_id`).
**Affects both phases.** `SECURITY_FILTERS_ENABLED=true` does not touch this — the
stale chunk is in-tier, curated-or-approved, and inside the distance gate. Every
control the secure pipeline has says yes to it.

## Vulnerability

Chunk ids are content-independent and position-based:

```python
def chunk_id(source: str, index: int) -> str:
    return hashlib.sha256(f"{source}:{index}".encode("utf-8")).hexdigest()[:32]
```

Re-indexing a document upserted ids `source:0 .. source:n-1` for the *new*
version and did nothing about anything above `n`. So the write path was
add-only in two directions:

- **A document that got shorter** left its old tail in the index. Redacting a
  paragraph and re-ingesting overwrites the chunks the new text happens to
  fill; the rest stays embedded and retrievable.
- **A document deleted from disk** was never retracted at all. `ingest_tier`
  only visited sources it had just read, so nothing ever noticed a file was
  gone.

`store_upload` already handled the first case for its own path — it called
`delete_source` before re-indexing, with a comment naming exactly this failure —
but the fix lived in one caller instead of in `_index`, so the curated sweep,
the uploads sweep, and `sync_connector`'s update branch all still had it.
`sync_connector` handled the second case for its own origin (it diffs upstream
and deletes what vanished); on-disk content had no equivalent.

The consequence that matters most is not the stale text itself but what happens
to its **metadata**. `mark_reviewed` stamps `reviewed=True` on the chunks that
exist when an approver signs off. When the record is later trimmed, the fresh
chunks are re-indexed `reviewed=False` (correct — the content changed) while
the orphaned tail keeps `reviewed=True`. `retriever.is_trusted` reads the chunk,
so the redacted text is trusted and answers, and the clean replacement is
quarantined. The control runs backwards.

## Exploit

No login, no injection, no privilege. The trigger is the corpus being
*corrected*:

- support removes payment details from a ticket and the connector re-syncs;
- an admin redacts a paragraph from a curated document and re-runs `/ingest`;
- an admin deletes a document from `data/documents/restricted/` entirely.

```
$ python3 redteam/attacks/stale_embedding_persistence.py
[*] indexing ticket 42 (with payment details), then approving it
[*] approver signed off 4 chunk(s) -> reviewed=True
[*] support redacts the payment details; the record re-syncs
[*] old write path (upsert only): 4 chunk(s) retrieved for 'what payment details did the customer give on ticket 42?'
      distance=0.233 reviewed=False current 'ts a failed checkout. Payment details redacted by support.'
      distance=0.636 reviewed=True STALE '. \nCard on file 4111111111111111, billing SSN 123-45-6789.'
      ...
[!] STALE DISCLOSURE — 1 orphaned chunk(s) still answer with content deleted at the source.
[!] and it is still marked reviewed=True: the redacted text is trusted, while the clean replacement came back unreviewed.
```

Distance `0.636` is inside `MAX_DISTANCE=0.75`, so secure mode's grounding gate
passes it into the prompt. The deletion half, measured the same way against a
throwaway store: after a curated document was removed from disk, the following
`ingest_tier` run wrote 0 chunks and left all 2 of that tier's existing chunks
in the collection.

## Detection

- `audit.log` shows `ingest.file` with a falling `chunks` count for a source
  while retrieval keeps returning more chunks than that for it. Before the fix
  there was no event at all for the difference — the retraction that should have
  happened had no log line, because it was not happening.
- Chunk count per source in the store exceeding what the current file chunks to
  (`vectorstore.indexed_state` vs. a fresh `chunk_text` of the source).
- A retrieved chunk whose `reviewed` differs from its siblings under the same
  `source` — with a delete-first write path, one source's chunks are always
  written in one pass and cannot disagree.

## Mitigation

Fixed in `app/ingest.py`. Two changes, both at the layer every path goes
through:

1. **`_index` deletes the source before writing it.** Re-indexing is now a
   replace, not an overlay, so no version of a document can outlive the one
   after it. This covers curated, uploads, and the connector's update branch in
   one place; `store_upload`'s local workaround was removed as redundant.

2. **`ingest_tier` reconciles deletions.** After the sweep it diffs
   `vectorstore.indexed_state(tier, origin)` against the sources it actually
   read and retracts the difference, logging `ingest.retract`. The sweep is
   scoped to the tier **and** the origin, so an uploads run can never retract
   curated content — without the origin scope, an `/ingest` with an empty
   uploads directory would delete a tier's whole curated corpus.

Regression tests: `tests/test_ingest_reconcile.py` (shrink, delete,
cross-origin safety). The attack script keeps reproducing the old behaviour
explicitly and then asserts the fixed path is clean, so it stays meaningful
after the fix rather than just exiting 1.

### What this does not fix

- **Ordering.** A retraction is only as timely as the next ingest run. Between
  the source edit and the sweep, the old text still answers. Nothing here makes
  deletion synchronous with the upstream change.
- **The bytes on disk.** `delete_source` removes the row; `data/chroma_db/`
  still holds every tier's text in the clear and SQLite does not zero freed
  pages. A filesystem attacker recovers redacted content from the file
  regardless — see [`vectorstore-no-access-control.md`](vectorstore-no-access-control.md).
- **Embedding inversion.** Even a correctly retracted corpus leaves vectors for
  everything still indexed, and embeddings are partially invertible back to
  their source text. Same root exposure as the point above: the store is
  unauthenticated at rest.
- **Approval semantics.** Re-indexing an approved upload resets it to
  unreviewed, which fails closed but means an approver must sign off again after
  any re-ingest. That is the safe direction and deliberately left alone.
