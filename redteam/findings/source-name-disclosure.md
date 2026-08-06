# Source-name disclosure

**Severity:** Medium — leaks document identity and tier metadata across the
clearance boundary, even when the answer body is clean.
**Attack:** [`redteam/attacks/source_name_disclosure.py`](../attacks/source_name_disclosure.py)
**Component:** `app/rag_chain.py` (`answer`), the `sources` response field.

## Vulnerability

Every `/query` and `/chat` response carries a `sources` list assembled from the
metadata of the chunks used to answer:

```python
sources = sorted({hit["metadata"].get("source", "unknown") for hit in grounded})
...
return {"answer": safe_text, "sources": [] if blocked else sources, ...}
```

The system prompt tells the *model* not to mention filenames in its prose, and a
12B model mostly complies — so the visible answer often names nothing. But
`sources` is structured data built separately from the model output and returned
unconditionally whenever the response is not blocked. Two consequences:

1. It is **not** governed by the "don't name filenames" instruction — that only
   shapes the prose, not this field.
2. In insecure mode there is no clearance scoping on retrieval, so `grounded` can
   contain chunks from tiers the caller cannot read — and their source paths,
   including the tier prefix (`restricted/…`), ship straight back.

The result: a caller learns which documents exist, what they are named, and what
tier they live in, for tiers above their clearance — a metadata leak that stands
on its own even when no restricted *content* appears in the answer text.

## Exploit

A single `/query` as a low-clearance reader. No planting, nothing to clean up.

```
$ python3 redteam/attacks/source_name_disclosure.py
[*] signed in as carol (clearance=public, role=reader)
[*] sources field: ['restricted/acquisition.md', 'tickets/2', 'tickets/3', 'upload/public/oncall.md']
[*] answer:        Project Redwood involves the intention to acquire Northwind Systems for 240 million dollars...

[!] DISCLOSED — public account learned over-clearance document name(s) via the sources field: ['restricted/acquisition.md']
```

Confirmed from the browser: sign in as `carol`/`pw-carol`, open DevTools →
Network, ask *"Tell me about Project Redwood."*, and read the `chat` response —
`sources` contains `restricted/acquisition.md`. The chat UI renders only
`answer`, so the leak rides in the response payload rather than the visible
bubble; the browser receives it regardless.

This shares the insecure retrieval path with the cross-tier content leak, but is
a distinct exposure: `sources` reveals document identity and tier even for a
response whose prose the model kept clean. Filenames are themselves sensitive —
`restricted/acquisition.md` discloses that a restricted acquisition document
exists and is named for its subject.

## Detection

The `sources` value is logged verbatim on every answered query:

```json
{"event": "query.answered", "actor": "carol", "mode": "insecure",
 "sources": ["restricted/acquisition.md", "tickets/2", "tickets/3", "upload/public/oncall.md"], ...}
```

Detection rule: **flag any `query.answered` where a source's tier prefix
outranks the actor's clearance** — a `public` actor with a `restricted/` source
is a confirmed disclosure. This is the same audit signal as the cross-tier
content leak; the two findings are caught by one rule because they share the
retrieval defect, and separated by whether the exposure is the chunk text or
just its name.

## Mitigation

Set `SECURITY_FILTERS_ENABLED=true`. Retrieval then scopes to
`allowed_tiers(user.clearance)`, so no over-clearance chunk is ever in
`grounded`, and there is no over-clearance source to name. For carol the
restricted collection is not searched, the query grounds on nothing, and the
response returns `"sources": []`, `"refused": true` — same request, no filename
disclosed.

**Residual risk (per the phase-3 mandate):**

- **Suppression is a side effect of tier scoping, not a dedicated control.** With
  filters on, `sources` is clean only because retrieval no longer returns
  over-clearance chunks. There is no independent guard that strips or authorizes
  the `sources` field before it ships; a future bug that lets an over-clearance
  chunk into `grounded` re-opens this leak the same instant it re-opens the
  content leak. If document identity is itself sensitive, `sources` should be
  filtered against the caller's clearance explicitly, not implicitly.
- **In-tier identity still ships.** Even correct, the response names the
  in-tier documents used. That is intended here, but worth stating: `sources` is
  a document-enumeration surface for anything the caller *can* read.
