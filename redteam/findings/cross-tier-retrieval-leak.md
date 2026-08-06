# Cross-tier retrieval leak

**Severity:** High — confidentiality breach across the primary authorization boundary.
**Attack:** [`redteam/attacks/cross_tier_retrieval_leak.py`](../attacks/cross_tier_retrieval_leak.py)
**Component:** `app/rag_chain.py` (`answer`), retrieval tier scoping.

## Vulnerability

Clearance is meant to bound what an account can read: `public` < `internal` <
`restricted`, and `allowed_tiers(clearance)` returns a caller's own tier and
everything below it. Retrieval is supposed to search only those tiers.

In the insecure configuration it does not. In `rag_chain.answer`:

```python
tiers = allowed_tiers(user.clearance) if secure else TIERS
hits = vector_query(tiers, question, k=TOP_K)
```

With `SECURITY_FILTERS_ENABLED=false` (the default), `tiers` is the full
`TIERS` tuple regardless of who is asking. `vectorstore.query` then searches
every per-tier Chroma collection, including `restricted`, for a caller who
holds only `public` clearance. The clearance check is present in the code and
simply gated off — this is the intended phase-1 vulnerability, not an accident.

The `vectorstore` layer is not at fault: `query()` faithfully searches whatever
tiers it is handed and fails closed on an empty list. The bypass is entirely in
the caller passing the wrong tier set.

## Exploit

No special tooling — a normal login and one `/query` (or `/chat`) call. The
attacker does not need to know the restricted document exists; they ask about
the *topic*, and semantic retrieval surfaces the restricted chunk.

```
$ python3 redteam/attacks/cross_tier_retrieval_leak.py
[*] signed in as carol (clearance=public, role=reader)
[*] sources returned: ['public/handbook.md', 'restricted/acquisition.md', 'tickets/2', 'tickets/3']
[*] answer: Project Redwood involves the intended acquisition of Northwind Systems
    for 240 million dollars. The board approved the term sheet for this project on March 14.

[!] LEAK CONFIRMED — public-clearance account retrieved restricted source(s): ['restricted/acquisition.md']
```

`carol` holds `public` clearance and read `restricted/acquisition.md` — the
Project Redwood acquisition target and price, content she has no clearance for.
The same request as `alice` (`restricted`) returns the identical answer, which
confirms it is the restricted document being read, not a public paraphrase.

The `sources` field is the load-bearing evidence: it comes straight from
retrieval, so the leak is provable without trusting the model's prose. (The chat
UI renders only `answer`, so hit `/query` directly to see `sources`.)

## Detection

Every leak is already visible in `audit.log`. The insecure path logs, per query:

```json
{"event": "query.answered", "actor": "carol", "mode": "insecure",
 "tiers": ["public", "internal", "restricted"],
 "sources": ["public/handbook.md", "restricted/acquisition.md", "tickets/2", "tickets/3"]}
```

Detection rule: **flag any `query.answered` where a source's tier prefix ranks
above the actor's clearance.** A `public` actor with a `restricted/` source, or
`mode: "insecure"` appearing at all outside phase 1, is a confirmed breach.
`tiers` listing more than the actor's clearance allows is the same signal one
step earlier, before the model is even called.

## Mitigation

Set `SECURITY_FILTERS_ENABLED=true`. The identical attack, same account, same
question, then:

```
secure-mode sources: []
refused: True
answer: I don't have documents that answer that. Nothing in the material you have access to covers it.
```

Retrieval scopes to `allowed_tiers(user.clearance)` — `("public",)` for carol —
so the restricted collection is never searched, nothing grounds the answer, and
the request is refused rather than answered from a tier she cannot read. The
attack script exits non-zero (BLOCKED) in this mode.

**Residual risk (per the project's phase-3 mandate — this is not "solved"):**

- **Filesystem bypass.** `data/chroma_db/` stores every tier's chunk text in the
  clear. Anyone with read access to that directory reads restricted content
  without touching the API or its clearance checks. The tier scoping above is an
  API-layer control only.
- **Correct-by-omission, not by construction.** The scoping is one `if secure`
  branch. `vectorstore.query` fails *closed* on an empty tier set, which limits
  the blast radius of a future mistake, but a caller that computes the wrong
  tier set (as the insecure path deliberately does) still leaks. A defence that
  derived the tier set from the authenticated principal inside the vectorstore,
  rather than trusting the caller's argument, would remove the footgun.
