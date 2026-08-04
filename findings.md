# Findings

Running log of security findings for secureRAGapp. Each entry follows
Vulnerability / Exploit / Detection / Mitigation.

Entries that are not exploitable — forensics and monitoring gaps, which degrade
response after an incident rather than enabling one — state that in a **Class**
line and replace *Exploit* with an impact section. Presenting them as
exploitable would inflate the report; omitting them would understate real
weaknesses.

**How to read this file.** Two columns decide whether a finding is real work or
scripted demo:

- **Status** — `Confirmed` means observed in a captured run or read directly
  from the code. `Unverified` means the reasoning holds but nothing has been
  executed against it yet. Nothing is marked Confirmed on the strength of an
  argument alone.
- **Persists with filters on** — the app ships with `SECURITY_FILTERS_ENABLED`
  defaulting to false (phase 1 is deliberately exploitable). Findings marked
  **No** disappear the moment that flag flips, so they demonstrate the intended
  before/after. Findings marked **Yes** survive phase 3 and are the ones that
  matter.

Environment at time of writing: `SECURITY_FILTERS_ENABLED=false`, local Ollama
(`gemma4:12b`), Chroma with one collection per tier, corpus of 3 synthetic
documents. Accounts: `alice` (clearance `restricted`), `carol` (clearance
`public`).

## Index

| ID | Finding | Class | Status | Persists with filters on |
|---|---|---|---|---|
| F-001 | Unauthenticated API documentation exposure | Information disclosure | Confirmed | **Yes** |
| F-002 | `/me` produces no audit record | Logging & monitoring | Confirmed | **Yes** |
| F-003 | `/me` reports policy, not enforced behaviour | Broken access control (evidence) | Confirmed | No |
| F-004 | Retrieval ignores caller clearance | Broken access control | Confirmed | No |
| F-005 | Username enumeration via the audit stream | Information disclosure | Partly confirmed | **Yes** |
| F-006 | Session tokens forgeable with a weak signing key | Broken authentication | Unverified | **Yes** |
| F-007 | No token revocation and no logout | Broken authentication | Confirmed by inspection | **Yes** |
| F-008 | No rate limiting on `/login` | Broken authentication | Confirmed by inspection | **Yes** |
| F-009 | Audit log has no integrity protection | Logging & monitoring | Confirmed by inspection | **Yes** |
| F-010 | Vector store holds every tier in cleartext on disk | Sensitive data exposure | Confirmed | **Yes** |
| F-011 | Grafana shares app credentials and exposes the full audit stream | Broken access control | Confirmed | **Yes** |
| F-012 | Corpus changes cannot be attributed to a user | Forensics gap | Confirmed | **Yes** |

---

## F-001 — Unauthenticated API documentation exposure

**Status:** Confirmed · **Persists with filters on:** Yes

**Vulnerability.** FastAPI serves `/docs` and `/openapi.json` without
authentication by default, and nothing in `app/main.py` disables them. The
complete API surface is published to anonymous callers.

**Exploit.** No credentials required:

```sh
curl -s localhost:8000/openapi.json | jq -r '.paths | keys[]'
# /health  /login  /me  /ingest  /query
curl -s localhost:8000/openapi.json | jq -c '.components.schemas | keys'
# ["HTTPValidationError","LoginRequest","QueryRequest","ValidationError"]
```

Returns every endpoint, method, and request schema — including exact field
names (`username`, `password`, `question`) needed to craft requests against
`/login` and `/query`.

**Detection.** None. `/docs` and `/openapi.json` are not audited, so this
reconnaissance leaves no trace in `audit.log` or Grafana. See F-002.

**Mitigation.** Set `docs_url=None, redoc_url=None, openapi_url=None` on the
`FastAPI()` constructor in production, or gate them behind the `current_user`
dependency. Keep them enabled in development via an env flag.

---

## F-002 — `/me` produces no audit record

**Status:** Confirmed · **Persists with filters on:** Yes

**Vulnerability.** `app/main.py::me()` calls no `audit_log.log(...)`. An
authenticated endpoint that discloses the caller's clearance and full readable
tier list is completely unlogged, in both modes.

**Exploit.** Not an exploit in itself — it removes the detection signal for the
reconnaissance phase. An attacker holding a stolen or forged token can
enumerate what that identity can reach and leave no record.

```sh
curl -s localhost:8000/me -H "authorization: Bearer $TOKEN"
# {"username":"alice","clearance":"restricted",
#  "readable_tiers":["public","internal","restricted"]}
tail -5 audit.log   # no corresponding entry
```

**Detection.** Currently none, which is the finding. `/login` and `/query` both
log; `/me` and `/health` do not, so audit coverage is per-endpoint rather than
systematic.

**Mitigation.** Log an `identity.read` event from `me()`. Better, move audit
logging into middleware so coverage is default-on and new endpoints inherit it
instead of each one having to remember.

---

## F-003 — `/me` reports policy, not enforced behaviour

**Status:** Confirmed · **Persists with filters on:** No

**Vulnerability.** `readable_tiers` is computed from
`auth.allowed_tiers(clearance)` — the same function `rag_chain.answer()`
bypasses while `SECURITY_FILTERS_ENABLED` is false. The endpoint therefore
describes a restriction the app is not applying.

**Exploit.** As `carol` (clearance `public`), `/me` returns
`readable_tiers: ["public"]` while `/query` returns content from all three
tiers. The API asserts a boundary that does not exist.

**Detection.** Compare `readable_tiers` from `/me` against the `tiers` field on
the `query.answered` audit event for the same user. A mismatch means the
reported policy and the executed policy have diverged.

**Mitigation.** Derive both from one call path so they cannot disagree. An
endpoint that misreports posture is worse than one that reports nothing,
because it supplies false assurance during review.

---

## F-004 — Retrieval ignores caller clearance

**Status:** Confirmed · **Persists with filters on:** No

**Vulnerability.** With `SECURITY_FILTERS_ENABLED` false,
`rag_chain.answer()` searches `TIERS` (all three) instead of
`allowed_tiers(user.clearance)`. Any authenticated user reads every tier.

This is the control deliberately disabled for phase 1, not an accident — it is
recorded here because it is the headline vulnerability the project exists to
demonstrate, and because phase 3 must re-test it rather than assume the flag
fixed it.

**Exploit.** `carol` holds `public` clearance:

```sh
curl -s localhost:8000/query -H "authorization: Bearer $CAROL" \
  -H 'content-type: application/json' \
  -d '{"question":"What is Project Redwood?"}'
```

Returned the contents of `restricted/acquisition.md` with
`refused: false` and `sources` listing all three documents.

**Detection.** The `query.answered` audit event carries both `actor` and
`tiers`. Any record where `tiers` exceeds the actor's clearance is an
escalation. In Grafana: `{event="query.answered", actor="carol"}` and inspect
`tiers`.

**Mitigation.** Set `SECURITY_FILTERS_ENABLED=true`. Longer term the insecure
branch should not exist outside this lab — scoping belongs in the query itself,
with no code path that searches unscoped.

---

## F-005 — Username enumeration via the audit stream

**Status:** Partly confirmed (mechanism verified, end-to-end exploit not run) ·
**Persists with filters on:** Yes

**Vulnerability.** `/login` is deliberately non-enumerable: identical `401` for
unknown user and wrong password, and `auth.authenticate()` runs a matching
scrypt round on unknown users so response time does not differ. However
`audit_log` records `reason: "no_such_user"` versus `reason: "bad_password"`,
and every Grafana account — including `carol` — can read the full stream.

The defence and the leak live in different components, which is how this class
of bug usually survives review.

**Exploit.** Submit logins for candidate usernames, then in Grafana query
`{event="auth.login", decision="deny"}` and read the `reason` field. Entries
reading `bad_password` identify real accounts.

**Detection.** A burst of `auth.login` / `decision=deny` events from one source
is the signal — currently unmonitored, and there is no source IP in the record.

**Mitigation.** Collapse both cases to one `reason` in the audit record, or
restrict audit visibility so low-clearance accounts cannot read authentication
outcomes. See F-011.

---

## F-006 — Session tokens forgeable with a weak signing key

**Status:** Unverified · **Persists with filters on:** Yes

**Vulnerability.** Tokens are `base64url(payload).hmac_sha256`. The payload is
encoded, not encrypted, and carries the authorisation decision:

```json
{"clr": "restricted", "exp": 1785846059, "sub": "alice"}
```

`auth.verify_token()` re-checks that `clr` is a known tier but otherwise trusts
it. The entire access-control model therefore rests on `SESSION_SIGNING_KEY`.
`.env.example` ships it blank with no strength requirement, so the realistic
failure is a developer entering `dev` or `changeme`.

**Exploit.** Not yet attempted. Intended test: set a weak
`SESSION_SIGNING_KEY`, recover it by brute force against a single captured
token, then mint `{"sub":"carol","clr":"restricted"}` and call `/query`.

**Detection.** A forged token is indistinguishable from a real one in the audit
log — `auth.login` never fires, yet `query.answered` appears for that actor. A
query with no preceding login is the anomaly to alert on.

**Mitigation.** Reject short or low-entropy signing keys at startup in
`secrets.check_required()`. Stop carrying `clr` in the token; look up clearance
server-side from `sub` on each request so a forged claim gains nothing.

---

## F-007 — No token revocation and no logout

**Status:** Confirmed by inspection · **Persists with filters on:** Yes

**Vulnerability.** Tokens are stateless bearer credentials valid until `exp`
(default 3600s). There is no logout endpoint, no deny list, and no server-side
session state. A leaked token cannot be cancelled.

**Exploit.** Any captured token grants that identity for up to an hour.
Rotating the user's password does not invalidate it.

**Detection.** Same token in use from multiple sources — not currently
detectable, as the audit record contains no client identifier.

**Mitigation.** Add a revocation list keyed by a token id (`jti`), checked on
each request; or shorten `SESSION_TTL_SECONDS` and add refresh. Record a client
fingerprint in the audit event so reuse is visible.

---

## F-008 — No rate limiting on `/login`

**Status:** Confirmed by inspection · **Persists with filters on:** Yes

**Vulnerability.** `/login` has no rate limit, lockout, or backoff. scrypt
makes each attempt costly but nothing bounds the number of attempts.

**Exploit.** Unbounded online password guessing against known usernames.

**Detection.** `{event="auth.login", decision="deny"}` volume over time. The
dashboard's "Failed logins" panel turns red at 5 in the range, which is the
current extent of monitoring.

**Mitigation.** Per-account and per-source rate limiting with exponential
backoff; temporary lockout after N failures. Record source IP in the audit
event — it is absent today, so per-source limiting is not yet possible.

---

## F-009 — Audit log has no integrity protection

**Status:** Confirmed by inspection · **Persists with filters on:** Yes

**Vulnerability.** `audit.log` is a plain JSON-lines file written by the app
process. No signing, no hash chaining, no append-only enforcement. Anything
running as the same user can edit or truncate it, and neither the app nor
Grafana would notice.

**Exploit.** After any action, delete the corresponding lines. Loki retains
what it already ingested, but a fresh rebuild reads the tampered file and the
edit becomes the record.

**Detection.** None at present. This is the finding.

**Mitigation.** Hash-chain each record to its predecessor so tampering breaks
the chain, and ship to an append-only sink the app user cannot rewrite. A
periodic heartbeat event also makes silent gaps detectable — an absence of
records is otherwise indistinguishable from an absence of activity.

---

## F-010 — Vector store holds every tier in cleartext on disk

**Status:** Confirmed · **Persists with filters on:** Yes

**Vulnerability.** Chroma persists chunk text alongside the embeddings, so
`data/chroma_db/` contains the full content of all three tiers unencrypted.
Access-control decisions happen in the query layer; the storage layer has none.

**Exploit.** Read the collections directly, bypassing `auth.py` entirely — no
token, no clearance check:

```python
import chromadb
c = chromadb.PersistentClient(path="data/chroma_db")
c.get_or_create_collection("docs_restricted").get(include=["documents"])
```

**Detection.** None. Direct filesystem or library access produces no audit
event — the app is not involved.

**Mitigation.** Encrypt at rest and restrict directory permissions to the
service account. This is a design property of embedded Chroma rather than a
bug: any deployment where untrusted parties can reach the data directory needs
a server-based store with its own authentication.

---

## F-011 — Grafana shares app credentials and exposes the full audit stream

**Status:** Confirmed · **Persists with filters on:** Yes

**Vulnerability.** `observability/provision.py` creates Grafana accounts from
`DEMO_USERS` using the same passwords as the API, and every account is a Viewer
over the entire audit stream. Grafana roles are not app clearances.

Two consequences: one captured credential unlocks both systems, and
`carol` — a `public`-clearance account — can read audit records naming
`restricted/acquisition.md`.

**Exploit.** Log into Grafana as `carol` and query `{job="securerag"}`. The
`sources` and `tiers` fields disclose restricted document names, and the
`reason` field enables F-005.

**Detection.** Grafana's own access logs, which are not currently forwarded
into this pipeline.

**Mitigation.** Separate credentials for the dashboard. For per-user log
visibility, Loki multi-tenancy with a tenant per clearance level — a
substantially larger build, and the reason this is documented rather than
fixed.

---

## F-012 — Corpus changes cannot be attributed to a user

**Status:** Confirmed · **Persists with filters on:** Yes

**Class:** Forensics gap. This is not an exploitable vulnerability and should
not be written up as one — no attacker action is required or enabled by it. It
degrades the ability to reconstruct what happened *after* an incident.

**Vulnerability.** `app/ingest.py` calls `audit_log.log("ingest.file", ...)` and
`audit_log.log("ingest.run", ...)` without an `actor`, so both default to
`"anonymous"`. Ingestion determines what every future query can retrieve, and
the record does not say who performed it. `ingest_all()` and `ingest_tier()`
never receive the user object, so the identity is already gone by the time the
log is written.

The denial path in `app/main.py` *does* pass `actor=user.username`. A refused
ingest names the user; a successful one does not. Attribution is present
exactly where it matters least.

**Observed.** `POST /ingest` authenticated as `alice`, immediately after an
`auth.login` correctly recorded as `actor: "alice"`:

```json
{"actor":"anonymous","event":"ingest.file","source":"public/poisoned.md","tier":"public","chunks":1,...}
{"actor":"anonymous","event":"ingest.run","public":2,"internal":0,"restricted":1,...}
```

**Impact on investigation.** `/ingest` accepts no body and cannot introduce a
document — it re-indexes files already present in `data/documents/`. Corpus
poisoning therefore requires filesystem write access, not API access, and an
attacker who has that can already read every tier from `data/chroma_db/`
(F-010) without touching the app.

The consequence is not that an attack becomes possible, but that after one you
cannot answer "who indexed this document, and when did it enter the corpus".
The trigger may also have been pulled by an innocent user, or by a scheduled
job, with nothing distinguishing the cases. Combined with F-009 — the log is
freely rewritable — there is no trustworthy account of corpus history at all.

**Detection.** Not detectable from the audit log; that is the finding. The only
available correlation is a preceding `auth.login` close in time, which is
circumstantial and fails under concurrent users.

**Mitigation.** Thread the authenticated user through `ingest_all(user)` and
`ingest_tier(tier, user)` and pass `actor=user.username` on every record. The
broader fix is the one in F-002: attribution belongs in middleware holding the
request identity, rather than depending on each call site to remember. To make
corpus history reconstructable, also record a content hash per indexed chunk so
a document's contents at index time can be compared against what is on disk
now.

---

## Not yet exercised

Phase 2 targets with nothing recorded against them yet:

- Prompt injection via retrieved documents (`public/poisoned.md` is indexed and
  currently reaches the model unfiltered)
- Jailbreaks against the system prompt
- Hallucination when retrieval is weak (grounding threshold is bypassed while
  filters are off)
- Injection payloads designed to survive the regex filter once it is enabled:
  homoglyphs, base64, translation framing, instructions split across chunks
