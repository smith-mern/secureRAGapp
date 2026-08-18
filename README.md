# secureRAGapp

![secureRAGapp](assets/banner.svg)

A local RAG application built to be attacked. Three phases: build it
exploitable, red-team it and capture the exploits as repeatable scripts, then
turn the defenses on and report honestly what still fails.

**Status: phase 2 done, phase 3 not started.** The app is fully implemented and
runs vulnerable by default — `SECURITY_FILTERS_ENABLED` defaults to `false`.
Nine findings are written up with working attack scripts. Phase 3 is underway:
the deployment `.env` now sets the flag `true`, and re-runs have begun.

| Phase | State |
|---|---|
| 1 — build vulnerable | complete |
| 2 — attack | complete: 9 findings, 11 attack scripts, spikee harness wired |
| 3 — secure & re-run | in progress: 1 of 9 re-run and verified |

## Findings

All nine live in `redteam/findings/` as Vulnerability / Exploit / Detection /
Mitigation, each citing a script in `redteam/attacks/`. "Flag closes it" is what
the finding *predicts* for phase 3; a finding is only settled once its
Mitigation section cites an observed run, so treat the column as a prediction
until then.

Verified so far:

- **chunk-injection-screening** — re-run 2026-08-17, `SCREENED` (exit 1), with a
  `retrieval.chunk_dropped` audit event supplying causation. Phase 3 also closed
  a gap the flag did not: `source` metadata reached the prompt unscreened and
  unescaped.
- **output-filter-bypass** — the flag blocks the verbatim planted credential,
  but six of eight reformulations of that same secret defeat it (one inserted
  space is enough). Enabling the filters also introduced a disclosure of their
  own — blocked responses returned the *name* of the rule that fired — now
  fixed. Script re-run still outstanding.

| Finding | Sev | Flag closes it |
|---|---|---|
| [cross-tier-retrieval-leak](redteam/findings/cross-tier-retrieval-leak.md) — public reader retrieves restricted docs | High | yes, with residual risk |
| [vectorstore-no-access-control](redteam/findings/vectorstore-no-access-control.md) — every tier readable from `data/chroma_db/`, no auth, no encryption | High | no — no in-app fix exists |
| [output-filter-bypass](redteam/findings/output-filter-bypass.md) — secrets and PII egress unscrubbed | High | partly — backstop, not a boundary |
| [chunk-injection-screening](redteam/findings/chunk-injection-screening.md) — retrieved chunks steer the model | High | partly — regex filter, beatable |
| [corpus-knowledge-poisoning](redteam/findings/corpus-knowledge-poisoning.md) — an `uploader` account makes the app assert false facts | High | no |
| [model-denial-of-service](redteam/findings/model-denial-of-service.md) — one reader stalls `/health` for everyone | High | no |
| [source-name-disclosure](redteam/findings/source-name-disclosure.md) — `sources` leaks filenames and tiers across clearance | Medium | yes |
| [improper-output-handling](redteam/findings/improper-output-handling.md) — attacker markup returned unencoded | Medium | no |
| [supply-chain-vulnerabilities](redteam/findings/supply-chain-vulnerabilities.md) — 0/10 deps pinned; embedding model cache unverified | Medium | outside the flag's scope |

Attack scripts run against a live app and are phase-agnostic — same script, both
phases. The eight Python exploits signal by exit code: 0 means the exploit
landed, 1 means it was blocked. The two DoS shell scripts and the supply-chain
probe report by output instead.

```sh
SECURERAG_URL=http://localhost:8000 ATTACK_USER=carol ATTACK_PASS=... \
  python redteam/attacks/cross_tier_retrieval_leak.py
```

## Pipeline

Retrieval and generation are one LCEL chain, composed in `rag_chain.build_chain`
and invoked by `answer`:

```
retrieve (TierScopedRetriever)
  | screen chunks     drop anything matching the injection filter
  | ground            drop chunks too distant to support an answer
  | branch
      no docs left -> refuse
      otherwise    -> prompt | model | parse | egress filter
```

The security guards are chain steps, bound with `secure=` when the chain is
built. Phase 2 builds them as pass-throughs and phase 3 builds them active — the
pipeline's shape is identical either way, which is what keeps the two runs
comparable.

Two properties worth naming, because they are load-bearing and easy to undo:

- The retriever's tier scope is **constructor state**, not a call argument.
  There is no `invoke(query, tiers=...)` overload to forget, and an empty scope
  retrieves nothing.
- `SYSTEM_PROMPT` is passed as a literal `SystemMessage`, and retrieved text
  goes in as a template **value**. LangChain does not re-template substituted
  values, so a chunk containing `{braces}` cannot introduce a placeholder.

Chroma is still the storage engine — `retriever.py` is the LangChain interface
over it, not a migration.

## Layout

```
app/
  main.py              FastAPI: /login /me /upload /ingest /query /chat /health, chat UI at /
  auth.py              identity, sessions, clearance + role checks
  ingest.py            document intake, chunking, provenance
  vectorstore.py       Chroma, one collection per tier
  retriever.py         TierScopedRetriever — Chroma as a LangChain BaseRetriever
  rag_chain.py         the LCEL pipeline + provider selection
  agent.py             agentic RAG: model calls retrieve() as a tool (opt-in)
  chat.py              in-memory multi-turn sessions
  connectors/tickets.py  scheduled sync from the upstream source system
  filters/             input validation, prompt screening, output egress — all gated off
  secrets.py           env-backed config, no defaults
  audit_log.py         structured security event log -> audit.log
  static/index.html    minimal chat UI (renders with textContent)
mocksource/            fake ticket queue: anyone can write, always tier public
redteam/
  attacks/             11 repeatable exploit scripts
  findings/            9 writeups
  fixtures/            injection payloads used by the attacks
  spikee/              spikee target adapters (direct + indirect/RAG), datasets, results
observability/         Loki + Alloy + Grafana, native binaries, run.sh
tests/                 22 tests: 9 role/clearance, 7 provider, 6 pipeline
  conftest.py          redirects AUDIT_LOG_PATH to tmp — audit.log is phase 2 evidence
```

## Setup

Generation and embedding both run locally by default — no model API key, no
document text leaves the machine.

```sh
ollama pull gemma4:12b          # or set OLLAMA_MODEL to one you already have
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set SESSION_SIGNING_KEY, DEMO_USERS, GRAFANA_ADMIN_PASSWORD
uvicorn app.main:app --reload
uvicorn mocksource.main:app --port 8001   # optional: upstream source for the connector
observability/run.sh                      # optional: Loki/Alloy/Grafana on the audit log
```

Startup prints a banner while the app is in its exploitable configuration.

Drop documents into `data/documents/{public,internal,restricted}/` — the
directory sets the tier — then `POST /ingest` as an `uploader` account.
`/upload` writes to `data/uploads/<tier>/` with `origin="upload"`, kept apart
from curated content because it is the only write path reachable with nothing
but a password.

## Model provider

Two env vars change what runs. **Both defaults are what phase 2 and phase 3
results must be produced under** — change either and the runs stop being
comparable to the findings.

| Var | Default | Effect |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | `ollama` keeps generation on this machine. `groq` uses Groq's free hosted tier — faster, but see below. |
| `AGENTIC_RAG` | `false` | `true` swaps the fixed pipeline for `agent.py`, where the model calls `retrieve()` as a tool. |

`LLM_PROVIDER=groq` needs a `GROQ_API_KEY` and **sends every question and every
retrieved chunk, restricted tier included, to a third party.** That voids the
offline property the threat model is built on, so the app prints a banner and
logs an `app.remote_llm` audit event on startup. Embeddings stay local either
way — Chroma's embedder never crosses the network.

`AGENTIC_RAG=true` is a separate track, not part of the phase-2/3 comparison. It
buys query rewriting for free: the model turns a bare follow-up like "and
internationally?" into a standalone search instead of retrieving on the raw
text. It needs a model that tool-calls reliably — Groq's 70B does, the local 12B
mostly does not. The tier is closed over from the authenticated request and is
never a tool argument, so a model steered by an injected chunk still cannot
widen its own scope.

## Authorization

Two independent axes. **Clearance** (`public` < `internal` < `restricted`) is
ordered and says which tiers an account may touch. **Role** is unordered and
says what it may do: `reader` gets `/query` and `/chat`, `uploader` gets
`/upload` and `/ingest`, neither gets the other's. Role defaults to `reader`.

## Phase 3

Set `SECURITY_FILTERS_ENABLED=true`, re-run the identical attack suite, record
before/after in each finding. The gated defenses are deliberately imperfect: the
prompt filter is regex and falls to homoglyphs, encoding, or an instruction
split across chunks; `data/chroma_db/` stores every tier in the clear so
filesystem access bypasses auth entirely; and a 12B local model follows a system
prompt loosely. Report what still fails — do not claim the attacks are solved.

Run it on the defaults: `LLM_PROVIDER=ollama`, `AGENTIC_RAG=false`. Phase 2 was
captured against the local model and the fixed pipeline, so a phase 3 run on a
hosted 70B or on the agentic path is measuring a different system.

The defense code is gated, not absent. Do not delete it, and do not enable it by
default before phase 3, or the two runs stop being comparable.
