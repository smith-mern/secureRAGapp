# secureRAGapp

![secureRAGapp](assets/banner.svg)

A local RAG application built to be attacked. Three phases: build it
exploitable, red-team it and capture the exploits as repeatable scripts, then
turn the defenses on and report honestly what still fails.

**Status: phase 2 done, phase 3 not started.** The app is fully implemented and
runs vulnerable — `SECURITY_FILTERS_ENABLED` defaults to `false`. Nine findings
are written up with working attack scripts. Nothing has been re-run with the
flag on yet.

| Phase | State |
|---|---|
| 1 — build vulnerable | complete |
| 2 — attack | complete: 9 findings, 11 attack scripts, spikee harness wired |
| 3 — secure & re-run | not started |

## Findings

All nine live in `redteam/findings/` as Vulnerability / Exploit / Detection /
Mitigation, each citing a script in `redteam/attacks/`. "Flag closes it" is what
the finding *predicts* for phase 3 — none of it is verified yet.

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
| [supply-chain-vulnerabilities](redteam/findings/supply-chain-vulnerabilities.md) — 0/7 deps pinned; embedding model cache unverified | Medium | outside the flag's scope |

Attack scripts run against a live app and are phase-agnostic — same script, both
phases. The eight Python exploits signal by exit code: 0 means the exploit
landed, 1 means it was blocked. The two DoS shell scripts and the supply-chain
probe report by output instead.

```sh
SECURERAG_URL=http://localhost:8000 ATTACK_USER=carol ATTACK_PASS=... \
  python redteam/attacks/cross_tier_retrieval_leak.py
```

## Layout

```
app/
  main.py              FastAPI: /login /me /upload /ingest /query /chat /health, chat UI at /
  auth.py              identity, sessions, clearance + role checks
  ingest.py            document intake, chunking, provenance
  vectorstore.py       Chroma, one collection per tier
  rag_chain.py         retrieve -> prompt -> local Ollama -> filter
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
tests/test_roles.py    5 tests on the role/clearance split
```

## Setup

Generation and embedding both run locally — no model API key, no document text
leaves the machine.

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

The defense code is gated, not absent. Do not delete it, and do not enable it by
default before phase 3, or the two runs stop being comparable.
