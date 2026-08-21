# secureRAGapp

![secureRAGapp](assets/banner.svg)

A local RAG application built to be attacked. Three phases: build it
exploitable, red-team it and capture the exploits as repeatable scripts, then
turn the defenses on and report honestly what still fails.

**Status: all three phases complete.** The app is fully implemented and still
runs vulnerable by default — `SECURITY_FILTERS_ENABLED` defaults to `false`, so
the phase-2 configuration stays reproducible. Fourteen findings are written up
with working attack scripts, each carrying an observed secure-mode result.

| Phase | State |
|---|---|
| 1 — build vulnerable | complete |
| 2 — attack | complete: 14 findings, 15 attack scripts, spikee harness wired |
| 3 — secure & re-run | complete: every finding cites an observed secure-mode run; residuals stated per finding |

## Findings

All fourteen live in `redteam/findings/` as Vulnerability / Exploit / Detection
/ Mitigation, each citing a script in `redteam/attacks/`. The state column
records what was **measured** in secure mode, not what the flag was expected to
do — a finding is settled only once its Mitigation section cites an observed
run.

Three states worth distinguishing, because the split is the phase-3 result:

- **Closed by the flag** — the gated defense was the fix, and turning it on was enough.
- **Fixed in code** — the flag did nothing, so the control is structural and (where it is a defect rather than a defense) unconditional in both modes.
- **Partial** — measured, still gets through, documented rather than claimed closed.

| Finding | Sev | State after phase 3 |
|---|---|---|
| [cross-tier-retrieval-leak](redteam/findings/cross-tier-retrieval-leak.md) — public reader retrieves restricted docs | High | **closed by the flag** — retrieval scopes to `allowed_tiers`; `sources: []`, refused |
| [vectorstore-no-access-control](redteam/findings/vectorstore-no-access-control.md) — every tier readable from `data/chroma_db/`, no auth | High | **partial** — bodies and free-text metadata encrypted at rest (`strings \| grep -ci northwind`: 69 → 0), store dir `0700`. Tier labels, source paths and embeddings still recoverable; the key lives where the app can read it. No in-app fix closes it |
| [output-filter-bypass](redteam/findings/output-filter-bypass.md) — secrets and PII egress unscrubbed | High | **closed by the flag** for registered secrets, including reframing (spacing, per-line, NATO, homoglyph, base64, rot13, reversal). An in-prompt cipher still escapes — backstop, not a boundary |
| [chunk-injection-screening](redteam/findings/chunk-injection-screening.md) — retrieved chunks steer the model | High | **closed by the flag** — re-run 2026-08-17, `SCREENED` (exit 1) with a `retrieval.chunk_dropped` event. Regex-based, so still beatable by homoglyphs or a split instruction |
| [corpus-knowledge-poisoning](redteam/findings/corpus-knowledge-poisoning.md) — an `uploader` account makes the app assert false facts | High | **fixed in code** — the flag does nothing here. Review gate plus disjoint `uploader`/`approver`: 6/6 → 0/6, holds at 40 copies and on uncovered topics |
| [hidden-context-exposure](redteam/findings/hidden-context-exposure.md) — the app discloses its own system prompt | High | **partial** — prompts self-register at their definition site, 8-gram overlap detection. Interleaving still serves at 3/3 and 5/2 dilution; the class is not closed |
| [misinformation-ungrounded-answers](redteam/findings/misinformation-ungrounded-answers.md) — app states figures no document contains | High | **partial** — fabricated quantities closed by a numeric support check (the question does not count as support); prose claims still open |
| [stale-embedding-persistence](redteam/findings/stale-embedding-persistence.md) — redacted content keeps answering | High | **fixed in code**, unconditional — `_index` deletes before write, `ingest_tier` reconciles deletions. Retraction is only as timely as the next sweep |
| [model-denial-of-service](redteam/findings/model-denial-of-service.md) — one reader stalls `/health` for everyone | High | **fixed in code**, unconditional — handlers off the event loop, bounded auth cost, body caps: 1970 ms → 26 ms |
| [source-name-disclosure](redteam/findings/source-name-disclosure.md) — `sources` leaks filenames and tiers across clearance | Medium | **closed by the flag**, but as a side effect of tier scoping — there is no dedicated guard on the `sources` field |
| [improper-output-handling](redteam/findings/improper-output-handling.md) — attacker markup returned unencoded | Medium | **fixed in code** — markup neutralized at egress, after a denylist of dangerous constructs lost three ways in one sitting |
| [excessive-agency](redteam/findings/excessive-agency.md) — the agent loop executes whatever tool call the model emits | Medium | **fixed in code** — `_mediate` dispatches by name, budgets, validates and screens; a chunk-relevance gate closed the padding bypass. `AGENTIC_RAG=true` only |
| [supply-chain-vulnerabilities](redteam/findings/supply-chain-vulnerabilities.md) — 0/10 deps pinned; embedding model cache unverified | Medium | **fixed in code** — lockfile plus periodic model-digest recheck. Residual TOCTOU window is now the recheck interval, not the process lifetime |
| [egress-filter-not-a-boundary](redteam/findings/egress-filter-not-a-boundary.md) — refusal oracle (N1) and format gaps (N2) | Low–Med | **N1 closed** — all refusals return one cause-free string. **N2 accepted residual** — no finite rule set closes the reframing class |

[hidden-context-exposure-coverage](redteam/findings/hidden-context-exposure-coverage.md)
is a companion map rather than a finding: all 63 enumerated vectors, what holds
each and what does not, with nothing marked closed on the strength of an
argument alone.

Attack scripts run against a live app and are phase-agnostic — same script, both
phases. Twelve of the thirteen Python exploits signal by exit code: 0 means the
exploit landed, 1 means it was blocked. The two DoS shell scripts and the
supply-chain probe report by output instead.

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
  | prefer trusted    keep curated/reviewed content; unreviewed content answers nobody
  | branch
      no docs left -> refuse
      otherwise    -> prompt | model | parse | egress filter
```

`prefer trusted` is the corpus-poisoning control. A false fact has no
instruction shape, so no content filter catches it; what decides is provenance.
A chunk is trusted if it is `curated` or an `approver` marked it `reviewed`.
Everything else — `upload`, `connector:*` — is dropped: beside trusted content,
where it would contradict it, *and* alone, where it would be the only answer.
An uncovered topic refuses rather than falling back, because the fallback was
how a password-only uploader established facts about anything nobody had
curated yet.

Retrieval searches each trust class under its own budget
(`vectorstore.query_by_trust`), so no number of uploaded copies can evict a
curated chunk from the candidate set — a shared window, however wide, only names
how many copies an attacker needs.

The pressure valve is `POST /review` (`approver` role, disjoint from
`uploader`): it flips a source to `reviewed`, after which it answers like
curated content. **Consequence for the red-team suite:** an attack script that
uploads and immediately queries now finds its document suppressed as unreviewed
in secure mode. Approve the fixture first if the point of the test is to exercise
the model rather than the retrieval gate — reviewed-but-malicious is also the
more realistic injection scenario. Once reviewed, such content answers like
curated text, so answers carry a provenance signal: any cited source that is not
`curated` is returned in `uploaded_sources`, and the UI flags the answer as
drawing on user-submitted content — keeping an approved-but-poisoned fact
distinguishable from a vetted one. See
[corpus-knowledge-poisoning](redteam/findings/corpus-knowledge-poisoning.md).

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
  main.py              FastAPI: /login /me /upload /ingest /review /query /chat /health, chat UI at /
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
tests/                 58 tests: 9 role/clearance, 7 provider, 6 pipeline, 9 agent agency, 10 model+generator integrity, 10 corpus trust, 7 other
  conftest.py          redirects AUDIT_LOG_PATH to tmp — audit.log is phase 2 evidence
```

## Setup

Generation and embedding both run locally by default — no model API key, no
document text leaves the machine.

```sh
ollama pull gemma4:12b          # or set OLLAMA_MODEL to one you already have
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.lock   # pinned + hash-verified
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

## Dependency integrity

`requirements.txt` is the human-edited list of the 10 direct dependencies, each
pinned to an exact version. `requirements.lock` is the generated artifact: all
103 packages in the resolved closure, pinned, with the SHA256 of every
distribution file PyPI serves for that version. Install from the lock —
`--require-hashes` makes pip refuse any artifact not listed, which is what turns
a substituted package into a failed build instead of code executing at install
time on the machine that holds every tier's document text.

Regenerate after changing `requirements.txt`, and commit the diff so a
resolution change is reviewable rather than silent:

```sh
pip install -r requirements.txt          # resolve into the venv
python - <<'EOF' > /tmp/lock.body        # then hash every resolved version
import json, subprocess, urllib.request
freeze = subprocess.run(["python","-m","pip","list","--format=freeze"],
                        capture_output=True, text=True).stdout
for line in sorted(freeze.splitlines(), key=str.lower):
    if "==" not in line:
        continue
    name, ver = line.split("==", 1)
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json") as r:
        hashes = sorted({f["digests"]["sha256"] for f in json.load(r)["urls"]})
    print(f"{name}=={ver} \\")
    print(" \\\n".join(f"    --hash=sha256:{h}" for h in hashes))
EOF
# keep the existing header comment, then append /tmp/lock.body
```

Two other artifacts the index does not cover:

- **The embedding model.** `verify_embedding_model` (`app/vectorstore.py`) hashes
  chroma's extracted model files against a pin taken from the archive chroma
  itself SHA-verifies, on every use, and fails closed. chromadb only checks that
  those files *exist*, so without this the model that decides what every tier
  retrieves is a mutable file nobody re-reads.
- **The generator.** `OLLAMA_MODEL` names a mutable tag. Set
  `OLLAMA_MODEL_DIGEST` to the digest you expect and the app refuses to start on
  a mismatch — or when the digest cannot be resolved at all, which is the same
  "running something unverified" state. It is re-checked every
  `OLLAMA_PIN_RECHECK_SECONDS` while running, so a tag that moves after startup
  is caught on the next query rather than at the next restart; the query is
  refused like any other model failure. Unset, the digest is only recorded in
  `app.start` for change detection.

  The test suite clears this variable in `conftest.py` — a deployment pin must
  not make the suite depend on a running Ollama.

`redteam/attacks/supply_chain_dependency_and_model.py` audits the dependency
posture and the model cache, and fails if either regresses.

One advisory rides along with pinning: `chromadb 1.5.9` carries
`CVE-2026-45829`, a pre-auth code injection in Chroma's **FastAPI server**, with
no patched release. This app uses the embedded `PersistentClient` — the
vulnerable module is installed but never imported, so it is unreachable *as long
as retrieval stays embedded*. Switching `_get_client` to `HttpClient` would make
it reachable.

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
text. It needs a model that tool-calls: Groq's 70B does, and so does the local
`llama3.2:3b` (verified against this system prompt — a 3B will malform or skip a
call more often than a 70B, which is what the forced-answer round is for). The
tier is closed over from the authenticated request and is never a tool argument,
so a model steered by an injected chunk still cannot widen its own scope. Every tool call the model asks for is mediated before it
runs: dispatched by name (an unknown tool is answered, not executed), arguments
validated and screened like any other untrusted input, drawn from a
`AGENT_MAX_TOOL_CALLS` budget, and checked for relevance to what the caller asked
(`AGENT_MIN_QUERY_RELEVANCE`) — with each decision in the audit log as
`agent.tool_call`. The gate that holds is on the *results*: a retrieved passage
must clear both `MAX_DISTANCE` and `AGENT_MIN_CHUNK_RELEVANCE` against the user's
own request, whatever search found it. Be precise about what that buys — it
bounds which *existing* documents the agent can be steered into fetching, and it
does not bound what a *planted* document says, because an uploader chooses their
own wording. That residual is corpus poisoning; the signal for it is the
`unverified` count on every answered query. See
[excessive-agency](redteam/findings/excessive-agency.md).

## Authorization

Two independent axes. **Clearance** (`public` < `internal` < `restricted`) is
ordered and says which tiers an account may touch. **Role** is unordered and
says what it may do: `reader` gets `/query` and `/chat`, `uploader` gets
`/upload` and `/ingest`, `approver` gets `/review`, and none gets another's.
Role defaults to `reader`. `approver` is disjoint from `uploader` so no account
can approve its own upload — the separation of duties the provenance flag and
review gate both rest on.

## Phase 3

`SECURITY_FILTERS_ENABLED=true`, the identical attack suite re-run unchanged,
before/after recorded in each finding. Runs were captured on the defaults —
`LLM_PROVIDER=ollama`, `OLLAMA_MODEL=llama3.2:3b`, `AGENTIC_RAG=false` — because
phase 2 was captured there too; a run on a hosted 70B or on the agentic path is
measuring a different system, not a secured one.

**The flag was the fix less than a third of the time.** That is the result worth
recording. Four findings closed because the gated defense was turned on. Six
needed a structural change the flag had nothing to do with. Three of those are
unconditional, because they are defects rather than defenses and there is nothing
to demonstrate by leaving them switched on: blocking the event loop, letting a
redacted document keep answering, and shipping unpinned dependencies against an
unverified model artifact. Four findings remain partially open.

What still fails, measured rather than predicted:

- **Injection screening is regex.** It drops the chunk that carries a `SYSTEM:`
  marker. It does not drop a plain false sentence, and a poisoned document
  asserting the wrong refund window matches none of its seven rules — that is
  why corpus poisoning needed a review gate instead.
- **Prompt disclosure dilutes.** Prompts now register themselves and detection is
  8-gram overlap, but interleaving legitimate sentences with disclosure still
  serves at 3/3 and 5/2. Each round of tightening buys a ratio, not the class.
- **The store is encrypted, and that is not the same as closed.** Document bodies
  and free-text metadata are ciphertext at rest, so a copied directory no longer
  yields sentences. The keys retrieval filters on stay readable because Chroma
  cannot match what it cannot read, embeddings stay readable because similarity
  search needs them and are partially invertible, and the app must hold the key
  to answer at all. An encrypted volume is the strictly stronger control.
- **The egress filter is a backstop.** It folds reframed *registered* secrets —
  spacing, per-line, NATO, homoglyphs, base64, rot13, reversal — back to a
  canonical core. A cipher agreed inside the prompt still passes, and no finite
  rule set fixes that. The boundaries that held this pass were retrieval-time
  clearance scoping, grounding, disjoint duties, and the review gate.
- **A 3B local model follows a system prompt loosely**, and is not usable as a
  second-layer judge: measured against a document containing all four legitimate
  sentences verbatim, it flagged 1 of 4 disclosure fragments while false-flagging
  2 of 4 grounded sentences in the clean control.

The defense code stays gated and the default stays `false`. Deleting it, or
flipping the default, is what would stop the two runs being comparable — and the
phase-2 configuration has to remain reproducible for any of the before/after
numbers in `redteam/findings/` to be checkable.
