# Supply chain — unpinned dependencies and an unverified runtime model artifact

**Severity:** Medium (both sub-findings). Neither is an unauthenticated request to
`/query` that wins — unlike the injection and DoS findings, these are *posture*
exposures with a real precondition. Their ceilings are high (code execution on the
box that stores restricted text in the clear; silent control of retrieval for every
tier), which is why they are Medium and not Low.
**Attack:** [`redteam/attacks/supply_chain_dependency_and_model.py`](../attacks/supply_chain_dependency_and_model.py)
(Part A audits the dependency posture; Part B demonstrates the model-cache gap on a
throwaway copy — the real cache is never modified).
**Component:** `requirements.txt` (0/7 pinned, no lockfile, no hashes);
`chromadb/utils/embedding_functions/onnx_mini_lm_l6_v2.py:281`
(`_download_model_if_not_exists` verifies only the download tarball) reached via
`app/vectorstore.py:57` (`_collection` → Chroma's default embedder).

Two distinct classes are grouped here because they are the same lifecycle stage —
*what the RAG trusts because of where it came from*, not what a caller sends at
runtime. Neither is gated by `SECURITY_FILTERS_ENABLED`; flipping the phase-3 flag
changes nothing here.

Related: [`vectorstore-no-access-control`](vectorstore-no-access-control.md) — same
"local filesystem is a trust boundary already broken" precondition. That finding is
a one-time confidentiality read of `data/chroma_db/`; sub-finding B below is the
*integrity/persistence* variant in the same zone.

---

## Sub-finding A — dependencies acquired with no version, lock, or integrity pin

### Vulnerability

`requirements.txt` names seven packages with **no version constraint on any of
them**, there is **no lockfile** (`poetry.lock` / `uv.lock` / `requirements.lock`
absent), and **no hash pinning** (`pip install --require-hashes` is not usable
because no `--hash=` lines exist). Those seven names resolve to a **90-package
transitive closure**, every one of which is trusted purely because the index served
it at build time.

Concretely, the installed direct deps have already drifted to whatever was newest at
last install (`chromadb==1.5.9`, `fastapi==0.141.1`, `pydantic==2.13.4`, …) — the
manifest exerts no control over that. A rebuild tomorrow can resolve to a different
set with no signal that anything changed.

### Exploit

There is no app-facing trigger to fire, which is exactly the point — the exploit is a
malicious artifact entering the resolved set on a rebuild:

- **Dependency confusion** — a public package shadowing an expected internal name.
- **Typosquat** — a lookalike pulled in as a new transitive dep of an unpinned dep.
- **Compromised release** — an upstream account or CI takeover republishes a version.

Any of these executes attacker code at install time (`setup.py`, or first import),
on the machine that holds **every tier's restricted document text in the clear**
(`data/chroma_db/`). That is the worst ceiling of the three findings and the reason
this is not Low. It is Medium rather than High because realizing it needs a poisoned
artifact to actually exist and resolve — it is latent, not attacker-triggerable
against this deployment today.

`supply_chain_dependency_and_model.py` Part A prints the standing numbers:

```
=== PART A: dependency acquisition posture ===
  requirements listed        : 7
  with a version constraint  : 0
  with an integrity hash     : 0
  lockfile present           : NONE
  resolved installed closure : 90 packages (all trusted on download)
```

### Detection

Effectively none today. There is no lockfile to diff, no hash manifest to compare a
rebuild against, and the audit log records queries, not `pip` activity. A swapped
dependency would leave no trace the app can see. Detection has to come from outside:
a committed lockfile + hash file diffed in CI, or an SBOM / dependency-audit step.

### Mitigation

- **Pin and hash.** Generate a fully pinned, hashed lockfile (`pip-compile
  --generate-hashes`, or `uv lock`) and install with `--require-hashes`. This closes
  confusion, typosquat, and silent-republish in one step.
- **Commit the lockfile** and diff it in CI so a resolution change is a reviewable
  event, not a silent one.
- **Scope the index** (explicit `--index-url`, no implicit fallback to a public
  index for internal names) to kill dependency confusion structurally.

### Fixed — phase 3, 2026-08-18

`requirements.txt` now pins all 10 direct dependencies to the exact versions this
deployment's phase-2 and phase-3 evidence was produced with, and
**`requirements.lock`** pins the whole 103-package closure with 2623 artifact
hashes. README's install line is `pip install --require-hashes -r
requirements.lock`.

Same probe, before and after:

| Part A | phase 2 | phase 3 |
| --- | --- | --- |
| direct deps with a version constraint | 0 / 7 | **10 / 10** |
| lockfile | NONE | **requirements.lock** |
| packages pinned in lock | 0 | **103** |
| integrity hashes | 0 | **2623** |

Enforcement was verified rather than assumed — pip accepts the entry and refuses
a corrupted one:

```
$ pip install --require-hashes --no-deps --dry-run -r mini.lock
Would install python-dotenv-1.2.2

$ pip install --require-hashes --no-deps --dry-run -r bad.lock   # one hex digit changed
ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE.
    Expected sha256 0c371a91...  Got 1d821478...
```

That second run is the whole mitigation in one line: a substituted artifact now
fails the build instead of executing its `setup.py` on the box that stores every
tier's text in the clear.

**Residual:** the lock records what PyPI served *today*. It makes a change
detectable and blocks substitution of a pinned artifact; it does not tell you
whether a pinned version was already malicious when it was hashed. Index scoping
(`--index-url` with no public fallback) is still not configured — it is a
deployment-level control, and this repo has no CI to enforce the lock diff either.
Regeneration is a documented manual step, which is exactly the kind of step that
rots; a CI job that regenerates and diffs is the next move.

---

## Sub-finding B — the cached embedding model is loaded with no runtime integrity check

### Vulnerability

Chroma's default embedder *does* pin the model with a hardcoded SHA256
(`_MODEL_SHA256`, `onnx_mini_lm_l6_v2.py:45`), but `_download_model_if_not_exists`
(`:281`) uses that hash **only to decide whether to download**. Its logic:

1. Are the six required files present under `…/onnx/`? If **yes → return
   immediately.**
2. Only if a file is missing does it check the tarball's SHA and re-extract.

So the hash guards the *download path*. Once the cache is populated —
`~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx/` — `__call__` (`:258`) loads and
runs `model.onnx` and `tokenizer.json` from disk on **every embedding**, with no
per-file verification, ever. The model that sits at the trust boundary for **all
three tiers** (`app/vectorstore.py` routes every tier's upsert and query through this
one embedder) is a plain, unverified, mutable file.

Precondition: local write to that cache path — the same threat the repo already
accepts for `data/chroma_db/`. The added value over that accepted property is that
this is an **integrity + persistence** primitive, not a confidentiality read.

### Exploit

`supply_chain_dependency_and_model.py` Part B proves the load path ignores integrity,
non-destructively — it copies the real cache to a temp dir, tampers one required file
in the copy, and loads the embedder against the copy. Real cache untouched:

```
=== PART B: embedding-model runtime integrity ===
  tampered file              : onnx/tokenizer.json (swapped ids 'knight'<->'lap')
  loaded tampered model      : YES, no error and no warning
  cosine pristine vs tampered: 0.973288  (1.0 == identical)
  max abs dim delta          : 0.035791
  -> _download_model_if_not_exists saw 6 files present and returned;
     the _MODEL_SHA256 pin guards only the download, never the load.
```

A differently-hashed `tokenizer.json` loaded silently and moved the vector. A real
attacker swaps `model.onnx` for a crafted one instead of nudging the tokenizer, which
lets them **steer retrieval**: bias the embedding space so a `restricted`-clearance
query pulls attacker-chosen chunks, or so the correct documents fall out of the top-k
and the model answers ungrounded. Because the retrieved set *is* the answer's
evidence, controlling the embedder is quiet control over what the RAG says — with no
document upload, no query payload, and no log line.

### Detection

Poor. The tampered file is never re-hashed, survives restarts, and produces **no
audit event** (unlike a `/query`). `query.answered` logs `chunks`/`sources` but has
no way to know the embedder that selected them was swapped. Detection requires
something the app does not do: hash the extracted model files at startup against a
pin the operator controls, or run the embedder read-only from an immutable/verified
location.

### Mitigation

- **Verify at load, not just at download.** Hash the six extracted files against a
  known-good manifest on startup (a dozen lines around `_collection`), or pre-stage
  the model read-only and mount it immutable so the cache is not attacker-writable.
- **Treat the model cache as a trust store.** It deserves the same "filesystem access
  = full compromise" note the repo already makes for `data/chroma_db/`; right now it
  is an *undocumented* second one.
- Upstream: chromadb's check belongs on the extracted artifact, not only the tarball.

### Fixed — phase 3, 2026-08-18

`vectorstore.verify_embedding_model()` hashes all six extracted files before the
embedder is used, and **fails closed** on a mismatch (`ModelIntegrityError`,
retrieval refused). It hangs off `_collection()` and `embed()` rather than
startup, so a model swapped mid-process is caught too, and it is memoized so the
90 MB `model.onnx` is hashed once per process.

The pin is derived from **the archive chromadb itself SHA256-pins**, not from the
local cache — a pin taken from the disk you are trying to distrust proves
nothing. Confirmed at generation time: the on-disk `onnx.tar.gz` hashes to
`913d7300…`, equal to chromadb's `_MODEL_SHA256`, and the per-file hashes were
read out of that verified archive.

Part B of the probe is unchanged and still passes — the gap is chromadb's and
cannot be closed from here. **Part C** was added to test the app path:

```
=== PART C: app-side load verification (phase-3 mitigation) ===
  tampered file              : onnx/tokenizer.json (one byte appended)
  app refused to use it      : YES — ModelIntegrityError
```

Detection went from *none* to an explicit event, in both directions:

```json
{"event": "model.integrity", "decision": "allow", "files": 6,
 "path": "~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx"}
{"event": "model.integrity", "decision": "deny", "artifact": "tokenizer.json",
 "reason": "sha256_mismatch"}
```

**Memoization removed — red-team follow-up.** The first version hashed once per
process, so a cache replaced *after* the first query ran unverified for the life
of the process. Verification now runs on every use: the five small files (~1 MB)
are re-hashed each call, and `model.onnx` (90 MB, unpayable per query) is
re-hashed whenever its size or mtime moves. `test_a_file_swapped_after_a_
successful_check_is_caught` pins the behaviour.

**Metadata forgery closed — red-team confirmed the bypass first.** The documented
`touch -r` weakness was not theoretical: a run replaced `model.onnx` with
same-size content and restored the nanosecond mtime, and the check accepted it.
The freshness key now includes `st_ctime_ns` and `st_ino`. ctime is stamped by
the kernel on any inode change and there is no API to backdate it, so the same
attack now fails:

```
same size:  True
same mtime: True
same ctime: False
RESULT: REFUSED — ModelIntegrityError
```

Regression test: `test_a_same_size_same_mtime_replacement_is_still_caught`.

**Residual:** still TOCTOU in the strict sense — a gap remains between our hash
and the `onnx` runtime's own read of the file, and ctime is defeatable by an
attacker with raw device writes or control of the system clock. That is a
materially different class of access than `touch -r`, but it is not zero. A
chromadb upgrade that
ships a new model turns the pin into a hard failure until it is regenerated;
that is the intended direction, but it is a maintenance edge that will surprise
someone. And the model cache is still attacker-writable — mounting it read-only
remains the stronger control, which this fix detects rather than prevents.

---

## Sub-finding C — generator pinned by mutable tag (Low / informational)

`app/rag_chain.py:45` selects the model by tag (`OLLAMA_MODEL`, currently
`llama3.2:3b` per `.env`). Ollama records a content digest, but the app pins the
*tag*, not the digest, so a re-pull of a moved or repointed tag silently swaps the
generator. No app-facing trigger and the precondition is entirely out of band (control
the registry/tag, or MITM a manual `ollama pull`), so this is a hardening note:
pin `OLLAMA_MODEL` to a digest (`llama3.2:3b@sha256:…`) if the registry is not fully
trusted.

**Partly addressed — phase 3, 2026-08-18.** Digest pinning stays out of the app's
hands (a tag is what `ChatOllama` takes), but the swap is now *visible*:
`rag_chain.model_fingerprint()` reads the resolved content digest from the Ollama
daemon and `app.start` records it on every boot, so a re-pointed tag becomes a
one-line diff between two startups instead of nothing at all.

```json
{"event": "app.start", "decision": "allow", "mode": "secure", "provider": "ollama",
 "model": "llama3.2:3b", "digest": "a80c4f17acd55265fee"}
```

Best-effort by construction — an unreachable daemon or a provider without digests
logs `"unknown"` rather than blocking startup.

**Enforcement added — after a red-team run hit exactly that hole.** Fingerprint
resolution returned `unknown` in a validation run, and the reviewer made the
right objection: log-only, `unknown` is indistinguishable from a swapped
generator, and nobody diffs two months of startup lines. So the comparison now
lives in code. `OLLAMA_MODEL_DIGEST` is an optional expectation; when set,
`rag_chain.check_model_pin()` refuses to start on a mismatch **and on an
unresolvable digest** — "cannot tell" fails the same way "wrong" does.

```json
{"event": "model.pin", "decision": "deny", "model": "llama3.2:3b",
 "expected": "sha256:…", "seen": "unknown", "reason": "unresolved"}
```

Left opt-in because pinning a digest is a deployment decision, and defaulting it
on would break every fresh clone whose daemon has not pulled the model yet. Unset
keeps the log-only behaviour, so the residual stands for anyone who does not set
it: **the generator is selected by a mutable tag unless the operator pins it.**
This deployment's `.env` now sets it.

**Startup-only checking closed.** A second red-team pass made the right point:
verifying at boot leaves a tag that moves *afterwards* undetected until the next
restart, and a long-lived process may not restart for weeks. The pin is now
re-checked on a timer (`OLLAMA_PIN_RECHECK_SECONDS`, default 60) inside
`_get_model()` — the one place both the fixed pipeline and the agent reach the
model, so neither call site needed changing.

`GeneratorPinMismatch` subclasses `ModelUnavailable`, so a mid-run mismatch is
refused through the path every other model failure already takes. Verified by
moving the fingerprint after a successful startup:

```
startup check: a80c4f17acd55265fee
refused: True
answer : Generator integrity check failed for 'llama3.2:3b'. Refusing to serve...
sources: []
```
```json
{"event": "model.pin", "decision": "deny", "expected": "a80c4f17acd55265fee",
 "seen": "b91d5e28bde66376aaf", "reason": "mismatch"}
{"event": "query.model_unavailable", "actor": "carol", "decision": "error",
 "reason": "GeneratorPinMismatch", "mode": "agentic"}
```

That test also exposed a real bug: the agent built its model *outside* its
`try`, so the refusal escaped as an unhandled 500 rather than a clean refusal.
Fixed.

**Residual:** the window is now the recheck interval, not the process lifetime —
a tag swapped and swapped back inside 60 seconds is missed, and the digest is
read from the same daemon that would be serving the swapped model. Ollama is
trusted to report on itself here.

---

---

## Sub-finding D — a pinned dependency carries a critical advisory (present, unreachable)

Pinning makes the version explicit, which makes its advisories explicit too. A
scan of the locked set reports one against a runtime package:

```
chromadb 1.5.9 — PYSEC-2026-311 / CVE-2026-45829
pre-auth code injection via the collection-creation endpoint of Chroma's
FastAPI server        https://github.com/advisories/GHSA-f4j7-r4q5-qw2c
```

**Not reachable in this deployment**, verified two ways rather than assumed:

```
$ grep -rn "HttpClient|chromadb.server|CHROMA_SERVER" app/     -> no matches
$ python -c "import app.main, sys; print([m for m in sys.modules
              if m.startswith('chromadb.server')])"            -> []
```

The app uses `chromadb.PersistentClient` (`app/vectorstore.py`), embedded and
in-process. No Chroma HTTP server is started, no `/api/v2/.../collections` route
exists in this application, and the vulnerable module is installed but never
imported at runtime. The advisory lists no patched release, so there is nothing
to upgrade to.

**What this changes:** nothing today, and that is worth stating plainly rather
than quietly. The exposure is *architectural* — it holds only while retrieval
stays embedded. Anyone who later switches to `chromadb.HttpClient` against a
Chroma server, for scale or to share the index, makes this immediately reachable
and pre-auth. That is a one-line change in `_get_client`, which is exactly the
kind of change that gets made without re-reading a finding.

**Detection:** none in-app; this is a scanner's job, not the audit log's. The
lockfile is what makes the scan meaningful — an unpinned build has no stable
version to report on.

`SECURITY_FILTERS_ENABLED` does not touch any of the above — the gated defenses screen
query/chunk *content*, not dependency acquisition or artifact integrity. Re-running
`supply_chain_dependency_and_model.py` with filters on produces the identical output.
Phase 3 must report this class as **outside the flag's scope**: the fixes are a
lockfile, load-time model verification, and a digest-pinned generator, none of which
the switch provides.
