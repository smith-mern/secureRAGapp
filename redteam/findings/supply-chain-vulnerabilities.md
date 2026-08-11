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

---

## Sub-finding C — generator pinned by mutable tag (Low / informational)

`app/rag_chain.py:45` selects the model by tag (`OLLAMA_MODEL`, currently
`llama3.2:3b` per `.env`). Ollama records a content digest, but the app pins the
*tag*, not the digest, so a re-pull of a moved or repointed tag silently swaps the
generator. No app-facing trigger and the precondition is entirely out of band (control
the registry/tag, or MITM a manual `ollama pull`), so this is a hardening note:
pin `OLLAMA_MODEL` to a digest (`llama3.2:3b@sha256:…`) if the registry is not fully
trusted.

---

## Phase-3 note

`SECURITY_FILTERS_ENABLED` does not touch any of the above — the gated defenses screen
query/chunk *content*, not dependency acquisition or artifact integrity. Re-running
`supply_chain_dependency_and_model.py` with filters on produces the identical output.
Phase 3 must report this class as **outside the flag's scope**: the fixes are a
lockfile, load-time model verification, and a digest-pinned generator, none of which
the switch provides.
