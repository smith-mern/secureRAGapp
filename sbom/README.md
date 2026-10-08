# SBOM

`secureragapp.cdx.json` is the software bill of materials for this repo, in
CycloneDX 1.6 JSON. It is generated, not hand-edited.

## What it covers

- **103 Python packages**: the full closure in `requirements.lock`. Each has its
  version, purl, declared license, dependency edges, whether it is `direct` or
  `transitive`, and every SHA256 that `pip --require-hashes` will accept for it.
  `langchain-groq` (opt-in hosted provider) and `pytest` (tests only) are marked
  `scope: optional`.
- **2 models**, as `machine-learning-model` components:
  - `all-MiniLM-L6-v2` (Chroma's ONNX embedder) with chromadb's archive pin and
    the six per-file pins `app/vectorstore.py` checks at load time.
  - `llama3.2:3b` (the default generator via Ollama). It has **no digest**
    because it is pinned only when `OLLAMA_MODEL_DIGEST` is set.
- **3 native tools**: Loki, Alloy and Grafana for the optional observability
  stack. Homebrew installs them, so they are **unpinned**.
- **2 services**: local Ollama, and Groq marked as a third-party trust
  boundary.

## Known gaps

- `multidict`, `overrides` and `protobuf` have no license in their packaging
  metadata, so the SBOM has none for them. Their upstream licenses are
  Apache-2.0, Apache-2.0 and BSD-3-Clause.
- Some licenses show up as trove classifiers (for example "OSI Approved ::
  Apache Software License") and not as SPDX ids, because that is how the
  package declares them.
- Ollama, the system Python, and the OS are not inventoried.

## Regenerate

Regenerate after any change to `requirements.lock`, and commit the diff:

```sh
python -m venv /tmp/sbom-env
/tmp/sbom-env/bin/pip install --require-hashes -r requirements.lock
python -m venv /tmp/sbom-tool && /tmp/sbom-tool/bin/pip install cyclonedx-bom
/tmp/sbom-tool/bin/cyclonedx-py environment --spec-version 1.6 \
    --output-reproducible --of JSON -o /tmp/raw.cdx.json /tmp/sbom-env/bin/python
python sbom/build_sbom.py /tmp/raw.cdx.json /tmp/sbom-env
```

`build_sbom.py` exits non-zero if the installed set differs from the lock in
any way: a missing package, an extra one, or a different version. A stale SBOM
fails instead of being written.
