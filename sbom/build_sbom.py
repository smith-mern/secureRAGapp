"""Build the repository SBOM (CycloneDX 1.6 JSON) from the locked environment.

cyclonedx-py reads the installed packages — names, versions, licenses, and the
dependency graph — but knows nothing about what this deployment cares about:
which packages are direct, that every one of them is hash-pinned, and that the
two models are components too. A model decides what every tier retrieves and
what every answer says, so leaving it out of the inventory would leave out the
part of the supply chain the threat model worries about most
(redteam/findings/supply-chain-vulnerabilities.md).

This script takes cyclonedx-py's output and adds that, then checks it against
requirements.lock in both directions so the SBOM cannot silently drift from the
lock. Stdlib only, so it runs outside the app's venv.

Regenerate (see sbom/README.md):

    python -m venv /tmp/sbom-env
    /tmp/sbom-env/bin/pip install --require-hashes -r requirements.lock
    python -m venv /tmp/sbom-tool && /tmp/sbom-tool/bin/pip install cyclonedx-bom
    /tmp/sbom-tool/bin/cyclonedx-py environment --spec-version 1.6 \\
        --output-reproducible --of JSON -o /tmp/raw.cdx.json /tmp/sbom-env/bin/python
    python sbom/build_sbom.py /tmp/raw.cdx.json /tmp/sbom-env
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "sbom" / "secureragapp.cdx.json"
ROOT_REF = "secureragapp"
NS = "secureragapp"

# Direct dependencies that are not part of the default runtime.
OPTIONAL = {
    "langchain-groq": "opt-in hosted provider; only imported when LLM_PROVIDER=groq",
    "pytest": "test-only",
}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pins(path: Path) -> dict[str, tuple[str, list[str]]]:
    """name -> (version, sha256 list) from a pip requirements file."""
    text = path.read_text()
    pins: dict[str, tuple[str, list[str]]] = {}
    # Join backslash continuations so each requirement is one logical line.
    for line in text.replace("\\\n", " ").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==(\S+)", line)
        if not m:
            continue
        pins[norm(m.group(1))] = (m.group(2), re.findall(r"sha256:([0-9a-f]{64})", line))
    return pins


def model_file_pins() -> dict[str, str]:
    """The per-file SHA256 pins app/vectorstore.py enforces at load time."""
    src = (REPO / "app" / "vectorstore.py").read_text()
    block = re.search(r"_MODEL_FILE_SHA256 = \{(.*?)\}", src, re.S)
    if not block:
        sys.exit("could not find _MODEL_FILE_SHA256 in app/vectorstore.py")
    return dict(re.findall(r'"([^"]+)":\s*"([0-9a-f]{64})"', block.group(1)))


def chroma_archive_pin(venv: Path) -> tuple[str, str]:
    """(download URL, archive SHA256) chromadb pins for its default embedder."""
    hits = list(venv.glob(
        "lib/python*/site-packages/chromadb/utils/embedding_functions/onnx_mini_lm_l6_v2.py"
    ))
    if not hits:
        sys.exit(f"chromadb embedder source not found under {venv}")
    src = hits[0].read_text()
    sha = re.search(r'_MODEL_SHA256 = "([0-9a-f]{64})"', src).group(1)
    url = re.search(r'MODEL_DOWNLOAD_URL = \(\s*"([^"]+)"', src).group(1)
    return url, sha


def prop(name: str, value: str) -> dict:
    return {"name": f"{NS}:{name}", "value": value}


def git_head() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def model_components(venv: Path) -> list[dict]:
    url, archive_sha = chroma_archive_pin(venv)
    files = model_file_pins()
    embedder = {
        "type": "machine-learning-model",
        "bom-ref": "model:all-MiniLM-L6-v2-onnx",
        "group": "sentence-transformers",
        "name": "all-MiniLM-L6-v2",
        "description": (
            "Chroma's default ONNX embedder. Embeds every chunk and every query for "
            "all three tiers, so it decides what each tier retrieves."
        ),
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "hashes": [{"alg": "SHA-256", "content": archive_sha}],
        "externalReferences": [
            {"type": "distribution", "url": url,
             "hashes": [{"alg": "SHA-256", "content": archive_sha}],
             "comment": "archive pin enforced by chromadb at download only"},
            {"type": "website", "url": "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2"},
        ],
        "components": [
            {"type": "file", "bom-ref": f"model:all-MiniLM-L6-v2-onnx/{name}", "name": name,
             "hashes": [{"alg": "SHA-256", "content": sha}]}
            for name, sha in sorted(files.items())
        ],
        "properties": [
            prop("integrity", "per-file SHA256 verified at load, fail-closed "
                              "(app/vectorstore.py verify_embedding_model)"),
            prop("location", "~/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx"),
            prop("pinned-by", "chromadb (archive) + app/vectorstore.py (extracted files)"),
        ],
        "modelCard": {
            "modelParameters": {
                "task": "sentence-similarity",
                "architectureFamily": "transformer",
                "modelArchitecture": "MiniLM-L6 (ONNX export)",
            },
            "considerations": {
                "technicalLimitations": [
                    "English-only; non-English paraphrases evade similarity-based "
                    "egress checks (hidden-context-exposure-coverage.md #11)."
                ],
            },
        },
    }
    generator = {
        "type": "machine-learning-model",
        "bom-ref": "model:llama3.2-3b",
        "group": "meta",
        "name": "llama3.2",
        "version": "3b",
        "description": (
            "Default generator, served by a local Ollama daemon (OLLAMA_MODEL). "
            "Also the judge for entailment checks and the advisory review agent."
        ),
        "licenses": [{"license": {
            "name": "Llama 3.2 Community License Agreement",
            "url": "https://www.llama.com/llama3_2/license/",
        }}],
        "externalReferences": [
            {"type": "distribution", "url": "https://ollama.com/library/llama3.2:3b"},
        ],
        "properties": [
            prop("integrity", "NOT pinned by default; enforced only when "
                              "OLLAMA_MODEL_DIGEST is set (app/rag_chain.py)"),
            prop("config", "OLLAMA_MODEL (default llama3.2:3b)"),
        ],
        "modelCard": {
            "modelParameters": {"task": "text-generation", "architectureFamily": "llama"},
            "considerations": {
                "technicalLimitations": [
                    "3B parameters; follows the system prompt loosely (see CLAUDE.md, phase 3)."
                ],
            },
        },
    }
    return [embedder, generator]


def native_tools() -> list[dict]:
    """Observability stack — installed by Homebrew outside the lock, unpinned."""
    out = []
    for name, group, desc in [
        ("loki", "grafana", "log store for audit.log"),
        ("alloy", "grafana", "tails audit.log into Loki"),
        ("grafana", "grafana", "dashboard over Loki"),
    ]:
        out.append({
            "type": "application",
            "bom-ref": f"tool:{name}",
            "group": group,
            "name": name,
            "description": f"Optional observability stack: {desc} (observability/run.sh).",
            "scope": "optional",
            "properties": [
                prop("install", "brew install grafana loki grafana-alloy"),
                prop("integrity", "NOT pinned: version and hash are whatever Homebrew serves"),
            ],
        })
    return out


def services() -> list[dict]:
    return [
        {
            "bom-ref": "service:ollama",
            "provider": {"name": "local host"},
            "name": "Ollama",
            "description": "Local LLM daemon. Default provider; nothing leaves the machine.",
            "endpoints": ["http://localhost:11434"],
            "authenticated": False,
            "x-trust-boundary": False,
            "trustZone": "local",
            "data": [
                {"flow": "bi-directional", "classification": "restricted",
                 "description": "questions and retrieved chunks from every tier the caller is cleared for"},
            ],
            "properties": [prop("config", "LLM_PROVIDER=ollama (default), OLLAMA_HOST")],
        },
        {
            "bom-ref": "service:groq",
            "provider": {"name": "Groq", "url": ["https://groq.com"]},
            "name": "Groq API",
            "description": (
                "Opt-in hosted provider. Sends questions and retrieved chunks to a third "
                "party, voiding the offline property; must never serve the restricted tier."
            ),
            "endpoints": ["https://api.groq.com"],
            "authenticated": True,
            "x-trust-boundary": True,
            "trustZone": "third-party",
            "data": [
                {"flow": "bi-directional", "classification": "internal",
                 "description": "questions and retrieved chunks"},
            ],
            "properties": [
                prop("config", "LLM_PROVIDER=groq, GROQ_API_KEY, GROQ_MODEL"),
                prop("model", "llama-3.3-70b-versatile (default GROQ_MODEL)"),
            ],
        },
    ]


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: build_sbom.py RAW_CDX_JSON LOCKED_VENV")
    raw = json.loads(Path(sys.argv[1]).read_text())
    venv = Path(sys.argv[2])

    lock = parse_pins(REPO / "requirements.lock")
    direct = parse_pins(REPO / "requirements.txt")

    # The SBOM must describe exactly the lock: same set, same versions.
    seen = {norm(c["name"]): c for c in raw["components"]}
    errors = []
    for name, (ver, _) in lock.items():
        if name not in seen:
            errors.append(f"in lock, not installed: {name}=={ver}")
        elif seen[name]["version"] != ver:
            errors.append(f"version drift: {name} lock={ver} installed={seen[name]['version']}")
    errors += [f"installed, not in lock: {n}" for n in seen if n not in lock]
    errors += [f"direct dependency missing from lock: {n}" for n in direct if n not in lock]
    if errors:
        sys.exit("SBOM does not match requirements.lock:\n  " + "\n  ".join(errors))

    direct_refs = []
    for comp in raw["components"]:
        n = norm(comp["name"])
        _, hashes = lock[n]
        is_direct = n in direct
        if is_direct:
            direct_refs.append(comp["bom-ref"])
        if n in OPTIONAL:
            comp["scope"] = "optional"
        props = comp.setdefault("properties", [])
        props.append(prop("dependency", "direct" if is_direct else "transitive"))
        props.append(prop("hash-pinned", f"{len(hashes)} sha256 digests in requirements.lock"))
        if n in OPTIONAL:
            props.append(prop("optional-reason", OPTIONAL[n]))
        # One distribution reference carrying every artifact digest pip will accept.
        comp.setdefault("externalReferences", []).append({
            "type": "distribution",
            "url": f"https://pypi.org/project/{comp['name']}/{comp['version']}/",
            "comment": "pip --require-hashes accepts only artifacts matching these digests",
            "hashes": [{"alg": "SHA-256", "content": h} for h in hashes],
        })

    models = model_components(venv)
    tools = native_tools()
    raw["components"] += models + tools

    raw["metadata"]["component"] = {
        "type": "application",
        "bom-ref": ROOT_REF,
        "name": "secureRAGapp",
        "description": (
            "Security-focused RAG application: FastAPI, Chroma (one collection per "
            "access tier), LangChain generation via local Ollama by default."
        ),
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/smith-mern/secureRAGapp"},
        ],
        "properties": [prop("source-commit", git_head())],
    }
    raw["metadata"]["properties"] = raw["metadata"].get("properties", []) + [
        prop("lockfile", "requirements.lock"),
        prop("generator", "sbom/build_sbom.py over cyclonedx-py environment"),
    ]

    deps = raw.setdefault("dependencies", [])
    by_ref = {d["ref"]: d for d in deps}
    chromadb = next(c["bom-ref"] for c in raw["components"] if norm(c["name"]) == "chromadb")
    by_ref[chromadb].setdefault("dependsOn", []).append("model:all-MiniLM-L6-v2-onnx")
    deps.append({
        "ref": ROOT_REF,
        "dependsOn": sorted(direct_refs) + ["model:llama3.2-3b"]
        + [t["bom-ref"] for t in tools] + ["service:ollama", "service:groq"],
    })
    deps.append({"ref": "model:all-MiniLM-L6-v2-onnx", "dependsOn": []})
    deps.append({"ref": "model:llama3.2-3b", "dependsOn": []})
    deps += [{"ref": t["bom-ref"], "dependsOn": []} for t in tools]

    svc = services()
    raw["services"] = svc
    deps.append({"ref": "service:ollama", "dependsOn": ["model:llama3.2-3b"]})
    deps.append({"ref": "service:groq", "dependsOn": []})

    OUT.write_text(json.dumps(raw, indent=2, sort_keys=False) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(raw['components'])} components "
          f"({len(direct_refs)} direct, {len(lock) - len(direct_refs)} transitive, "
          f"{len(models)} models, {len(tools)} native tools), {len(svc)} services")


if __name__ == "__main__":
    main()
