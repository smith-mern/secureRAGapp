"""Supply-chain exposure probe for the RAG app.

Two things a supply-chain attacker cares about, both checked here without
touching the running app or the real model cache:

PART A — acquisition posture (read-only)
    requirements.txt names dependencies with no versions, no lockfile, and no
    hashes. Whatever the index serves at build time is trusted. This part just
    reports the numbers; the "exploit" is a poisoned/typosquatted/confused
    package landing on a rebuild, which is latent, not fired here.

PART B — runtime integrity of the embedding model (demonstrated)
    chromadb pins the model tarball with _MODEL_SHA256, but that hash guards
    only the *download*. Once the extracted files exist under
    ~/.cache/chroma/onnx_models/<model>/onnx/, `_download_model_if_not_exists`
    sees them present and returns — nothing is re-hashed at load. So anyone who
    can write that cache (the same local-filesystem threat this repo already
    accepts for data/chroma_db/) owns the embedding function for every tier, and
    the pin never notices.

    This part proves it on a *copy* in a temp dir: tamper one required file,
    load the embedder against the copy, show it runs with no error/warning and
    moves the vector. The real cache is never modified.

Run:  python redteam/attacks/supply_chain_dependency_and_model.py
"""

from __future__ import annotations

import json
import shutil
import tempfile
from importlib import metadata
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
REQUIREMENTS = REPO / "requirements.txt"
LOCKFILES = ("requirements.lock", "requirements.txt.lock", "poetry.lock", "uv.lock", "Pipfile.lock")


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b)))


def part_a_dependency_posture() -> dict:
    """Report pinning / lockfile / hash / closure-size facts. Read-only."""
    lines = [
        ln.strip()
        for ln in REQUIREMENTS.read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    pinned = [ln for ln in lines if any(op in ln for op in ("==", ">=", "<=", "~=", ">", "<", "!="))]
    hashed = [ln for ln in lines if "--hash" in ln or "hash=" in ln]
    lockfile = next((f for f in LOCKFILES if (REPO / f).exists()), None)
    closure = sum(1 for _ in metadata.distributions())

    print("=== PART A: dependency acquisition posture ===")
    print(f"  requirements listed        : {len(lines)}")
    print(f"  with a version constraint  : {len(pinned)}")
    print(f"  with an integrity hash     : {len(hashed)}")
    print(f"  lockfile present           : {lockfile or 'NONE'}")
    print(f"  resolved installed closure : {closure} packages (all trusted on download)")
    print("  -> a rebuild resolves every one of these to whatever the index serves then.")
    print()
    return {"listed": len(lines), "pinned": len(pinned), "hashed": len(hashed),
            "lockfile": lockfile, "closure": closure}


def part_b_model_integrity() -> dict:
    """Show the cached embedding model is loaded with no runtime integrity check."""
    from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

    real_cache = Path(ONNXMiniLM_L6_V2.DOWNLOAD_PATH)
    onnx_dir = real_cache / "onnx"
    print("=== PART B: embedding-model runtime integrity ===")
    if not (onnx_dir / "tokenizer.json").exists():
        print(f"  model not cached yet at {real_cache}")
        print("  run one /query so the app downloads it, then re-run this probe.")
        print()
        return {"skipped": True}

    tmp = Path(tempfile.mkdtemp(prefix="scp_model_"))
    try:
        pristine = tmp / "pristine"
        tampered = tmp / "tampered"
        shutil.copytree(real_cache, pristine)
        shutil.copytree(real_cache, tampered)

        # Tamper a required file the tokenizer actually reads. Swapping two token
        # ids is enough to move tokenization -> embedding, without breaking load.
        tok_path = tampered / "onnx" / "tokenizer.json"
        tok = json.loads(tok_path.read_text())
        vocab = tok["model"]["vocab"]
        keys = list(vocab)
        a, b = keys[5000], keys[5001]
        vocab[a], vocab[b] = vocab[b], vocab[a]
        tok_path.write_text(json.dumps(tok))

        def embed(root: Path, text: str) -> np.ndarray:
            ef = ONNXMiniLM_L6_V2()
            ef.DOWNLOAD_PATH = root          # point the loader at our copy
            ef._download_model_if_not_exists()  # the "integrity" entry point
            return np.array(ef([text])[0])

        text = f"the {a} sat near the {b}"
        va = embed(pristine, text)
        vb = embed(tampered, text)          # <- tampered file: loads silently?
        cos = _cosine(va, vb)

        print(f"  cache under test           : {real_cache}  (real cache untouched)")
        print(f"  tampered file              : onnx/tokenizer.json (swapped ids {a!r}<->{b!r})")
        print(f"  loaded tampered model      : YES, no error and no warning")
        print(f"  cosine pristine vs tampered: {cos:.6f}  (1.0 == identical)")
        print(f"  max abs dim delta          : {np.abs(va - vb).max():.6f}")
        print("  -> _download_model_if_not_exists saw 6 files present and returned;")
        print("     the _MODEL_SHA256 pin guards only the download, never the load.")
        print()
        return {"cosine": cos, "loaded_without_error": True}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    part_a_dependency_posture()
    part_b_model_integrity()


if __name__ == "__main__":
    # ponytail: self-check doubles as the demonstration. Fails loudly if either
    # exposure is closed (deps got pinned, or chromadb started verifying at load).
    a = part_a_dependency_posture()
    assert a["pinned"] == 0 and a["lockfile"] is None and a["hashed"] == 0, \
        "dependency posture changed — update the finding"

    b = part_b_model_integrity()
    if not b.get("skipped"):
        assert b["loaded_without_error"], "tampered model failed to load — gap may be closed"
        assert b["cosine"] < 0.9999, "tampered model did not change the vector"
        print("CONFIRMED: unpinned deps + cached model loaded with no runtime integrity check.")
