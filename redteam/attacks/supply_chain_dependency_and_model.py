"""Supply-chain exposure probe for the RAG app.

Two things a supply-chain attacker cares about, both checked here without
touching the running app or the real model cache:

PART A — acquisition posture (read-only)
    Reports what a rebuild would trust: version pins on the direct dependencies,
    whether a lockfile exists, and how many integrity hashes it carries. Phase 2
    ran this at 0/0/none — whatever the index served at build time was trusted.
    Phase 3 pinned requirements.txt and added requirements.lock, so this part now
    asserts the *fixed* posture and fails if it regresses. The "exploit" was
    always latent (a poisoned/typosquatted/confused package landing on a
    rebuild), so there is nothing to fire either way.

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

    It stays true after phase 3 — the gap is chromadb's, and this repo cannot
    close it upstream.

PART C — app-side verification (the phase-3 mitigation, demonstrated)
    Same tampering, same throwaway copy, but through `vectorstore`: the app
    hashes every extracted file against a pin derived from the archive chromadb
    itself SHA-verifies, and refuses to embed on a mismatch. What Part B shows
    the library accepting, Part C shows the app rejecting.

Run:  python redteam/attacks/supply_chain_dependency_and_model.py
"""

from __future__ import annotations

import json
import shutil
import sys
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

    # Hashes live in the lockfile, not in requirements.txt — count them there, or
    # a repo that pinned everything correctly still reports zero.
    locked, lock_hashes = 0, 0
    if lockfile:
        lock_lines = (REPO / lockfile).read_text().splitlines()
        locked = sum(1 for ln in lock_lines if ln and not ln.startswith((" ", "#")))
        lock_hashes = sum(1 for ln in lock_lines if "--hash=sha256:" in ln)

    print("=== PART A: dependency acquisition posture ===")
    print(f"  requirements listed        : {len(lines)}")
    print(f"  with a version constraint  : {len(pinned)}")
    print(f"  lockfile present           : {lockfile or 'NONE'}")
    print(f"  packages pinned in lock    : {locked}")
    print(f"  integrity hashes in lock   : {lock_hashes}")
    print(f"  resolved installed closure : {closure} packages")
    if lockfile and lock_hashes:
        print(f"  -> a rebuild from {lockfile} with --require-hashes gets these artifacts")
        print("     or fails; the index cannot substitute one.")
    else:
        print("  -> a rebuild resolves every one of these to whatever the index serves then.")
    print()
    return {"listed": len(lines), "pinned": len(pinned), "hashed": lock_hashes,
            "lockfile": lockfile, "closure": closure, "locked": locked}


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


def part_c_app_side_verification() -> dict:
    """Does the *app* refuse the tampered cache that chromadb loaded happily?

    Part B tests the library and stays true regardless of what this repo does —
    chromadb still checks only that the files exist. This part tests the
    mitigation added in phase 3: `vectorstore.verify_embedding_model` hashes the
    extracted files against a pin derived from chromadb's own SHA-pinned archive,
    and fails closed. Same tampering, same throwaway copy, app code path.
    """
    # This part imports app code (the others are pure inspection), so make the
    # repo importable regardless of where the script is run from.
    sys.path.insert(0, str(REPO))
    from app import vectorstore

    print("=== PART C: app-side load verification (phase-3 mitigation) ===")
    onnx_dir = vectorstore._extracted_model_dir()
    if not (onnx_dir / "tokenizer.json").exists():
        print(f"  model not cached yet at {onnx_dir}")
        print()
        return {"skipped": True}

    tmp = Path(tempfile.mkdtemp(prefix="scp_verify_"))
    try:
        tampered = tmp / "onnx"
        shutil.copytree(onnx_dir, tampered)
        # One byte is enough — the check is a hash, not a heuristic.
        tok_path = tampered / "tokenizer.json"
        tok_path.write_bytes(tok_path.read_bytes() + b" ")

        vectorstore._model_verified = False
        vectorstore._extracted_model_dir = lambda: tampered  # type: ignore[assignment]
        try:
            vectorstore.verify_embedding_model()
            print("  app loaded tampered model  : YES — mitigation is NOT working")
            return {"refused": False}
        except vectorstore.ModelIntegrityError as exc:
            print("  tampered file              : onnx/tokenizer.json (one byte appended)")
            print(f"  app refused to use it      : YES — {type(exc).__name__}")
            print("  -> verify_embedding_model hashes every extracted file against the")
            print("     pin taken from chromadb's SHA-verified archive, and fails closed.")
            print()
            return {"refused": True}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    part_a_dependency_posture()
    part_b_model_integrity()
    part_c_app_side_verification()


if __name__ == "__main__":
    # Phase 3: sub-finding A is fixed in-repo, so the assertions now run the other
    # way — a regression is an unpinned dep or a missing lock, not a pinned one.
    a = part_a_dependency_posture()
    assert a["lockfile"] is not None, "lockfile is gone — sub-finding A has regressed"
    assert a["hashed"] > 0, "lockfile carries no hashes — sub-finding A has regressed"
    assert a["pinned"] == a["listed"], "a direct dependency lost its version pin"

    # Sub-finding B is upstream behaviour and stays true: chromadb still loads
    # whatever is on disk. What must hold is that the app refuses it.
    b = part_b_model_integrity()
    if not b.get("skipped"):
        assert b["loaded_without_error"], "chromadb behaviour changed — re-read the finding"
        assert b["cosine"] < 0.9999, "tampered model did not change the vector"

    c = part_c_app_side_verification()
    if not c.get("skipped"):
        assert c["refused"], "app-side model verification is not blocking a tampered cache"
        print("MITIGATED: deps pinned + hashed; tampered model cache refused at load.")
