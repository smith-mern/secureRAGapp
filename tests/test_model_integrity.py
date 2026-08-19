"""Embedding-model integrity checks — no network, no Chroma client.

The embedder decides what every tier retrieves, and chromadb only checks that
its files *exist* after the first download. These cover the check that closes
that gap: tampering is refused, a cold cache is not mistaken for tampering, and
the pin shipped in the repo actually matches the artifact chromadb ships.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from app import rag_chain, vectorstore


@pytest.fixture(autouse=True)
def _unverified(monkeypatch):
    """Each test starts before verification has been memoized."""
    monkeypatch.setattr(vectorstore, "_model_verified", False)
    monkeypatch.setattr(vectorstore, "_seen_metadata", {})


def _write_model(folder, contents: dict[str, bytes]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        (folder / name).write_bytes(data)


def test_a_tampered_file_fails_closed(monkeypatch, tmp_path):
    # Every filename present and the right size range — only the bytes differ,
    # which is exactly what chromadb's existence check cannot see.
    _write_model(tmp_path, {name: b"tampered" for name in vectorstore._MODEL_FILE_SHA256})
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path)

    with pytest.raises(vectorstore.ModelIntegrityError):
        vectorstore.verify_embedding_model()
    assert vectorstore._model_verified is False  # never memoized as good


def test_a_cold_cache_is_not_a_failure(monkeypatch, tmp_path):
    """Nothing downloaded yet: chromadb will fetch under its own archive pin."""
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path / "absent")

    vectorstore.verify_embedding_model()  # must not raise
    # Not marked verified, so the files get checked once they do exist.
    assert vectorstore._model_verified is False


def test_matching_files_verify(monkeypatch, tmp_path):
    contents = {name: f"content of {name}".encode() for name in vectorstore._MODEL_FILE_SHA256}
    _write_model(tmp_path, contents)
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path)
    monkeypatch.setattr(
        vectorstore, "_MODEL_FILE_SHA256",
        {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    )

    vectorstore.verify_embedding_model()
    assert vectorstore._model_verified is True


def test_a_file_swapped_after_a_successful_check_is_caught(monkeypatch, tmp_path):
    """Verification is per-use, not per-process.

    The earlier version memoized the pass, so a cache replaced after the first
    query ran unverified for the life of the process.
    """
    contents = {name: f"content of {name}".encode() for name in vectorstore._MODEL_FILE_SHA256}
    _write_model(tmp_path, contents)
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path)
    monkeypatch.setattr(
        vectorstore, "_MODEL_FILE_SHA256",
        {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    )

    vectorstore.verify_embedding_model()
    assert vectorstore._model_verified is True

    # Swap a small file: re-hashed on every call, so this is caught immediately.
    (tmp_path / "tokenizer.json").write_bytes(b"swapped after verification")
    with pytest.raises(vectorstore.ModelIntegrityError):
        vectorstore.verify_embedding_model()


def test_a_same_size_same_mtime_replacement_is_still_caught(monkeypatch, tmp_path):
    """The reported bypass: pad to the original size, restore mtime with utime.

    mtime and size are forgeable, so they cannot be the whole freshness key.
    ctime is not — the kernel stamps it on any inode change and exposes no way
    to backdate it — so a replaced file fails the check even when the attacker
    matches everything they *can* control.
    """
    contents = {name: f"content of {name}".encode() for name in vectorstore._MODEL_FILE_SHA256}
    _write_model(tmp_path, contents)
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path)
    monkeypatch.setattr(
        vectorstore, "_MODEL_FILE_SHA256",
        {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    )
    vectorstore.verify_embedding_model()

    target = tmp_path / "model.onnx"
    before = target.stat()
    target.write_bytes(b"X" * before.st_size)          # identical length
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # identical mtime

    assert target.stat().st_size == before.st_size
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    with pytest.raises(vectorstore.ModelIntegrityError):
        vectorstore.verify_embedding_model()


def test_the_large_file_is_rechecked_when_its_metadata_moves(monkeypatch, tmp_path):
    """model.onnx is 90 MB, so it is re-hashed on a metadata change, not blindly."""
    contents = {name: f"content of {name}".encode() for name in vectorstore._MODEL_FILE_SHA256}
    _write_model(tmp_path, contents)
    monkeypatch.setattr(vectorstore, "_extracted_model_dir", lambda: tmp_path)
    monkeypatch.setattr(
        vectorstore, "_MODEL_FILE_SHA256",
        {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    )
    vectorstore.verify_embedding_model()

    (tmp_path / "model.onnx").write_bytes(b"a tampered model of a different size")
    with pytest.raises(vectorstore.ModelIntegrityError):
        vectorstore.verify_embedding_model()


def test_the_shipped_pin_matches_the_real_cache():
    """The pin is only worth anything if it matches what chromadb actually ships.

    Skipped rather than failed on a machine that has not downloaded the model —
    absence is not a mismatch.
    """
    folder = vectorstore._extracted_model_dir()
    if not (folder / "model.onnx").is_file():
        pytest.skip("embedding model not downloaded on this machine")

    vectorstore.verify_embedding_model()
    assert vectorstore._model_verified is True


def test_an_unpinned_generator_only_logs(monkeypatch):
    """Default behaviour is unchanged: record the digest, do not enforce it."""
    monkeypatch.delenv("OLLAMA_MODEL_DIGEST", raising=False)
    monkeypatch.setattr(rag_chain, "model_fingerprint", lambda: "sha256:abc")

    assert rag_chain.check_model_pin() == "sha256:abc"


def test_a_pinned_generator_refuses_a_different_digest(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "sha256:expected")
    monkeypatch.setattr(rag_chain, "model_fingerprint", lambda: "sha256:something-else")

    with pytest.raises(rag_chain.GeneratorPinMismatch):
        rag_chain.check_model_pin()


def test_an_unresolvable_digest_fails_when_pinned(monkeypatch):
    """The gap the red-team run hit: fingerprinting returned 'unknown'.

    Log-only, that is indistinguishable from a swapped generator. With a pin set,
    'cannot tell' must fail the same way 'wrong' does.
    """
    monkeypatch.setenv("OLLAMA_MODEL_DIGEST", "sha256:expected")
    monkeypatch.setattr(rag_chain, "model_fingerprint", lambda: None)

    with pytest.raises(rag_chain.GeneratorPinMismatch):
        rag_chain.check_model_pin()
