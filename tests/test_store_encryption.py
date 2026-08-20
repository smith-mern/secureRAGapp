"""Document bodies are ciphertext at rest, and tampering is detected.

The store keeps every tier's text where a backup or a copied directory picks it
up. Encrypting the bodies is what makes those copies useless without the key —
it does nothing about the app's own user, who can read the key.

No Chroma here: this covers the construction. `test_pipeline.py` covers that
retrieval still returns readable text through the real store.
"""

from __future__ import annotations

import pytest

from app import crypto

SECRET = "Project Redwood: acquire Northwind Systems for 240 million dollars."


def test_roundtrip_recovers_the_original():
    assert crypto.decrypt(crypto.encrypt(SECRET)) == SECRET


def test_ciphertext_does_not_contain_the_plaintext():
    blob = crypto.encrypt(SECRET)
    assert "Northwind" not in blob
    assert "Redwood" not in blob
    assert blob.startswith("v1:")


def test_the_same_text_encrypts_differently_each_time():
    """A fresh nonce per call. Deterministic encryption would leak which
    documents share passages, which across a policy corpus is most of it."""
    assert crypto.encrypt(SECRET) != crypto.encrypt(SECRET)


def test_tampering_is_rejected_rather_than_decrypted():
    blob = crypto.encrypt(SECRET)
    flipped = blob[:-4] + ("AAAA" if not blob.endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        crypto.decrypt(flipped)


def test_a_wrong_key_fails_closed(monkeypatch):
    """Fails authentication, not silently returns garbage."""
    blob = crypto.encrypt(SECRET)
    monkeypatch.setenv("STORE_ENCRYPTION_KEY", "a-different-key-of-sufficient-length")
    with pytest.raises(ValueError):
        crypto.decrypt(blob)


def test_truncated_ciphertext_is_rejected():
    with pytest.raises(ValueError):
        crypto.decrypt("v1:" + "AAAA")


def test_unicode_survives_the_roundtrip():
    """Keystream XOR happens on bytes; a naive implementation corrupts these."""
    text = "café — naïve — 日本語 — 🔐"
    assert crypto.decrypt(crypto.encrypt(text)) == text


def test_attacker_chosen_v1_prefix_does_not_escape_encryption(tmp_path, monkeypatch):
    """A `v1:`-prefixed title is attacker input, not a claim about encryption.

    Anyone can file a ticket upstream, so a connector `title` of `v1:AAAA` is
    reachable with no account at all. The first version of the sealing code read
    that prefix as "already encrypted", stored it in the clear, and then failed
    to authenticate it on the way out — an exception raised inside `query()`,
    before the unreviewed-content suppression the record should have hit. One
    ticket took down every search that retrieved it.
    """
    from app import vectorstore

    monkeypatch.setattr(vectorstore, "CHROMA_DIR", tmp_path / "chroma")
    # The client is a module global and outlives the patched path, so without
    # this the second store test reuses the first one's collections.
    monkeypatch.setattr(vectorstore, "_client", None)
    hostile = "v1:AAAA"
    metadata = {"source": "tickets/9", "origin": "connector:tickets", "title": hostile}

    sealed = vectorstore._seal_metadata(dict(metadata))
    assert sealed["title"] != hostile, "attacker prefix skipped encryption"

    vectorstore.add_chunks(
        "public",
        [(vectorstore.chunk_id("tickets/9", 0), "A ticket about refunds.", metadata)],
    )
    hits = vectorstore.query(("public",), "refunds", k=2)

    assert len(hits) == 1, "hostile title broke retrieval"
    assert hits[0]["metadata"]["title"] == hostile
    assert "enc" not in hits[0]["metadata"]


def test_a_corrupt_record_is_dropped_not_raised_on(tmp_path, monkeypatch):
    """One unreadable chunk must not fail the whole search."""
    from app import vectorstore

    monkeypatch.setattr(vectorstore, "CHROMA_DIR", tmp_path / "chroma")
    # The client is a module global and outlives the patched path, so without
    # this the second store test reuses the first one's collections.
    monkeypatch.setattr(vectorstore, "_client", None)
    for i, text in enumerate(["refund policy details", "refund window rules"]):
        vectorstore.add_chunks(
            "public",
            [(vectorstore.chunk_id(f"doc{i}", 0), text, {"source": f"doc{i}"})],
        )

    # One record fails authentication on the way out — a tampered file, a
    # half-rotated key. Simulated at the decrypt boundary because that is the
    # only thing `query` reacts to.
    real_decrypt = crypto.decrypt

    def decrypt_one_badly(value: str) -> str:
        plain = real_decrypt(value)
        if plain == "refund policy details":
            raise ValueError("ciphertext failed authentication")
        return plain

    monkeypatch.setattr(vectorstore.crypto, "decrypt", decrypt_one_badly)
    hits = vectorstore.query(("public",), "refund", k=4)

    assert [h["text"] for h in hits] == ["refund window rules"]


def test_a_short_key_is_refused_at_boot(monkeypatch):
    """Authenticated ciphertext means a weak key is brute-forceable offline."""
    from app import secrets as app_secrets

    monkeypatch.setenv("SESSION_SIGNING_KEY", "x" * 64)
    monkeypatch.setenv("STORE_ENCRYPTION_KEY", "password")
    with pytest.raises(app_secrets.MissingSecret) as caught:
        app_secrets.check_required()
    assert "password" not in str(caught.value), "error echoed the secret"
