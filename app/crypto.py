"""Authenticated encryption for document bodies at rest.

The vector store keeps every tier's chunk text in the clear, so anything that
reads `data/chroma_db/` — a backup, a snapshot, a copied directory — recovers
restricted content without touching the app. Encrypting the bodies means those
copies carry ciphertext instead of sentences.

Stdlib only, on purpose: adding `cryptography` means regenerating
`requirements.lock`, which is phase-3 supply-chain evidence. What is here is a
composition of `hmac`/`hashlib`, not a hand-rolled cipher — HMAC-SHA256 used as
a PRF in counter mode for the keystream (the same construction as HKDF-Expand
and HMAC_DRBG), with encrypt-then-MAC over the nonce and ciphertext under an
independent key.

ponytail: HMAC-CTR + encrypt-then-MAC, not AES-GCM. The ceiling is speed and
the lack of hardware acceleration, not soundness. Swap in AES-GCM from
`cryptography` if that dependency ever becomes acceptable — `encrypt`/`decrypt`
are the only two functions that would change, and `VERSION` is what lets old
records still decrypt afterwards.

**What this does not protect.** The key lives where the app can read it, so any
principal that can run as the app user reads the key and the plaintext both —
this is not a defence against `vectorstore-no-access-control.md`, which is a
same-user problem and has no in-app fix. Embeddings stay in the clear because
similarity search needs them, and they are partially invertible back toward
their source text. Metadata (source, tier, origin, reviewed) stays in the clear
because retrieval filters on it. An encrypted volume is the strictly stronger
control and covers all three; this covers exact document text only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets as stdlib_secrets

from app.secrets import require_key

# Bumped only if the construction changes. Ciphertexts carry it so a later
# version can still read what an earlier one wrote.
VERSION = "v1"
_PREFIX = f"{VERSION}:"

_NONCE_BYTES = 16
_TAG_BYTES = 32  # full SHA256; truncating buys nothing here
_BLOCK = hashlib.sha256().digest_size


def _keys(nonce: bytes) -> tuple[bytes, bytes]:
    """Derive independent encryption and MAC keys for this message.

    HKDF-Expand with the nonce in the info string, so the two keys differ from
    each other and from every other message's. Reusing one key for both the
    keystream and the tag is the classic way this construction goes wrong.
    """
    master = require_key("STORE_ENCRYPTION_KEY").encode("utf-8")
    # Extract first: the configured value is a passphrase, not uniform key
    # material, and HMAC's key padding alone does not fix that.
    prk = hmac.new(b"securerag/store/v1", master, hashlib.sha256).digest()
    enc = hmac.new(prk, b"enc" + nonce, hashlib.sha256).digest()
    mac = hmac.new(prk, b"mac" + nonce, hashlib.sha256).digest()
    return enc, mac


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 in counter mode. One PRF call per 32 bytes of output."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(
            key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        counter += 1
    return bytes(out[:length])


def encrypt(text: str) -> str:
    """Encrypt one document body. Returns `v1:<base64>`, safe to store as text.

    A fresh random nonce per call, so identical chunks do not produce identical
    ciphertext — deterministic encryption here would leak which documents share
    passages, which for a corpus of policy documents is most of the signal.
    """
    nonce = stdlib_secrets.token_bytes(_NONCE_BYTES)
    plaintext = text.encode("utf-8")
    enc_key, mac_key = _keys(nonce)
    ciphertext = bytes(
        a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    )
    # Encrypt-then-MAC, covering the nonce as well as the ciphertext.
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return _PREFIX + base64.b64encode(nonce + ciphertext + tag).decode("ascii")


def _has_prefix(value: str) -> bool:
    """Format check only — never a decision about whether to decrypt.

    Deliberately private, and deliberately not called `is_ciphertext`. A public
    "does this look encrypted?" helper reads as a safe thing to branch on, and it
    is not: the prefix is just leading characters, and plenty of the text this
    app stores is written by someone who would happily start a title with `v1:`.
    Callers decide from the record's `enc` marker; see `vectorstore._ENC_MARKER`.
    """
    return isinstance(value, str) and value.startswith(_PREFIX)


def decrypt(value: str) -> str:
    """Decrypt, verifying the tag first. Raises on tamper or wrong key."""
    if not _has_prefix(value):
        raise ValueError("not a ciphertext produced by this module")
    raw = base64.b64decode(value[len(_PREFIX) :])
    if len(raw) < _NONCE_BYTES + _TAG_BYTES:
        raise ValueError("ciphertext is truncated")

    nonce = raw[:_NONCE_BYTES]
    ciphertext = raw[_NONCE_BYTES : -_TAG_BYTES]
    tag = raw[-_TAG_BYTES:]

    enc_key, mac_key = _keys(nonce)
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    # Verify before decrypting, and in constant time. Decrypting first and
    # checking afterwards is how padding-oracle-shaped bugs start.
    if not hmac.compare_digest(tag, expected):
        raise ValueError("ciphertext failed authentication")

    return bytes(
        a ^ b for a, b in zip(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))
    ).decode("utf-8")
