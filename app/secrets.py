"""Secret loading and access.

Single place that reads API keys, database URLs, and signing keys from the
environment. Fails loudly at startup on a missing required secret rather than
falling back to a default — no insecure defaults.

Secrets are returned to callers on request and never logged, echoed in errors,
or included in responses. See .env.example for the expected variables.

Note: this module shadows the stdlib `secrets` only for `from app import
secrets`. Absolute imports mean `import secrets` inside this package still
resolves to the stdlib.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_REPO_ROOT = Path(__file__).resolve().parent.parent

DOCUMENTS_DIR = _REPO_ROOT / "data" / "documents"
# Uploads land outside DOCUMENTS_DIR so provenance survives: sweeping the two
# roots separately is what lets a chunk keep origin="upload" instead of being
# re-indexed as curated content on the next rebuild.
UPLOADS_DIR = _REPO_ROOT / "data" / "uploads"
CHROMA_DIR = _REPO_ROOT / "data" / "chroma_db"
AUDIT_LOG_PATH = Path(os.environ.get("AUDIT_LOG_PATH") or _REPO_ROOT / "audit.log")


class MissingSecret(RuntimeError):
    """Raised when a required secret is absent. Never carries the value."""


def require(name: str) -> str:
    """Return the secret `name`, or raise. Empty string counts as missing.

    The error names the variable but never its value, and never guesses a
    default — a RAG app that silently starts with an unsigned session key is
    worse than one that refuses to boot.
    """
    value = os.environ.get(name, "")
    if not value:
        raise MissingSecret(
            f"{name} is not set. Copy .env.example to .env and fill it in."
        )
    return value


# Roughly what `secrets.token_urlsafe(24)` produces. Below this a key stops
# being key material and becomes a password, and the store is full of
# authenticated ciphertext — an attacker holding a copy can test guesses offline
# against the tag as fast as they like, with no rate limit and nothing logged.
MIN_KEY_CHARS = 32


def require_key(name: str) -> str:
    """Return a secret that must be long enough to be a key, or raise.

    Length is a crude proxy for entropy and does not stop `"a" * 32`. It is
    still worth having: it rejects `password`, `changeme`, and the single
    character someone types to get the app to boot, which is the failure this
    actually sees. The error never echoes the value.
    """
    value = require(name)
    if len(value) < MIN_KEY_CHARS:
        raise MissingSecret(
            f"{name} must be at least {MIN_KEY_CHARS} characters. Generate one "
            'with: python3 -c "import secrets;print(secrets.token_urlsafe(32))"'
        )
    return value


def optional(name: str, default: str) -> str:
    """Return the secret `name`, or `default`.

    Only for non-security settings (log level, chunk size). Anything that
    weakens the app when absent belongs in `require`.
    """
    return os.environ.get(name) or default


def filters_enabled() -> bool:
    """Whether the security layer is active.

    Defaults to FALSE. Phase 1 of this project ships deliberately exploitable so
    phase 2 can demonstrate working attacks; phase 3 sets this to true and re-runs
    the same attack suite to show them failing. Read at call time, not import, so
    a test can flip it without reimporting the app.

    This is an insecure default on purpose and only defensible because this is a
    lab artifact. Do not copy this pattern into anything real.
    """
    return os.environ.get("SECURITY_FILTERS_ENABLED", "false").strip().lower() in (
        "1", "true", "yes", "on",
    )


def agentic_enabled() -> bool:
    """Whether the model drives retrieval as a tool (agentic RAG).

    Defaults to FALSE, so the phase-2/3 pipeline is unchanged unless asked for.
    Needs a tool-calling model: Groq's 70B and the local llama3.2:3b both do.
    Read at call time, like `filters_enabled`.
    """
    return os.environ.get("AGENTIC_RAG", "false").strip().lower() in (
        "1", "true", "yes", "on",
    )


def check_required() -> None:
    """Verify every required secret is present. Call once at startup.

    SESSION_SIGNING_KEY is always required — without it tokens are
    unforgeable-in-name-only.

    A model API key is required only when LLM_PROVIDER sends prompts off the
    machine. The default provider is the local Ollama daemon, which needs no
    key, so the offline configuration still boots with nothing but the signing
    key set.
    """
    # STORE_ENCRYPTION_KEY is required for the same reason as the signing key:
    # defaulting it would mean a store that looks encrypted and is not, which is
    # worse than one that plainly is not. Kept separate from the signing key so
    # rotating sessions does not make the corpus undecryptable.
    # Both are key material and both get the length floor: a short signing key
    # is forgeable and a short store key is guessable offline against the
    # ciphertext. An API key is whatever the provider issued, so it only has to
    # be present.
    for name in ("SESSION_SIGNING_KEY", "STORE_ENCRYPTION_KEY"):
        require_key(name)
    if os.environ.get("LLM_PROVIDER", "ollama").strip().lower() == "groq":
        require("GROQ_API_KEY")
