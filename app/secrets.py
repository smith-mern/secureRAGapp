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
    names = ["SESSION_SIGNING_KEY"]
    if os.environ.get("LLM_PROVIDER", "ollama").strip().lower() == "groq":
        names.append("GROQ_API_KEY")
    for name in names:
        require(name)
