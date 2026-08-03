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


def check_required() -> None:
    """Verify every required secret is present. Call once at startup."""
    for name in ("ANTHROPIC_API_KEY", "SESSION_SIGNING_KEY"):
        require(name)
