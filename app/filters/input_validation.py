"""Input validation at the trust boundary.

Validates and normalizes everything arriving from a user before it reaches any
other module: type, length, encoding, and allowed character ranges. Rejects
rather than sanitizes where a value can't be made safe.

Applies to query strings, uploaded filenames and metadata, and any path or
identifier used to look up a resource. Rejects on failure with a message that
does not echo the offending input back verbatim.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

MAX_QUERY_CHARS = 2000
MIN_QUERY_CHARS = 3
MAX_USERNAME_CHARS = 64
MAX_FILENAME_CHARS = 128


class ValidationError(ValueError):
    """Rejected input. The message describes the rule, never the value."""


def _strip_control_chars(text: str) -> str:
    """Drop control and format characters.

    Zero-width and bidi-override characters (Cf) are the interesting ones: they
    are invisible in a rendered prompt but present in the tokens the model
    sees, which makes them a way to smuggle instructions past a human reviewer.
    """
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


def validate_query(raw: object) -> str:
    """Return a normalized query string or raise ValidationError."""
    if not isinstance(raw, str):
        raise ValidationError("query must be a string")

    # NFKC first: normalization can change length, so bound it afterwards.
    text = _strip_control_chars(unicodedata.normalize("NFKC", raw)).strip()

    if len(text) < MIN_QUERY_CHARS:
        raise ValidationError(f"query must be at least {MIN_QUERY_CHARS} characters")
    if len(text) > MAX_QUERY_CHARS:
        raise ValidationError(f"query must be at most {MAX_QUERY_CHARS} characters")
    return text


def validate_username(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("username must be a string")
    text = raw.strip()
    if not text or len(text) > MAX_USERNAME_CHARS:
        raise ValidationError(f"username must be 1-{MAX_USERNAME_CHARS} characters")
    if not all(ch.isalnum() or ch in "._-" for ch in text):
        raise ValidationError("username may contain only letters, digits, '.', '_' and '-'")
    return text


def validate_filename(raw: object, allowed_suffixes: set[str]) -> str:
    """Return a bare filename safe to join onto a directory, or raise.

    Rejects rather than sanitizes: a name containing a separator or `..` is
    stripped of meaning by "fixing" it, and silently renaming an upload hides
    the traversal attempt from whoever reads the audit log. `safe_document_path`
    still checks the joined result — this is the first of two gates, not the
    only one.
    """
    if not isinstance(raw, str):
        raise ValidationError("filename must be a string")
    text = _strip_control_chars(unicodedata.normalize("NFKC", raw)).strip()
    if not text or len(text) > MAX_FILENAME_CHARS:
        raise ValidationError(f"filename must be 1-{MAX_FILENAME_CHARS} characters")
    if text != Path(text).name or text in (".", ".."):
        raise ValidationError("filename may not contain a path")
    if not all(ch.isalnum() or ch in "._- " for ch in text):
        raise ValidationError("filename may contain only letters, digits, '.', '_', '-' and spaces")
    if Path(text).suffix.lower() not in allowed_suffixes:
        raise ValidationError(f"filename must end in one of: {', '.join(sorted(allowed_suffixes))}")
    return text


def validate_tier(raw: object, allowed: tuple[str, ...]) -> str:
    if not isinstance(raw, str) or raw not in allowed:
        raise ValidationError("unknown tier")
    return raw


def safe_document_path(root: Path, candidate: Path) -> Path:
    """Resolve `candidate` and confirm it stays inside `root`.

    Resolution happens before the check so `..` segments and symlinks are
    collapsed first — checking the raw string would let either escape.
    """
    root = root.resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValidationError("path escapes the document root")
    return resolved
