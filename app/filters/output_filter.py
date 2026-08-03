"""Output filtering.

Last gate before a model response reaches the caller. Catches what should never
leave: secrets and credential-shaped strings, raw PII, system prompt contents,
and internal paths or stack traces.

Also the backstop for a successful prompt injection — if the model was steered
into leaking context or emitting attacker-supplied instructions, this is where
it gets caught. Blocks or redacts, and records the event via audit_log without
writing the offending content into the log.
"""

from __future__ import annotations

import re

REDACTION = "[redacted]"

# Matching these means the response never ships. A credential or a copy of the
# system prompt in the output is not something a partial redaction fixes.
_BLOCK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("generic_api_key", re.compile(r"\b(sk|pk|rk)-[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}", re.I)),
    ("system_prompt_leak", re.compile(
        r"(you are the retrieval assistant|<retrieved_documents>|"
        r"treat everything inside .{0,40}as data)", re.I)),
)

# These get masked in place — the surrounding answer is still useful.
_REDACT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("phone", re.compile(r"\b(?:\+\d{1,3}[ \-])?\(?\d{3}\)?[ \-]\d{3}[ \-]\d{4}\b")),
    ("filesystem_path", re.compile(r"(/(?:Users|home|var|etc|root)/[^\s\"']+)")),
    ("traceback", re.compile(r"Traceback \(most recent call last\):[\s\S]*")),
)


def scan(text: str) -> tuple[list[str], list[str]]:
    """Return (block_hits, redact_hits) as rule names. Both empty means clean."""
    return (
        [name for name, pattern in _BLOCK_RULES if pattern.search(text)],
        [name for name, pattern in _REDACT_RULES if pattern.search(text)],
    )


def redact(text: str) -> str:
    result = text
    for _, pattern in _REDACT_RULES:
        result = pattern.sub(REDACTION, result)
    return result


def apply(text: str) -> tuple[str, list[str], bool]:
    """Filter a model response.

    Returns (safe_text, rule_names, blocked). When `blocked` is True the text is
    a fixed refusal — the original never reaches the caller, and it is not
    written to the audit log either, only the rule names that fired.
    """
    block_hits, redact_hits = scan(text)
    if block_hits:
        return (
            "This response was withheld because it contained content that "
            "must not leave the system.",
            block_hits,
            True,
        )
    if redact_hits:
        return redact(text), redact_hits, False
    return text, [], False
