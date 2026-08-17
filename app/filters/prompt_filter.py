"""Prompt injection defense.

Screens text on its way into the model's context — both the user's query and
the chunks the retriever returns. Retrieved documents are the harder case: an
attacker who can get a document indexed controls text that lands in the prompt
without ever talking to the API.

Looks for instruction-shaped content in data positions (role overrides,
"ignore previous", exfiltration requests) and reports which rules matched.
Detection is pattern-based and therefore beatable — it is one of three layers,
alongside prompt structure in rag_chain and output filtering on the way out.
Phase 2 should assume this filter can be bypassed and check what stops the
attack next.
"""

from __future__ import annotations

import re
from typing import Any

# (rule name, pattern). Names are stable identifiers — they end up in the audit
# log and in phase 2 findings, so don't rename them casually.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b"
        r"(previous|prior|earlier|above|all)\b.{0,20}"
        r"\b(instruction|prompt|rule|direction|context)s?\b", re.I | re.S)),
    ("role_reassignment", re.compile(
        r"\b(you\s+are\s+now|from\s+now\s+on\s+you|act\s+as|pretend\s+to\s+be|"
        r"new\s+(system\s+)?(prompt|instruction|role))\b", re.I)),
    ("chat_role_marker", re.compile(
        r"(^|\n)\s*(system|assistant|human|user)\s*:", re.I)),
    ("tag_injection", re.compile(
        r"</?\s*(system|instructions?|document|context)\s*>", re.I)),
    ("prompt_disclosure", re.compile(
        r"\b(reveal|repeat|print|show|output|dump)\b.{0,30}\b"
        r"(system\s+prompt|your\s+instructions?|initial\s+prompt)\b", re.I | re.S)),
    ("exfiltration", re.compile(
        r"\b(send|post|upload|leak|email|exfiltrate)\b.{0,40}\b"
        r"(http|url|endpoint|webhook|attacker)\b", re.I | re.S)),
    ("guardrail_bypass", re.compile(
        r"\b(dan\s+mode|developer\s+mode|jailbreak|no\s+restrictions|"
        r"without\s+any\s+(filter|restriction|limitation)s?)\b", re.I)),
)


def scan(text: str) -> list[str]:
    """Return the names of every rule that matched. Empty means clean."""
    return [name for name, pattern in _RULES if pattern.search(text)]


def screen_query(text: str) -> list[str]:
    """Screen a user-supplied query.

    A hostile query is the caller attacking their own session, so the blast
    radius is small — the answer is refused rather than quarantined.
    """
    return scan(text)


def screen_chunk(text: str) -> list[str]:
    """Screen one retrieved chunk before it enters the prompt.

    This is the dangerous direction: the text belongs to whoever wrote the
    document, not to the caller, and the caller may never see it. A chunk with
    any match should be dropped by rag_chain rather than delimited and passed
    through — the cost is one missing source, the alternative is executing an
    attacker's instructions on a third party's behalf.
    """
    return scan(text)


def screen_document(document: Any) -> list[str]:
    """Screen everything about a retrieved document that reaches the prompt.

    `screen_chunk` alone is not enough: `_format_documents` also interpolates
    `metadata["source"]`, and that string is attacker-reachable (an upstream
    connector record id, a curated filename — neither goes through
    `validate_filename`). Screening the body but not the source leaves a data
    position that lands in the prompt uninspected, which is exactly the hole
    the chunk screen exists to close.

    Scanned separately rather than on a joined string so a rule cannot match
    across the seam between source and body and report a match that is in
    neither. Rule names are deduplicated but order is kept stable for the log.
    """
    seen: dict[str, None] = {}
    for part in (str(document.metadata.get("source", "")), document.page_content):
        for rule in scan(part):
            seen[rule] = None
    return list(seen)
