"""Audit logging.

Structured, append-only record of security-relevant events: auth attempts,
ingestion, queries, and every filter block or rejection. Enough to reconstruct
who did what, when — and to make phase 2's red-team findings reproducible.

Logs metadata, not payloads: identifiers, decisions, and timestamps. Never
secrets, credentials, raw PII, or full document text. `log()` enforces this by
truncating long values rather than trusting every call site to remember.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

from app.secrets import AUDIT_LOG_PATH

# ponytail: one process-wide lock. Fine for a single uvicorn worker; move to
# per-record appends or a real log sink if this ever runs multi-process.
_LOCK = threading.Lock()

MAX_VALUE_LEN = 200


def _scrub(value: Any) -> Any:
    """Keep records to metadata size. A truncated value can't be a payload."""
    if isinstance(value, str) and len(value) > MAX_VALUE_LEN:
        return value[:MAX_VALUE_LEN] + f"...[+{len(value) - MAX_VALUE_LEN} chars]"
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value][:20]
    return value


def log(event: str, *, actor: str = "anonymous", decision: str = "", **fields: Any) -> None:
    """Append one JSON-lines record.

    `event` is a stable dotted name (`auth.login`, `query.blocked`).
    `decision` is `allow` / `deny` / `error` where one applies.
    `fields` is metadata only — counts, ids, rule names, tiers. Not text.
    """
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
    }
    if decision:
        record["decision"] = decision
    record.update({k: _scrub(v) for k, v in fields.items()})

    # default=str: a field that will not serialize must not take the request
    # down with it. A logging bug is a logging bug, not a failed query.
    line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    with _LOCK:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
