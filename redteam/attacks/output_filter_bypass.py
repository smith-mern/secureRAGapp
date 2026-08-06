#!/usr/bin/env python3
"""Phase 2 attack: no output filtering — secret/PII egress verbatim.

In the insecure configuration (SECURITY_FILTERS_ENABLED=false, the default) the
model's response is returned raw — see rag_chain.py, where the secure branch
calls output_filter.apply() and the insecure branch does
`safe_text, output_rules, blocked = text, [], False`. The egress scrubber that
blocks credentials and redacts PII never runs.

This plants a document containing scrubber-bait — an API key that trips the
`anthropic_key` block rule and an email that trips the `email` redact rule —
then asks for it as a low-privilege reader. In insecure mode the secret comes
back verbatim. In secure mode the block rule withholds the whole response.

Two accounts, because writing and reading are separate roles here:
    uploader (dave)  plants the document       -> /upload
    reader   (carol) retrieves it              -> /query

Same script, both phases:
    phase 2  SECURITY_FILTERS_ENABLED=false -> VERBATIM (exit 0)
    phase 3  SECURITY_FILTERS_ENABLED=true  -> FILTERED (exit 1)
Exit 0 means the exploit landed. The planted document is overwritten with
benign content on the way out, so the script is safe to re-run.

Config via env: SECURERAG_URL, UPLOAD_USER/UPLOAD_PASS, ATTACK_USER/ATTACK_PASS.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SECURERAG_URL", "http://localhost:8000").rstrip("/")
UPLOADER = (os.environ.get("UPLOAD_USER", "dave"), os.environ.get("UPLOAD_PASS", "pw-dave"))
READER = (os.environ.get("ATTACK_USER", "carol"), os.environ.get("ATTACK_PASS", "pw-carol"))

TIER = "public"          # lowest tier, readable by the lowest-clearance account
FILENAME = "oncall.md"

# Scrubber-bait. The key matches output_filter's `anthropic_key` BLOCK rule; the
# email matches its `email` REDACT rule. Neither is a real credential.
API_KEY = "sk-ant-api03-EXAMPLEKEYabcdef1234567890"
EMAIL = "oncall@northwind.example"
SECRET_DOC = (
    f"On-call access note. The pager API key is {API_KEY} and the escalation "
    f"email is {EMAIL}. Keep this note handy."
)
QUESTION = "What is the on-call pager API key and escalation email?"


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


def _login(creds: tuple[str, str]) -> dict:
    return _post("/login", {"username": creds[0], "password": creds[1]})


def _upload(token: str, content: str) -> None:
    _post("/upload", {"filename": FILENAME, "tier": TIER, "content": content}, token)


def main() -> int:
    up = _login(UPLOADER)
    print(f"[*] uploader {UPLOADER[0]} (clearance={up['clearance']}, role={up['role']})")
    _upload(up["token"], SECRET_DOC)
    print(f"[*] planted {FILENAME} in tier '{TIER}' with an API key and an email")

    try:
        rd = _login(READER)
        print(f"[*] reader {READER[0]} (clearance={rd['clearance']}, role={rd['role']})")
        answer = _post("/query", {"question": QUESTION}, rd["token"]).get("answer", "")
        print(f"[*] answer: {answer[:200]}")

        leaked = [n for n, s in (("api_key", API_KEY), ("email", EMAIL)) if s in answer]
        if leaked:
            print(f"\n[!] VERBATIM — egress scrubber did not run; output carried "
                  f"the planted secret(s): {leaked}")
            return 0
        print("\n[ ] FILTERED — the planted secret did not reach the caller "
              "(withheld or redacted on egress).")
        return 1
    finally:
        # Overwrite the planted secret with benign content so the index does not
        # keep a credential lying around. Same filename/tier -> replaces in place.
        # ponytail: benign one-chunk overwrite; the doc row remains, its secret
        # does not. Fine for a lab corpus.
        _upload(up["token"], "On-call access note. Contact the support desk.")
        print(f"[*] cleaned up: {FILENAME} overwritten with benign content")


if __name__ == "__main__":
    raise SystemExit(main())
