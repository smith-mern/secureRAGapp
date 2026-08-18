"""Unbounded-consumption probe: event-loop starvation and unbounded request body.

Self-contained — boots the app in-process on a spare port and needs no Ollama
daemon, unlike `dos_carol.sh`, which drives real generations against a running
server. Both parts here get their cost from `/login` instead, so the numbers are
reproducible on any machine:

PART A — event-loop starvation (amplification)
    `/login` spends ~31 ms of CPU and ~16 MB of RAM in scrypt (n=2**14, r=8) for
    every attempt, including attempts for users that do not exist — `authenticate`
    hashes anyway so a missing user is not distinguishable by latency. With the
    handler declared `async def`, that cost runs *on the event loop*, so N
    concurrent attempts serialise and stall every unrelated endpoint. `/health`
    returns a static dict and never touches auth or the model, so its latency
    measures the loop alone. No credentials needed.

PART B — unbounded request body
    Starlette buffers the whole body before any validator runs, so the 2000-char
    `validate_query` cap and the 2 MB document cap in `app/ingest.py` are both
    applied to bytes that are already resident. Sends 20 MB at `/login` and
    reports whether it was accepted.

Run twice — the mode is read from the environment the same way the app reads it:

    SECURITY_FILTERS_ENABLED=false python redteam/attacks/unbounded_consumption.py
    SECURITY_FILTERS_ENABLED=true  python redteam/attacks/unbounded_consumption.py

Measured on this machine, and note which numbers the flag actually moves:

    pre-fix (commit 9d08bfd)   [A]  1 ms ->  1970 ms   [B] 20 MB accepted
    post-fix, filters off      [A]  1 ms ->   194 ms   [B] 20 MB accepted
    post-fix, filters on       [A]  1 ms ->    26 ms   [B] 413

Part A's *first* row cannot be reproduced from this checkout: moving the handlers
from `async def` to `def` is a correctness fix, not a gated filter, so it applies
in both modes and the 1970 ms figure needs the pre-fix commit. What the flag
moves in part A is the rate limit and the concurrency slot; the 194 -> 26 ms
residue is those. Part B is gated end to end.

RATE_LIMIT_REQUESTS is raised for part A on purpose. The point of that part is
the *event loop*, and letting the rate limiter answer 50 of the 60 requests with
a cheap 429 would hide whether the remaining work still blocks. Part B is
unaffected by it.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Importable regardless of where the script is run from.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

os.environ["AUDIT_LOG_PATH"] = os.path.join(tempfile.gettempdir(), "redteam-audit.log")
os.environ.setdefault("SESSION_SIGNING_KEY", "x" * 43)
os.environ["DEMO_USERS"] = (
    '{"carol":{"password":"pw","clearance":"public","role":"reader"}}'
)
os.environ["CONNECTOR_SYNC_SECONDS"] = "0"
os.environ["OLLAMA_MODEL_DIGEST"] = ""
os.environ["RATE_LIMIT_REQUESTS"] = "500"

import httpx
import uvicorn

from app.main import app
from app.secrets import filters_enabled

PORT = int(os.environ.get("PROBE_PORT", "8123"))
CONCURRENCY = 60
BIG_BODY_BYTES = 20 * 1024 * 1024
BASE = f"http://127.0.0.1:{PORT}"


def _serve() -> None:
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="critical")


async def _wait_ready(client: httpx.AsyncClient) -> None:
    for _ in range(50):
        try:
            if (await client.get("/health")).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.2)
    raise SystemExit("app did not come up")


async def _probe() -> None:
    async with httpx.AsyncClient(base_url=BASE, timeout=120) as client:
        await _wait_ready(client)

        start = time.perf_counter()
        await client.get("/health")
        baseline = (time.perf_counter() - start) * 1000
        print(f"[A] baseline /health                        {baseline:8.0f} ms")

        flood = [
            asyncio.create_task(
                client.post("/login", json={"username": f"u{i}", "password": "p" * 64})
            )
            for i in range(CONCURRENCY)
        ]
        # Long enough for the flood to be in flight, short enough that a healthy
        # server has not finished it.
        await asyncio.sleep(0.05)
        start = time.perf_counter()
        response = await client.get("/health")
        stalled = (time.perf_counter() - start) * 1000
        print(
            f"[A] /health under {CONCURRENCY} concurrent /login       "
            f"{stalled:8.0f} ms  ({response.status_code})  "
            f"= {stalled / max(baseline, 0.1):.0f}x baseline"
        )
        await asyncio.gather(*flood, return_exceptions=True)

        start = time.perf_counter()
        response = await client.post(
            "/login", json={"username": "carol", "password": "A" * BIG_BODY_BYTES}
        )
        elapsed = (time.perf_counter() - start) * 1000
        verdict = "REFUSED" if response.status_code == 413 else "ACCEPTED AND PARSED"
        print(
            f"[B] {BIG_BODY_BYTES // 1024 // 1024} MB body -> {response.status_code}"
            f"  {verdict}  ({elapsed:.0f} ms)"
        )


if __name__ == "__main__":
    mode = "secure" if filters_enabled() else "insecure"
    print(f"[*] SECURITY_FILTERS_ENABLED={filters_enabled()} ({mode} mode)")
    threading.Thread(target=_serve, daemon=True).start()
    asyncio.run(_probe())
