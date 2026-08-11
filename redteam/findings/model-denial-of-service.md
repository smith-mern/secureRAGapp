# Model denial of service — one reader freezes the whole app

**Severity:** High — the lowest-privilege role (`reader`, the default) can make the
API stop responding to *every* user, not just to other model calls. A few
concurrent `/query` requests from one account froze `/health` — an endpoint that
does no model work at all — for the full duration of generation, reproducibly.
Availability is the asset, and nothing in the app protects it: no output cap, no
rate limit, and blocking model calls on the single event loop.
**Attack:** [`redteam/attacks/dos_carol.sh`](../attacks/dos_carol.sh) (sustained
availability DoS), [`redteam/attacks/dos_chat_leak.sh`](../attacks/dos_chat_leak.sh)
(session-store memory leak), [`redteam/attacks/model_denial_of_service.py`](../attacks/model_denial_of_service.py)
(single-request amplification)
**Component:** `app/main.py:194` (`/query` is `async def`);
`app/rag_chain.py:105` (blocking `httpx.Client.post` on the event loop, no
`num_predict`); `app/vectorstore.py:46` (serialized retrieval); no rate limit
anywhere.

Distinct from the injection findings: those are about *what the model says*. This
is about *how much work a caller can force* and *who else it starves* — a
resource-exhaustion / availability class.

## Vulnerability

Three app-level facts compound, all independent of retrieved content:

1. **Blocking work on the single event loop.** `/query` (`app/main.py:194`) is
   `async def`, but it calls `rag_chain.answer` directly, which does a **blocking**
   `httpx.Client.post` (`app/rag_chain.py:105`, sync client, no
   `run_in_threadpool`/`to_thread`). Uvicorn runs one event loop by default. A
   blocking call inside an `async def` handler freezes that loop for its whole
   duration — so while one generation runs, **every other request stalls,
   including `/health` and `/login`.** This is the load-bearing bug: the outage
   hits endpoints that never touch the model.

2. **No output cap.** `_generate` sends the model only `temperature` and
   `num_ctx` — no `num_predict` — so a caller controls how long generation runs
   via the question text, bounded only by `REQUEST_TIMEOUT` (180s). Each blocked
   interval can therefore be stretched to minutes.

3. **No rate limit, no concurrency guard.** Neither `/query` nor `/chat` throttles
   a caller (`grep num_predict|rate.?limit|semaphore|max_tokens app/` → nothing but
   a comment), and one local Ollama instance serves generations sequentially. So
   concurrent long requests both block the loop and queue at the model.

Reachability is what makes this High: `/query` needs only the `reader` role, which
is the **default** for any seeded account. No clearance, no uploader role, no
planted document — just a password.

## Exploit

`dos_carol.sh` logs in as `carol` (public clearance, reader role — nothing but a
password) and sustains 4 concurrent max-generation queries, probing `/health`
every 0.5s throughout. `/health` returns a static `{"status":"ok"}` and never
calls the model, so its latency measures the event loop alone. Unedited excerpt:

```
$ ./redteam/attacks/dos_carol.sh
[*] logged in as carol (reader)
[*] sustaining 4 concurrent max-generation queries — Ctrl-C to stop
[*] the app stays unresponsive for as long as this runs
    health: 0.000863s
    health: STALL (>3s, app not responding)
    health: STALL (>3s, app not responding)
    health: STALL (>3s, app not responding)
    health: STALL (>3s, app not responding)
    health: 2.741564s
    health: STALL (>3s, app not responding)
    health: STALL (>3s, app not responding)
    health: 1.515492s
    ... (continuous STALL for as long as the attack runs) ...
```

`/health` runs at ~0.9ms at rest, then holds at **STALL (>3s)** continuously for
the entire time the attack runs — only occasional 1–2.7s partial responses slip
through between blocked intervals. Because the stall hits an endpoint that does no
model work, the cause is the event loop being blocked: the app is down for *all*
callers, not just for model requests. Visible from the UI too: a normal reader
session (asking the wellness/refund questions) hangs for the duration and resumes
only when the attack stops.

**A refresh of the UI is not a counter-example.** The page shell (`GET /`) returns
static `index.html` with `ETag`/`Last-Modified` and no `no-store`, so a soft
refresh serves it from browser cache without reaching the frozen server — the page
appears while the API is dead. Any actual API action from that page (`/login`,
`/query`, `/chat`) hits the blocked loop and hangs. Confirm with cache disabled
(DevTools → Network → "Disable cache"): the reload itself then stalls like
`/health`.

**Nature of the outage:** this is a load-duration availability DoS — the app is
unavailable for exactly as long as the attacker keeps sending, and recovers when
they stop (a real attacker does not). Even a single long `/query` freezes
`/health` for its duration, because the blocking call is on the loop; the
concurrent requests keep the loop saturated back-to-back so the stall never lets
up. One account, one role, no privilege escalation, no planted document.

A related, *self-persisting* variant exists but is not practical to force on this
setup: the session store in `app/chat.py` has no session cap and no eviction, so a
sustained `/chat` flood leaks memory until the process is OOM-killed and stays
dead until restart. That leak is real but slow here — session creation is gated by
the same blocking model call (≈one leaked session per generation) — and macOS does
not support the per-process memory cap that would force the crash quickly, so it is
recorded as a latent defect rather than a demonstrated crash.

## Detection

The audit log cannot see this. `query.answered` records `model`, `chunks`,
`tiers`, `sources` — but **no duration and no token count**
(`app/rag_chain.py:227`) — and there is no request-received event to diff a
timestamp against. A 2-second answer and a 120-second answer log the same record
shape. An operator watching the log sees an ordinary query rate while the server is
frozen. Detection has to come from outside the log: request-latency histograms, an
Ollama generation-duration metric, or a per-actor request-rate counter — none of
which the app emits.

## Mitigation

Cheap, app-side controls in priority order:

- **Do model I/O off the event loop.** Make `/query`/`/chat` handlers `def`
  (FastAPI offloads sync handlers to a threadpool) or wrap `rag_chain.answer` in
  `run_in_threadpool` / `asyncio.to_thread`, or switch `_generate` to
  `httpx.AsyncClient` and `await` it. This alone stops one request from freezing
  unrelated endpoints — the highest-severity part of this finding.
- **Cap output.** Add `num_predict` to `_generate`'s options
  (`app/rag_chain.py:115`); turns "up to 180s per request" into a bounded cost.
- **Rate-limit per account.** A per-actor request/second and in-flight cap on
  `/query`/`/chat` (e.g. `slowapi`, or a small token bucket keyed on
  `user.username`) stops one reader from monopolizing the model.
- **Shorten / role-scope the 180s timeout** — it is a long time to hold the only
  model instance for one caller.

**Residual risk (per the phase-3 mandate — filters on does NOT close this):**

- **`SECURITY_FILTERS_ENABLED` does nothing here.** None of the three facts above
  is behind the flag: secure mode shrinks the *input* to 2000 chars via
  `validate_query`, but the handler is still `async def` doing a blocking call,
  still has no `num_predict`, and still has no rate limit. Flipping the switch and
  re-running `dos_carol.sh` produces the same `/health` stall. Phase 3 must report
  this class as **not mitigated by the gated defenses** — the fix is the code
  changes above, which the flag does not provide.
- **The single model instance is an architectural ceiling.** Even with the loop
  unblocked and output capped, one local Ollama serving sequentially means enough
  concurrent requests still queue; a rate limit raises the bar but a single-laptop
  deployment can always be saturated. The honest phase-3 statement is "much
  harder, not impossible."
