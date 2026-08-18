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
(single-request amplification),
[`redteam/attacks/unbounded_consumption.py`](../attacks/unbounded_consumption.py)
(self-contained before/after probe added in phase 3 — event-loop starvation and
unbounded request body, no Ollama needed)
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

Applied in phase 3. Attack script:
[`redteam/attacks/unbounded_consumption.py`](../attacks/unbounded_consumption.py),
which is self-contained (boots the app in-process, needs no Ollama) and so gives
a number rather than a stall description. `/login` is the cost source there —
`authenticate` spends ~31 ms of CPU and ~16 MB of RAM in scrypt per attempt and
hashes even for users that do not exist, so the amplifier needs no credentials at
all. Measured before/after, 60 concurrent logins against a `/health` that touches
neither auth nor the model:

```
pre-fix (commit 9d08bfd)   [A]  1 ms ->  1970 ms   [B] 20 MB body accepted
post-fix, filters off      [A]  1 ms ->   194 ms   [B] 20 MB body accepted
post-fix, filters on       [A]  1 ms ->    26 ms   [B] 413
```

**Unconditional — not behind the flag.** Blocking work on the event loop is a
defect, not a defense to demonstrate, so these apply in both modes:

- **Handlers moved off the event loop.** `/login`, `/query`, `/chat`, `/upload`,
  `/ingest` and `/review` are now plain `def`; FastAPI dispatches a sync handler
  to the threadpool, which also caps how many run at once. `/health` and `/` do no
  blocking work and stay `async def`. This is the 1970 -> 194 ms line, and it is
  the load-bearing part of the finding: one request no longer freezes endpoints it
  has nothing to do with.
- **Output capped.** `MAX_OUTPUT_TOKENS` (default 1024) is passed as
  `num_predict` to `ChatOllama` and `max_tokens` to `ChatGroq`
  (`app/rag_chain.py`). Unset, Ollama's `num_predict` is -1 — unlimited — so
  "repeat this forever" ran until `REQUEST_TIMEOUT` or the context ended it.
- **Session store bounded.** `app/chat.py` evicts oldest-first at
  `MAX_SESSIONS` (1000). This closes the leak in
  [`dos_chat_leak.sh`](../attacks/dos_chat_leak.sh): `/chat` with no `session_id`
  minted a session per call and nothing ever removed one, so the cost of an
  unbounded memory footprint is now the cost of an idle conversation's history.

**Gated on `SECURITY_FILTERS_ENABLED`,** in `app/limits.py`, so the phase 2 and
phase 3 runs of the rest of the attack suite stay comparable:

- **Per-caller rate limit** (`RATE_LIMIT_REQUESTS`, default 30 per 60 s;
  `RATE_LIMIT_GENERATE`, 10, on `/query` and `/chat`; 10 on `/login`; 2 on
  `/ingest`, which re-embeds the whole corpus). Metered on the **account** the
  bearer token names — see UC-01 below, which is the bug from keying it on the
  token — and on the peer address when there is no valid token, which is all an
  unauthenticated `/login` offers. The token's HMAC is verified before its `sub`
  claim is used, so a caller cannot mint a bucket per request, or spend someone
  else's quota, by editing the claim. The limiter purges expired windows and
  denies past `_MAX_KEYS` — fail closed, so it cannot itself become the
  unbounded thing.
- **Concurrent-generation ceiling** (`MAX_CONCURRENT_GENERATIONS`, default 2). A
  rate limit bounds requests per window, not how many models are resident at
  once. Held across the agentic loop as well, which can spend
  `AGENT_MAX_TOOL_ITERS` model calls on one request. Past the ceiling a caller
  waits `GENERATION_WAIT_SECONDS` and then gets a 503 with `Retry-After` rather
  than joining an unbounded queue.
- **Request body ceiling** (`MAX_BODY_BYTES`, default 4 MB), decided from
  `Content-Length` in middleware before Starlette buffers anything. This is the
  20 MB -> 413 line. Every input validator in the app ran *after* the body was
  already resident, so `validate_query`'s 2000-char cap and the 2 MB document cap
  in `app/ingest.py` were both bounding a copy of memory the caller had already
  spent.

Check: `tests/test_limits.py` — rate limit denies past the cap in secure mode and
never in insecure mode, an oversized body is refused before parsing, the session
store evicts, and a full generation ceiling refuses with 503.

### UC-01 — per-token rate-limit bypass (found by red-team, fixed)

The first cut of `app/limits.py` keyed the limiter on
`sha256(bearer_token)`, on the reasoning that a token identifies its holder more
tightly than an address does. It does not: `issue_token` embeds an `exp`
timestamp, so **logging in twice yields two different token strings for one
account**, each landing in its own bucket with its own fresh allowance. Looping
`/login` — itself limited only per address, and cheap for a caller who already
has valid credentials — multiplied the generation budget without bound. Two
tokens for one account got 20 allowed `/query` calls against a limit of 10. On a
hosted provider that is direct cost amplification, and it needed nothing but
`reader`, the default role.

The credential is not the identity. `_caller` now returns `"u:" + username` from
`verify_token`, which checks the HMAC first so the `sub` claim cannot be chosen
by the caller, and falls back to the peer address for any token that is absent,
malformed, expired or forged.

Regression guards, both of which fail against the token-keyed version
(confirmed by reverting it — the quota test reports 11 allowed where 10 are
intended):
`test_rate_limit_bucket_is_the_account_not_the_token` alternates two genuine
tokens for one account and asserts the 11th call is a 429;
`test_unverified_token_cannot_choose_its_bucket` asserts a forged signature
falls back to the address bucket.

**Residual risk (filters on does NOT close this class):**

- **A body with no `Content-Length` is refused rather than measured.** The
  middleware decides from the declared length, so a chunked body-carrying request
  gets the same 413 as an oversized one — "cannot tell" and "too large" are the
  same answer, because the alternative is reading an unbounded stream to find
  out. Correct for every client of this API, and it would reject a legitimate
  streaming client. Counting bytes as they arrive is the upgrade.
- **Fixed windows in a process-local dict.** A burst can straddle a window
  boundary and get up to 2x the budget, and each worker keeps its own count, so
  the effective limit scales with worker count. Correct bound for the
  single-process laptop deployment this is; needs a shared store with a sliding
  window otherwise.
- **`request.client.host` is the peer, not `X-Forwarded-For`.** Deliberate —
  reading a client-settable header would hand every caller its own bucket — but
  behind a proxy every unauthenticated caller shares one bucket, which turns the
  `/login` limit into a self-inflicted lockout. Needs trusted-proxy handling
  before anything sits in front.
- **A refused request is cheaper, not free.** Over the concurrency ceiling a
  caller waits `GENERATION_WAIT_SECONDS` before the 503, and it waits holding a
  threadpool worker. Enough callers past the ceiling therefore still occupy
  capacity that endpoints doing no model work would want, and the rate limit —
  which is per window, not per in-flight request — does not bound that. Lower
  the wait toward zero to trade queueing for more 503s; the honest position is
  that this bounds the *model* well and the *threadpool* only loosely.
- **The single model instance is still an architectural ceiling.** With the loop
  unblocked, output capped, and concurrency bounded, one local Ollama serving
  sequentially means enough concurrent requests still queue behind each other.
  A rate limit raises the bar; a single-laptop deployment can always be
  saturated. The honest statement stays "much harder, not impossible."
- **Detection is still blind.** Nothing above added a duration or token count to
  `query.answered`, so the gap in the Detection section is unchanged for
  *answered* requests. What is new is that refusals are visible: `limit.rate`,
  `limit.generation` and `limit.body` events name the bucket, the caller and the
  ceiling, so saturation now leaves a trace even though normal cost does not.
