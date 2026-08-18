"""Resource limits at the trust boundary — OWASP LLM10, Unbounded Consumption.

Every guard elsewhere in this app bounds *what* a request may reach. Nothing
bounded *how much* it may spend, and the costs here are not small:

- **Request body.** Starlette buffers the entire body before any validator
  runs, so `validate_query`'s 2000-char cap is applied to text that is already
  resident. A 20 MB body was accepted and parsed on the way to a 401.
- **Request rate.** One `/query` is an LLM generation; one `/login` is a scrypt
  at 31 ms of CPU and 16 MB of RAM (measured, `n=2**14, r=8`). Unmetered, both
  are amplifiers — 60 concurrent unauthenticated logins took a 1 ms `/health`
  to 1970 ms.
- **Concurrent generations.** A rate limit bounds requests per window, not how
  many models run at once. Generation is the expensive resource and gets its
  own ceiling; past it, callers wait briefly and then get a 503 rather than
  joining an unbounded queue.

Gated on SECURITY_FILTERS_ENABLED like every other defense here, so the phase 2
and phase 3 runs of the attack suite stay comparable.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from app import audit_log
from app.auth import verify_token
from app.secrets import filters_enabled, optional

# 4 MB clears the 2 MB document cap in ingest.py plus JSON escaping overhead.
MAX_BODY_BYTES = int(optional("MAX_BODY_BYTES", str(4 * 1024 * 1024)))

RATE_LIMIT_REQUESTS = int(optional("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(optional("RATE_LIMIT_WINDOW_SECONDS", "60"))
# Generation is much dearer than an average request, so it is metered separately
# and far tighter than the general per-window budget.
RATE_LIMIT_GENERATE = int(optional("RATE_LIMIT_GENERATE", "10"))

MAX_CONCURRENT_GENERATIONS = int(optional("MAX_CONCURRENT_GENERATIONS", "2"))
GENERATION_WAIT_SECONDS = float(optional("GENERATION_WAIT_SECONDS", "5"))

# ponytail: fixed windows in a process-local dict, so a burst can straddle a
# window boundary and each worker keeps its own count. Correct bound per process
# and that is what this deployment is; move to Redis with a sliding window when
# there is more than one worker.
_MAX_KEYS = 10_000
_LOCK = threading.Lock()
_HITS: dict[str, tuple[float, int]] = {}

_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_GENERATIONS)


def _allow(key: str, limit: int, window: int) -> bool:
    now = time.monotonic()
    with _LOCK:
        if len(_HITS) > _MAX_KEYS:
            # The limiter must not become the unbounded thing it exists to
            # prevent: a caller rotating source addresses would otherwise grow
            # this dict without end. Drop expired windows, and if that does not
            # bring it back under the cap, deny — fail closed, not fail open.
            for stale in [k for k, (start, _) in _HITS.items() if now - start >= window]:
                del _HITS[stale]
            if len(_HITS) > _MAX_KEYS:
                return False

        start, count = _HITS.get(key, (now, 0))
        if now - start >= window:
            start, count = now, 0
        count += 1
        _HITS[key] = (start, count)
        return count <= limit


def _caller(request: Request) -> str:
    """Stable identity to meter against: the account, or the peer address.

    The quota belongs to the *account*, so the key is the username the bearer
    token names — not the token. Hashing the token itself looked equivalent and
    was not: `issue_token` embeds an `exp` timestamp, so logging in twice yields
    two different strings for one account, each with its own fresh allowance.
    Re-authenticating in a loop then multiplied the generation budget without
    limit, which is exactly what the budget existed to prevent.

    The token is verified, not merely parsed. `verify_token` checks the HMAC
    before returning a username, so a caller cannot pick its own bucket — or
    somebody else's — by editing the `sub` claim. An absent, malformed, expired
    or forged token falls back to the peer address, which is all an
    unauthenticated `/login` offers anyway.

    ponytail: `request.client.host` is the peer, not a forwarded-for header.
    Correct behind no proxy — which is this deployment — and deliberately not
    reading a client-settable header, since that would hand every caller its own
    bucket. Add trusted-proxy handling when one is actually in front.
    """
    token = request.headers.get("authorization", "").partition(" ")[2]
    if token:
        user = verify_token(token)
        if user is not None:
            return "u:" + user.username
    return "a:" + (request.client.host if request.client else "unknown")


def rate_limit(bucket: str, limit: int | None = None):
    """FastAPI dependency factory: cap one bucket per caller per window."""
    ceiling = RATE_LIMIT_REQUESTS if limit is None else limit

    async def dependency(request: Request) -> None:
        if not filters_enabled():
            return
        caller = _caller(request)
        if not _allow(f"{bucket}:{caller}", ceiling, RATE_LIMIT_WINDOW_SECONDS):
            audit_log.log(
                "limit.rate", decision="deny", bucket=bucket,
                caller=caller, limit=ceiling, window=RATE_LIMIT_WINDOW_SECONDS,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests",
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

    return dependency


@contextlib.contextmanager
def generation_slot(actor: str) -> Iterator[None]:
    """Hold one of the concurrent-generation slots for the duration of a call."""
    if not filters_enabled():
        yield
        return
    if not _SLOTS.acquire(timeout=GENERATION_WAIT_SECONDS):
        audit_log.log(
            "limit.generation", actor=actor, decision="deny",
            reason="no_slot", concurrent=MAX_CONCURRENT_GENERATIONS,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Busy, retry shortly",
            headers={"Retry-After": "5"},
        )
    try:
        yield
    finally:
        _SLOTS.release()


async def body_size_guard(request: Request, call_next):
    """Reject an oversized body before Starlette buffers it.

    Decided from `Content-Length` rather than by counting bytes as they arrive,
    which means it must also refuse a body-carrying request that declares no
    length at all — "cannot tell" and "too large" get the same answer, because
    the alternative is reading an unbounded stream to find out. Every client of
    this API sends a length.
    """
    if filters_enabled() and request.method in ("POST", "PUT", "PATCH"):
        declared = request.headers.get("content-length")
        too_big = declared is None or not declared.isdigit() or int(declared) > MAX_BODY_BYTES
        if too_big:
            audit_log.log(
                "limit.body", decision="deny", path=request.url.path,
                declared=declared, limit=MAX_BODY_BYTES,
            )
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": f"body must be at most {MAX_BODY_BYTES} bytes"},
            )
    return await call_next(request)
