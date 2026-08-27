"""FastAPI application entrypoint.

Wires the API layer: creates the app, mounts routes, and applies auth. Endpoints
are thin — they validate input, delegate to the module that owns the work, and
shape the response. No business logic here.

Errors are returned as fixed messages. A handler that echoes an exception back
to the caller turns every internal failure into an information leak, so
unexpected errors are logged by type and answered with a generic 500.

Run: uvicorn app.main:app --reload
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from typing import Any
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app import audit_log, ingest, limits, rag_chain, review_agent, secrets, vectorstore
from app import chat as chat_store

STATIC_DIR = Path(__file__).resolve().parent / "static"
from app.auth import (
    User,
    allowed_tiers,
    authenticate,
    current_user,
    issue_token,
    require_role,
    seed_users,
)
from app.filters.input_validation import ValidationError, validate_tier, validate_username


SYNC_SECONDS = int(secrets.optional("CONNECTOR_SYNC_SECONDS", "60"))


async def _connector_sync_loop(interval: int) -> None:
    """Periodic background pull from the upstream source.

    Runs with no user in the request — which is what production connector
    ingestion looks like, and why `actor` is "system" rather than a person.
    Failures are logged and the loop continues; an unreachable source should
    not take the API down.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(ingest.sync_connector)
        except Exception as exc:  # noqa: BLE001 - loop must survive any failure
            audit_log.log(
                "connector.sync", decision="error", reason=type(exc).__name__
            )


def register_egress_secrets() -> None:
    """Register known secret values so the output filter blocks them verbatim.

    The signing/encryption keys must never appear in an answer; CANARY_TOKENS is
    a comma-separated list of canary strings (e.g. one planted in a restricted
    document) so a red-team run can confirm the egress block end to end. Values
    are registered, never logged.
    """
    from app.filters import output_filter

    for name in ("SESSION_SIGNING_KEY", "STORE_ENCRYPTION_KEY", "GROQ_API_KEY"):
        value = os.environ.get(name, "")
        if value:
            output_filter.protect_secret(value)
    for token in os.environ.get("CANARY_TOKENS", "").split(","):
        if token.strip():
            output_filter.protect_secret(token.strip())


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail at boot, not on the first request, if a secret is missing.
    secrets.check_required()
    seed_users()
    register_egress_secrets()
    secure = secrets.filters_enabled()
    # `digest` is what a swapped generator changes. The app pins a mutable tag,
    # so recording the content digest each boot is the only way a re-pointed tag
    # shows up as anything: a one-line diff between two `app.start` events.
    # Raises if OLLAMA_MODEL_DIGEST is set and the running generator is not it —
    # boot is the right place to fail, not the first query.
    digest = rag_chain.check_model_pin()
    audit_log.log(
        "app.start", decision="allow", mode="secure" if secure else "insecure",
        provider=rag_chain.PROVIDER, model=rag_chain.MODEL, digest=digest,
    )
    if not secure:
        # Loud on purpose. An app running exploitable should never be a surprise.
        print(
            "\n*** SECURITY FILTERS DISABLED — this instance is deliberately "
            "exploitable.\n*** Set SECURITY_FILTERS_ENABLED=true to run the "
            "hardened configuration.\n",
            file=sys.stderr,
            flush=True,
        )
    if rag_chain.PROVIDER != "ollama":
        # Same reasoning as the banner above: a change this consequential to the
        # threat model should never be discovered by reading the config later.
        audit_log.log(
            "app.remote_llm", decision="allow",
            provider=rag_chain.PROVIDER, model=rag_chain.MODEL,
        )
        print(
            f"\n*** REMOTE LLM — LLM_PROVIDER={rag_chain.PROVIDER}. Questions and "
            "retrieved document text,\n*** including the restricted tier, are sent "
            "to a third party. Set LLM_PROVIDER=ollama\n*** to keep generation on "
            "this machine.\n",
            file=sys.stderr,
            flush=True,
        )

    task = None
    if SYNC_SECONDS > 0:
        task = asyncio.create_task(_connector_sync_loop(SYNC_SECONDS))
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="secureRAGapp", version="0.1.0", lifespan=lifespan)

# First middleware registered is outermost, so the size check runs before any
# body is buffered. See app/limits.py for what each ceiling costs unbounded.
app.middleware("http")(limits.body_size_guard)


# Headers the browser enforces, on every response. The answer body carries text
# the model can be steered into producing, so the two that matter here are
# `nosniff` — without it a browser pointed straight at /query may sniff the JSON
# as HTML and render the payload inside it — and `connect-src 'self'`, which
# stops the exfiltration half of an XSS even where the markup does execute.
#
# `unsafe-inline` is present because index.html carries an inline <style> and
# <script>. That makes the script-src clause worth little against injected
# markup; the clauses doing real work are connect-src, img-src, frame-ancestors,
# and form-action, which bound where a payload could send anything. Moving the
# inline blocks into files and dropping unsafe-inline is the upgrade.
# ponytail: one policy for the JSON API and the one HTML page. Split it if the
# app ever serves a second page with different needs.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'none'"
    ),
}


@app.middleware("http")
async def security_headers(request: Request, call_next: Any) -> Response:
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


class LoginRequest(BaseModel):
    username: str
    password: str


class QueryRequest(BaseModel):
    question: str


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class RejectRequest(BaseModel):
    tier: str
    source: str
    content_hash: str
    # Free text for the audit trail and for whoever has to fix the document. Not
    # echoed back to the uploader by any endpoint here — /upload has no channel
    # for it — so it is a record, not a message.
    reason: str = ""


class ReviewRequest(BaseModel):
    tier: str
    source: str
    # Required, not optional. An approval that may omit the revision is an
    # approval an attacker omits it from, and the whole binding is gone.
    content_hash: str


class UploadRequest(BaseModel):
    filename: str
    tier: str
    # Text body rather than multipart: the ingest pipeline only accepts .txt and
    # .md, so there is nothing binary to carry and no upload parser to add.
    content: str


@app.exception_handler(ValidationError)
async def _validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
    # The message states which rule failed and never repeats the input back.
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def _unhandled_handler(_: Request, exc: Exception) -> JSONResponse:
    audit_log.log("app.error", decision="error", exception=type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "Internal error"})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/login")
def login(
    body: LoginRequest, _: None = Depends(limits.rate_limit("login", 10))
) -> dict[str, str]:
    # Sync `def`, not `async def`: authenticate() spends ~31 ms of CPU and 16 MB
    # of RAM in scrypt. On the event loop that cost is serialised across the
    # whole process — measured, 60 concurrent logins took /health from 1 ms to
    # 1970 ms. A plain `def` is dispatched to the threadpool instead, which also
    # caps how many run at once. Same reasoning on every handler below that
    # blocks; /health and / do not and stay async.
    username = validate_username(body.username)
    user = authenticate(username, body.password)
    if user is None:
        # One message for both unknown-user and bad-password: telling them
        # apart hands an attacker a user enumeration oracle.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    return {"token": issue_token(user), "clearance": user.clearance, "role": user.role}


@app.get("/me")
async def me(user: User = Depends(current_user)) -> dict[str, object]:
    tiers = allowed_tiers(user.clearance)
    return {
        "username": user.username,
        "clearance": user.clearance,
        "role": user.role,
        # Which lists are populated is the whole authorization model in one
        # response, and it is what the UI switches on.
        "readable_tiers": list(tiers) if user.role == "reader" else [],
        "writable_tiers": list(tiers) if user.role == "uploader" else [],
        "approvable_tiers": list(tiers) if user.role == "approver" else [],
    }


@app.post("/upload")
def upload(
    body: UploadRequest,
    user: User = Depends(require_role("uploader")),
    _: None = Depends(limits.rate_limit("upload")),
) -> dict[str, object]:
    """Add one document to the index. `uploader` role only.

    The only write path into retrieval that an ordinary account can reach, which
    is why it is the one endpoint fenced off to a single role rather than to a
    clearance level. The tier is still bounded by the uploader's clearance — the
    role says they may write, the clearance says how far.
    """
    return ingest.store_upload(
        filename=body.filename,
        tier=body.tier,
        content=body.content,
        actor=user.username,
        allowed_tiers=allowed_tiers(user.clearance),
    )


@app.post("/ingest")
def run_ingest(
    user: User = Depends(require_role("uploader")),
    # A full rebuild re-embeds the whole corpus; it is the dearest call here and
    # gets the tightest budget.
    _: None = Depends(limits.rate_limit("ingest", 2)),
) -> dict[str, object]:
    """Rebuild the index from every source. `uploader` role only.

    Same trust boundary as /upload: ingestion decides what every future query
    can retrieve, so both live behind the role that exists to write, not behind
    a high clearance that exists to read.
    """
    # A manual sync has a user behind it, unlike the scheduled loop.
    return {"indexed": ingest.ingest_all(actor=user.username), "totals": vectorstore.stats()}


@app.get("/review")
def review_queue(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require_role("approver")),
    _: None = Depends(limits.rate_limit("review")),
) -> dict[str, object]:
    """Everything awaiting approval, worst first. `approver` only.

    /review has always taken an exact `source` string, which assumed an approver
    already knew what was pending — there was no way to enumerate it. A gate
    whose queue cannot be read is a gate that gets bypassed by neglect, and
    unreviewed uploads pile up until someone approves a batch unread.

    Risk is read from metadata written at index time, not recomputed per request.
    Rescanning here made the listing cost scale with how much was waiting, which
    an uploader controls: the 50 KB cap bounds one document, not how many get
    submitted. Paginated for the same reason — an unbounded response is the other
    half of that lever.

    Scanning at ingest never gates ingestion: a document is stored and indexed
    `reviewed=false` whatever the scan says, and a scan that failed shows as
    `unknown` risk here rather than as clean. Bodies are not returned — this
    lists what is waiting, and reading the content is GET /review/document.
    """
    pending: list[dict[str, object]] = []
    for tier in allowed_tiers(user.clearance):
        pending.extend(vectorstore.pending_review(tier))

    # Riskiest first: a queue sorted by arrival buries the one document that
    # needed a human under fifty that did not. `unknown` outranks `low` — a
    # document whose scan did not complete is not a document known to be fine.
    order = {"high": 0, "unknown": 1, "missing": 1, "medium": 2, "low": 3}
    pending.sort(key=lambda item: (order.get(str(item["risk"]), 1), str(item["source"])))

    total = len(pending)
    page = pending[offset : offset + limit]
    audit_log.log(
        "review.queue", actor=user.username, decision="allow",
        pending=total, returned=len(page),
    )
    return {"pending": page, "count": len(page), "total": total,
            "offset": offset, "limit": limit}


@app.get("/review/document")
def review_document(
    tier: str,
    source: str,
    user: User = Depends(require_role("approver")),
    _: None = Depends(limits.rate_limit("review")),
) -> dict[str, object]:
    """One pending document with its advisory scan. `approver` only.

    This is the only endpoint that returns unreviewed text, and it is bounded by
    the approver's clearance like every other read. That is the trade the review
    gate requires: somebody has to read the thing to approve it. The scan's job
    is to make that reading tractable by naming the lines worth looking at.
    """
    tier = validate_tier(tier, allowed_tiers(user.clearance))
    text = vectorstore.source_text(tier, source)
    if not text:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such source")

    revision = vectorstore.source_revision(tier, source)
    report = review_agent.review(text, source)
    audit_log.log(
        "review.scan", actor=user.username, decision="allow", tier=tier, source=source,
        risk=report["risk"], rules=[f["rule"] for f in report["findings"]],
        classifier=report["classifier"]["verdict"], revision=revision,
    )
    # `content_hash` is what POST /review must echo back. It identifies the bytes
    # rendered above, so approving a document that was replaced in the meantime
    # fails with 409 instead of signing off on text nobody read.
    return {"tier": tier, "text": text, "report": report, "content_hash": revision}


@app.post("/review/reject")
def review_reject(
    body: RejectRequest,
    user: User = Depends(require_role("approver")),
    _: None = Depends(limits.rate_limit("review")),
) -> dict[str, object]:
    """Reject a pending document and take it out of circulation. `approver` only.

    Approval is all-or-nothing: it trusts the document as written, flagged
    passages included. There is deliberately no partial approval and no
    sanitizer — an approver who removes the one line a scan flagged is editing
    an attacker's document into a shape that passes the scan, and the
    split-instruction case means "the flagged line" and "the instruction" are
    not reliably the same thing. So the two outcomes are: approve this exact
    revision, or reject it and ask for a clean replacement.

    Leaving it pending is not the third option it looks like. A pending document
    stays in the queue forever, so a stream of bad uploads becomes the queue
    padding the size cap exists to prevent — the reject path is what keeps the
    queue drainable.

    Rejection drops the chunks and moves the file out of `data/uploads/`, since
    `ingest_uploads` re-sweeps that directory and would otherwise reinstate the
    document on the next `POST /ingest`. The file is moved to `data/quarantine/`
    rather than deleted: it is evidence.

    A `connector:*` record has no file here. Its chunks are dropped, but the
    upstream system owns the record and the next sync reinstates it unless it is
    fixed there. `requeued` in the response says which case happened rather than
    reporting a durable rejection this application cannot make.
    """
    tier = validate_tier(body.tier, allowed_tiers(user.clearance))
    try:
        chunks = vectorstore.reject_source(tier, body.source, body.content_hash)
    except vectorstore.StaleRevision:
        # The uploader may have replaced a flagged document with a corrected one
        # while it sat in the queue. Rejecting the version that was read must not
        # destroy the version that was not.
        audit_log.log(
            "review.reject", actor=user.username, decision="deny",
            tier=tier, source=body.source, reason="stale_revision",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document changed since it was read; review it again",
        )

    if not chunks:
        audit_log.log(
            "review.reject", actor=user.username, decision="deny",
            tier=tier, source=body.source, reason="unknown_source",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such source")

    quarantined = ingest.quarantine_upload(tier, body.source, user.username)
    audit_log.log(
        "review.reject", actor=user.username, decision="allow",
        tier=tier, source=body.source, chunks=chunks, revision=body.content_hash,
        quarantined=quarantined, note=body.reason[:200],
    )
    return {
        "source": body.source, "tier": tier, "chunks": chunks, "rejected": True,
        "quarantined": quarantined,
        # True where this app cannot make the rejection stick on its own.
        "requeued_on_next_sync": not quarantined,
    }


@app.post("/review")
def review(
    body: ReviewRequest,
    user: User = Depends(require_role("approver")),
    _: None = Depends(limits.rate_limit("review")),
) -> dict[str, object]:
    """Approve one source so its chunks may answer questions. `approver` only.

    Uploaded and connector-sourced content is indexed unreviewed and cannot
    answer anyone until it passes through here — that is what stops a
    password-only account from asserting facts to every reader. The role is
    disjoint from `uploader` so nobody approves their own writes, and bounded by
    clearance so an approver cannot reach into a tier they may not read.
    """
    tier = validate_tier(body.tier, allowed_tiers(user.clearance))
    try:
        chunks = vectorstore.mark_reviewed(
            tier, body.source, user.username, body.content_hash
        )
    except vectorstore.StaleRevision:
        # 409, not a silent re-approval: the document under this name is not the
        # one that was read. Deliberately does not say what changed — the
        # approver re-reads it, which is the only thing that restores the
        # property this check exists to protect.
        audit_log.log(
            "review.approve", actor=user.username, decision="deny",
            tier=tier, source=body.source, reason="stale_revision",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document changed since it was read; review it again",
        )
    if not chunks:
        # 404 rather than a cheerful no-op: "approved" for a source that does not
        # exist is a lie an operator would act on.
        audit_log.log(
            "review.approve", actor=user.username, decision="deny",
            tier=tier, source=body.source, reason="unknown_source",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such source")

    audit_log.log(
        "review.approve", actor=user.username, decision="allow",
        tier=tier, source=body.source, chunks=chunks, revision=body.content_hash,
    )
    return {
        "source": body.source, "tier": tier, "chunks": chunks,
        "reviewed": True, "content_hash": body.content_hash,
    }


def _without_filter_telemetry(result: dict[str, object]) -> dict[str, object]:
    """Drop the names of the filter rules that fired before responding.

    `flags` is internal telemetry: it names the exact rule that blocked a
    chunk, a query, or a response. Server-side that is the audit trail. Handed
    back to the caller it is an oracle, and the block cases are the worst of
    them — withholding an answer because it contained an `anthropic_key` and
    then reporting `anthropic_key` discloses the class of secret the refusal
    existed to protect. It also lets a caller tune a payload against named
    rules until the list comes back empty.

    The rule names stay in `audit.log` (`output_rules`, `retrieval.chunk_dropped`),
    so nothing is lost for defenders. `refused` still tells an honest client
    that its request did not produce an answer.
    """
    return {**result, "flags": []}


@app.post("/query")
def query(
    body: QueryRequest,
    user: User = Depends(require_role("reader")),
    _: None = Depends(limits.rate_limit("generate", limits.RATE_LIMIT_GENERATE)),
) -> dict[str, object]:
    """Single-shot question. No conversation state."""
    return _without_filter_telemetry(rag_chain.answer(body.question, user))


@app.post("/chat")
def chat(
    body: ChatRequest,
    user: User = Depends(require_role("reader")),
    _: None = Depends(limits.rate_limit("generate", limits.RATE_LIMIT_GENERATE)),
) -> dict[str, object]:
    """Multi-turn question. Omit session_id to start a conversation.

    An unknown or foreign session_id is rejected rather than silently starting a
    new conversation — quietly issuing a fresh session would hide the fact that
    the caller was reaching for someone else's.
    """
    if body.session_id:
        session = chat_store.get(body.session_id, user.username)
        if session is None:
            audit_log.log(
                "chat.session", actor=user.username, decision="deny",
                reason="unknown_or_not_owned",
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such session")
    else:
        session = chat_store.create(user.username)
        audit_log.log("chat.session", actor=user.username, decision="allow", turns=0)

    result = rag_chain.answer(body.message, user, chat_store.as_messages(session))
    chat_store.append(session, body.message, result["answer"])
    return {
        "session_id": session.session_id,
        "turns": len(session.turns),
        **_without_filter_telemetry(result),
    }


@app.get("/")
async def index() -> FileResponse:
    """Minimal chat UI. Unauthenticated — it logs in via /login like any client."""
    return FileResponse(STATIC_DIR / "index.html")
