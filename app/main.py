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
import sys
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app import audit_log, ingest, rag_chain, secrets, vectorstore
from app import chat as chat_store

STATIC_DIR = Path(__file__).resolve().parent / "static"
from app.auth import User, allowed_tiers, authenticate, current_user, issue_token, seed_users
from app.filters.input_validation import ValidationError, validate_username


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


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail at boot, not on the first request, if a secret is missing.
    secrets.check_required()
    seed_users()
    secure = secrets.filters_enabled()
    audit_log.log("app.start", decision="allow", mode="secure" if secure else "insecure")
    if not secure:
        # Loud on purpose. An app running exploitable should never be a surprise.
        print(
            "\n*** SECURITY FILTERS DISABLED — this instance is deliberately "
            "exploitable.\n*** Set SECURITY_FILTERS_ENABLED=true to run the "
            "hardened configuration.\n",
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


class LoginRequest(BaseModel):
    username: str
    password: str


class QueryRequest(BaseModel):
    question: str


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


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
async def login(body: LoginRequest) -> dict[str, str]:
    username = validate_username(body.username)
    user = authenticate(username, body.password)
    if user is None:
        # One message for both unknown-user and bad-password: telling them
        # apart hands an attacker a user enumeration oracle.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    return {"token": issue_token(user), "clearance": user.clearance}


@app.get("/me")
async def me(user: User = Depends(current_user)) -> dict[str, object]:
    return {
        "username": user.username,
        "clearance": user.clearance,
        "readable_tiers": list(allowed_tiers(user.clearance)),
    }


@app.post("/ingest")
async def run_ingest(user: User = Depends(current_user)) -> dict[str, object]:
    """Re-index data/documents/. Restricted clearance only.

    Ingestion decides what every future query can retrieve, so it sits behind
    the highest clearance rather than plain authentication.
    """
    if user.clearance != "restricted":
        audit_log.log("ingest.run", actor=user.username, decision="deny", reason="clearance")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    # A manual sync has a user behind it, unlike the scheduled loop.
    return {"indexed": ingest.ingest_all(actor=user.username), "totals": vectorstore.stats()}


@app.post("/query")
async def query(body: QueryRequest, user: User = Depends(current_user)) -> dict[str, object]:
    """Single-shot question. No conversation state."""
    return rag_chain.answer(body.question, user)


@app.post("/chat")
async def chat(body: ChatRequest, user: User = Depends(current_user)) -> dict[str, object]:
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
    return {"session_id": session.session_id, "turns": len(session.turns), **result}


@app.get("/")
async def index() -> FileResponse:
    """Minimal chat UI. Unauthenticated — it logs in via /login like any client."""
    return FileResponse(STATIC_DIR / "index.html")
