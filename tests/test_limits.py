"""Resource limits — OWASP LLM10, Unbounded Consumption.

Asserts the bounds exist in secure mode and are absent in insecure mode, which
is the before/after the phase 3 writeup cites. Nothing here calls a model: the
limits sit ahead of generation, so `/login` and `/chat` session minting exercise
them without an Ollama daemon.
"""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _fresh_buckets():
    """Each test starts with an empty limiter and leaves the mode as it found it.

    `filters_enabled()` reads the environment at call time (see
    `app.secrets.filters_enabled`), so switching modes needs no reimport —
    reloading `app.main` here would hand every later test file a different app
    object than the one it imported, which is a subtler bug than the one being
    tested.
    """
    from app import limits

    limits._HITS.clear()
    yield
    limits._HITS.clear()
    os.environ.pop("SECURITY_FILTERS_ENABLED", None)


def _client(monkeypatch, *, secure: bool) -> TestClient:
    monkeypatch.setenv("SECURITY_FILTERS_ENABLED", "true" if secure else "false")
    monkeypatch.setenv("SESSION_SIGNING_KEY", "k" * 43)
    monkeypatch.setenv("CONNECTOR_SYNC_SECONDS", "0")
    monkeypatch.setenv(
        "DEMO_USERS",
        '{"alice":{"password":"pw","clearance":"public","role":"reader"}}',
    )
    from app.main import app

    return TestClient(app)


def test_login_rate_limited_when_secure(monkeypatch):
    with _client(monkeypatch, secure=True) as client:
        body = {"username": "nobody", "password": "wrong"}
        codes = [client.post("/login", json=body).status_code for _ in range(12)]
    # Ten attempts allowed, the rest refused — an unmetered /login is a scrypt
    # amplifier (31 ms CPU and 16 MB each) reachable with no credentials.
    assert codes.count(401) == 10
    assert codes[-1] == 429


def test_login_unmetered_when_insecure(monkeypatch):
    with _client(monkeypatch, secure=False) as client:
        body = {"username": "nobody", "password": "wrong"}
        codes = [client.post("/login", json=body).status_code for _ in range(12)]
    assert set(codes) == {401}


def test_oversized_body_refused_before_parsing(monkeypatch):
    with _client(monkeypatch, secure=True) as client:
        from app import limits

        oversized = "A" * (limits.MAX_BODY_BYTES + 1)
        response = client.post("/login", json={"username": "alice", "password": oversized})
    assert response.status_code == 413


def test_session_store_evicts_oldest(monkeypatch):
    from app import chat

    monkeypatch.setattr(chat, "MAX_SESSIONS", 3)
    chat._SESSIONS.clear()
    first = chat.create("alice")
    for _ in range(3):
        chat.create("alice")
    assert len(chat._SESSIONS) == 3
    # The oldest is gone rather than the process growing per unreused session_id.
    assert chat.get(first.session_id, "alice") is None


@pytest.mark.parametrize("concurrency", [1])
def test_generation_slot_refuses_when_full(monkeypatch, concurrency):
    from app import limits

    monkeypatch.setenv("SECURITY_FILTERS_ENABLED", "true")
    monkeypatch.setattr(limits, "GENERATION_WAIT_SECONDS", 0.01)
    monkeypatch.setattr(limits, "_SLOTS", __import__("threading").BoundedSemaphore(concurrency))
    from fastapi import HTTPException

    with limits.generation_slot("alice"):
        with pytest.raises(HTTPException) as excinfo:
            with limits.generation_slot("bob"):
                pass
    assert excinfo.value.status_code == 503


def test_rate_limit_bucket_is_the_account_not_the_token(monkeypatch):
    """Re-authenticating must not buy a fresh allowance.

    `issue_token` embeds an `exp` timestamp, so two logins a second apart yield
    two different bearer strings for one account. Keying the limiter on the token
    let a caller multiply its generation budget just by looping /login; the key is
    the username the token names instead. Generation itself is stubbed — this is
    about which bucket the request lands in, not about the model.
    """
    real_time = time.time
    with _client(monkeypatch, secure=True) as client:
        from app import limits, main

        monkeypatch.setattr(
            main.rag_chain, "answer",
            lambda *a, **k: {"answer": "stub", "sources": [], "refused": False, "flags": []},
        )

        first = client.post("/login", json={"username": "alice", "password": "pw"})
        clock = real_time() + 5
        monkeypatch.setattr("app.auth.time.time", lambda: clock)
        second = client.post("/login", json={"username": "alice", "password": "pw"})
        assert (first.status_code, second.status_code) == (200, 200)

        tokens = [first.json()["token"], second.json()["token"]]
        assert tokens[0] != tokens[1], "tokens must differ for the bypass to exist"

        # Same account, alternating tokens, one call past the /query budget.
        codes = [
            client.post(
                "/query",
                json={"question": "what is the policy?"},
                headers={"Authorization": f"Bearer {tokens[i % 2]}"},
            ).status_code
            for i in range(limits.RATE_LIMIT_GENERATE + 1)
        ]

    assert codes.count(200) == limits.RATE_LIMIT_GENERATE, codes
    assert codes[-1] == 429, f"alternating tokens bypassed the account quota: {codes}"


def test_unverified_token_cannot_choose_its_bucket(monkeypatch):
    """A forged `sub` must not name a bucket; the peer address is the fallback.

    `_caller` verifies the HMAC rather than just decoding the payload, so an
    attacker cannot mint an arbitrary bucket per request — nor spend someone
    else's quota — by editing the claim.
    """
    monkeypatch.setenv("SESSION_SIGNING_KEY", "k" * 43)
    from app import auth, limits

    class _Request:
        def __init__(self, token: str) -> None:
            self.headers = {"authorization": f"Bearer {token}"} if token else {}
            self.client = type("C", (), {"host": "10.0.0.1"})()

    genuine = auth.issue_token(auth.User(username="alice", clearance="public", role="reader"))
    assert limits._caller(_Request(genuine)) == "u:alice"

    body = genuine.partition(".")[0]
    assert limits._caller(_Request(f"{body}.forged")) == "a:10.0.0.1"
    assert limits._caller(_Request("")) == "a:10.0.0.1"
