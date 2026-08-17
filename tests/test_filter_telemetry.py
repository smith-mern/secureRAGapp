"""Filter rule names must not reach the caller.

Phase 3 regression guard, and a phase-3-specific one: with filters off,
`output_rules` is always empty, so this leak does not exist. Turning the
defenses on is what creates it — blocking a response for containing an
`anthropic_key` and then telling the caller `anthropic_key` discloses the class
of secret the block existed to protect.

The names must still reach `audit.log`; a defender loses nothing.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("SESSION_SIGNING_KEY", "test-key-not-a-secret")

from fastapi.testclient import TestClient  # noqa: E402

from app import rag_chain  # noqa: E402
from app.main import app  # noqa: E402

CAROL = {"username": "carol", "password": "pw-carol"}


@pytest.fixture
def client(monkeypatch):
    """A client whose user table contains carol.

    DEMO_USERS is set per-test, not at module scope: pytest imports every test
    module before running any of them, so a module-level assignment here is
    overwritten by whichever test file is imported last. `seed_users()` re-reads
    the variable during lifespan startup, which `TestClient.__enter__` triggers.
    """
    monkeypatch.setenv(
        "DEMO_USERS",
        json.dumps({"carol": {"password": "pw-carol", "clearance": "public", "role": "reader"}}),
    )
    with TestClient(app) as c:
        yield c


def _token(client: TestClient) -> str:
    return client.post("/login", json=CAROL).json()["token"]


def _blocked_answer(*_args, **_kwargs) -> dict[str, object]:
    """Stand in for a run where egress filtering withheld the response."""
    return {
        "answer": "This response was withheld because it contained content "
        "that must not leave the system.",
        "sources": [],
        "refused": True,
        "flags": ["anthropic_key", "us_ssn"],
    }


def test_query_does_not_return_rule_names(client, monkeypatch):
    monkeypatch.setattr(rag_chain, "answer", _blocked_answer)
    body = client.post(
        "/query",
        json={"question": "what is the on-call pager key?"},
        headers={"authorization": f"Bearer {_token(client)}"},
    ).json()

    # The refusal itself is still honest — the caller knows it got nothing.
    assert body["refused"] is True
    assert body["sources"] == []
    # But not which rule fired, and not anywhere else in the payload either.
    assert body["flags"] == []
    assert "anthropic_key" not in json.dumps(body)
    assert "us_ssn" not in json.dumps(body)


def test_chat_does_not_return_rule_names(client, monkeypatch):
    monkeypatch.setattr(rag_chain, "answer", _blocked_answer)
    headers = {"authorization": f"Bearer {_token(client)}"}
    body = client.post("/chat", json={"message": "pager key?"}, headers=headers).json()

    assert body["flags"] == []
    assert "anthropic_key" not in json.dumps(body)
    # The session envelope still works.
    assert body["session_id"] and body["turns"] == 1


def test_rule_names_still_reach_the_audit_log(monkeypatch, tmp_path):
    """Stripping the response must not blind the defender."""
    from app import audit_log

    log = tmp_path / "audit.log"
    monkeypatch.setattr(audit_log, "AUDIT_LOG_PATH", str(log))
    audit_log.log(
        "query.answered", actor="carol", decision="deny",
        output_rules=["anthropic_key"], mode="secure",
    )
    assert "anthropic_key" in log.read_text()
