"""Role separation: only `uploader` writes, only `reader` reads.

The one thing that must not regress is that the two abilities never overlap, so
this asserts both directions — a reader is refused the write endpoints and an
uploader is refused the read ones. Checking only half would pass an app that
gave everybody everything.

Runs against the API with filters off (the default), because role enforcement is
authorization, not one of the gated phase-3 filters. It is supposed to hold in
both modes.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("SESSION_SIGNING_KEY", "test-key-not-a-secret")
os.environ["DEMO_USERS"] = json.dumps(
    {
        "r-user": {"password": "pw-r", "clearance": "restricted", "role": "reader"},
        "u-user": {"password": "pw-u", "clearance": "internal", "role": "uploader"},
        "d-user": {"password": "pw-d", "clearance": "public"},
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from app import vectorstore  # noqa: E402
from app.main import app  # noqa: E402
from app.secrets import UPLOADS_DIR  # noqa: E402

PROBE = "role-test.md"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True, scope="module")
def _clean_probe():
    """Remove the probe document from disk and from the index afterwards.

    CHROMA_DIR and UPLOADS_DIR are fixed paths, so this test writes into the
    same store the dev instance serves. Leaving the probe behind would put a
    test artifact in front of real queries.
    """
    yield
    for tier in ("public", "internal", "restricted"):
        vectorstore.delete_source(tier, f"upload/{tier}/{PROBE}")
        (UPLOADS_DIR / tier / PROBE).unlink(missing_ok=True)


def _token(client, username, password):
    res = client.post("/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return res.json()


def test_role_is_reported_and_defaults_to_reader(client):
    assert _token(client, "u-user", "pw-u")["role"] == "uploader"
    # No "role" key in DEMO_USERS must not grant write access.
    assert _token(client, "d-user", "pw-d")["role"] == "reader"


def test_reader_cannot_write(client):
    auth = {"authorization": "Bearer " + _token(client, "r-user", "pw-r")["token"]}
    # Restricted clearance — the highest read privilege there is — still cannot
    # reach either write path.
    body = {"filename": "x.md", "tier": "public", "content": "hello"}
    assert client.post("/upload", json=body, headers=auth).status_code == 403
    assert client.post("/ingest", headers=auth).status_code == 403


def test_uploader_cannot_read(client):
    auth = {"authorization": "Bearer " + _token(client, "u-user", "pw-u")["token"]}
    assert client.post("/query", json={"question": "what is the policy?"},
                       headers=auth).status_code == 403
    assert client.post("/chat", json={"message": "what is the policy?"},
                       headers=auth).status_code == 403


def test_uploader_writes_only_within_its_clearance(client):
    auth = {"authorization": "Bearer " + _token(client, "u-user", "pw-u")["token"]}
    ok = client.post(
        "/upload",
        json={"filename": PROBE, "tier": "internal", "content": "upload probe"},
        headers=auth,
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["chunks"] > 0

    # internal clearance grants public+internal, not restricted.
    over = client.post(
        "/upload",
        json={"filename": PROBE, "tier": "restricted", "content": "upload probe"},
        headers=auth,
    )
    assert over.status_code == 400


@pytest.mark.parametrize(
    "filename",
    ["../escape.md", "sub/dir.md", "no-suffix", "shell.sh", ""],
)
def test_upload_rejects_unsafe_filenames(client, filename):
    auth = {"authorization": "Bearer " + _token(client, "u-user", "pw-u")["token"]}
    res = client.post(
        "/upload",
        json={"filename": filename, "tier": "public", "content": "probe"},
        headers=auth,
    )
    assert res.status_code == 400, filename
