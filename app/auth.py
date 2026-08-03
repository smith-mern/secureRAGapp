"""Authentication and authorization.

Owns identity: credential verification, session token issuance and validation,
and the FastAPI dependency that endpoints use to require an authenticated
caller.

Enforces least privilege — a caller's clearance determines which document tiers
the retriever is allowed to see, so `allowed_tiers()` is passed down into every
vectorstore query rather than applied to results afterward.

Never logs credentials, tokens, or password material.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app import audit_log
from app.secrets import optional, require

# Ordered least- to most-privileged. A clearance grants its own tier and every
# tier below it.
TIERS: tuple[str, ...] = ("public", "internal", "restricted")

TOKEN_TTL_SECONDS = int(optional("SESSION_TTL_SECONDS", "3600"))

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


@dataclass(frozen=True)
class User:
    username: str
    clearance: str


@dataclass(frozen=True)
class _Credential:
    salt: bytes
    digest: bytes
    clearance: str


_USERS: dict[str, _Credential] = {}


def allowed_tiers(clearance: str) -> tuple[str, ...]:
    """Tiers a clearance may read: its own and everything below it.

    Unknown clearance yields an empty tuple — fail closed. Callers must treat
    an empty result as "retrieve nothing", never as "no filter".
    """
    if clearance not in TIERS:
        return ()
    return TIERS[: TIERS.index(clearance) + 1]


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    return salt, hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


def create_user(username: str, password: str, clearance: str) -> None:
    if clearance not in TIERS:
        raise ValueError(f"unknown clearance: {clearance}")
    salt, digest = hash_password(password)
    _USERS[username] = _Credential(salt=salt, digest=digest, clearance=clearance)


def seed_users() -> int:
    """Load synthetic users from the DEMO_USERS env var (JSON).

    Shape: {"alice": {"password": "...", "clearance": "restricted"}}

    Deliberately not a default user table — an app that ships with a known
    account is an insecure default. Absent or malformed DEMO_USERS seeds
    nothing and every login fails, which is the safe direction.
    """
    raw = os.environ.get("DEMO_USERS", "")
    if not raw:
        return 0
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError:
        audit_log.log("auth.seed", decision="error", reason="DEMO_USERS is not valid JSON")
        return 0

    for username, entry in spec.items():
        try:
            create_user(username, entry["password"], entry["clearance"])
        except (KeyError, TypeError, ValueError) as exc:
            audit_log.log(
                "auth.seed", decision="error", user=username, reason=type(exc).__name__
            )
    audit_log.log("auth.seed", decision="allow", count=len(_USERS))
    return len(_USERS)


def _sign(payload: bytes) -> str:
    mac = hmac.new(require("SESSION_SIGNING_KEY").encode("utf-8"), payload, hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode("ascii").rstrip("=")


def issue_token(user: User) -> str:
    payload = json.dumps(
        {"sub": user.username, "clr": user.clearance, "exp": int(time.time()) + TOKEN_TTL_SECONDS},
        sort_keys=True,
    ).encode("utf-8")
    body = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{body}.{_sign(payload)}"


def verify_token(token: str) -> User | None:
    """Return the User a token names, or None. Never raises on bad input."""
    body, _, signature = token.partition(".")
    if not body or not signature:
        return None
    try:
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(_sign(payload), signature):
        return None
    try:
        claims = json.loads(payload)
        if claims["exp"] < time.time():
            return None
        clearance = claims["clr"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    # Re-check the clearance against the current tier list rather than trusting
    # whatever was signed at issue time.
    if clearance not in TIERS:
        return None
    return User(username=claims["sub"], clearance=clearance)


def authenticate(username: str, password: str) -> User | None:
    """Verify credentials. Constant-time, and identical work for unknown users."""
    credential = _USERS.get(username)
    if credential is None:
        # Spend comparable time so a missing user isn't distinguishable by latency.
        hash_password(password, salt=b"\x00" * 16)
        audit_log.log("auth.login", actor=username, decision="deny", reason="no_such_user")
        return None
    _, digest = hash_password(password, salt=credential.salt)
    if not hmac.compare_digest(digest, credential.digest):
        audit_log.log("auth.login", actor=username, decision="deny", reason="bad_password")
        return None
    audit_log.log("auth.login", actor=username, decision="allow", clearance=credential.clearance)
    return User(username=username, clearance=credential.clearance)


async def current_user(authorization: str = Header(default="")) -> User:
    """FastAPI dependency. Requires `Authorization: Bearer <token>`."""
    scheme, _, token = authorization.partition(" ")
    user = verify_token(token) if scheme.lower() == "bearer" and token else None
    if user is None:
        audit_log.log("auth.token", decision="deny", reason="invalid_or_expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
