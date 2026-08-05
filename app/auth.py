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

from fastapi import Depends, Header, HTTPException, status

from app import audit_log
from app.secrets import optional, require

# Ordered least- to most-privileged. A clearance grants its own tier and every
# tier below it.
TIERS: tuple[str, ...] = ("public", "internal", "restricted")

# Role is separate from clearance and is not ordered: clearance says which tiers
# you may read, role says what you may do. They are deliberately disjoint so
# "can write to the index" never falls out of "has a high clearance" — a reader
# with restricted clearance still cannot ingest, and the uploader cannot query.
ROLES: tuple[str, ...] = ("reader", "uploader")
DEFAULT_ROLE = "reader"

TOKEN_TTL_SECONDS = int(optional("SESSION_TTL_SECONDS", "3600"))

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


@dataclass(frozen=True)
class User:
    username: str
    clearance: str
    role: str = DEFAULT_ROLE


@dataclass(frozen=True)
class _Credential:
    salt: bytes
    digest: bytes
    clearance: str
    role: str


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


def create_user(username: str, password: str, clearance: str, role: str = DEFAULT_ROLE) -> None:
    if clearance not in TIERS:
        raise ValueError(f"unknown clearance: {clearance}")
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")
    salt, digest = hash_password(password)
    _USERS[username] = _Credential(salt=salt, digest=digest, clearance=clearance, role=role)


def seed_users() -> int:
    """Load synthetic users from the DEMO_USERS env var (JSON).

    Shape: {"alice": {"password": "...", "clearance": "restricted", "role": "reader"}}

    `role` is optional and defaults to "reader". Uploading is an opt-in role, so
    a DEMO_USERS entry that forgets the field grants no write access.

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
            create_user(
                username,
                entry["password"],
                entry["clearance"],
                entry.get("role", DEFAULT_ROLE),
            )
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
        {
            "sub": user.username,
            "clr": user.clearance,
            "rol": user.role,
            "exp": int(time.time()) + TOKEN_TTL_SECONDS,
        },
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
        role = claims["rol"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    # Re-check both against the current lists rather than trusting whatever was
    # signed at issue time. A token missing "rol" fails here rather than
    # defaulting — an old token should not silently acquire a role.
    if clearance not in TIERS or role not in ROLES:
        return None
    return User(username=claims["sub"], clearance=clearance, role=role)


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
    audit_log.log(
        "auth.login", actor=username, decision="allow",
        clearance=credential.clearance, role=credential.role,
    )
    return User(username=username, clearance=credential.clearance, role=credential.role)


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


def require_role(role: str):
    """Dependency that admits exactly one role. Not a hierarchy.

    Uploader is not "reader plus writing" — an account that can put text into
    the index cannot also pull text out of it, which keeps the ingestion
    identity useless for reading anything it wrote.
    """

    async def dependency(user: User = Depends(current_user)) -> User:
        if user.role != role:
            audit_log.log(
                "auth.role", actor=user.username, decision="deny",
                required=role, actual=user.role,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return user

    return dependency
