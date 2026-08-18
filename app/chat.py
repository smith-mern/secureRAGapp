"""Conversation session store.

Holds per-session turn history so `/chat` can be multi-turn while the RAG
pipeline itself stays stateless.

Sessions are owned by the user who created them and `get()` refuses to return
another user's history — a session id is a bearer-style reference, so without
that check anyone holding or guessing an id could read someone else's
conversation, including answers drawn from a tier they cannot access.

ponytail: in-memory dict, lost on restart, FIFO eviction at MAX_SESSIONS.
Fine for a single-process laptop deployment; needs a real store the moment
there is more than one worker.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field

# Turns kept per session. History is replayed into the prompt on every request,
# so this bounds both context size and cost.
MAX_TURNS = 10

# Sessions live for the process, and `/chat` with no session_id mints a new one
# on every call — unbounded, that is a memory leak any reader can drive by
# looping requests that never reuse an id. Oldest is evicted first (dicts keep
# insertion order), which costs an idle conversation its history rather than
# costing the process its memory.
MAX_SESSIONS = 1000


@dataclass
class Turn:
    question: str
    answer: str


@dataclass
class Session:
    session_id: str
    owner: str
    turns: list[Turn] = field(default_factory=list)


_LOCK = threading.Lock()
_SESSIONS: dict[str, Session] = {}


def create(owner: str) -> Session:
    session = Session(session_id=str(uuid.uuid4()), owner=owner)
    with _LOCK:
        _SESSIONS[session.session_id] = session
        while len(_SESSIONS) > MAX_SESSIONS:
            del _SESSIONS[next(iter(_SESSIONS))]
    return session


def get(session_id: str, owner: str) -> Session | None:
    """Return the session only if `owner` created it. None otherwise.

    Deliberately does not distinguish "no such session" from "not yours" —
    telling them apart would confirm the existence of other users' sessions.
    """
    with _LOCK:
        session = _SESSIONS.get(session_id)
    if session is None or session.owner != owner:
        return None
    return session


def append(session: Session, question: str, answer: str) -> None:
    with _LOCK:
        session.turns.append(Turn(question=question, answer=answer))
        if len(session.turns) > MAX_TURNS:
            del session.turns[: len(session.turns) - MAX_TURNS]


def as_messages(session: Session) -> list[dict[str, str]]:
    """History in the shape the model API expects, oldest first."""
    messages: list[dict[str, str]] = []
    for turn in session.turns:
        messages.append({"role": "user", "content": turn.question})
        messages.append({"role": "assistant", "content": turn.answer})
    return messages
