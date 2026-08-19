"""Tier-scoped LangChain retriever.

Wraps `vectorstore.query` as a `BaseRetriever` so retrieval is a step inside the
LCEL chain rather than a separate call the chain knows nothing about.

The clearance scope is constructor state, not a call argument. A retriever
instance is built per request from the caller's allowed tiers and cannot widen
itself afterwards — there is no `invoke(query, tiers=...)` overload to forget.
An empty `allowed` yields nothing, matching the fail-closed contract in
`vectorstore.query`.

Chroma stays the storage engine. This is the LangChain *interface* over it, not
a migration: swapping the backend later means reimplementing this one method.
"""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever

from app.vectorstore import query as vector_query
from app.vectorstore import query_by_trust


class TierScopedRetriever(BaseRetriever):
    """Retriever restricted to a fixed set of access tiers."""

    allowed: tuple[str, ...] = ()
    k: int = 4
    # Secure mode searches each trust class separately so a flood of uploads
    # cannot evict curated content from the candidate set. Off in phase 2, which
    # keeps that run's retrieval exactly as it was.
    trust_split: bool = False

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun | None = None
    ) -> list[Document]:
        search = query_by_trust if self.trust_split else vector_query
        hits = search(self.allowed, query, k=self.k)
        return [
            Document(
                page_content=hit["text"],
                # distance rides in metadata because the grounding gate
                # downstream needs it and Document has nowhere else to put it.
                metadata={**hit["metadata"], "distance": hit["distance"]},
            )
            for hit in hits
        ]


def source_of(document: Document) -> Any:
    return document.metadata.get("source", "unknown")


# Origins anyone with a password can write: /upload, and the connector's upstream
# where "anyone can file a ticket". `curated` is the only origin that took host
# access to produce.
CURATED_ORIGIN = "curated"


def origin_of(document: Document) -> str:
    return str(document.metadata.get("origin", CURATED_ORIGIN))


def is_curated(document: Document) -> bool:
    return origin_of(document) == CURATED_ORIGIN


def is_trusted(document: Document) -> bool:
    """Curated content, or password-writable content a human signed off.

    Two ways to be trusted, one way to become it. `curated` took host access to
    produce. Everything else starts unreviewed and stays unanswerable until an
    `approver` account marks it reviewed — which is the difference between "we
    know who could have written this" and "someone looked at it".

    Chunks indexed before review existed carry no `reviewed` key. They are
    treated as unreviewed, because defaulting an unknown to trusted is how a
    migration quietly reopens the hole it was meant to close.
    """
    return is_curated(document) or document.metadata.get("reviewed") is True


def prefer_trusted(documents: list[Document]) -> tuple[list[Document], list[Document]]:
    """Split retrieved documents into (kept, suppressed) by trust.

    Trusted content answers. Unreviewed content never does — not beside trusted
    content, where it would contradict it, and not alone either, which is the
    part that changed after a red-team pass: falling back to unreviewed content
    on topics the curated set does not cover let a password-only uploader
    establish arbitrary facts for any subject nobody had written about yet.
    Returning nothing here puts the request on the chain's refusal branch.

    This is the structural half of the corpus-poisoning defense. A planted
    document never reaches the model, so the model never has to adjudicate
    between it and the truth — which it cannot do, having no way to tell a true
    sentence from a false one. It does nothing about a poisoned *curated*
    document, or one an approver waved through.
    """
    trusted = [doc for doc in documents if is_trusted(doc)]
    return trusted, [doc for doc in documents if not is_trusted(doc)]
