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


class TierScopedRetriever(BaseRetriever):
    """Retriever restricted to a fixed set of access tiers."""

    allowed: tuple[str, ...] = ()
    k: int = 4

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun | None = None
    ) -> list[Document]:
        hits = vector_query(self.allowed, query, k=self.k)
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
