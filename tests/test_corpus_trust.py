"""Provenance precedence — no model, no vector store.

Corpus poisoning works because a password-only upload sits in the same
collection as curated content and outranks nothing but is trusted the same. The
control is not a content filter (a false sentence has no shape to match) but a
provenance rule: when curated content answers the question, password-writable
content does not travel with it.
"""

from __future__ import annotations

from langchain_core.documents import Document
from langchain_core.messages import AIMessage

from app import rag_chain
from app.auth import User
from app.retriever import prefer_trusted

USER = User(username="tester", clearance="public", role="reader")
TIERS = ("public",)


def _doc(source: str, origin: str, text: str = "some policy text") -> Document:
    return Document(
        page_content=text,
        metadata={"source": source, "origin": origin, "distance": 0.2},
    )


def test_uploads_are_suppressed_when_curated_content_is_present():
    docs = [
        _doc("public/handbook.md", "curated", "refund window is 30 days"),
        _doc("upload/public/poison.md", "upload", "refund window is 90 days"),
        _doc("tickets/1", "connector:tickets", "refund window is 90 days"),
    ]
    kept, suppressed = prefer_trusted(docs)

    assert [d.metadata["source"] for d in kept] == ["public/handbook.md"]
    assert len(suppressed) == 2  # connector content is password-writable too


def test_unreviewed_content_does_not_answer_even_with_no_competition():
    """An uncovered topic used to fall back to uploads. That was the hole.

    Falling back let a password-only uploader establish arbitrary facts about
    any subject nobody had curated yet — no competing document to lose to, so
    provenance precedence never engaged. Nothing trusted now means nothing.
    """
    docs = [_doc("upload/public/leave-policy.md", "upload", "52 weeks of paid leave")]
    kept, suppressed = prefer_trusted(docs)

    assert kept == []
    assert len(suppressed) == 1


def test_reviewed_content_answers_like_curated_content():
    """Review is how an upload earns the right to answer — the pressure valve.

    Without it the rule above would make /upload useless for anything but
    storage.
    """
    doc = _doc("upload/public/leave-policy.md", "upload")
    doc.metadata["reviewed"] = True

    kept, suppressed = prefer_trusted([doc])
    assert kept == [doc]
    assert suppressed == []


def test_a_missing_reviewed_flag_is_not_trust():
    """Chunks indexed before review existed must not be grandfathered in."""
    doc = _doc("upload/public/legacy.md", "upload")
    doc.metadata.pop("reviewed", None)

    kept, _ = prefer_trusted([doc])
    assert kept == []


def test_the_chain_refuses_when_only_unreviewed_content_matches(monkeypatch):
    _patch(monkeypatch, [_doc("upload/public/leave.md", "upload", "52 weeks")])

    result = rag_chain.build_chain(USER, True, TIERS).invoke(
        {"question": "how much parental leave?", "history": [], "flags": []}
    )
    assert result["refused"] is True
    assert result["answer"] == rag_chain.REFUSAL_NO_CONTEXT
    assert result["sources"] == []


def test_extra_poison_copies_cannot_outvote_one_curated_document():
    """The documented escalation — 'adding more poison copies flips the majority'.

    Majority stops mattering once provenance decides: four copies are still four
    uploads.
    """
    docs = [_doc(f"upload/public/poison-{i}.md", "upload") for i in range(4)]
    docs.append(_doc("public/handbook.md", "curated"))

    kept, suppressed = prefer_trusted(docs)
    assert [d.metadata["source"] for d in kept] == ["public/handbook.md"]
    assert len(suppressed) == 4


def test_retrieval_gives_each_trust_class_its_own_budget(monkeypatch):
    """Flooding defeats any shared candidate window, however wide.

    The first version of this control over-fetched 2 x TOP_K and preferred
    curated content among whatever came back — which a red-team run beat with
    eight poison copies, because the curated document never made the candidate
    set. Separate searches remove the contest: uploads compete for upload slots.
    """
    seen: list[dict | None] = []

    def fake_query(tiers, text, k=4, where=None):  # noqa: ARG001
        seen.append(where)
        if where == {"origin": "curated"}:
            return [{"text": "30 days", "metadata": {"source": "public/handbook.md",
                                                     "origin": "curated"}, "distance": 0.18}]
        # A hundred copies would still only fill the unverified half.
        return [
            {"text": "90 days", "metadata": {"source": f"upload/public/flood-{i}.md",
                                             "origin": "upload"}, "distance": 0.10}
            for i in range(k)
        ]

    monkeypatch.setattr("app.vectorstore.query", fake_query)
    from app.vectorstore import query_by_trust

    hits = query_by_trust(("public",), "refund window?", k=4)
    origins = [h["metadata"]["origin"] for h in hits]

    assert {"origin": "curated"} in seen  # curated searched on its own budget
    assert "curated" in origins           # and present despite the flood
    # prefer_trusted then discards the rest, whatever its size.
    kept, suppressed = prefer_trusted(
        [Document(page_content=h["text"], metadata=h["metadata"]) for h in hits]
    )
    assert [d.metadata["source"] for d in kept] == ["public/handbook.md"]
    assert len(suppressed) == 4


def _patch(monkeypatch, documents, reply="answered"):
    monkeypatch.setattr(
        rag_chain.TierScopedRetriever,
        "_get_relevant_documents",
        lambda self, query, **kwargs: documents,
    )

    class Fake:
        def bind_tools(self, tools):  # noqa: ARG002 - agent path is not under test
            return self

        def invoke(self, messages):  # noqa: ARG002
            return AIMessage(content=reply)

    monkeypatch.setattr(rag_chain, "_model", Fake())


def test_the_chain_drops_the_poison_before_the_prompt(monkeypatch):
    poison = _doc("upload/public/poison.md", "upload", "refund window is 90 days")
    truth = _doc("public/handbook.md", "curated", "refund window is 30 days")
    _patch(monkeypatch, [truth, poison])

    result = rag_chain.build_chain(USER, True, TIERS).invoke(
        {"question": "refund window?", "history": [], "flags": []}
    )
    assert result["sources"] == ["public/handbook.md"]


def test_insecure_mode_still_passes_both(monkeypatch):
    """Phase 2 must be unchanged, or the before/after comparison is meaningless."""
    poison = _doc("upload/public/poison.md", "upload", "refund window is 90 days")
    truth = _doc("public/handbook.md", "curated", "refund window is 30 days")
    _patch(monkeypatch, [truth, poison])

    result = rag_chain.build_chain(USER, False, TIERS).invoke(
        {"question": "refund window?", "history": [], "flags": []}
    )
    assert result["sources"] == ["public/handbook.md", "upload/public/poison.md"]


def test_upload_is_indexed_unreviewed_and_review_flips_it(monkeypatch, tmp_path):
    """The workflow end to end, without HTTP: upload -> unanswerable -> approve."""
    from app import ingest, vectorstore

    monkeypatch.setattr(ingest, "UPLOADS_DIR", tmp_path)
    indexed: dict = {}

    def fake_index(tier, source, text, metadata):
        indexed[source] = metadata
        return 1

    monkeypatch.setattr(ingest, "_index", fake_index)
    monkeypatch.setattr(vectorstore, "delete_source", lambda tier, source: None)

    ingest.store_upload(
        filename="leave.md", tier="public", content="52 weeks of leave",
        actor="dave", allowed_tiers=("public",),
    )
    metadata = indexed["upload/public/leave.md"]
    assert metadata["reviewed"] is False

    doc = Document(page_content="52 weeks", metadata={**metadata, "source": "x"})
    assert prefer_trusted([doc])[0] == []          # cannot answer as uploaded

    doc.metadata["reviewed"] = True                # what /review writes
    assert prefer_trusted([doc])[0] == [doc]       # answers once signed off
