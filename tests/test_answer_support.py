"""The answer-side support check: a figure the documents never carried.

Retrieval grounding proves the model was *handed* something on topic. These
cover the separate question — whether what it wrote is in what it was handed —
which is what `rag_chain.unsupported_figures` answers. No model, no vector
store, no network.

The strings are the answers actually observed from llama3.2:3b against the
curated corpus with SECURITY_FILTERS_ENABLED=true; see
redteam/findings/misinformation-ungrounded-answers.md.
"""

from __future__ import annotations

from langchain_core.documents import Document

from app.rag_chain import unsupported_figures

HANDBOOK = [
    Document(page_content="The refund window for standard orders is 30 days from delivery.")
]


def test_figure_present_in_the_documents_is_supported():
    assert unsupported_figures("The refund window is 30 days from delivery.", HANDBOOK) == []


def test_invented_figure_is_caught():
    # Observed fabrication: no document mentions a restocking fee at all.
    assert unsupported_figures(
        "The restocking fee percentage for standard returns is 20%.", HANDBOOK
    ) == ["20"]


def test_a_premise_from_the_question_is_not_support():
    # The false-premise fabrication. "90" came from the caller, and crediting
    # the question as evidence is exactly how this one gets served.
    assert unsupported_figures(
        "The refund window was extended from 30 days to 90 days.", HANDBOOK
    ) == ["90"]


def test_thousands_separators_compare_equal():
    docs = [Document(page_content="We intend to acquire Northwind for 1,200 million.")]
    assert unsupported_figures("The price is 1200 million.", docs) == []


def test_no_documents_means_nothing_is_supported():
    assert unsupported_figures("The fee is 20%.", []) == ["20"]


def test_number_words_are_normalised_to_digits():
    # Landed bypass: asked to write numbers as words, the model served
    # "extended from thirty days to ninety days" against a document saying 30.
    assert unsupported_figures(
        "The refund window was extended from thirty days to ninety days.", HANDBOOK
    ) == ["90"]


def test_a_word_matching_a_digit_in_the_document_is_supported():
    # Both sides normalise, so correct prose is not refused for its notation.
    assert unsupported_figures("The refund window is thirty days.", HANDBOOK) == []


def test_one_as_a_pronoun_does_not_refuse_a_correct_answer():
    assert unsupported_figures(
        "Only one of the documents mentions a refund window, and it is 30 days.",
        HANDBOOK,
    ) == []


def test_compound_numerals_compose_rather_than_decompose():
    # "one hundred twenty" is 120, not {100, 20} — decomposing refused a correct
    # answer against a document that states the very figure.
    docs = [Document(page_content="The refund window is 120 days from delivery.")]
    assert unsupported_figures("The refund window is one hundred twenty days.", docs) == []
    assert unsupported_figures("The refund window is one hundred and twenty days.", docs) == []


def test_composed_numeral_absent_from_the_documents_is_caught():
    assert unsupported_figures("The refund window is one hundred and twenty days.", HANDBOOK) == ["120"]


def test_quantity_idiom_is_a_quantity():
    assert unsupported_figures("The refund window is a dozen days.", HANDBOOK) == ["12"]


# --- entailment gate -------------------------------------------------------
# These pin the parts that hold without a model: claim splitting, and the two
# fail-closed paths. The judge's own accuracy is a runtime measurement and lives
# in the finding, not here — a unit test cannot assert what a 3B model decides.


def test_no_documents_means_nothing_is_entailed():
    from app.rag_chain import unentailed_claims

    claims = unentailed_claims("The refund window is 30 days from delivery.", [])
    assert claims == ["The refund window is 30 days from delivery."]


def test_an_unreachable_judge_fails_closed(monkeypatch):
    from app import rag_chain

    def boom():
        raise RuntimeError("ollama down")

    monkeypatch.setattr(rag_chain, "_judge_model", boom)
    claims = rag_chain.unentailed_claims(
        "The refund window is 30 days from delivery.", HANDBOOK
    )
    assert claims, "a judge that could not be reached must not pass the answer"


def test_a_leading_fragment_attaches_to_what_it_introduces():
    # Nothing is dropped any more — a fragment is judged with the sentence that
    # gives it meaning, rather than discarded and served unchecked.
    from app.rag_chain import _claims

    assert _claims("Yes. The refund window is 30 days from delivery.") == [
        "Yes. The refund window is 30 days from delivery."
    ]


def test_short_declaratives_are_claims():
    # Three-word sentences are complete assertions. Requiring four words meant
    # the gate never ran on them: "No refunds permitted." was served unchecked.
    from app.rag_chain import _claims

    for short in ("Refunds are impossible.", "No refunds permitted.", "Policy never changed."):
        assert _claims(short) == [short], short


def test_an_unsegmentable_answer_is_still_judged(monkeypatch):
    # The fail-open that mattered: no parsed sentences used to mean "clean".
    from app import rag_chain

    monkeypatch.setattr(rag_chain, "_claims", lambda answer: [])
    monkeypatch.setattr(rag_chain, "_judge_model", lambda: (_ for _ in ()).throw(RuntimeError()))
    assert rag_chain.unentailed_claims("Refunds impossible.", HANDBOOK) == ["Refunds impossible."]


def test_an_empty_answer_asserts_nothing():
    from app.rag_chain import unentailed_claims as u

    assert u("   ", HANDBOOK) == []


def test_claims_cover_the_whole_answer():
    """The invariant that kills the fragment-bypass class.

    Three separate bypasses came from `_claims` discarding text that was still
    served to the reader. Segmentation may change; coverage may not.
    """
    from app.rag_chain import _claims

    for answer in (
        "The refund window is 30 days. Unlimited.",
        "The refund window is 30 days. Never.",
        "Yes. The refund window is 30 days.",
        "No refunds permitted.",
        "One. Two. Three.",
    ):
        covered = " ".join(_claims(answer)).split()
        assert covered == answer.split(), answer


def test_a_trailing_fragment_is_judged_with_its_neighbour():
    from app.rag_chain import _claims

    assert _claims("The refund window is 30 days. Unlimited.") == [
        "The refund window is 30 days. Unlimited."
    ]


def test_numerals_normalise_before_the_judge_sees_them():
    from app.rag_chain import _normalise_numerals as n

    assert n("The refund window is thirty days.") == "The refund window is 30 days."
    assert n("one hundred and twenty days") == "120 days"
    assert n("a dozen days") == "a 12 days"
    # "one" as a pronoun is left alone; rewriting it hands the judge nonsense.
    assert n("no one has stated a date") == "no one has stated a date"


def test_the_judge_never_sees_document_filenames(monkeypatch):
    """Provenance is an attacker's lever on verification, so it is withheld.

    Measured before this: the same passage and claim were served under source
    "public/handbook.md" and refused under "DISPUTED-do-not-rely.md".
    """
    from app import rag_chain

    seen = {}

    class _Reply:
        content = "1: SUPPORTED"

    class _Judge:
        def invoke(self, messages):
            seen["text"] = "\n".join(str(m.content) for m in messages)
            return _Reply()

    monkeypatch.setattr(rag_chain, "_judge_model", _Judge)
    docs = [
        Document(
            page_content="The refund window is 30 days.",
            metadata={"source": "DISPUTED-do-not-rely.md"},
        )
    ]
    rag_chain.unentailed_claims("The refund window is 30 days.", docs)
    assert "DISPUTED-do-not-rely.md" not in seen["text"]
    assert "The refund window is 30 days." in seen["text"]
