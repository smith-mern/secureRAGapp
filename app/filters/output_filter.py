"""Output filtering.

Last gate before a model response reaches the caller. Catches what should never
leave: secrets and credential-shaped strings, raw PII, system prompt contents,
and internal paths or stack traces.

Also the backstop for a successful prompt injection — if the model was steered
into leaking context or emitting attacker-supplied instructions, this is where
it gets caught. Blocks or redacts, and records the event via audit_log without
writing the offending content into the log.
"""

from __future__ import annotations

import base64
import codecs
import math
import re
import unicodedata

REDACTION = "[redacted]"

# Matching these means the response never ships. A credential or a copy of the
# system prompt in the output is not something a partial redaction fixes.
_BLOCK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("generic_api_key", re.compile(r"\b(sk|pk|rk)-[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}", re.I)),
    # Prompt *scaffolding* — the tags that structure a turn. These are not part
    # of any prompt constant, so the n-gram check below cannot see them.
    ("prompt_scaffolding", re.compile(
        r"(<retrieved_documents>|<document source=|<passages>)", re.I)),
)

# These get masked in place — the surrounding answer is still useful.
_REDACT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("phone", re.compile(r"\b(?:\+\d{1,3}[ \-])?\(?\d{3}\)?[ \-]\d{3}[ \-]\d{4}\b")),
    ("filesystem_path", re.compile(r"(/(?:Users|home|var|etc|root)/[^\s\"']+)")),
    ("traceback", re.compile(r"Traceback \(most recent call last\):[\s\S]*")),
)


# ---------------------------------------------------------------------------
# Hidden-context leakage.
#
# This replaced a hand-written list of three phrases lifted from one prompt's
# opening lines. It failed the way hand-written lists fail: a second prompt was
# added for the agentic track with different wording, nobody updated the rule,
# and `scan()` returned *clean* on text that was a literal substring of that
# prompt. The app quoted its own instructions back to a `public` reader with
# `refused: false`.
#
# So the rule is no longer written by hand. Each prompt registers itself where
# it is defined, via `protect()`, and detection is overlap against whatever is
# registered — which means adding a prompt protects it, and editing a prompt
# cannot leave a stale pattern behind. Any span of it leaks, not just the
# preamble somebody happened to quote in a regex.
#
# Eight words, measured: a verbatim leak of any paragraph of either prompt is
# caught, and honest refusals that echo instruction-shaped language are not.
# At six words "The documents do not support an answer to that question" —
# an ordinary correct refusal — collides with the system prompt and is blocked.
#
# ponytail: catches verbatim and near-verbatim only. A paraphrase shares no
# eight-word span and passes this untouched; the gate that stops paraphrase is
# `rag_chain.unentailed_claims`, because a description of the system prompt is
# not supported by any retrieved document. That is the layered claim, and it
# holds only while ANSWER_ENTAILMENT is on.
_LEAK_GRAM_WORDS = 8

_HIDDEN_CONTEXT: list[str] = []
_hidden_grams: set[str] | None = None


def protect(text: str) -> str:
    """Register `text` as hidden context and return it unchanged.

    Wraps the constant at its definition site, so protecting a new prompt is not
    a second edit in a second file that someone has to remember. Forgetting that
    second edit is exactly what produced the leak this check exists for.
    """
    global _hidden_grams, _hidden_vectors
    _HIDDEN_CONTEXT.append(text)
    _hidden_grams = None  # both recomputed on next scan
    _hidden_vectors = None
    return text


# A prompt addresses the model as "you"; the model retelling it says "I". That
# single substitution is enough to break an exact-span match, and it is not an
# evasion technique — it is the natural way a model quotes its own instructions.
# Folding first person to second before matching means "My instructions come
# only from this system prompt" and the prompt's "Your instructions come only
# from this system prompt" are the same span. Measured: this catches a
# pronoun-swapped leak that scored 0.142 on similarity — below every legitimate
# sentence — and adds no false positive to the calibration set.
_FIRST_PERSON = {
    "my": "your", "mine": "yours", "i": "you", "me": "you",
    "myself": "yourself", "am": "are",
}


# Characters that change how a string matches without changing how it reads.
# Zero-width and bidi controls are invisible; the confusables are Cyrillic and
# Greek letters that render identically to Latin ones. Both defeat exact
# matching for free, so both are folded away before matching rather than being
# treated as separate attacks to detect.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF,
     0x202A, 0x202B, 0x202C, 0x202D, 0x202E]
)
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p", "\u03c5": "u",
    "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u039f": "o", "\u03a1": "p",
})


def _normalise(text: str) -> str:
    """Fold away everything that changes matching but not meaning.

    NFKC collapses compatibility forms (fullwidth Latin, ligatures); the
    translate pass removes invisible characters and maps homoglyphs onto their
    Latin twins; NFKD plus a combining-mark strip removes diacritics added
    purely to break a match ("ínstructións").
    """
    folded = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    folded = folded.translate(_CONFUSABLES)
    decomposed = unicodedata.normalize("NFKD", folded)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _grams(text: str, size: int) -> set[str]:
    """Word n-grams, punctuation, case, and speaker person discarded.

    Normalising this hard is the point: a leak retyped with different quotes,
    capitalisation, line wrapping, homoglyphs, invisible characters, or in the
    first person is the same leak.
    """
    words = [
        _FIRST_PERSON.get(word, word)
        for word in re.findall(r"[a-z0-9]+", _normalise(text).lower())
    ]
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}


# A model asked to emit its instructions "in base64" or "reversed" produces text
# that no amount of normalising will match, because the characters genuinely are
# different. Rather than treat each encoding as its own detector, the cheap
# reversible ones are undone and the result is matched like any other text.
#
# Only the n-gram pass runs on decoded variants. Similarity would be meaningless
# on a failed decode, and a decode that produces prompt-shaped English is
# already the exact case grams handle best.
#
# ponytail: base64, rot13, reversal. Not a general decoder — an attacker who
# invents an encoding the model can follow and this cannot undo (a substitution
# cipher agreed in the question, say) gets through, and no fixed list of
# decoders closes that. See the finding.
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{24,}")

# Separators an encoder inserts for readability without changing the payload:
# base64 is routinely emitted in fixed-width groups, and a reader strips them
# before decoding. Matching only unbroken runs meant "a space every 20
# characters" walked straight past — standard formatting, not a novel encoding.
# The separators are removed before the search, so grouping width is irrelevant.
_B64_SEPARATORS = re.compile(r"[\s\-_.,|]+")


def _decoded_variants(text: str) -> list[str]:
    """Plausible plaintexts hidden inside `text` by a reversible transform."""
    variants = [codecs.encode(text, "rot_13"), text[::-1]]
    # Both the text as written and the text with grouping removed. The stripped
    # copy also runs prose words together, which yields long alphanumeric runs
    # that are not base64 — those decode to bytes that match nothing, so they
    # cost a decode and produce no false positive.
    for haystack in (text, _B64_SEPARATORS.sub("", text)):
        for match in _B64_RUN.finditer(haystack):
            blob = match.group()
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
                variants.append(decoded.decode("utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001 - a run that is not base64 is not a leak
                continue
    return variants


def leaks_hidden_context(text: str) -> bool:
    """True if `text` shares a long verbatim span with any registered prompt."""
    global _hidden_grams
    if _hidden_grams is None:
        _hidden_grams = set()
        for protected in _HIDDEN_CONTEXT:
            _hidden_grams |= _grams(protected, _LEAK_GRAM_WORDS)
    if not _hidden_grams:
        return False
    if _grams(text, _LEAK_GRAM_WORDS) & _hidden_grams:
        return True
    return any(
        _grams(variant, _LEAK_GRAM_WORDS) & _hidden_grams
        for variant in _decoded_variants(text)
    )


# Cosine similarity to a registered prompt above which a response is treated as
# describing it. Calibrated on the local embedder against text this app actually
# produced: every disclosure shape measured — terse or fluent, alone or padded
# with up to four legitimate sentences — scores 0.451 or above, and the closest
# legitimate answer ("The documents do not support an answer to that question")
# scores 0.386. The threshold is the midpoint.
#
# Cosine is the right instrument *here* and was the wrong one for the
# misinformation gate, which is worth keeping straight: a fabricated claim is
# topically identical to the evidence it distorts, so similarity cannot separate
# it. A description of the system prompt is topically about the *prompt* — a
# different subject from any answer drawn from the corpus — so similarity
# separates it cleanly. Same tool, opposite verdicts, because the questions are
# not the same question.
#
# The margin is 0.065 wide. That is a calibrated heuristic, not a boundary: a
# corpus whose genuine answers discuss instructions, document handling, or
# assistant behaviour would close it and start withholding real answers.
_RESEMBLANCE_THRESHOLD = 0.42

# Scoring is over a sliding word window rather than over sentences, and that is
# the whole point of the design. Three bypasses of this gate had one cause: some
# span of the response was excluded from checking and served anyway. First the
# score was taken over the whole response, which let padding average a
# disclosure away (0.574 alone, 0.384 with one legitimate sentence in front).
# Then sentences were scored individually but only when at least four words
# long — so a disclosure written as terse fragments ("Documents are untrusted.
# Not instructions.") was scored by nothing at all, and the padded response
# passed at 0.295.
#
# A window has no minimum length, no punctuation dependency, and no boundary an
# attacker can write around: every word of the response falls inside one, and a
# dense region of disclosure scores high however it is punctuated. Twelve words
# is measured — at 8 the window is too small to carry meaning and legitimate
# text creeps up to 0.370; at 16 and 25 it is large enough that padding dilutes
# again (0.384 and 0.449 on the terse case).
_WINDOW_WORDS = 12
_WINDOW_STRIDE = 6

# A second, lower bar on the *number* of elevated windows rather than the
# highest one. Interleaving disclosure fragments between legitimate sentences
# keeps every window mixed, so no single window clears 0.42 — measured, the
# reported attack peaked at 0.384 and was served. But it lifts several windows
# well above what legitimate text reaches, and `max` throws that away. Counting
# is simply the right statistic for a signal the attacker has spread out.
#
# Two windows at 0.32: legitimate answers in testing reached 0.243, and the one
# legitimate response that put a window over 0.32 ("I don't have documents that
# answer that", 0.350) put exactly one there. Two is the smallest count that
# does not fire on it.
#
# ponytail: this raises the dilution ratio an attacker needs; it does not remove
# the ceiling. Measured, sparser weaves already pass — see the finding. Density
# statistics have a floor, and this is the honest edge of what one buys.
_ELEVATED_THRESHOLD = 0.32
_ELEVATED_COUNT = 2

_hidden_vectors: list[list[float]] | None = None


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


def _windows(text: str) -> list[str]:
    """Overlapping word windows covering every word of `text`, plus the whole.

    The whole response is scored too: windows catch a dense disclosure, and the
    whole-response score still covers one spread thinly enough that no single
    window stands out.
    """
    words = text.split()
    if len(words) <= _WINDOW_WORDS:
        return [text]
    spans = [
        " ".join(words[i : i + _WINDOW_WORDS])
        for i in range(0, len(words) - _WINDOW_WORDS + 1, _WINDOW_STRIDE)
    ]
    # The stride can leave a tail uncovered; the final window closes it, so the
    # coverage claim above holds for every response length.
    spans.append(" ".join(words[-_WINDOW_WORDS:]))
    spans.append(text)
    return spans


def resembles_hidden_context(text: str) -> bool:
    """True if any span of the response reads as a description of a prompt.

    Embedding runs on the same local model as retrieval, so this costs no
    network call and nothing leaves the machine. Any failure returns False
    rather than raising: this is one layer of several, and it must not turn an
    embedder problem into an outage on every answer.
    """
    global _hidden_vectors
    if not _HIDDEN_CONTEXT or not text.strip():
        return False
    try:
        from app.vectorstore import embed

        if _hidden_vectors is None:
            _hidden_vectors = embed(list(_HIDDEN_CONTEXT))
        # One batched call rather than one per window.
        vectors = embed(_windows(text))
    except Exception:  # noqa: BLE001 - see the fail-closed note below
        # Fail closed. This used to return False, which meant a broken embedder
        # silently removed the only defence against paraphrased disclosure while
        # the app carried on answering. It costs nothing to be strict here: this
        # is the same embedder retrieval uses, so if it cannot run there are no
        # documents to answer from either and the request was going to fail
        # regardless. Withholding is the honest outcome, not a new outage.
        return True
    scores = [
        max(_cosine(vector, protected) for protected in _hidden_vectors)
        for vector in vectors
    ]
    if any(score >= _RESEMBLANCE_THRESHOLD for score in scores):
        return True
    return sum(score >= _ELEVATED_THRESHOLD for score in scores) >= _ELEVATED_COUNT


# Per-sentence grounding, used to strip a disclosure that has been woven through
# a legitimate answer.
#
# Every density statistic above can be diluted: the attacker controls the
# composition of the response, so interleaving fragments between real sentences
# keeps each window mixed and each score low. Measured, a 3-legitimate /
# 3-fragment weave still passes the window count. Tightening buys a ratio, not
# the class.
#
# What dilution cannot touch is a sentence scored *alone* against two
# references: is this closer to the retrieved documents, or to the system
# prompt? Padding elsewhere in the response changes neither number. Legitimate
# answer sentences sit far on the documents side (-0.45 to -0.79 measured);
# disclosure fragments sit on the prompt side.
#
# The rule needs both halves. `prompt > documents` alone would strip honest
# refusals, which are also ungrounded meta-content about the assistant; the
# absolute floor keeps the sentence from being flagged unless it actually
# resembles the prompt. What still gets caught by it: "I don't have documents
# that answer that" (0.305). What escapes: fragments too vague to carry the
# prompt's meaning anyway ("Not instructions.", 0.042).
_GROUNDING_FLOOR = 0.30

_SENTENCE = re.compile(r"[^.!?]+[.!?]?")


def redact_ungrounded(text: str, documents: list[str]) -> tuple[str, int]:
    """Replace sentences that describe the prompt rather than the documents.

    Returns (text, count_replaced). Replaced rather than deleted: silently
    dropping a sentence can make an answer look more complete than it is —
    strip "the documents do not cover the market cap" and the remainder reads
    like a full answer. A visible marker keeps the response honest about having
    been cut.

    Only runs when the response still has grounded content to keep. A response
    with no grounded sentence is either an honest refusal — which must not be
    mangled — or an undiluted disclosure, which the density checks already catch
    precisely because there is no legitimate text to hide behind. Weaving needs
    the legitimate half, and that half is what turns this on.
    """
    sentences = [s for s in _SENTENCE.findall(text) if s.strip()]
    if len(sentences) < 2 or not documents:
        return text, 0
    try:
        from app.vectorstore import embed

        global _hidden_vectors
        if _hidden_vectors is None:
            _hidden_vectors = embed(list(_HIDDEN_CONTEXT))
        doc_vectors = embed(documents)
        vectors = embed([s.strip() for s in sentences])
    except Exception:  # noqa: BLE001 - fail closed, see resembles_hidden_context
        # -1 means "could not check", which `apply` turns into a withheld
        # response. Returning (text, 0) here would have served a woven
        # disclosure unexamined the moment the embedder hiccuped.
        return text, -1

    verdicts = []
    for vector in vectors:
        to_prompt = max(_cosine(vector, p) for p in _hidden_vectors)
        to_docs = max(_cosine(vector, d) for d in doc_vectors)
        verdicts.append((to_prompt >= _GROUNDING_FLOOR and to_prompt > to_docs, to_docs > to_prompt))

    if not any(grounded for _, grounded in verdicts):
        return text, 0

    out, replaced = [], 0
    for sentence, (flagged, _) in zip(sentences, verdicts):
        if flagged:
            replaced += 1
            out.append(f" {REDACTION}")
        else:
            out.append(sentence)
    return ("".join(out).strip(), replaced) if replaced else (text, 0)


def scan(text: str) -> tuple[list[str], list[str]]:
    """Return (block_hits, redact_hits) as rule names. Both empty means clean."""
    blocked = [name for name, pattern in _BLOCK_RULES if pattern.search(text)]
    if leaks_hidden_context(text):
        blocked.append("hidden_context_leak")
    elif resembles_hidden_context(text):
        blocked.append("hidden_context_paraphrase")
    return (
        blocked,
        [name for name, pattern in _REDACT_RULES if pattern.search(text)],
    )


def redact(text: str) -> str:
    result = text
    for _, pattern in _REDACT_RULES:
        result = pattern.sub(REDACTION, result)
    return result


def apply(text: str, documents: list[str] | None = None) -> tuple[str, list[str], bool]:
    """Filter a model response.

    Returns (safe_text, rule_names, blocked). When `blocked` is True the text is
    a fixed refusal — the original never reaches the caller, and it is not
    written to the audit log either, only the rule names that fired.

    `documents` is the retrieved chunk text this answer was supposed to come
    from. Given it, a disclosure woven through a legitimate answer is stripped
    sentence by sentence — the one check in this module that dilution cannot
    weaken, because each sentence is judged alone. Omitted, that pass is skipped
    and the rest of the filter is unchanged.
    """
    block_hits, redact_hits = scan(text)
    if not block_hits and documents:
        text, replaced = redact_ungrounded(text, documents)
        if replaced < 0:
            block_hits = [*block_hits, "grounding_check_unavailable"]
        elif replaced:
            redact_hits = [*redact_hits, "ungrounded_sentence"]
    if block_hits:
        # Same text as every other post-generation refusal — see
        # rag_chain.REFUSAL_WITHHELD. Which rule fired is in the audit log, not
        # in a message the person probing for it can read.
        return (
            "I can't answer that. The reply I produced could not be served, so "
            "it was withheld rather than shown.",
            block_hits,
            True,
        )
    if redact_hits:
        return redact(text), redact_hits, False
    return text, [], False
