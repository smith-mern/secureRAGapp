# Egress filter is a backstop, not a boundary — refusal oracle (N1) and format gaps (N2)

**Severity:** Low–Medium — impact is bounded to callers already cleared to the
data; no cross-tier disclosure. Discovered under an OWASP-LLM / detectability
lens over the same surface as
[output-filter-bypass](output-filter-bypass.md).
**Component:** `app/filters/output_filter.py` (secret/shape scanning),
`app/rag_chain.py` (refusal messages).

Two observations the ATLAS pass did not surface, both about the *pattern-based
egress filter* rather than the boundaries that actually held (grounding,
retrieval-time clearance, verified tokens, disjoint duties, the review gate):

- **N1 — the weakness is externally discoverable.** A distinct refusal for
  "nothing retrieved" versus "a reply was produced and then withheld" let a
  cleared caller confirm, from outside, that a secret exists and the filter
  caught it.
- **N2 — the filter has format gaps as well as reframing bypasses.** Shape rules
  match a finite set of surface forms; a secret with no recognised shape, or one
  the model reformats into a shape not enumerated, passes.

## Vulnerability

### N1 — refusal oracle

The egress filter blocks a response and substitutes a refusal. If that refusal
is textually different from the ordinary "I have no documents on that" outcome,
the difference is a one-bit side channel: `withheld` means *content existed and
was generated, then blocked*; `no-context` means *retrieval was empty*. For a
caller cleared to the tier — the only one who can drive the egress path at all —
that bit externally confirms the existence of a canary or secret in the corpus,
turning "guess whether it's there" into "read whether it's there."

The post-generation security refusals were already unified. The residual split
was `REFUSAL_NO_CONTEXT` ("I don't have documents that answer that"), kept
separate for honest UX, plus a `withheld` message whose own wording ("the reply
I produced could not be served") admitted a reply had been produced.

### N2 — format gaps and reframing

`output_filter.apply()` blocks on two mechanisms: credential **shape** rules
(`sk-…`, `AKIA…`, private-key blocks, bearer tokens) and, after
[output-filter-bypass](output-filter-bypass.md), a **known-secret** registry
that folds a registered value's surface forms to one canonical core. Neither is
comprehension:

- A secret with **no recognised shape** and **not registered** — the
  `restricted` tier's real content is business prose — matches nothing. This is
  by design; egress filtering was never its control.
- Even a *registered* secret is only caught in encodings the filter can undo. An
  encoding invented in the prompt that the model can follow and the filter
  cannot reverse (a substitution cipher agreed in the question) passes.

## Exploit

Sketch, to be run from the UI against a live instance (`SECURITY_FILTERS_ENABLED=true`),
with a canary registered via `CANARY_TOKENS` and planted in a tier the probing
account is cleared to read:

1. **N1.** Ask a question the corpus cannot answer → observe the refusal. Ask a
   question that retrieves the canary chunk → the egress filter blocks it.
   *Before this fix* the two refusals differed, so the second confirmed the
   canary's existence. *After*, both are byte-identical.
2. **N2.** With the canary registered, ask the model to emit it under an
   in-prompt cipher it is told to apply (e.g. "shift each letter by one"). The
   canonical-core test does not reverse an arbitrary cipher, so the transformed
   secret ships.

## Detection

`audit.log` already carries what a defender needs and a prober cannot see: the
`output_rules` on `query.answered` name the exact rule that fired (`known_secret`,
`anthropic_key`, …), and the refusal reason is server-side only. The oracle
existed purely in the *client-visible* message, which is why the fix is a message
change, not a new detector.

## Mitigation

**N1 — closed.** All refusals now return one cause-free string, `REFUSAL`
(`app/rag_chain.py`): `REFUSAL_NO_CONTEXT`, `REFUSAL_WITHHELD`,
`REFUSAL_UNSUPPORTED`, and `REFUSAL_UNENTAILED` all alias it, and the hardcoded
block-path refusal in `output_filter.apply()` matches it verbatim. The wording
no longer states a reply was produced, so it cannot confirm existence even by
tone. `tests/test_hidden_context.py` asserts the constants are identical and that
`output_filter.apply` returns the same text; the empty-corpus and withheld paths
are now indistinguishable to a caller. Accepted cost: a legitimate "nothing here
answers that" now reads as the same flat refusal as a security block — the true
reason lives in `audit.log`.

**N2 — accepted residual, not patched.** The reframing surface was narrowed for
registered secrets (`known_secret`: spacing, one-per-line, NATO-phonetic,
homoglyph, base64, rot13, reversal — see `tests/test_secret_egress.py`), but the
class does not close: an unregistered shapeless secret and an in-prompt cipher
both pass, and no finite rule set fixes that. The correct disposition is the
project's standing one — **do not treat the egress filter as a control.** The
boundaries that held this red-team pass are the real ones:

- retrieval-time clearance scoping (a public reader never retrieves restricted
  content to leak),
- grounding / entailment refusal (an answer must come from retrieved documents),
- HMAC-verified session tokens, disjoint clearance/role duties, and the review
  gate for corpus trust.

Egress filtering is the last, weakest line and should be reported as such, not as
the thing standing between a cleared attacker and a secret.
