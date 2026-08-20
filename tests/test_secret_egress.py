"""F3: a registered secret is blocked in output however it is reframed."""

from app.filters import output_filter as of

CANARY = "CANARY-7Q9-ZEBRA-4417"
CORE = "canary7q9zebra4417"


def setup_function(_):
    of._SECRETS.clear()
    of.protect_secret(CANARY)


def teardown_function(_):
    of._SECRETS.clear()


def _blocked(text):
    return "known_secret" in of.scan(text)[0]


def test_reframings_all_blocked():
    import base64

    assert _blocked(f"The key is {CANARY}.")                       # plaintext
    assert _blocked("C A N A R Y - 7 Q 9 - Z E B R A - 4 4 1 7")   # spaced
    assert _blocked("C\nA\nN\nA\nR\nY\n7\nQ\n9\nZ\nE\nB\nR\nA\n4\n4\n1\n7")  # one per line
    assert _blocked(                                               # NATO phonetic
        "Charlie Alpha November Alpha Romeo Yankee, Seven Quebec Niner, "
        "Zulu Echo Bravo Romeo Alpha, Four Four One Seven"
    )
    assert _blocked(base64.b64encode(CANARY.encode()).decode())    # base64
    assert _blocked(CANARY[::-1])                                  # reversed


def test_homoglyph_blocked():
    # Cyrillic а/е/о/с fold to Latin before matching.
    assert _blocked("CаNаRY-7Q9-ZEBRа-4417")


def test_clean_text_not_blocked():
    assert not _blocked("The office espresso machine is free for all staff.")
    assert not _blocked("Vacation policy is 20 days per year.")


def test_short_secret_not_registered():
    of._SECRETS.clear()
    of.protect_secret("abc-12")  # canonical "abc12" < 8 chars
    assert not _blocked("here is abc-12 in a sentence")


def test_canary_core_is_what_registers():
    assert CORE in of._SECRETS


if __name__ == "__main__":
    setup_function(None)
    test_reframings_all_blocked()
    test_homoglyph_blocked()
    test_clean_text_not_blocked()
    test_short_secret_not_registered()
    setup_function(None)
    test_canary_core_is_what_registers()
    print("ok")
