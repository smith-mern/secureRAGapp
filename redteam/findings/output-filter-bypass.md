# No output filtering — secret/PII egress verbatim

**Severity:** High — credentials and PII leave the system unscrubbed.
**Attack:** [`redteam/attacks/output_filter_bypass.py`](../attacks/output_filter_bypass.py)
**Component:** `app/rag_chain.py` (`answer`), egress filtering; `app/filters/output_filter.py`.

## Vulnerability

The model's response is the last thing to leave the system, and it is where a
successful injection or a sensitive retrieved chunk turns into an actual leak.
`output_filter.apply()` exists to catch that: it **blocks** responses containing
credential-shaped strings (API keys, private-key blocks, bearer tokens) or a
copy of the system prompt, and **redacts** PII (email, SSN, credit card, phone,
filesystem paths, tracebacks).

In the insecure configuration it never runs. In `rag_chain.answer`:

```python
if secure:
    safe_text, output_rules, blocked = output_filter.apply(text)
else:
    safe_text, output_rules, blocked = text, [], False
```

With `SECURITY_FILTERS_ENABLED=false` (the default), the raw model text is
returned as `safe_text` with no scan. Whatever the model emits — a credential it
read from a document, PII, or the system prompt it was steered into repeating —
ships to the caller as-is. This is the intended phase-1 gap, not an accident.

## Exploit

Writing and reading are separate roles, so the exploit uses two accounts: the
`uploader` plants a document, the `reader` retrieves it. The planted note
carries scrubber-bait — an API key (block rule) and an email (redact rule).

```
$ python3 redteam/attacks/output_filter_bypass.py
[*] uploader dave (clearance=internal, role=uploader)
[*] planted oncall.md in tier 'public' with an API key and an email
[*] reader carol (clearance=public, role=reader)
[*] answer: The pager API key is sk-ant-api03-EXAMPLEKEYabcdef1234567890 and the
    escalation email is oncall@northwind.example.

[!] VERBATIM — egress scrubber did not run; output carried the planted secret(s): ['api_key', 'email']
[*] cleaned up: oncall.md overwritten with benign content
```

Confirmed the same way from the UI: sign in as `dave`/`pw-dave`, upload the note
to the `public` tier; sign in as `carol`/`pw-carol`, ask *"What is the on-call
pager API key and escalation email?"* — the reply contains the key and email
verbatim. The chat UI shows only `answer`, which is exactly what a real caller
sees, so no privileged view is needed to observe the leak.

Note the two failure modes chain: a low-clearance reader can retrieve a
credential a curated document was never supposed to expose (see the cross-tier
retrieval leak), and this finding is why nothing catches it on the way out.

## Detection

`audit.log` records what egress filtering *would* have fired, per query, in the
`output_rules` field of `query.answered`:

```json
{"event": "query.answered", "actor": "carol", "mode": "insecure", "output_rules": [], ...}
```

In insecure mode `output_rules` is always empty because the scanner never runs —
so the signal is `mode: "insecure"` itself: any `query.answered` with that mode
outside phase 1 means responses are leaving unscanned. In secure mode a populated
`output_rules` (e.g. `["anthropic_key"]`) with `decision: "deny"` is the record
of a leak that was *stopped*, and is worth alerting on in its own right — it
means a credential reached the model's output and only the last gate caught it.
The scanner deliberately logs rule names, never the offending content, so the
audit trail does not itself become a copy of the secret.

## Mitigation

Set `SECURITY_FILTERS_ENABLED=true`, which routes the response through
`output_filter.apply()`:

- The planted API key matches the `anthropic_key` **block** rule, so the entire
  response is replaced with *"This response was withheld because it contained
  content that must not leave the system."* and `refused` is `True`.
- A payload carrying only the email (no key) is **redacted** instead: the address
  is replaced with `[redacted]` and the rest of the answer still ships.

Same account, same question, opposite egress. The attack script exits non-zero
(FILTERED) in this mode.

**Residual risk (per the phase-3 mandate — this is a backstop, not a boundary):**

- **Regex, not understanding.** The rules match shapes. A secret the model
  reformats — spaced-out digits, an "AKIA" key described in words, a base64'd
  blob, a key split across a sentence — passes straight through. The filter
  raises the cost of a leak; it does not close the class.
- **Last line only.** Egress filtering fires *after* the sensitive text has been
  retrieved into the model's context and generated. It cannot un-leak content
  the model paraphrases below the pattern threshold, and it does nothing about
  the `data/chroma_db/` filesystem exposure. It should be paired with — not
  substituted for — clearance-scoped retrieval and not indexing credentials in
  the first place.
