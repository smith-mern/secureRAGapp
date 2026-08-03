"""Output filtering.

Last check before a model response reaches the caller. Catches what should
never leave: secrets and credential-shaped strings, raw PII, system prompt
contents, and internal paths or stack traces.

Also the backstop for a successful prompt injection — if the model was steered
into leaking context or emitting attacker-supplied instructions, this is where
it gets caught. Blocks or redacts; records the event via audit_log without
writing the offending content into the log.
"""
