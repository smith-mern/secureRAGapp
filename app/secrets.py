"""Secret loading and access.

Single place that reads API keys, database URLs, and signing keys from the
environment. Fails loudly at startup on a missing required secret rather than
falling back to a default — no insecure defaults.

Secrets are returned to callers on request and never logged, echoed in errors,
or included in responses. See .env.example for the expected variables.

Note: this module shadows the stdlib `secrets` only for `from app import
secrets`. Absolute imports mean `import secrets` inside this package still
resolves to the stdlib.
"""
