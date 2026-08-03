"""Audit logging.

Structured, append-only record of security-relevant events: auth attempts,
ingestion, queries, and every filter block or rejection. Enough to reconstruct
who did what, when — and to make phase 2's red-team findings reproducible.

Logs metadata, not payloads: identifiers, decisions, and timestamps. Never
secrets, credentials, raw PII, or full document text.
"""
