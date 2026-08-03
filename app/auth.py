"""Authentication and authorization.

Owns identity: credential verification, session/token issuance and validation,
and the FastAPI dependency that endpoints use to require an authenticated
caller.

Enforces least privilege — a caller's identity determines which documents the
retriever is allowed to see, so authorization decisions made here must be
passed down to vectorstore queries rather than applied after retrieval.

Never logs credentials, tokens, or password material.
"""
