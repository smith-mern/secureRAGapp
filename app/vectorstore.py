"""Vector store interface.

Wraps the embedding model and the vector database: upsert chunks, similarity
search, delete by source. The rest of the app talks to this module rather than
to the database client directly.

Every query is scoped to the caller's access rights — filtering happens in the
query, not on the result set, so a caller never receives chunks they aren't
entitled to.

Backend not yet chosen (Chroma / pgvector / Qdrant); keep the surface small
enough that swapping it stays a one-file change.
"""
