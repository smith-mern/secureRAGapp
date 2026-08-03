"""Document ingestion pipeline.

Takes source documents (upload, file, URL), extracts text, chunks it, and hands
chunks to the vectorstore for embedding and indexing. Attaches per-chunk
metadata — source, owner, access tier — that authorization depends on at query
time.

The tier comes from the directory a document was loaded from
(data/documents/{public,internal,restricted}) and must be written into chunk
metadata here. After chunking, the directory is gone: if the tier isn't
recorded at ingest, the vector store has no way to enforce it and every tier
becomes readable by every caller.

Ingested content is untrusted. Anything read here may later be retrieved into
the model's context, so this is the first place to record provenance and the
last place that should treat document text as instructions.

Validates file type, size, and encoding at the boundary; never executes or
evaluates document content.
"""
