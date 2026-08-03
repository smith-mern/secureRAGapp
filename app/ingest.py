"""Document ingestion pipeline.

Takes source documents (upload, file, URL), extracts text, chunks it, and hands
chunks to the vectorstore for embedding and indexing. Attaches per-chunk
metadata — source, owner, access scope — that authorization depends on at query
time.

Ingested content is untrusted. Anything read here may later be retrieved into
the model's context, so this is the first place to record provenance and the
last place that should treat document text as instructions.

Validates file type, size, and encoding at the boundary; never executes or
evaluates document content.
"""
