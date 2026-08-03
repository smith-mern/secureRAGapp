"""FastAPI application entrypoint.

Wires the API layer: creates the app, mounts routes, and applies auth and
filter middleware. Endpoints are thin — they validate input, delegate to the
module that owns the work, and shape the response. No business logic here.

Run: uvicorn app.main:app --reload
"""
