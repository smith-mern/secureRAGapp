"""Input validation at the trust boundary.

Validates and normalizes everything arriving from a user before it reaches any
other module: type, length, encoding, and allowed character ranges. Rejects
rather than sanitizes where a value can't be made safe.

Applies to query strings, uploaded filenames and metadata, and any path or
identifier used to look up a resource. Rejects on failure with a message that
does not echo the offending input back verbatim.
"""
