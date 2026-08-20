#!/usr/bin/env python3
"""Phase 2 attack: redacted content survives in the vector index.

Vector and embedding weakness, not a prompt weakness. Nothing here is
instruction-shaped, nothing crosses a tier, and no account is over-privileged.
The corpus is *corrected* — a paragraph is deleted at the source — and the
index keeps answering from the version that no longer exists.

Chunk ids are `sha256(source:index)`. Re-indexing a document writes ids
0..n-1 of the new version and touches nothing else, so a document that got
shorter leaves its old tail behind under the higher ids: still embedded, still
retrievable, still carrying the metadata it had when it was longer. That last
part is the sharp edge — an approved record whose sensitive paragraph is later
removed upstream leaves an orphan chunk stamped `reviewed=True`, so the
redacted text stays *trusted* while the clean replacement comes back in
unreviewed and gets quarantined. The controls invert.

Runs against a throwaway Chroma directory, not the repo's store: the point is
the write path, and the attack should not mutate phase-2 evidence. No server,
no login — this is below the HTTP layer, like vectorstore_no_access_control.py.

Reproduces the pre-fix behaviour explicitly (`_upsert_only`, which is what
`ingest._index` used to do) so the script keeps demonstrating the bug after the
fix lands, and then runs the real `ingest._index` to show it closed.

Exit 0 if redacted text was recovered under the old write path (attack
demonstrated). Exit 1 if it was not.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AUDIT_LOG_PATH", tempfile.mktemp(prefix="securerag-attack-"))

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import ingest, vectorstore  # noqa: E402

# Isolated store. Must be set before the first collection is created.
vectorstore.CHROMA_DIR = Path(tempfile.mkdtemp(prefix="securerag-attack-chroma-"))

TIER = "internal"
SOURCE = "tickets/42"
QUESTION = "what payment details did the customer give on ticket 42?"

# Long enough to span more than one chunk, with the sensitive part in the tail.
FILLER = "Ticket 42: customer reports a failed checkout. "
V1 = FILLER * 70 + "\nCard on file 4111111111111111, billing SSN 123-45-6789.\n"

# Support removes the payment details from the ticket. This is the corrected,
# authoritative version of the record.
V2 = "Ticket 42: customer reports a failed checkout. Payment details redacted by support."

MARKERS = ("4111111111111111", "123-45-6789")

# The distance gate secure mode applies in rag_chain._ground. A stale chunk only
# matters if it is close enough to be retrieved into the prompt.
MAX_DISTANCE = float(os.environ.get("MAX_DISTANCE", "0.75"))


def _upsert_only(source: str, text: str, metadata: dict) -> int:
    """What `ingest._index` did before this finding: write, never retract."""
    return vectorstore.add_chunks(
        TIER,
        (
            (vectorstore.chunk_id(source, i), chunk, {**metadata, "source": source})
            for i, chunk in enumerate(ingest.chunk_text(text))
        ),
    )


def _report(label: str) -> list[dict]:
    hits = vectorstore.query((TIER,), QUESTION, k=4)
    print(f"[*] {label}: {len(hits)} chunk(s) retrieved for {QUESTION!r}")
    leaked = []
    for hit in hits:
        stale = any(marker in hit["text"] for marker in MARKERS)
        reachable = hit["distance"] <= MAX_DISTANCE
        print(
            f"      distance={hit['distance']:.3f} "
            f"reviewed={hit['metadata'].get('reviewed')} "
            f"{'STALE' if stale else 'current'} "
            f"{hit['text'][-58:]!r}"
        )
        if stale and reachable:
            leaked.append(hit)
    return leaked


def main() -> int:
    metadata = {"origin": "connector:tickets", "reviewed": False}

    print("[*] indexing ticket 42 (with payment details), then approving it")
    _upsert_only(SOURCE, V1, metadata)
    approved = vectorstore.mark_reviewed(TIER, SOURCE, reviewer="erin")
    print(f"[*] approver signed off {approved} chunk(s) -> reviewed=True")

    print("[*] support redacts the payment details; the record re-syncs")
    _upsert_only(SOURCE, V2, metadata)

    leaked = _report("old write path (upsert only)")
    if not leaked:
        print("[-] redacted text was not retrieved; attack did not land")
        return 1

    print(
        f"\n[!] STALE DISCLOSURE — {len(leaked)} orphaned chunk(s) still answer "
        f"with content deleted at the source."
    )
    for hit in leaked:
        if hit["metadata"].get("reviewed") is True:
            print(
                "[!] and it is still marked reviewed=True: the redacted text is "
                "trusted, while the clean replacement came back unreviewed."
            )
            break

    print("\n[*] same sequence through the fixed ingest._index (delete, then write)")
    vectorstore.delete_source(TIER, SOURCE)
    ingest._index(TIER, SOURCE, V1, metadata)
    vectorstore.mark_reviewed(TIER, SOURCE, reviewer="erin")
    ingest._index(TIER, SOURCE, V2, metadata)
    if _report("fixed write path"):
        print("[!] REGRESSION — redacted text is still retrievable after the fix")
        return 1
    print("[+] redacted text is gone from the index")
    return 0


if __name__ == "__main__":
    sys.exit(main())
