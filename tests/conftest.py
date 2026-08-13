"""Test-wide isolation.

`audit.log` is phase 2 evidence — the findings in redteam/ cite it, and a test
run that appends to it corrupts the record with events no attacker generated.
Point the audit sink at a throwaway file before any app module imports, since
`audit_log` binds AUDIT_LOG_PATH at import time.

This must stay the first thing that happens in the test session. Setting it
inside a fixture is too late: the import has already resolved the path.
"""

from __future__ import annotations

import os
import tempfile

os.environ["AUDIT_LOG_PATH"] = os.path.join(
    tempfile.gettempdir(), "securerag-test-audit.log"
)

# Tests assert on the vulnerable-by-default behaviour and build the secure
# variant explicitly, so never inherit a real .env's phase switch.
os.environ.pop("SECURITY_FILTERS_ENABLED", None)
