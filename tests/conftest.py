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

# Document bodies are encrypted at rest, so anything that touches the store
# needs a key. A fixed test value, not the deployment's — a suite that could
# decrypt the real corpus is a suite that can leak it into a failure message.
os.environ["STORE_ENCRYPTION_KEY"] = "test-store-key-not-the-deployments"

# Tests assert on the vulnerable-by-default behaviour and build the secure
# variant explicitly, so never inherit a real .env's phase switch.
os.environ.pop("SECURITY_FILTERS_ENABLED", None)

# Nor the deployment's entailment switch. That gate calls a live model on every
# answer; inheriting it from a phase-3 .env makes pipeline tests with stubbed
# models fail in ways that have nothing to do with what they assert. Set empty
# rather than popped, for the same reason as the pin below: load_dotenv() would
# otherwise put the deployment's value back. Tests that exercise the gate set it
# themselves.
os.environ["ANSWER_ENTAILMENT"] = ""

# Nor the deployment's generator pin. `OLLAMA_MODEL_DIGEST` makes startup fail
# closed when the daemon cannot be reached — correct for a deployment, wrong for
# a suite that runs with no Ollama at all: every test that builds a TestClient
# would error in setup on an unrelated machine state. The pin's own behaviour is
# covered explicitly in test_model_integrity.py, which sets the variable itself.
#
# Set empty rather than popped: `load_dotenv()` runs later, when app.secrets is
# imported, and would put the deployment's value back — it skips keys already
# present in the environment, and an empty string counts as present. `optional()`
# treats empty as unset, so this reads as "no pin configured".
os.environ["OLLAMA_MODEL_DIGEST"] = ""
