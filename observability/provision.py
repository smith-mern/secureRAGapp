"""Create Grafana users from DEMO_USERS and import the audit dashboard.

Grafana logins mirror the app's synthetic accounts, so alice and carol sign in
to the dashboard with the same credentials they use against the API.

Two things this deliberately does not pretend to be:

1. Shared credentials are a weakness, not a feature. One password now unlocks
   both the API and the dashboard, so a credential captured in phase 2 gets the
   attacker both. Fine for a lab, and worth naming in the writeup.

2. Grafana roles are not app clearances. Every provisioned user is a Viewer and
   sees the whole audit stream — including `source` fields naming restricted
   documents. Read access to the dashboard therefore leaks restricted filenames
   to a public-clearance user. Per-user log filtering needs Loki multi-tenancy,
   which is out of scope here; treat it as a finding rather than a gap to
   quietly paper over.

Run after `observability/run.sh`, with the app's venv or any Python 3.11+.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAFANA = "http://localhost:3000"


def read_env(path: Path) -> dict[str, str]:
    """Minimal .env reader — avoids depending on the app's venv."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def call(method: str, path: str, admin_password: str, payload: dict | None = None) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(f"{GRAFANA}{path}", data=body, method=method)
    request.add_header("Content-Type", "application/json")
    token = base64.b64encode(f"admin:{admin_password}".encode("utf-8")).decode("ascii")
    request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def wait_for_grafana(admin_password: str, attempts: int = 40) -> bool:
    for _ in range(attempts):
        try:
            status, _ = call("GET", "/api/health", admin_password)
            if status == 200:
                return True
        except urllib.error.URLError:
            pass
        time.sleep(1)
    return False


def main() -> int:
    env = read_env(REPO_ROOT / ".env")
    admin_password = env.get("GRAFANA_ADMIN_PASSWORD", "")
    if not admin_password:
        print("GRAFANA_ADMIN_PASSWORD is not set in .env", file=sys.stderr)
        return 1

    raw_users = env.get("DEMO_USERS", "")
    if not raw_users:
        print("DEMO_USERS is not set in .env — nothing to provision", file=sys.stderr)
        return 1

    if not wait_for_grafana(admin_password):
        print(f"Grafana did not become healthy at {GRAFANA}", file=sys.stderr)
        return 1

    for username, spec in json.loads(raw_users).items():
        status, body = call("POST", "/api/admin/users", admin_password, {
            "name": username,
            "login": username,
            "email": f"{username}@securerag.local",
            "password": spec["password"],
        })
        if status in (200, 412):  # 412 == already exists
            print(f"user {username}: {'created' if status == 200 else 'already present'}")
        else:
            print(f"user {username}: FAILED {status} {body}", file=sys.stderr)

    dashboard = json.loads((REPO_ROOT / "observability" / "dashboard.json").read_text())
    status, body = call("POST", "/api/dashboards/db", admin_password, {
        "dashboard": dashboard,
        "overwrite": True,
    })
    if status == 200:
        print(f"dashboard: {GRAFANA}{json.loads(body)['url']}")
    else:
        print(f"dashboard: FAILED {status} {body}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
