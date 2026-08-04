#!/usr/bin/env bash
# Start (or stop) the local observability stack: Loki, Alloy, Grafana.
# Native Homebrew binaries — no containers.
#
#   observability/run.sh          start
#   observability/run.sh stop     stop
#
# Logs for each service land in observability/data/<service>.log
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
DATA="$REPO/observability/data"
PIDS="$DATA/pids"

stop_stack() {
  for name in alloy loki grafana; do
    if [ -f "$PIDS/$name.pid" ]; then
      pid=$(cat "$PIDS/$name.pid")
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" && echo "stopped $name ($pid)"
      fi
      rm -f "$PIDS/$name.pid"
    fi
  done
}

if [ "${1:-start}" = "stop" ]; then
  stop_stack
  exit 0
fi

for binary in loki alloy grafana; do
  command -v "$binary" >/dev/null || {
    echo "missing '$binary' — run: brew install grafana loki grafana-alloy" >&2
    exit 1
  }
done

# Alloy reads the log path from the environment so this isn't hardcoded to one
# machine. The file must exist before Alloy starts or it has nothing to tail.
export AUDIT_LOG_FILE="$REPO/audit.log"
touch "$AUDIT_LOG_FILE"

mkdir -p "$DATA"/{loki,alloy,grafana/logs,grafana/plugins} "$PIDS"

admin_password=$(
  grep -E '^GRAFANA_ADMIN_PASSWORD=' .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d "\"'" || true
)
if [ -z "$admin_password" ]; then
  echo "GRAFANA_ADMIN_PASSWORD is not set in .env" >&2
  exit 1
fi

stop_stack

# nohup so the stack outlives the shell that launched it.
echo "starting loki      -> http://localhost:3100"
nohup loki -config.file=observability/loki-config.yaml \
  >"$DATA/loki.log" 2>&1 &
echo $! > "$PIDS/loki.pid"

echo "starting alloy     -> tailing $AUDIT_LOG_FILE"
nohup alloy run observability/alloy-config.alloy \
  --storage.path="$DATA/alloy" \
  --server.http.listen-addr=127.0.0.1:12345 \
  >"$DATA/alloy.log" 2>&1 &
echo $! > "$PIDS/alloy.pid"

echo "starting grafana   -> http://localhost:3000"
nohup env \
GF_PATHS_DATA="$DATA/grafana" \
GF_PATHS_LOGS="$DATA/grafana/logs" \
GF_PATHS_PLUGINS="$DATA/grafana/plugins" \
GF_PATHS_PROVISIONING="$REPO/observability/grafana/provisioning" \
GF_SECURITY_ADMIN_PASSWORD="$admin_password" \
GF_USERS_ALLOW_SIGN_UP=false \
GF_ANALYTICS_REPORTING_ENABLED=false \
  grafana server --homepath "$(brew --prefix grafana)/share/grafana" \
  >"$DATA/grafana.log" 2>&1 &
echo $! > "$PIDS/grafana.pid"

echo
echo "provisioning users and dashboard..."
PY="python3"
[ -x "$REPO/.venv/bin/python" ] && PY="$REPO/.venv/bin/python"
"$PY" observability/provision.py

echo
echo "Grafana:  http://localhost:3000   (admin, or any DEMO_USERS account)"
echo "Stop:     observability/run.sh stop"
