#!/usr/bin/env bash
# Run a single attacker experiment: start the victim server in the background,
# run the attacker, tee victim stdout into the attacker's run directory.
#
# Usage: scripts/run_experiment.sh [run_id]
#
# Requires: scapy (for attacker), a UDP listener on the configured port.
# The victim is started via python3 src/victim_server.py.

set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

RUN_ID="${1:-}"
if [[ -n "$RUN_ID" ]]; then
  export UDP_FLOOD_RUN_ID="$RUN_ID"   # not currently read; reserved for future
fi

OUT_DIR_BASE="$(python3 -c "import yaml; print(yaml.safe_load(open('src/config.yaml'))['logging'].get('output_dir','logs'))")"

# Start victim in background, capture its stdout.
VICTIM_LOG_TMP="$(mktemp)"
python3 src/victim_server.py > "$VICTIM_LOG_TMP" 2>&1 &
VICTIM_PID=$!
trap 'kill "$VICTIM_PID" 2>/dev/null || true; wait "$VICTIM_PID" 2>/dev/null || true' EXIT

sleep 0.5

# Run attacker (creates logs/<run_id>/ itself)
python3 src/udp_flood.py

# Find the newest run dir and copy the victim log into it.
NEWEST="$(ls -1dt "$OUT_DIR_BASE"/*/ 2>/dev/null | head -n1 || true)"
if [[ -n "$NEWEST" ]]; then
  cp "$VICTIM_LOG_TMP" "${NEWEST%/}/victim.log"
  echo "[runner] victim log copied to ${NEWEST%/}victim.log"
fi

rm -f "$VICTIM_LOG_TMP"
