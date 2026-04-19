#!/usr/bin/env bash
# Run a single scenario-trial:
#   1. merge base config + scenario overlay -> RUN_DIR/config.effective.yaml
#   2. start os-ken-manager src/controller.py with EXP_LOG_DIR=RUN_DIR
#   3. run Mininet topology in harness mode (spawns per-host workloads)
#   4. stop controller, clean up Mininet state
#
# Usage: sudo -E scripts/run_scenario.sh <scenario.yaml> <exp_id> [trial_index]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[run_scenario] must run as root (mininet requires it)." >&2
  echo "[run_scenario] try: sudo -E $0 $*" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

SCENARIO="${1:?scenario YAML path required}"
EXP_ID="${2:?exp_id required}"
TRIAL="${3:-0}"

if [[ ! -f "$SCENARIO" ]]; then
  echo "[run_scenario] scenario file not found: $SCENARIO" >&2
  exit 2
fi

SCENARIO_ID="$(basename "$SCENARIO" .yaml)"
RUN_DIR="$HERE/logs/$EXP_ID/$SCENARIO_ID/trial$TRIAL"
mkdir -p "$RUN_DIR"

# Resolve a Python that has the project's deps (scapy, mininet, yaml, os_ken).
# `sudo` resets PATH to secure_path, so a bare `python3` usually lands at
# /usr/bin/python3 instead of the invoking user's conda env. Prefer explicit
# PYTHON_BIN, else try the invoking user's conda `sdn` env, else fall back.
if [[ -z "${PYTHON_BIN:-}" ]]; then
  _INVOKER="${SUDO_USER:-$USER}"
  _INVOKER_HOME="$(getent passwd "$_INVOKER" 2>/dev/null | cut -d: -f6 || echo "")"
  for _candidate in \
      "${CONDA_PREFIX:-}/bin/python3" \
      "$_INVOKER_HOME/miniconda3/envs/sdn/bin/python3" \
      "$_INVOKER_HOME/anaconda3/envs/sdn/bin/python3"; do
    if [[ -n "$_candidate" && -x "$_candidate" ]]; then
      PYTHON_BIN="$_candidate"
      break
    fi
  done
fi
PYTHON="${PYTHON_BIN:-python3}"
OS_KEN="${OS_KEN_MANAGER:-os-ken-manager}"
echo "[run_scenario] using PYTHON=$PYTHON"

echo "[run_scenario] scenario=$SCENARIO_ID trial=$TRIAL run_dir=$RUN_DIR"

# 1. Merge config.
"$PYTHON" "$HERE/scripts/merge_config.py" \
  "$HERE/src/config.yaml" "$SCENARIO" "$RUN_DIR/config.effective.yaml" \
  >>"$RUN_DIR/runner.log" 2>&1

export EE122_CONFIG="$RUN_DIR/config.effective.yaml"
export EXP_LOG_DIR="$RUN_DIR"

# 2. Clean any stray Mininet state.
mn -c >>"$RUN_DIR/runner.log" 2>&1 || true

# 3. Start controller.
echo "[run_scenario] launching os-ken-manager" >>"$RUN_DIR/runner.log"
"$OS_KEN" --ofp-tcp-listen-port 6653 "$HERE/src/controller.py" \
  >"$RUN_DIR/controller_stdout.log" 2>"$RUN_DIR/controller_stderr.log" &
CTRL_PID=$!

cleanup() {
  if kill -0 "$CTRL_PID" 2>/dev/null; then
    kill "$CTRL_PID" 2>/dev/null || true
    sleep 0.5
    kill -9 "$CTRL_PID" 2>/dev/null || true
  fi
  wait "$CTRL_PID" 2>/dev/null || true
  mn -c >>"$RUN_DIR/runner.log" 2>&1 || true
}
trap cleanup EXIT

# 4. Wait for controller socket.
CTRL_READY=0
for i in $(seq 1 30); do
  if ss -lnt 2>/dev/null | grep -q ':6653 ' \
     || (command -v lsof >/dev/null && lsof -iTCP:6653 -sTCP:LISTEN >/dev/null 2>&1); then
    CTRL_READY=1
    break
  fi
  sleep 0.2
done
if [[ $CTRL_READY -ne 1 ]]; then
  echo "[run_scenario] controller failed to bind :6653; see $RUN_DIR/controller_stderr.log" >&2
  tail -n 20 "$RUN_DIR/controller_stderr.log" >&2 || true
  exit 3
fi

# 5. Run topology in harness mode.
echo "[run_scenario] launching topology (harness mode)" >>"$RUN_DIR/runner.log"
TOPO_STATUS=0
TOPO_MODE=harness "$PYTHON" "$HERE/src/topology.py" \
  >"$RUN_DIR/topology_stdout.log" 2>"$RUN_DIR/topology_stderr.log" \
  || TOPO_STATUS=$?

# 6. Controller has seen the events -- give it a moment to flush CSVs.
sleep 0.5

echo "[run_scenario] done (topology_status=$TOPO_STATUS)"
exit "$TOPO_STATUS"
