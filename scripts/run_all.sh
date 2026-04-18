#!/usr/bin/env bash
# Run the full evaluation matrix: every scenario in scripts/scenarios/*.yaml,
# repeated N_TRIALS times. Results land under logs/<exp_id>/.
#
# Usage: sudo -E scripts/run_all.sh [exp_id] [n_trials]
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[run_all] must run as root; try: sudo -E $0 $*" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

EXP_ID="${1:-exp-$(date -u +%Y%m%dT%H%M%SZ)}"
N_TRIALS="${2:-3}"

PYTHON="${PYTHON_BIN:-python3}"

# Regenerate scenario files so they always reflect the current matrix spec.
"$PYTHON" "$HERE/scripts/gen_scenarios.py"

EXP_DIR="$HERE/logs/$EXP_ID"
mkdir -p "$EXP_DIR"
SUMMARY="$EXP_DIR/run_all.log"
: > "$SUMMARY"

SCENARIO_FILES=( "$HERE"/scripts/scenarios/*.yaml )
N_SCENARIOS=${#SCENARIO_FILES[@]}
echo "[run_all] exp_id=$EXP_ID trials=$N_TRIALS scenarios=$N_SCENARIOS" | tee -a "$SUMMARY"
echo "[run_all] expected wall time ~$(( N_SCENARIOS * N_TRIALS * 40 / 60 )) minutes" | tee -a "$SUMMARY"

PASS=0
FAIL=0
FAILED_LIST=()
IDX=0
for SC in "${SCENARIO_FILES[@]}"; do
  IDX=$((IDX + 1))
  for T in $(seq 0 $((N_TRIALS - 1))); do
    LABEL="$(basename "$SC" .yaml)#$T"
    printf "[run_all] (%d/%d) %s ... " "$IDX" "$N_SCENARIOS" "$LABEL" | tee -a "$SUMMARY"
    if "$HERE/scripts/run_scenario.sh" "$SC" "$EXP_ID" "$T" >>"$SUMMARY" 2>&1; then
      echo "OK" | tee -a "$SUMMARY"
      PASS=$((PASS + 1))
    else
      echo "FAIL" | tee -a "$SUMMARY"
      FAIL=$((FAIL + 1))
      FAILED_LIST+=("$LABEL")
    fi
  done
done

echo "[run_all] done: pass=$PASS fail=$FAIL" | tee -a "$SUMMARY"
if [[ $FAIL -gt 0 ]]; then
  echo "[run_all] failed scenarios:" | tee -a "$SUMMARY"
  printf '  %s\n' "${FAILED_LIST[@]}" | tee -a "$SUMMARY"
fi

echo "[run_all] results in $EXP_DIR"
echo "[run_all] next:"
echo "    $PYTHON $HERE/scripts/aggregate.py $EXP_DIR"
echo "    $PYTHON $HERE/scripts/generate_report.py $EXP_DIR"
