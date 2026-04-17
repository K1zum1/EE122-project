#!/usr/bin/env bash
# Run attacker once per traffic profile (constant, burst, ramp), writing each
# to its own run directory. Emits a combined sweep_summary.json at the end.
#
# Usage: scripts/sweep_profiles.sh [duration_seconds]

set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

DUR="${1:-10}"
SWEEP_ID="sweep-$(date -u +%Y%m%dT%H%M%SZ)"
SWEEP_DIR="logs/$SWEEP_ID"
mkdir -p "$SWEEP_DIR"

ORIG_CONFIG="src/config.yaml"
BACKUP="$(mktemp)"
cp "$ORIG_CONFIG" "$BACKUP"
trap 'cp "$BACKUP" "$ORIG_CONFIG"; rm -f "$BACKUP"' EXIT

python3 - "$ORIG_CONFIG" "$DUR" <<'PY'
import sys, yaml
path, dur = sys.argv[1], int(sys.argv[2])
cfg = yaml.safe_load(open(path))
cfg["attack"]["duration"] = dur
yaml.safe_dump(cfg, open(path, "w"), sort_keys=False)
PY

for MODE in constant burst ramp; do
  echo "=== sweep: mode=$MODE ==="
  python3 - "$ORIG_CONFIG" "$MODE" "$SWEEP_ID" <<'PY'
import sys, yaml
path, mode, sweep_id = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(open(path))
cfg["attack"]["mode"] = mode
cfg.setdefault("logging", {})["run_id"] = f"{sweep_id}/{mode}"
yaml.safe_dump(cfg, open(path, "w"), sort_keys=False)
PY
  python3 src/udp_flood.py
done

# Combine summaries.
python3 - "$SWEEP_DIR" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
combined = {}
for mode in ("constant", "burst", "ramp"):
    p = root / mode / "summary.json"
    if p.exists():
        combined[mode] = json.loads(p.read_text())
(root / "sweep_summary.json").write_text(json.dumps(combined, indent=2))
print(f"[sweep] combined summary -> {root}/sweep_summary.json")
PY
