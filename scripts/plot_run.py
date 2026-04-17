#!/usr/bin/env python3
"""Plot attacker achieved pps over time for a single run directory.

Usage: scripts/plot_run.py logs/<run_id>
Outputs: <run_dir>/attacker_rate.png

Requires matplotlib. Install with: pip install matplotlib
"""

import csv
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)

    run_dir = Path(sys.argv[1])
    csv_path = run_dir / "attacker_rate.csv"
    if not csv_path.exists():
        print(f"not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; pip install matplotlib", file=sys.stderr)
        sys.exit(1)

    t, pps = [], []
    with csv_path.open() as fh:
        r = csv.DictReader(fh)
        for row in r:
            t.append(float(row["t_mono_s"]))
            pps.append(float(row["achieved_pps"]))

    fig, ax = plt.subplots(figsize=(8, 3.5))
    ax.plot(t, pps, linewidth=1.2)
    ax.set_xlabel("time since attack start (s)")
    ax.set_ylabel("achieved pps")
    ax.set_title(f"Attacker send rate — {run_dir.name}")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out = run_dir / "attacker_rate.png"
    fig.savefig(out, dpi=120)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
