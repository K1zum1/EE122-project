#!/usr/bin/env python3
"""Deep-merge a scenario overlay into the base config and write the result.

Usage: merge_config.py <base.yaml> <scenario.yaml> <out.yaml>

The scenario YAML is expected to have two top-level keys:

* ``meta``       - descriptive metadata (id, rq, description). Written into
                   the merged output under the ``meta`` key so the aggregator
                   can group scenarios by research question.
* ``overrides``  - dict that is deep-merged into the base config.
"""

import sys
from pathlib import Path

import yaml


def deep_merge(base, overlay):
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return overlay
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def main():
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    base_path, scenario_path, out_path = map(Path, sys.argv[1:])

    base = yaml.safe_load(open(base_path)) or {}
    scenario = yaml.safe_load(open(scenario_path)) or {}
    overrides = scenario.get("overrides") or {}
    meta = scenario.get("meta") or {}

    merged = deep_merge(base, overrides)
    merged["meta"] = meta

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        yaml.safe_dump(merged, fh, sort_keys=False)
    print(f"[merge_config] wrote {out_path}")


if __name__ == "__main__":
    main()
