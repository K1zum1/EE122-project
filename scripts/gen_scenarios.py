#!/usr/bin/env python3
"""Generate per-scenario YAML overlays for the full 9-RQ evaluation matrix.

Running this writes one YAML per scenario into ``scripts/scenarios/``. Each
file has two top-level keys (``meta`` and ``overrides``) that are consumed
by ``scripts/merge_config.py`` when building the effective per-run config.

All scenarios share a common base (benign senders + latency probe enabled,
30 s duration with 3 s warmup). Individual cells change only the knobs
relevant to their research question.
"""

from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "scenarios"


COMMON = {
    "attack": {"duration": 30, "warmup_s": 3},
    "benign": {"enabled": True, "pps": 50, "payload_size": 64},
    "probe": {"enabled": True, "pps": 50, "payload_size": 32},
}


def scenario(id_, rq, description, overrides):
    body = {}
    # Deep copy of COMMON merged with overrides (shallow merge at top level).
    for key, val in COMMON.items():
        body.setdefault(key, {}).update(val)
    for key, val in overrides.items():
        if isinstance(val, dict) and isinstance(body.get(key), dict):
            body[key].update(val)
        else:
            body[key] = val
    return {
        "meta": {"id": id_, "rq": rq, "description": description},
        "overrides": body,
    }


def attack(mode="constant", pps=100, enabled=True):
    return {"attack": {"enabled": enabled, "mode": mode, "target_pps": pps}}


def no_attack():
    return {"attack": {"enabled": False}}


def spoof(pps=100, many=False, n=20):
    return {
        "spoof": {
            "enabled": True,
            "pps": pps,
            "many_identities": many,
            "num_identities": n,
        }
    }


def no_spoof():
    return {"spoof": {"enabled": False}}


def sdn(mode, threshold=None, delay_ms=None):
    s = {"defense_mode": mode}
    if threshold is not None:
        s["threshold_pps"] = threshold
    if delay_ms is not None:
        s["inject_controller_delay_ms"] = delay_ms
    return {"sdn": s}


def merge(*ds):
    out = {}
    for d in ds:
        for k, v in d.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
    return out


SCENARIOS = [
    # ------------- RQ1: baseline vulnerability (defense=off) -------------
    scenario("rq1_benign_only", 1, "Benign-only baseline, no defense",
             merge(sdn("off"), no_attack(), no_spoof())),
    scenario("rq1_flood_low", 1, "Flood 100 pps, no defense",
             merge(sdn("off"), attack(pps=100), no_spoof())),
    scenario("rq1_flood_med", 1, "Flood 1000 pps, no defense",
             merge(sdn("off"), attack(pps=1000), no_spoof())),
    scenario("rq1_flood_high", 1, "Flood 5000 pps, no defense",
             merge(sdn("off"), attack(pps=5000), no_spoof())),
    scenario("rq1_spoof_single", 1, "Spoof (1 identity) 100 pps, no defense",
             merge(sdn("off"), no_attack(), spoof(pps=100, many=False))),
    scenario("rq1_spoof_many", 1, "Spoof (20 identities) 100 pps, no defense",
             merge(sdn("off"), no_attack(), spoof(pps=100, many=True, n=20))),
    scenario("rq1_mixed", 1, "Mixed flood_med + spoof_single, no defense",
             merge(sdn("off"), attack(pps=1000), spoof(pps=100, many=False))),

    # ------------- RQ2: detection accuracy (defense=detect_only) -------------
    scenario("rq2_benign_only", 2, "Benign-only under detect_only (FP test)",
             merge(sdn("detect_only"), no_attack(), no_spoof())),
    scenario("rq2_flood_low", 2, "Flood 100 pps, detect_only",
             merge(sdn("detect_only"), attack(pps=100), no_spoof())),
    scenario("rq2_flood_med", 2, "Flood 1000 pps, detect_only",
             merge(sdn("detect_only"), attack(pps=1000), no_spoof())),
    scenario("rq2_flood_high", 2, "Flood 5000 pps, detect_only",
             merge(sdn("detect_only"), attack(pps=5000), no_spoof())),
    scenario("rq2_spoof_single", 2, "Spoof (1 identity), detect_only",
             merge(sdn("detect_only"), no_attack(), spoof(pps=100, many=False))),
    scenario("rq2_spoof_many", 2, "Spoof (20 identities), detect_only",
             merge(sdn("detect_only"), no_attack(), spoof(pps=100, many=True, n=20))),
    scenario("rq2_thresh_50_flood_med", 2, "Threshold sweep: 50 pps on flood_med",
             merge(sdn("detect_only", threshold=50), attack(pps=1000), no_spoof())),
    scenario("rq2_thresh_2000_flood_med", 2, "Threshold sweep: 2000 pps on flood_med (should miss)",
             merge(sdn("detect_only", threshold=2000), attack(pps=1000), no_spoof())),

    # ------------- RQ3: mitigation effectiveness (defense=detect_mitigate) -------------
    scenario("rq3_flood_low", 3, "Flood 100 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=100), no_spoof())),
    scenario("rq3_flood_med", 3, "Flood 1000 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=1000), no_spoof())),
    scenario("rq3_flood_high", 3, "Flood 5000 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=5000), no_spoof())),
    scenario("rq3_spoof_single", 3, "Spoof (1 id), detect_mitigate",
             merge(sdn("detect_mitigate"), no_attack(), spoof(pps=100, many=False))),
    scenario("rq3_spoof_many", 3, "Spoof (20 ids), detect_mitigate",
             merge(sdn("detect_mitigate"), no_attack(), spoof(pps=100, many=True, n=20))),
    scenario("rq3_mixed", 3, "Mixed flood + spoof, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=1000), spoof(pps=100, many=False))),

    # ------------- RQ4/5: selectivity + overhead (benign only, defense on) -------------
    scenario("rq5_benign_only_mitigate", 5,
             "Benign only, detect_mitigate on (overhead + selectivity FP check)",
             merge(sdn("detect_mitigate"), no_attack(), no_spoof())),

    # ------------- RQ6: intensity sweep (detect_mitigate) -------------
    scenario("rq6_flood_pps_500", 6, "Flood 500 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=500), no_spoof())),
    scenario("rq6_flood_pps_2000", 6, "Flood 2000 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=2000), no_spoof())),
    scenario("rq6_flood_pps_10000", 6, "Flood 10000 pps, detect_mitigate",
             merge(sdn("detect_mitigate"), attack(pps=10000), no_spoof())),
    scenario("rq6_spoof_ids_100", 6, "Spoof 100 identities, detect_mitigate",
             merge(sdn("detect_mitigate"), no_attack(), spoof(pps=100, many=True, n=100))),

    # ------------- RQ8: controller bottleneck / delay -------------
    scenario("rq8_delay_10_flood_med", 8, "detect_mitigate + 10ms injected controller delay",
             merge(sdn("detect_mitigate", delay_ms=10), attack(pps=1000), no_spoof())),
    scenario("rq8_delay_50_flood_med", 8, "detect_mitigate + 50ms injected controller delay",
             merge(sdn("detect_mitigate", delay_ms=50), attack(pps=1000), no_spoof())),
    scenario("rq8_delay_200_flood_med", 8, "detect_mitigate + 200ms injected controller delay",
             merge(sdn("detect_mitigate", delay_ms=200), attack(pps=1000), no_spoof())),
    scenario("rq8_delay_200_flood_10k", 8, "detect_mitigate + 200ms delay + high-rate flood",
             merge(sdn("detect_mitigate", delay_ms=200), attack(pps=10000), no_spoof())),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for sc in SCENARIOS:
        id_ = sc["meta"]["id"]
        path = OUT_DIR / f"{id_}.yaml"
        with open(path, "w") as fh:
            yaml.safe_dump(sc, fh, sort_keys=False)
    print(f"[gen_scenarios] wrote {len(SCENARIOS)} scenarios to {OUT_DIR}")


if __name__ == "__main__":
    main()
