#!/usr/bin/env python3
"""Aggregate a full experiment directory (logs/<exp_id>/) into:

* ``metrics.csv``  - long-format tidy metrics (one row per scenario-trial-metric)
* ``summary.json`` - nested mean/stddev per scenario + derived detection stats
* ``plots/*.png``  - one plot per research question

Designed to be robust to missing files (failed runs) - it emits NaNs rather
than crashing and records the skipped scenarios in ``summary.json``.

Usage: python3 scripts/aggregate.py logs/<exp_id>
"""

import csv
import json
import math
import statistics
import sys
from pathlib import Path

import yaml


BENIGN_IPS = {"10.0.0.10", "10.0.0.11"}
ATTACKER_IP = "10.0.0.1"
SPOOFER_REAL_IP = "10.0.0.3"
SPOOF_SYNTHETIC_PREFIX = "10.0.66."


def _safe_mean(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return statistics.fmean(xs) if xs else float("nan")


def _safe_stdev(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return statistics.stdev(xs) if len(xs) >= 2 else 0.0


def _read_csv(path):
    if not path.exists():
        return []
    with path.open() as fh:
        return list(csv.DictReader(fh))


def _read_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _parse_attack_start(run_dir):
    """Return attack start offset in seconds from scenario start (0 if absent)."""
    path = run_dir / "attack_start.txt"
    if not path.exists():
        return None
    try:
        for line in path.read_text().splitlines():
            if line.startswith("attack_start_mono_s="):
                return None  # absolute monotonic; we prefer controller's t=0
    except Exception:
        pass
    return None


def _first_event_time(events, event_names):
    """Return t_mono_s of the first matching event, or None."""
    for row in events:
        if row.get("event") in event_names:
            try:
                return float(row["t_mono_s"])
            except Exception:
                return None
    return None


def _load_cfg(run_dir):
    p = run_dir / "config.effective.yaml"
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return {}


def _is_benign_mac(mac):
    return mac in {"00:00:00:00:00:10", "00:00:00:00:00:11"}


def compute_trial_metrics(run_dir):
    cfg = _load_cfg(run_dir)
    meta = cfg.get("meta") or {}
    sdn = cfg.get("sdn") or {}
    atk = cfg.get("attack") or {}
    spoof = cfg.get("spoof") or {}
    benign = cfg.get("benign") or {}
    probe = cfg.get("probe") or {}

    defense_mode = sdn.get("defense_mode", "off")
    threshold = float(sdn.get("threshold_pps", 0) or 0)
    ctrl_delay_ms = float(sdn.get("inject_controller_delay_ms", 0) or 0)
    attack_enabled = bool(atk.get("enabled", False))
    spoof_enabled = bool(spoof.get("enabled", False))
    many_ids = bool(spoof.get("many_identities", False))
    num_ids = int(spoof.get("num_identities", 0) or 0)
    duration = float(atk.get("duration", 30) or 30)
    warmup = float(atk.get("warmup_s", 3) or 3)
    atk_pps_nominal = float(atk.get("target_pps", 0) or 0) if attack_enabled else 0.0
    spoof_pps_nominal = float(spoof.get("pps", 0) or 0) if spoof_enabled else 0.0
    benign_pps_nominal = float(benign.get("pps", 0) or 0) if benign.get("enabled") else 0.0

    # ---- per-file reads ----
    rx_rows = _read_csv(run_dir / "victim_rx.csv")
    probe_rows = _read_csv(run_dir / "probe_rtt.csv")
    ctrl_stats = _read_csv(run_dir / "controller_stats.csv")
    ctrl_events = _read_csv(run_dir / "controller_events.csv")
    atk_summary = _read_json(run_dir / "attacker_summary.json")
    spoof_summary = _read_json(run_dir / "spoofer_summary.json")

    metrics = {
        "scenario_id": meta.get("id", run_dir.parent.name),
        "rq": meta.get("rq", 0),
        "trial": run_dir.name,
        "defense_mode": defense_mode,
        "threshold_pps": threshold,
        "controller_delay_ms": ctrl_delay_ms,
        "attack_enabled": attack_enabled,
        "spoof_enabled": spoof_enabled,
        "many_identities": many_ids,
        "num_identities": num_ids,
        "attack_pps_nominal": atk_pps_nominal,
        "spoof_pps_nominal": spoof_pps_nominal,
        "benign_pps_nominal": benign_pps_nominal,
        "duration_s": duration,
        "warmup_s": warmup,
    }

    # ---- victim rx breakdown ----
    rx_counts = {"benign": 0, "attacker": 0, "spoof_synthetic": 0, "other": 0}
    rx_bytes = {"benign": 0, "attacker": 0, "spoof_synthetic": 0, "other": 0}
    rx_total = 0
    rx_bytes_total = 0
    rx_benign_post_mitigate = 0
    mit_event_t = _first_event_time(ctrl_events, ("mitigate_mac", "mitigate_port"))

    for r in rx_rows:
        try:
            t = float(r["t_mono_s"])
            src = r.get("src_ip", "")
            b = int(r.get("bytes", 0) or 0)
        except Exception:
            continue
        rx_total += 1
        rx_bytes_total += b
        if src in BENIGN_IPS:
            key = "benign"
        elif src == ATTACKER_IP:
            key = "attacker"
        elif src.startswith(SPOOF_SYNTHETIC_PREFIX):
            key = "spoof_synthetic"
        else:
            key = "other"
        rx_counts[key] += 1
        rx_bytes[key] += b
        if key == "benign" and mit_event_t is not None and t >= mit_event_t:
            rx_benign_post_mitigate += 1

    metrics["victim_rx_total"] = rx_total
    metrics["victim_rx_benign"] = rx_counts["benign"]
    metrics["victim_rx_attacker"] = rx_counts["attacker"]
    metrics["victim_rx_spoof_synthetic"] = rx_counts["spoof_synthetic"]
    metrics["victim_rx_other"] = rx_counts["other"]
    metrics["victim_rx_bytes_total"] = rx_bytes_total

    # Legit PDR: measure both benign hosts vs their expected send count.
    benign_expected = benign_pps_nominal * duration * 2  # two benign hosts
    legit_pdr = (rx_counts["benign"] / benign_expected) if benign_expected > 0 else float("nan")
    metrics["legit_pdr"] = min(legit_pdr, 1.0) if not math.isnan(legit_pdr) else float("nan")
    metrics["legit_throughput_pps"] = rx_counts["benign"] / duration if duration > 0 else float("nan")

    # ---- attacker / spoofer totals ----
    atk_sent = (atk_summary or {}).get("sent", 0) if atk_summary else 0
    spoof_sent = (spoof_summary or {}).get("sent", 0) if spoof_summary else 0
    malicious_sent = atk_sent + spoof_sent
    metrics["attacker_sent"] = atk_sent
    metrics["spoofer_sent"] = spoof_sent
    metrics["malicious_sent"] = malicious_sent

    # Malicious delivered: attacker IP is unambiguous. For spoof many_identities,
    # 10.0.66.* is also unambiguous. For spoof single_identity (fake_src_ip=benign1),
    # we approximate spoof-delivered by the excess over expected benign1 traffic.
    malicious_delivered = rx_counts["attacker"] + rx_counts["spoof_synthetic"]
    if spoof_enabled and not many_ids:
        expected_one_benign = benign_pps_nominal * duration
        benign1_excess = max(0, rx_counts["benign"] - 2 * expected_one_benign)
        malicious_delivered += int(benign1_excess)
    metrics["malicious_delivered"] = malicious_delivered
    metrics["malicious_blocked"] = max(0, malicious_sent - malicious_delivered)
    metrics["attack_success_rate"] = (
        malicious_delivered / malicious_sent if malicious_sent > 0 else float("nan")
    )

    # ---- probe RTT / loss / jitter ----
    rtts = []
    probe_total = 0
    probe_lost = 0
    for r in probe_rows:
        probe_total += 1
        lost = r.get("lost", "0")
        try:
            lost_int = int(lost) if lost not in ("", None) else 0
        except Exception:
            lost_int = 0
        if lost_int == 1:
            probe_lost += 1
            continue
        rtt_raw = r.get("rtt_ms", "")
        if rtt_raw in ("", None):
            continue
        try:
            rtts.append(float(rtt_raw))
        except Exception:
            pass
    if rtts:
        rtts_sorted = sorted(rtts)
        p95_idx = max(0, int(0.95 * len(rtts_sorted)) - 1)
        metrics["probe_rtt_mean_ms"] = statistics.fmean(rtts)
        metrics["probe_rtt_p95_ms"] = rtts_sorted[p95_idx]
        metrics["probe_jitter_ms"] = statistics.stdev(rtts) if len(rtts) >= 2 else 0.0
    else:
        metrics["probe_rtt_mean_ms"] = float("nan")
        metrics["probe_rtt_p95_ms"] = float("nan")
        metrics["probe_jitter_ms"] = float("nan")
    metrics["probe_loss_rate"] = (probe_lost / probe_total) if probe_total > 0 else float("nan")
    metrics["probe_total"] = probe_total

    # ---- controller timing / load ----
    t_detect = _first_event_time(ctrl_events, ("detect", "detect_port"))
    t_mitigate = _first_event_time(ctrl_events, ("mitigate_mac", "mitigate_port"))
    # Attack starts at t=warmup (scenario relative). Controller events are relative
    # to controller start, which is earlier than topology start by a few seconds.
    # We approximate: controller started just before topology; attack start ~= warmup_s
    # from topology start; add a small skew allowance.
    t_attack = warmup
    metrics["t_detect_s"] = (t_detect - t_attack) if t_detect is not None else float("nan")
    metrics["t_mitigate_s"] = (t_mitigate - t_attack) if t_mitigate is not None else float("nan")
    metrics["rule_install_delay_s"] = (
        (t_mitigate - t_detect) if (t_mitigate is not None and t_detect is not None) else float("nan")
    )
    metrics["detection_occurred"] = bool(t_detect is not None)
    metrics["mitigation_occurred"] = bool(t_mitigate is not None)

    cpu_vals, mem_vals, flow_vals, pktin_vals = [], [], [], []
    for r in ctrl_stats:
        try:
            cpu_vals.append(float(r.get("cpu_percent", "nan")))
        except Exception:
            pass
        try:
            mem_vals.append(float(r.get("mem_rss_mb", "nan")))
        except Exception:
            pass
        try:
            flow_vals.append(int(r.get("flow_count", "0")))
        except Exception:
            pass
        try:
            pktin_vals.append(float(r.get("packet_in_rate", "0")))
        except Exception:
            pass
    metrics["ctrl_cpu_mean"] = _safe_mean(cpu_vals)
    metrics["ctrl_cpu_max"] = max(cpu_vals) if cpu_vals else float("nan")
    metrics["ctrl_mem_max_mb"] = max(mem_vals) if mem_vals else float("nan")
    metrics["ctrl_flow_count_max"] = max(flow_vals) if flow_vals else 0
    metrics["ctrl_pktin_rate_max"] = max(pktin_vals) if pktin_vals else 0.0

    # ---- collateral damage: any benign MAC mitigated? ----
    benign_mitigated = 0
    for r in ctrl_events:
        if r.get("event") == "mitigate_mac" and _is_benign_mac(r.get("eth_src", "")):
            benign_mitigated += 1
    metrics["benign_macs_blocked"] = benign_mitigated

    # ---- recovery time (post-mitigation): time after mitigate for benign rx to
    # reach >= 80% of warmup-period rate. Approximation using 1s windows. ----
    recovery = float("nan")
    if mit_event_t is not None and rx_rows:
        # Baseline: mean benign rx rate during first warmup_s seconds.
        pre = [
            1 for r in rx_rows
            if r.get("src_ip") in BENIGN_IPS and 0 <= float(r.get("t_mono_s", "0")) < warmup
        ]
        base_rate = len(pre) / warmup if warmup > 0 else 0
        if base_rate > 0:
            # 1s windows starting at mit_event_t
            window_size = 1.0
            t_end_prog = duration + warmup + 2
            bins = {}
            for r in rx_rows:
                if r.get("src_ip") not in BENIGN_IPS:
                    continue
                try:
                    t = float(r["t_mono_s"])
                except Exception:
                    continue
                if t < mit_event_t:
                    continue
                k = int((t - mit_event_t) // window_size)
                bins[k] = bins.get(k, 0) + 1
            for k in sorted(bins.keys()):
                if bins[k] >= 0.8 * base_rate * window_size:
                    recovery = k * window_size
                    break
    metrics["recovery_time_s"] = recovery

    return metrics


def collect_all(exp_dir):
    trials = []
    missing = []
    for sc_dir in sorted(p for p in exp_dir.iterdir() if p.is_dir() and p.name.startswith("rq")):
        for trial_dir in sorted(q for q in sc_dir.iterdir() if q.is_dir() and q.name.startswith("trial")):
            try:
                m = compute_trial_metrics(trial_dir)
                trials.append(m)
            except Exception as e:
                missing.append({"run_dir": str(trial_dir), "error": repr(e)})
    return trials, missing


def _num(x):
    if x is None:
        return None
    if isinstance(x, bool):
        return int(x)
    try:
        f = float(x)
        if math.isnan(f):
            return None
        return f
    except Exception:
        return None


def write_metrics_csv(trials, path):
    if not trials:
        path.write_text("")
        return
    # Long-format: scenario_id, rq, trial, metric, value
    keys = [
        "legit_pdr", "legit_throughput_pps",
        "probe_rtt_mean_ms", "probe_rtt_p95_ms", "probe_jitter_ms", "probe_loss_rate",
        "attacker_sent", "spoofer_sent", "malicious_sent",
        "malicious_delivered", "malicious_blocked", "attack_success_rate",
        "victim_rx_benign", "victim_rx_attacker", "victim_rx_spoof_synthetic",
        "t_detect_s", "t_mitigate_s", "rule_install_delay_s",
        "detection_occurred", "mitigation_occurred",
        "ctrl_cpu_mean", "ctrl_cpu_max", "ctrl_mem_max_mb",
        "ctrl_flow_count_max", "ctrl_pktin_rate_max",
        "benign_macs_blocked", "recovery_time_s",
    ]
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "scenario_id", "rq", "trial",
            "defense_mode", "attack_pps_nominal", "spoof_enabled", "many_identities",
            "num_identities", "threshold_pps", "controller_delay_ms",
            "metric", "value",
        ])
        for t in trials:
            for k in keys:
                v = t.get(k)
                v_num = _num(v)
                w.writerow([
                    t["scenario_id"], t["rq"], t["trial"],
                    t["defense_mode"], t["attack_pps_nominal"],
                    int(t["spoof_enabled"]), int(t["many_identities"]),
                    t["num_identities"], t["threshold_pps"], t["controller_delay_ms"],
                    k, "" if v_num is None else v_num,
                ])


def aggregate_by_scenario(trials):
    by_sc = {}
    for t in trials:
        by_sc.setdefault(t["scenario_id"], []).append(t)
    summary = {}
    for sc_id, rows in by_sc.items():
        agg = {
            "rq": rows[0].get("rq"),
            "defense_mode": rows[0].get("defense_mode"),
            "attack_pps_nominal": rows[0].get("attack_pps_nominal"),
            "spoof_enabled": rows[0].get("spoof_enabled"),
            "many_identities": rows[0].get("many_identities"),
            "num_identities": rows[0].get("num_identities"),
            "threshold_pps": rows[0].get("threshold_pps"),
            "controller_delay_ms": rows[0].get("controller_delay_ms"),
            "n_trials": len(rows),
            "metrics": {},
        }
        # numeric metric keys
        numeric_keys = [
            "legit_pdr", "legit_throughput_pps",
            "probe_rtt_mean_ms", "probe_rtt_p95_ms", "probe_jitter_ms", "probe_loss_rate",
            "attacker_sent", "spoofer_sent", "malicious_sent",
            "malicious_delivered", "malicious_blocked", "attack_success_rate",
            "victim_rx_benign", "victim_rx_attacker",
            "t_detect_s", "t_mitigate_s", "rule_install_delay_s",
            "ctrl_cpu_mean", "ctrl_cpu_max", "ctrl_mem_max_mb",
            "ctrl_flow_count_max", "ctrl_pktin_rate_max",
            "benign_macs_blocked", "recovery_time_s",
        ]
        for k in numeric_keys:
            vals = [_num(r.get(k)) for r in rows]
            vals = [v for v in vals if v is not None]
            agg["metrics"][k] = {
                "mean": _safe_mean(vals),
                "stdev": _safe_stdev(vals),
                "n": len(vals),
            }
        # boolean detection: fraction of trials that detected / mitigated
        for k in ("detection_occurred", "mitigation_occurred"):
            vs = [bool(r.get(k)) for r in rows]
            agg["metrics"][k] = {
                "mean": sum(1 for v in vs if v) / len(vs) if vs else 0.0,
                "n": len(vs),
            }
        summary[sc_id] = agg
    return summary


def compute_detection_confusion(summary):
    """Aggregate TP/FP/FN/TN over detect-capable scenarios (RQ2)."""
    tp = fp = tn = fn = 0
    detail = {}
    for sc_id, agg in summary.items():
        if agg["defense_mode"] not in ("detect_only", "detect_mitigate"):
            continue
        is_attack = bool(agg["attack_pps_nominal"]) or bool(agg["spoof_enabled"])
        det_rate = agg["metrics"]["detection_occurred"]["mean"]
        detected = det_rate > 0.5
        label = ("attack" if is_attack else "benign")
        outcome = ("detected" if detected else "missed")
        detail[sc_id] = {"label": label, "detection_rate": det_rate}
        if is_attack and detected:
            tp += 1
        elif is_attack and not detected:
            fn += 1
        elif not is_attack and detected:
            fp += 1
        else:
            tn += 1
    total_pos = tp + fn
    total_neg = fp + tn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr": tp / total_pos if total_pos else float("nan"),
        "fpr": fp / total_neg if total_neg else float("nan"),
        "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
        "recall": tp / total_pos if total_pos else float("nan"),
        "per_scenario": detail,
    }


def make_plots(summary, trials, out_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[aggregate] matplotlib not installed; skipping plots", file=sys.stderr)
        return

    out_dir.mkdir(parents=True, exist_ok=True)

    def by_rq(rq):
        return {k: v for k, v in summary.items() if v.get("rq") == rq}

    def _mean(agg, key):
        return agg["metrics"].get(key, {}).get("mean", float("nan"))

    def _stdev(agg, key):
        return agg["metrics"].get(key, {}).get("stdev", 0)

    # --- RQ1: legit PDR + malicious delivered across no-defense scenarios ---
    rq1 = by_rq(1)
    if rq1:
        ids = sorted(rq1.keys())
        pdr = [_mean(rq1[i], "legit_pdr") for i in ids]
        pdr_err = [_stdev(rq1[i], "legit_pdr") for i in ids]
        mal = [_mean(rq1[i], "malicious_delivered") for i in ids]
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        ax1.bar(ids, pdr, yerr=pdr_err)
        ax1.set_ylabel("legit PDR (benign delivered / sent)")
        ax1.set_title("RQ1: legitimate packet delivery ratio (no defense)")
        ax1.set_ylim(0, 1.05)
        ax1.tick_params(axis="x", rotation=45)
        ax2.bar(ids, mal)
        ax2.set_ylabel("malicious packets delivered")
        ax2.set_title("RQ1: attacker packets reaching victim")
        ax2.tick_params(axis="x", rotation=45)
        fig.tight_layout()
        fig.savefig(out_dir / "rq1_baseline.png", dpi=120)
        plt.close(fig)

    # --- RQ2: detection rate per scenario + threshold sweep ---
    rq2 = by_rq(2)
    if rq2:
        # A: detection rate per scenario
        ids = sorted(rq2.keys())
        det = [_mean(rq2[i], "detection_occurred") for i in ids]
        fig, ax = plt.subplots(figsize=(10, 4))
        colors = [
            "#d62728" if rq2[i]["attack_pps_nominal"] or rq2[i]["spoof_enabled"] else "#2ca02c"
            for i in ids
        ]
        ax.bar(ids, det, color=colors)
        ax.set_ylabel("detection rate (fraction of trials)")
        ax.set_title("RQ2: detection rate per scenario (red=attack, green=benign)")
        ax.set_ylim(0, 1.05)
        ax.tick_params(axis="x", rotation=45)
        fig.tight_layout()
        fig.savefig(out_dir / "rq2_detection_rate.png", dpi=120)
        plt.close(fig)

        # B: threshold sweep (detection delay vs threshold on flood_med)
        sweeps = [(sc_id, agg) for sc_id, agg in rq2.items() if "thresh" in sc_id]
        base = [(sc_id, agg) for sc_id, agg in rq2.items() if sc_id == "rq2_flood_med"]
        pts = sweeps + base
        if pts:
            pts_sorted = sorted(pts, key=lambda x: x[1]["threshold_pps"])
            thrs = [p[1]["threshold_pps"] for p in pts_sorted]
            delays = [_mean(p[1], "t_detect_s") for p in pts_sorted]
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.plot(thrs, delays, marker="o")
            ax.set_xlabel("detection threshold (pps)")
            ax.set_ylabel("detection delay (s)")
            ax.set_title("RQ2: threshold sweep on flood_med (1000 pps)")
            ax.grid(True, alpha=0.3)
            fig.tight_layout()
            fig.savefig(out_dir / "rq2_threshold_sweep.png", dpi=120)
            plt.close(fig)

    # --- RQ3: detection + mitigation delay ---
    rq3 = by_rq(3)
    if rq3:
        ids = sorted(rq3.keys())
        det = [_mean(rq3[i], "t_detect_s") for i in ids]
        mit = [_mean(rq3[i], "t_mitigate_s") for i in ids]
        install = [_mean(rq3[i], "rule_install_delay_s") for i in ids]
        x = range(len(ids))
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar([i - 0.25 for i in x], det, 0.25, label="detection")
        ax.bar([i for i in x], mit, 0.25, label="mitigation")
        ax.bar([i + 0.25 for i in x], install, 0.25, label="install delay")
        ax.set_xticks(list(x))
        ax.set_xticklabels(ids, rotation=45, ha="right")
        ax.set_ylabel("seconds since attack start")
        ax.set_title("RQ3: detection + mitigation timing (detect_mitigate)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / "rq3_timing.png", dpi=120)
        plt.close(fig)

    # --- RQ4: PDR comparison no_attack / attack_no_defense / attack_with_defense ---
    # Build groups from RQ1 (no defense) + RQ3 (mitigate) + rq5_benign_only_mitigate.
    comp = []
    for sc in ("rq1_benign_only", "rq1_flood_med", "rq3_flood_med"):
        if sc in summary:
            comp.append((sc, _mean(summary[sc], "legit_pdr"), _stdev(summary[sc], "legit_pdr")))
    if len(comp) == 3:
        labels = [c[0] for c in comp]
        vals = [c[1] for c in comp]
        errs = [c[2] for c in comp]
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(labels, vals, yerr=errs)
        ax.set_ylabel("legit PDR")
        ax.set_title("RQ4: legit PDR\n(no attack vs attack no-def vs attack with-def)")
        ax.set_ylim(0, 1.05)
        fig.tight_layout()
        fig.savefig(out_dir / "rq4_selectivity.png", dpi=120)
        plt.close(fig)

    # --- RQ5: overhead of SDN layers (benign only) ---
    r5_off = summary.get("rq1_benign_only")
    r5_det = summary.get("rq2_benign_only")
    r5_mit = summary.get("rq5_benign_only_mitigate")
    triples = [(n, v) for n, v in [
        ("off", r5_off), ("detect_only", r5_det), ("detect_mitigate", r5_mit)
    ] if v is not None]
    if len(triples) >= 2:
        labels = [t[0] for t in triples]
        lat = [_mean(t[1], "probe_rtt_mean_ms") for t in triples]
        jit = [_mean(t[1], "probe_jitter_ms") for t in triples]
        cpu = [_mean(t[1], "ctrl_cpu_mean") for t in triples]
        fig, axes = plt.subplots(1, 3, figsize=(12, 4))
        axes[0].bar(labels, lat); axes[0].set_title("mean RTT (ms)")
        axes[1].bar(labels, jit); axes[1].set_title("jitter (ms)")
        axes[2].bar(labels, cpu); axes[2].set_title("controller CPU %")
        fig.suptitle("RQ5: overhead of SDN layer (benign traffic only)")
        fig.tight_layout()
        fig.savefig(out_dir / "rq5_overhead.png", dpi=120)
        plt.close(fig)

    # --- RQ6: intensity sweep ---
    rq6 = by_rq(6)
    # Include rq3_flood_low/med/high + rq6_flood_* as the flood intensity sweep.
    intensity_pts = []
    for src in (by_rq(3), by_rq(6)):
        for sc_id, agg in src.items():
            if "flood" in sc_id and not agg.get("spoof_enabled"):
                intensity_pts.append((agg["attack_pps_nominal"], agg))
    intensity_pts = sorted(intensity_pts, key=lambda x: x[0])
    if intensity_pts:
        x = [p[0] for p in intensity_pts]
        pdr = [_mean(p[1], "legit_pdr") for p in intensity_pts]
        mal = [_mean(p[1], "malicious_delivered") for p in intensity_pts]
        det = [_mean(p[1], "t_detect_s") for p in intensity_pts]
        fig, axes = plt.subplots(1, 3, figsize=(14, 4))
        axes[0].plot(x, pdr, marker="o"); axes[0].set_title("legit PDR vs attack pps")
        axes[0].set_xscale("log")
        axes[1].plot(x, mal, marker="o"); axes[1].set_title("malicious delivered vs attack pps")
        axes[1].set_xscale("log")
        axes[2].plot(x, det, marker="o"); axes[2].set_title("detection delay vs attack pps")
        axes[2].set_xscale("log")
        for a in axes:
            a.set_xlabel("attacker pps")
            a.grid(True, alpha=0.3)
        fig.suptitle("RQ6: intensity sweep (detect_mitigate)")
        fig.tight_layout()
        fig.savefig(out_dir / "rq6_intensity.png", dpi=120)
        plt.close(fig)

    # --- RQ8: controller bottleneck vs injected delay ---
    rq8 = by_rq(8)
    base3 = summary.get("rq3_flood_med")
    delay_pts = []
    if base3:
        delay_pts.append((0.0, base3))
    for sc_id, agg in rq8.items():
        if agg["attack_pps_nominal"] == 1000:
            delay_pts.append((agg["controller_delay_ms"], agg))
    delay_pts = sorted(delay_pts, key=lambda x: x[0])
    if len(delay_pts) >= 2:
        x = [p[0] for p in delay_pts]
        det = [_mean(p[1], "t_detect_s") for p in delay_pts]
        pdr = [_mean(p[1], "legit_pdr") for p in delay_pts]
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        axes[0].plot(x, det, marker="o"); axes[0].set_title("detection delay vs controller delay")
        axes[1].plot(x, pdr, marker="o"); axes[1].set_title("legit PDR vs controller delay")
        for a in axes:
            a.set_xlabel("injected controller delay (ms)")
            a.grid(True, alpha=0.3)
        fig.suptitle("RQ8: SPOF / bottleneck characterization")
        fig.tight_layout()
        fig.savefig(out_dir / "rq8_controller_delay.png", dpi=120)
        plt.close(fig)


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    exp_dir = Path(sys.argv[1])
    if not exp_dir.is_dir():
        print(f"not a directory: {exp_dir}", file=sys.stderr)
        sys.exit(2)

    trials, missing = collect_all(exp_dir)
    print(f"[aggregate] loaded {len(trials)} trials, {len(missing)} errors")
    if missing:
        for m in missing:
            print(f"  ! {m['run_dir']}: {m['error']}", file=sys.stderr)

    summary = aggregate_by_scenario(trials)
    confusion = compute_detection_confusion(summary)

    (exp_dir / "metrics.csv").parent.mkdir(parents=True, exist_ok=True)
    write_metrics_csv(trials, exp_dir / "metrics.csv")
    (exp_dir / "summary.json").write_text(json.dumps(
        {
            "exp_dir": str(exp_dir),
            "n_trials": len(trials),
            "n_scenarios": len(summary),
            "missing": missing,
            "scenarios": summary,
            "detection_confusion": confusion,
        },
        indent=2,
        default=lambda o: None,
    ))
    make_plots(summary, trials, exp_dir / "plots")
    print(f"[aggregate] wrote {exp_dir}/metrics.csv, summary.json, plots/")


if __name__ == "__main__":
    main()
