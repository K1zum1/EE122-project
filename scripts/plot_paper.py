#!/usr/bin/env python3
"""Paper-quality figure suite for the SDN-DDoS evaluation.

Reads aggregated results (logs/<exp>/summary.json, metrics.csv) and per-run
artifacts (probe_rtt.csv, controller_stats.csv, controller_events.csv,
victim_rx.csv, attack_start.txt). Emits 20 PNGs into logs/<exp>/plots/paper/.

Run: python scripts/plot_paper.py --exp-dir logs/my_exp
     python scripts/plot_paper.py --exp-dir logs/my_exp --only attack_rate_vs_rtt
     python scripts/plot_paper.py --list
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ------------------------------ style ---------------------------------------

MODE_COLORS = {
    "off": "#d62728",
    "detect_only": "#ff7f0e",
    "detect_mitigate": "#2ca02c",
}
MODE_LABELS = {
    "off": "defense off",
    "detect_only": "detect-only",
    "detect_mitigate": "detect+mitigate",
}
MODE_ORDER = ["off", "detect_only", "detect_mitigate"]


def _save(fig, out_dir: Path, name: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.png"
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    print(f"  wrote {path}")


def _is_finite(x):
    return x is not None and isinstance(x, (int, float)) and not math.isnan(x)


# ------------------------------ loaders -------------------------------------


def load_summary(exp_dir: Path) -> dict:
    return json.loads((exp_dir / "summary.json").read_text())


def load_metrics_long(exp_dir: Path) -> list[dict]:
    p = exp_dir / "metrics.csv"
    if not p.exists():
        return []
    with p.open() as fh:
        return list(csv.DictReader(fh))


def load_run_csv(exp_dir: Path, scenario: str, trial: str, fname: str) -> list[dict]:
    p = exp_dir / scenario / trial / fname
    if not p.exists():
        return []
    with p.open() as fh:
        return list(csv.DictReader(fh))


def load_attack_start(exp_dir: Path, scenario: str, trial: str) -> float | None:
    p = exp_dir / scenario / trial / "attack_start.txt"
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        if line.startswith("attack_start_mono_s="):
            try:
                return float(line.split("=", 1)[1])
            except ValueError:
                return None
    return None


def trial_dirs(exp_dir: Path, scenario: str) -> list[str]:
    sc = exp_dir / scenario
    if not sc.is_dir():
        return []
    return sorted(d.name for d in sc.iterdir() if d.is_dir() and d.name.startswith("trial"))


# ------------------------------ summary helpers -----------------------------


def m_mean(agg: dict, key: str) -> float:
    v = agg.get("metrics", {}).get(key, {}).get("mean", float("nan"))
    return float(v) if v is not None else float("nan")


def m_stdev(agg: dict, key: str) -> float:
    v = agg.get("metrics", {}).get(key, {}).get("stdev", 0.0)
    return float(v) if v is not None else 0.0


def m_n(agg: dict, key: str) -> int:
    return int(agg.get("metrics", {}).get(key, {}).get("n", 0))


def scenarios_by_filter(scenarios: dict, **filters) -> list[tuple[str, dict]]:
    """Return (sc_id, agg) pairs matching all filter keys, sorted by sc_id."""
    out = []
    for sc_id, agg in scenarios.items():
        if all(agg.get(k) == v for k, v in filters.items()):
            out.append((sc_id, agg))
    return sorted(out, key=lambda x: x[0])


# ------------------------------ plots 1-4: attack rate sweeps ---------------


def _flood_sweep_points(scenarios: dict, mode: str) -> list[tuple[float, dict]]:
    """Return (pps, agg) sorted by pps for flood-only no-delay scenarios in given mode.

    Includes RQ1/2/3/6/6b scenarios where attack is enabled, spoof disabled,
    threshold is the default 500, and controller_delay_ms == 0.
    """
    pts = []
    seen_pps = set()
    for sc_id, agg in scenarios.items():
        if agg.get("defense_mode") != mode:
            continue
        if agg.get("spoof_enabled"):
            continue
        if not agg.get("attack_pps_nominal"):
            continue
        if (agg.get("controller_delay_ms") or 0) != 0:
            continue
        # Use only default-threshold runs to avoid mixing threshold-sweep points.
        thr = agg.get("threshold_pps")
        if thr not in (500.0, 500, None) and mode != "off":
            continue
        pps = float(agg["attack_pps_nominal"])
        if pps in seen_pps:
            continue
        seen_pps.add(pps)
        pts.append((pps, agg))
    return sorted(pts, key=lambda x: x[0])


def plot_attack_rate_vs_rtt(exp_dir, scenarios, _metrics, out_dir):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    plotted = False
    for mode in MODE_ORDER:
        pts = _flood_sweep_points(scenarios, mode)
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [m_mean(p[1], "probe_rtt_mean_ms") for p in pts]
        es = [m_stdev(p[1], "probe_rtt_mean_ms") for p in pts]
        ax.errorbar(xs, ys, yerr=es, marker="o", linewidth=1.5, alpha=0.85,
                    color=MODE_COLORS[mode], label=MODE_LABELS[mode], capsize=3)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("  [skip] attack_rate_vs_rtt: no flood scenarios found")
        return
    ax.set_xscale("log")
    ax.set_xlabel("attack rate (pps, log scale)")
    ax.set_ylabel("mean probe RTT (ms)")
    ax.set_title("Probe RTT vs attack intensity")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    _save(fig, out_dir, "01_attack_rate_vs_rtt")


def plot_attack_rate_vs_loss(exp_dir, scenarios, _metrics, out_dir):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    plotted = False
    for mode in MODE_ORDER:
        pts = _flood_sweep_points(scenarios, mode)
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [100.0 * m_mean(p[1], "probe_loss_rate") for p in pts]
        es = [100.0 * m_stdev(p[1], "probe_loss_rate") for p in pts]
        ax.errorbar(xs, ys, yerr=es, marker="o", linewidth=1.5, alpha=0.85,
                    color=MODE_COLORS[mode], label=MODE_LABELS[mode], capsize=3)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("  [skip] attack_rate_vs_loss")
        return
    ax.set_xscale("log")
    ax.set_xlabel("attack rate (pps, log scale)")
    ax.set_ylabel("probe packet loss (%)")
    ax.set_title("Probe loss vs attack intensity")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    _save(fig, out_dir, "02_attack_rate_vs_loss")


def plot_attack_rate_vs_malicious(exp_dir, scenarios, _metrics, out_dir):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    plotted = False
    for mode in ("off", "detect_only", "detect_mitigate"):
        pts = _flood_sweep_points(scenarios, mode)
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [m_mean(p[1], "malicious_delivered") for p in pts]
        ax.plot(xs, ys, marker="o", linewidth=1.5, alpha=0.85,
                color=MODE_COLORS[mode], label=MODE_LABELS[mode])
        plotted = True
    if not plotted:
        plt.close(fig)
        print("  [skip] attack_rate_vs_malicious")
        return
    ax.set_xscale("log")
    ax.set_yscale("symlog")
    ax.set_xlabel("attack rate (pps, log scale)")
    ax.set_ylabel("malicious packets reaching victim (symlog)")
    ax.set_title("Attacker traffic delivered vs intensity")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    _save(fig, out_dir, "03_attack_rate_vs_malicious")


def plot_attack_rate_vs_legit(exp_dir, scenarios, _metrics, out_dir):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    plotted = False
    for mode in MODE_ORDER:
        pts = _flood_sweep_points(scenarios, mode)
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [m_mean(p[1], "victim_rx_benign") for p in pts]
        es = [m_stdev(p[1], "victim_rx_benign") for p in pts]
        ax.errorbar(xs, ys, yerr=es, marker="o", linewidth=1.5, alpha=0.85,
                    color=MODE_COLORS[mode], label=MODE_LABELS[mode], capsize=3)
        plotted = True
    if not plotted:
        plt.close(fig)
        print("  [skip] attack_rate_vs_legit")
        return
    ax.set_xscale("log")
    ax.set_xlabel("attack rate (pps, log scale)")
    ax.set_ylabel("benign packets delivered to victim")
    ax.set_title("Legitimate traffic preservation vs intensity")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    _save(fig, out_dir, "04_attack_rate_vs_legit")


# ------------------------------ plot 5: grouped bar one scenario ------------


def plot_grouped_bar_one_scenario(exp_dir, scenarios, _metrics, out_dir):
    """Compare modes on the high-flood scenario across 4 metrics."""
    targets = {"off": "rq1_flood_high", "detect_only": "rq2_flood_high",
               "detect_mitigate": "rq3_flood_high"}
    if not all(t in scenarios for t in targets.values()):
        print("  [skip] grouped_bar_one_scenario: missing flood_high variant")
        return
    metrics = [
        ("probe_rtt_mean_ms", "RTT (ms)"),
        ("probe_loss_rate", "loss (frac)"),
        ("malicious_delivered", "malicious rx"),
        ("victim_rx_benign", "benign rx"),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))
    for ax, (key, label) in zip(axes, metrics):
        bars, errs, colors, names = [], [], [], []
        for mode in MODE_ORDER:
            agg = scenarios[targets[mode]]
            bars.append(m_mean(agg, key))
            errs.append(m_stdev(agg, key))
            colors.append(MODE_COLORS[mode])
            names.append(MODE_LABELS[mode])
        ax.bar(names, bars, yerr=errs, color=colors, capsize=3)
        ax.set_title(label)
        ax.tick_params(axis="x", rotation=20)
    fig.suptitle("Mode comparison at 5000 pps flood (rq*_flood_high)", y=1.02)
    _save(fig, out_dir, "05_grouped_bar_flood_high")


# ------------------------------ plot 6/7: detect / mitigate time ------------


def plot_detection_time_by_scenario(exp_dir, scenarios, _metrics, out_dir):
    """Bar of t_detect_s for all detect-capable attack scenarios.

    Bars are drawn for every attack scenario in detect_only or detect_mitigate
    mode; scenarios where no trial fired detection get a thin gray bar at 0
    with a 'not detected' label.
    """
    rows = [(sc, agg) for sc, agg in scenarios.items()
            if agg.get("defense_mode") in ("detect_only", "detect_mitigate")
            and (agg.get("attack_pps_nominal") or agg.get("spoof_enabled"))
            and (agg.get("controller_delay_ms") or 0) == 0]
    if not rows:
        print("  [skip] detection_time_by_scenario: no attack scenarios under detection")
        return
    rows.sort(key=lambda x: (x[1]["defense_mode"], x[0]))
    ids = [r[0] for r in rows]
    means, stds, colors = [], [], []
    for _sc, agg in rows:
        if m_n(agg, "t_detect_s") > 0:
            means.append(m_mean(agg, "t_detect_s"))
            stds.append(m_stdev(agg, "t_detect_s"))
            colors.append("#ff7f0e" if agg["defense_mode"] == "detect_only" else "#2ca02c")
        else:
            means.append(0.0); stds.append(0.0); colors.append("#cccccc")
    fig, ax = plt.subplots(figsize=(13, 5))
    bars = ax.bar(range(len(ids)), means, yerr=stds, color=colors, capsize=3)
    for i, (b, (_sc, agg)) in enumerate(zip(bars, rows)):
        if m_n(agg, "t_detect_s") == 0:
            ax.text(i, 0.05, "not detected", ha="center", va="bottom",
                    rotation=90, fontsize=8, color="gray")
    ax.set_xticks(range(len(ids)))
    ax.set_xticklabels(ids, rotation=40, ha="right")
    ax.set_ylabel("time to detect (s, since attack start)")
    ax.set_title("Detection time per attack scenario (orange=detect_only, green=detect_mitigate)")
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, out_dir, "06_detection_time_by_scenario")


def plot_mitigation_time_by_scenario(exp_dir, scenarios, _metrics, out_dir):
    rows = [(sc, agg) for sc, agg in scenarios.items()
            if agg.get("defense_mode") == "detect_mitigate"
            and (agg.get("attack_pps_nominal") or agg.get("spoof_enabled"))
            and (agg.get("controller_delay_ms") or 0) == 0]
    if not rows:
        print("  [skip] mitigation_time_by_scenario: no detect_mitigate attack scenarios")
        return
    rows.sort(key=lambda x: x[0])
    ids = [r[0] for r in rows]
    has_data = [m_n(agg, "t_mitigate_s") > 0 for _sc, agg in rows]
    means = [m_mean(r[1], "t_mitigate_s") if has_data[i] else 0.0 for i, r in enumerate(rows)]
    install = [m_mean(r[1], "rule_install_delay_s") if has_data[i] else 0.0
               for i, r in enumerate(rows)]
    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(ids))
    ax.bar(x - 0.2, means, 0.4, label="time to mitigate", color="#9467bd")
    ax.bar(x + 0.2, install, 0.4, label="rule install delay (mit−det)", color="#8c564b")
    for i, ok in enumerate(has_data):
        if not ok:
            ax.text(i, 0.05, "not mitigated", ha="center", va="bottom",
                    rotation=90, fontsize=8, color="gray")
    ax.set_xticks(x)
    ax.set_xticklabels(ids, rotation=35, ha="right")
    ax.set_ylabel("seconds since attack start")
    ax.set_title("Mitigation timing per attack scenario (detect_mitigate)")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, out_dir, "07_mitigation_time_by_scenario")


# ------------------------------ plot 8/9/10: controller delay sweeps --------


def _delay_sweep(scenarios: dict, anchor_keys: list[str]) -> list[tuple[float, dict, str]]:
    """For each anchor scenario, collect 0ms baseline + all rq8_* delay variants
    that share its attack profile (target_pps, spoof flags). Returns
    (delay_ms, agg, attack_label) tuples grouped by attack_label."""
    out = []
    # Build a map: target_pps -> [rq8 variants]
    delay_variants = [(sc, agg) for sc, agg in scenarios.items()
                      if sc.startswith("rq8_") and agg.get("defense_mode") == "detect_mitigate"]
    for anchor_id in anchor_keys:
        if anchor_id not in scenarios:
            continue
        anchor = scenarios[anchor_id]
        target_pps = anchor.get("attack_pps_nominal")
        spoof = anchor.get("spoof_enabled")
        label = anchor_id.replace("rq3_", "")
        out.append((0.0, anchor, label))
        for sc, agg in delay_variants:
            if (agg.get("attack_pps_nominal") == target_pps
                    and bool(agg.get("spoof_enabled")) == bool(spoof)):
                out.append((float(agg.get("controller_delay_ms", 0)), agg, label))
    return out


def plot_controller_delay_vs_detection(exp_dir, scenarios, _metrics, out_dir):
    pts = _delay_sweep(scenarios, ["rq3_flood_med", "rq3_flood_high"])
    if not pts:
        print("  [skip] controller_delay_vs_detection")
        return
    by_label: dict[str, list[tuple[float, float]]] = {}
    for d, agg, label in pts:
        if m_n(agg, "t_detect_s") > 0:
            by_label.setdefault(label, []).append((d, m_mean(agg, "t_detect_s")))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for label, series in by_label.items():
        series.sort()
        xs = [p[0] for p in series]
        ys = [p[1] for p in series]
        ax.plot(xs, ys, marker="o", linewidth=1.5, alpha=0.85, label=label)
    ax.set_xlabel("injected controller delay (ms)")
    ax.set_ylabel("time to detect (s)")
    ax.set_title("Detection latency vs controller delay")
    ax.grid(True, alpha=0.3)
    ax.legend()
    _save(fig, out_dir, "08_controller_delay_vs_detection")


def plot_controller_delay_vs_mitigation_success(exp_dir, scenarios, _metrics, out_dir):
    pts = _delay_sweep(scenarios, ["rq3_flood_med", "rq3_flood_high"])
    if not pts:
        print("  [skip] controller_delay_vs_mitigation_success")
        return
    by_label: dict[str, list[tuple[float, float]]] = {}
    for d, agg, label in pts:
        sent = m_mean(agg, "malicious_sent")
        blocked = m_mean(agg, "malicious_blocked")
        if not _is_finite(sent) or sent <= 0:
            continue
        by_label.setdefault(label, []).append((d, 100.0 * blocked / sent))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for label, series in by_label.items():
        series.sort()
        xs = [p[0] for p in series]
        ys = [p[1] for p in series]
        ax.plot(xs, ys, marker="o", linewidth=1.5, alpha=0.85, label=label)
    ax.set_xlabel("injected controller delay (ms)")
    ax.set_ylabel("malicious packets blocked (%)")
    ax.set_title("Mitigation effectiveness vs controller delay")
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3)
    ax.legend()
    _save(fig, out_dir, "09_controller_delay_vs_mitigation_success")


def plot_controller_delay_vs_benign_rtt(exp_dir, scenarios, _metrics, out_dir):
    """Multi-series: no-attack baseline, under flood_med, under flood_10k."""
    pts = _delay_sweep(scenarios, ["rq3_flood_med", "rq3_flood_high"])
    if not pts:
        print("  [skip] controller_delay_vs_benign_rtt")
        return
    by_label: dict[str, list[tuple[float, float]]] = {}
    for d, agg, label in pts:
        rtt = m_mean(agg, "probe_rtt_mean_ms")
        if not _is_finite(rtt):
            continue
        by_label.setdefault(label, []).append((d, rtt))
    # Add no-attack benign baseline if available (rq5 has no delay variants).
    if "rq5_benign_only_mitigate" in scenarios:
        agg = scenarios["rq5_benign_only_mitigate"]
        rtt = m_mean(agg, "probe_rtt_mean_ms")
        if _is_finite(rtt):
            by_label.setdefault("no attack", []).append((0.0, rtt))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for label, series in by_label.items():
        series.sort()
        xs = [p[0] for p in series]
        ys = [p[1] for p in series]
        ax.plot(xs, ys, marker="o", linewidth=1.5, alpha=0.85, label=label)
    ax.set_xlabel("injected controller delay (ms)")
    ax.set_ylabel("mean probe RTT (ms)")
    ax.set_title("Probe RTT vs controller delay")
    ax.grid(True, alpha=0.3)
    ax.legend()
    _save(fig, out_dir, "10_controller_delay_vs_benign_rtt")


# ------------------------------ plot 11: benign overhead --------------------


def plot_benign_overhead(exp_dir, scenarios, _metrics, out_dir):
    """Benign-only runs across modes: CPU, memory, flow count."""
    targets = {
        "off": "rq1_benign_only",
        "detect_only": "rq2_benign_only",
        "detect_mitigate": "rq5_benign_only_mitigate",
    }
    if not all(t in scenarios for t in targets.values()):
        print("  [skip] benign_overhead: missing benign-only variant")
        return
    panels = [
        ("ctrl_cpu_mean", "controller CPU (% mean)"),
        ("ctrl_mem_max_mb", "controller memory (MB max)"),
        ("ctrl_flow_count_max", "active flow rules (max)"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, (key, label) in zip(axes, panels):
        bars, errs, colors, names = [], [], [], []
        for mode in MODE_ORDER:
            agg = scenarios[targets[mode]]
            bars.append(m_mean(agg, key))
            errs.append(m_stdev(agg, key))
            colors.append(MODE_COLORS[mode])
            names.append(MODE_LABELS[mode])
        ax.bar(names, bars, yerr=errs, color=colors, capsize=3)
        ax.set_title(label)
        ax.tick_params(axis="x", rotation=20)
    fig.suptitle("Steady-state controller overhead (benign-only workload)", y=1.02)
    _save(fig, out_dir, "11_benign_overhead")


# ------------------------------ plot 12/13: detection accuracy / confusion --


def plot_detection_accuracy_summary(exp_dir, scenarios, _metrics, out_dir):
    summary_path = exp_dir / "summary.json"
    summary = json.loads(summary_path.read_text())
    conf = summary.get("detection_confusion") or {}
    if not conf:
        print("  [skip] detection_accuracy_summary: no detection_confusion in summary")
        return
    keys = ["tpr", "fpr", "precision", "recall"]
    labels = ["TPR", "FPR", "precision", "recall"]
    vals = []
    for k in keys:
        v = conf.get(k)
        if v is None or (isinstance(v, float) and math.isnan(v)):
            vals.append(0.0)
        else:
            vals.append(float(v))
    fig, ax = plt.subplots(figsize=(6.5, 4))
    colors = ["#2ca02c", "#d62728", "#1f77b4", "#9467bd"]
    bars = ax.bar(labels, vals, color=colors)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02,
                f"{v:.2f}", ha="center", fontsize=9)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("value")
    ax.set_title("Detection accuracy summary "
                 f"(TP={conf.get('tp')}, FP={conf.get('fp')}, "
                 f"FN={conf.get('fn')}, TN={conf.get('tn')})")
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, out_dir, "12_detection_accuracy_summary")


def plot_confusion_matrix_heatmap(exp_dir, scenarios, _metrics, out_dir):
    summary = json.loads((exp_dir / "summary.json").read_text())
    conf = summary.get("detection_confusion") or {}
    if not conf:
        print("  [skip] confusion_matrix_heatmap")
        return
    cm = np.array([[conf.get("tn", 0), conf.get("fp", 0)],
                   [conf.get("fn", 0), conf.get("tp", 0)]])
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["pred benign", "pred attack"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["actual benign", "actual attack"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black",
                    fontsize=14, fontweight="bold")
    ax.set_title("Detection confusion matrix\n(scenario-level, detect-capable runs)")
    fig.colorbar(im, ax=ax, fraction=0.046)
    _save(fig, out_dir, "13_confusion_matrix")


# ------------------------------ plot 14: attack coverage heatmap ------------


def plot_attack_coverage_heatmap(exp_dir, scenarios, _metrics, out_dir):
    """For each attack-type scenario in detect_mitigate, did we (a) detect,
    (b) mitigate, (c) preserve benign delivery, (d) avoid severe RTT damage?"""
    attack_scs = [
        ("rq3_flood_low", "flood low (100 pps)"),
        ("rq3_flood_med", "flood med (1000 pps)"),
        ("rq3_flood_high", "flood high (5000 pps)"),
        ("rq3_spoof_single", "spoof single ID"),
        ("rq3_spoof_many", "spoof many IDs"),
        ("rq3_mixed", "mixed flood+spoof"),
    ]
    rows, row_labels = [], []
    for sc_id, label in attack_scs:
        if sc_id not in scenarios:
            continue
        agg = scenarios[sc_id]
        det = m_mean(agg, "detection_occurred")
        mit = m_mean(agg, "mitigation_occurred")
        legit = m_mean(agg, "legit_pdr")
        loss = m_mean(agg, "probe_loss_rate")
        cells = [
            1 if (_is_finite(det) and det >= 0.5) else 0,
            1 if (_is_finite(mit) and mit >= 0.5) else 0,
            1 if (_is_finite(legit) and legit >= 0.95) else 0,
            1 if (_is_finite(loss) and loss <= 0.05) else 0,
        ]
        rows.append(cells)
        row_labels.append(label)
    if not rows:
        print("  [skip] attack_coverage_heatmap: no rq3_* attack scenarios found")
        return
    cols = ["detected", "mitigated", "benign preserved\n(PDR ≥ 0.95)",
            "severe RTT damage\navoided (loss ≤ 5%)"]
    arr = np.array(rows)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    im = ax.imshow(arr, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(cols))); ax.set_xticklabels(cols, fontsize=9)
    ax.set_yticks(range(len(row_labels))); ax.set_yticklabels(row_labels)
    for i in range(arr.shape[0]):
        for j in range(arr.shape[1]):
            ax.text(j, i, "✓" if arr[i, j] else "✗", ha="center", va="center",
                    color="black", fontsize=14, fontweight="bold")
    ax.set_title("Attack coverage (detect_mitigate mode)")
    _save(fig, out_dir, "14_attack_coverage_heatmap")


# ------------------------------ plot 15: stacked traffic composition --------


def plot_traffic_composition_stacked(exp_dir, scenarios, _metrics, out_dir):
    targets = {
        "off": "rq1_flood_high",
        "detect_only": "rq2_flood_high",
        "detect_mitigate": "rq3_flood_high",
    }
    if not all(t in scenarios for t in targets.values()):
        print("  [skip] traffic_composition_stacked")
        return
    fig, ax = plt.subplots(figsize=(8, 5))
    bottom = np.zeros(len(MODE_ORDER))
    benign = np.array([m_mean(scenarios[targets[m]], "victim_rx_benign") for m in MODE_ORDER])
    attacker = np.array([m_mean(scenarios[targets[m]], "victim_rx_attacker") for m in MODE_ORDER])
    spoof = np.array([m_mean(scenarios[targets[m]], "victim_rx_spoof_synthetic") for m in MODE_ORDER])
    sent = np.array([m_mean(scenarios[targets[m]], "malicious_sent") for m in MODE_ORDER])
    delivered = attacker + spoof
    blocked = np.maximum(sent - delivered, 0)
    labels = [MODE_LABELS[m] for m in MODE_ORDER]
    ax.bar(labels, benign, label="benign delivered", color="#2ca02c"); bottom = benign
    ax.bar(labels, attacker, bottom=bottom, label="attacker delivered", color="#d62728"); bottom = bottom + attacker
    ax.bar(labels, spoof, bottom=bottom, label="spoof delivered", color="#ff7f0e"); bottom = bottom + spoof
    ax.bar(labels, blocked, bottom=bottom, label="malicious blocked", color="#7f7f7f", alpha=0.6)
    ax.set_yscale("symlog")
    ax.set_ylabel("packets (symlog)")
    ax.set_title("Traffic composition at victim — flood_high (5000 pps)")
    ax.legend(loc="upper right")
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, out_dir, "15_traffic_composition_stacked")


# ------------------------------ plot 16: timeline for one run ---------------


def plot_timeline_one_run(exp_dir, scenarios, _metrics, out_dir):
    """RTT and victim ingress rate vs time for rq3_flood_high/trial0,
    with vertical markers for attack start, detect, mitigate."""
    sc = "rq3_flood_high"
    trial = "trial0"
    if not (exp_dir / sc / trial).is_dir():
        print(f"  [skip] timeline_one_run: missing {sc}/{trial}")
        return
    probe = load_run_csv(exp_dir, sc, trial, "probe_rtt.csv")
    rx = load_run_csv(exp_dir, sc, trial, "victim_rx.csv")
    events = load_run_csv(exp_dir, sc, trial, "controller_events.csv")
    atk_start = load_attack_start(exp_dir, sc, trial)
    if not probe or not rx:
        print("  [skip] timeline_one_run: empty probe or victim_rx")
        return
    warmup = float(scenarios.get(sc, {}).get("metrics", {}).get("warmup_s", {})
                   .get("mean", 3.0)) if sc in scenarios else 3.0
    # Hardcode warmup=3 (config default) since aggregator doesn't expose it.
    warmup = 3.0

    # Probe RTT: subtract attack_start_mono_s to get attack-relative time (s).
    probe_t, probe_rtt = [], []
    for r in probe:
        try:
            t_recv = float(r["t_recv_mono_s"])
            rtt = float(r["rtt_ms"])
        except (ValueError, KeyError):
            continue
        if int(r.get("lost", "0") or 0):
            continue
        if atk_start is None:
            probe_t.append(t_recv); probe_rtt.append(rtt)
        else:
            probe_t.append(t_recv - atk_start); probe_rtt.append(rtt)

    # Victim ingress: 0.5s bins, attack-relative time = t_mono_s - warmup.
    bin_size = 0.5
    rx_times = []
    for r in rx:
        try:
            rx_times.append(float(r["t_mono_s"]) - warmup)
        except (ValueError, KeyError):
            continue
    if rx_times:
        t_min = min(rx_times); t_max = max(rx_times)
        edges = np.arange(t_min, t_max + bin_size, bin_size)
        counts, _ = np.histogram(rx_times, bins=edges)
        rates = counts / bin_size
        bin_centers = (edges[:-1] + edges[1:]) / 2
    else:
        bin_centers, rates = np.array([]), np.array([])

    # Event markers (controller-relative t_mono_s, adjust to attack-relative).
    t_detect = t_mitigate = None
    for r in events:
        if r.get("event") in ("detect", "detect_port") and t_detect is None:
            try: t_detect = float(r["t_mono_s"]) - warmup
            except ValueError: pass
        elif r.get("event") in ("mitigate_mac", "mitigate_port") and t_mitigate is None:
            try: t_mitigate = float(r["t_mono_s"]) - warmup
            except ValueError: pass

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
    ax1.plot(probe_t, probe_rtt, marker=".", linestyle="none", markersize=3,
             color="#1f77b4", alpha=0.7, label="probe RTT")
    ax1.set_ylabel("probe RTT (ms)")
    ax1.set_title(f"Timeline — {sc}/{trial}")
    ax1.grid(True, alpha=0.3)
    ax2.plot(bin_centers, rates, color="#d62728", linewidth=1.2, label="victim ingress")
    ax2.set_ylabel("packets/sec at victim")
    ax2.set_xlabel("seconds since attack start")
    ax2.grid(True, alpha=0.3)
    for ax in (ax1, ax2):
        ax.axvline(0, color="black", linestyle="--", linewidth=1, label="attack start" if ax is ax1 else None)
        if t_detect is not None:
            ax.axvline(t_detect, color="#ff7f0e", linestyle="--", linewidth=1,
                       label="detect" if ax is ax1 else None)
        if t_mitigate is not None:
            ax.axvline(t_mitigate, color="#2ca02c", linestyle="--", linewidth=1,
                       label="mitigate" if ax is ax1 else None)
    ax1.legend(loc="upper right", fontsize=9)
    _save(fig, out_dir, "16_timeline_one_run")


# ------------------------------ plot 17: CDF of RTT -------------------------


def plot_cdf_rtt(exp_dir, scenarios, _metrics, out_dir):
    """Pool RTT samples across trials of flood_med per mode."""
    targets = {"off": "rq1_flood_med", "detect_only": "rq2_flood_med",
               "detect_mitigate": "rq3_flood_med"}
    fig, ax = plt.subplots(figsize=(7, 4.5))
    plotted = False
    for mode, sc in targets.items():
        if not (exp_dir / sc).is_dir():
            continue
        rtts = []
        for trial in trial_dirs(exp_dir, sc):
            for r in load_run_csv(exp_dir, sc, trial, "probe_rtt.csv"):
                if int(r.get("lost", "0") or 0):
                    continue
                try:
                    rtts.append(float(r["rtt_ms"]))
                except (ValueError, KeyError):
                    continue
        if not rtts:
            continue
        rtts.sort()
        ys = np.arange(1, len(rtts) + 1) / len(rtts)
        ax.plot(rtts, ys, color=MODE_COLORS[mode], linewidth=1.7, alpha=0.85,
                label=f"{MODE_LABELS[mode]} (n={len(rtts)})")
        plotted = True
    if not plotted:
        plt.close(fig)
        print("  [skip] cdf_rtt")
        return
    ax.set_xscale("log")
    ax.set_xlabel("probe RTT (ms, log scale)")
    ax.set_ylabel("cumulative probability")
    ax.set_title("RTT CDF under flood_med (1000 pps)")
    ax.set_ylim(0, 1.02)
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    _save(fig, out_dir, "17_cdf_rtt")


# ------------------------------ plot 18: box plot of RTT --------------------


def plot_box_rtt(exp_dir, scenarios, _metrics, out_dir):
    """Box plot of RTT, x=scenario_severity, hue=mode (positional offset)."""
    severities = ["low", "med", "high"]
    fig, ax = plt.subplots(figsize=(10, 5))
    positions, datasets, colors, x_labels = [], [], [], []
    base_x = np.arange(len(severities))
    width = 0.25
    for mode_idx, mode in enumerate(MODE_ORDER):
        prefix = {"off": "rq1", "detect_only": "rq2", "detect_mitigate": "rq3"}[mode]
        for sev_idx, sev in enumerate(severities):
            sc = f"{prefix}_flood_{sev}"
            if not (exp_dir / sc).is_dir():
                continue
            rtts = []
            for trial in trial_dirs(exp_dir, sc):
                for r in load_run_csv(exp_dir, sc, trial, "probe_rtt.csv"):
                    if int(r.get("lost", "0") or 0):
                        continue
                    try:
                        rtts.append(float(r["rtt_ms"]))
                    except (ValueError, KeyError):
                        pass
            if not rtts:
                continue
            datasets.append(rtts)
            positions.append(base_x[sev_idx] + (mode_idx - 1) * width)
            colors.append(MODE_COLORS[mode])
    if not datasets:
        plt.close(fig)
        print("  [skip] box_rtt")
        return
    bp = ax.boxplot(datasets, positions=positions, widths=width * 0.9,
                    patch_artist=True, showfliers=False)
    for box, c in zip(bp["boxes"], colors):
        box.set_facecolor(c); box.set_alpha(0.6)
    ax.set_xticks(base_x); ax.set_xticklabels([f"flood_{s}" for s in severities])
    ax.set_yscale("log")
    ax.set_ylabel("probe RTT (ms, log scale)")
    ax.set_title("RTT distribution by scenario × mode")
    handles = [plt.Rectangle((0, 0), 1, 1, color=MODE_COLORS[m], alpha=0.6) for m in MODE_ORDER]
    ax.legend(handles, [MODE_LABELS[m] for m in MODE_ORDER])
    ax.grid(True, alpha=0.3, axis="y", which="both")
    _save(fig, out_dir, "18_box_rtt")


# ------------------------------ plot 19: packet loss distribution -----------


def plot_packet_loss_distribution(exp_dir, scenarios, metrics_long, out_dir):
    """Box per scenario × mode, using per-trial probe_loss_rate from metrics.csv."""
    severities = ["low", "med", "high"]
    fig, ax = plt.subplots(figsize=(10, 5))
    positions, datasets, colors = [], [], []
    base_x = np.arange(len(severities))
    width = 0.25
    # Index metrics by (scenario, metric) -> [values]
    by_sc: dict[tuple[str, str], list[float]] = {}
    for r in metrics_long:
        if r["metric"] != "probe_loss_rate":
            continue
        try:
            v = float(r["value"]) if r["value"] != "" else None
        except ValueError:
            v = None
        if v is None:
            continue
        by_sc.setdefault((r["scenario_id"], r["metric"]), []).append(100.0 * v)
    for mode_idx, mode in enumerate(MODE_ORDER):
        prefix = {"off": "rq1", "detect_only": "rq2", "detect_mitigate": "rq3"}[mode]
        for sev_idx, sev in enumerate(severities):
            sc = f"{prefix}_flood_{sev}"
            vs = by_sc.get((sc, "probe_loss_rate"), [])
            if not vs:
                continue
            datasets.append(vs)
            positions.append(base_x[sev_idx] + (mode_idx - 1) * width)
            colors.append(MODE_COLORS[mode])
    if not datasets:
        plt.close(fig)
        print("  [skip] packet_loss_distribution")
        return
    bp = ax.boxplot(datasets, positions=positions, widths=width * 0.9,
                    patch_artist=True, showfliers=True)
    for box, c in zip(bp["boxes"], colors):
        box.set_facecolor(c); box.set_alpha(0.6)
    ax.set_xticks(base_x); ax.set_xticklabels([f"flood_{s}" for s in severities])
    ax.set_ylabel("probe loss (%) — per-trial")
    ax.set_title("Probe loss distribution across trials")
    handles = [plt.Rectangle((0, 0), 1, 1, color=MODE_COLORS[m], alpha=0.6) for m in MODE_ORDER]
    ax.legend(handles, [MODE_LABELS[m] for m in MODE_ORDER])
    ax.grid(True, alpha=0.3, axis="y")
    _save(fig, out_dir, "19_packet_loss_distribution")


# ------------------------------ plot 20: flow rule count over time ----------


def plot_flow_rule_count_over_time(exp_dir, scenarios, _metrics, out_dir):
    targets = [("rq3_flood_high", "flood high"),
               ("rq3_spoof_many", "spoof many IDs"),
               ("rq3_mixed", "mixed flood+spoof")]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    plotted = False
    warmup = 3.0
    for sc, label in targets:
        if not (exp_dir / sc / "trial0").is_dir():
            continue
        rows = load_run_csv(exp_dir, sc, "trial0", "controller_stats.csv")
        if not rows:
            continue
        ts, fc = [], []
        for r in rows:
            try:
                ts.append(float(r["t_mono_s"]) - warmup)
                fc.append(int(r["flow_count"]))
            except (ValueError, KeyError):
                continue
        if not ts:
            continue
        ax.plot(ts, fc, linewidth=1.5, alpha=0.85, label=label)
        plotted = True
    if not plotted:
        print("  [skip] flow_rule_count_over_time")
        plt.close(fig)
        return
    ax.axvline(0, color="black", linestyle="--", linewidth=1, label="attack start")
    ax.set_xlabel("seconds since attack start")
    ax.set_ylabel("active flow rules")
    ax.set_title("Flow rule count over time (detect_mitigate, trial0)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    _save(fig, out_dir, "20_flow_rule_count_over_time")


# ------------------------------ dispatch ------------------------------------


PLOTS = {
    "attack_rate_vs_rtt": plot_attack_rate_vs_rtt,
    "attack_rate_vs_loss": plot_attack_rate_vs_loss,
    "attack_rate_vs_malicious": plot_attack_rate_vs_malicious,
    "attack_rate_vs_legit": plot_attack_rate_vs_legit,
    "grouped_bar_one_scenario": plot_grouped_bar_one_scenario,
    "detection_time_by_scenario": plot_detection_time_by_scenario,
    "mitigation_time_by_scenario": plot_mitigation_time_by_scenario,
    "controller_delay_vs_detection": plot_controller_delay_vs_detection,
    "controller_delay_vs_mitigation_success": plot_controller_delay_vs_mitigation_success,
    "controller_delay_vs_benign_rtt": plot_controller_delay_vs_benign_rtt,
    "benign_overhead": plot_benign_overhead,
    "detection_accuracy_summary": plot_detection_accuracy_summary,
    "confusion_matrix_heatmap": plot_confusion_matrix_heatmap,
    "attack_coverage_heatmap": plot_attack_coverage_heatmap,
    "traffic_composition_stacked": plot_traffic_composition_stacked,
    "timeline_one_run": plot_timeline_one_run,
    "cdf_rtt": plot_cdf_rtt,
    "box_rtt": plot_box_rtt,
    "packet_loss_distribution": plot_packet_loss_distribution,
    "flow_rule_count_over_time": plot_flow_rule_count_over_time,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exp-dir", default="logs/my_exp", help="experiment directory")
    ap.add_argument("--only", action="append", default=None,
                    help="produce only the named plot(s); may be repeated")
    ap.add_argument("--list", action="store_true", help="list plot names and exit")
    args = ap.parse_args()

    if args.list:
        for name in PLOTS:
            print(name)
        return 0

    exp_dir = Path(args.exp_dir).resolve()
    if not exp_dir.is_dir():
        print(f"error: {exp_dir} not a directory", file=sys.stderr)
        return 1

    summary = load_summary(exp_dir)
    scenarios = summary.get("scenarios", {})
    metrics_long = load_metrics_long(exp_dir)
    out_dir = exp_dir / "plots" / "paper"

    targets = list(PLOTS.keys()) if not args.only else args.only
    failed = []
    for name in targets:
        fn = PLOTS.get(name)
        if fn is None:
            print(f"  [skip] unknown plot: {name}", file=sys.stderr)
            failed.append(name); continue
        print(f"[plot] {name}")
        try:
            fn(exp_dir, scenarios, metrics_long, out_dir)
        except Exception as e:
            print(f"  [error] {name}: {e!r}", file=sys.stderr)
            failed.append(name)
    print(f"\n{len(targets) - len(failed)}/{len(targets)} plots written to {out_dir}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
