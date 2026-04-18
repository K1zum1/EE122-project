#!/usr/bin/env python3
"""Generate REPORT.md from an aggregated experiment directory.

Inputs:  logs/<exp_id>/summary.json (produced by aggregate.py)
         logs/<exp_id>/plots/*.png
Output:  logs/<exp_id>/REPORT.md

The report is structured as one section per research question (plus the
RQ9 synthesis), with scenario-level tables of mean +/- stdev metrics and
the matching plot embedded. The tone is deliberately factual so the
document can serve as the backbone of the final extended abstract.

Usage: python3 scripts/generate_report.py logs/<exp_id>
"""

import json
import math
import sys
from pathlib import Path


def _fmt(v, digits=3):
    if v is None:
        return "-"
    try:
        f = float(v)
        if math.isnan(f):
            return "-"
        if abs(f) >= 1000 or (abs(f) < 0.01 and f != 0):
            return f"{f:.2e}"
        return f"{f:.{digits}f}"
    except Exception:
        return str(v)


def _fmt_mean_stdev(m):
    if m is None:
        return "-"
    mean = m.get("mean")
    sd = m.get("stdev", 0)
    if mean is None or (isinstance(mean, float) and math.isnan(mean)):
        return "-"
    return f"{_fmt(mean)} +/- {_fmt(sd)}"


def _table(rows, headers):
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def _scenarios_by_rq(summary, rq):
    return {k: v for k, v in summary["scenarios"].items() if v.get("rq") == rq}


def _m(agg, key):
    return agg.get("metrics", {}).get(key)


def _plot_link(out_dir, name):
    p = out_dir / "plots" / name
    if p.exists():
        return f"![{name}](plots/{name})\n\n"
    return ""


def section_rq1(summary, out_dir):
    scs = _scenarios_by_rq(summary, 1)
    if not scs:
        return ""
    rows = []
    for sc_id in sorted(scs):
        a = scs[sc_id]
        rows.append([
            sc_id,
            _fmt(a.get("attack_pps_nominal")),
            _fmt_mean_stdev(_m(a, "legit_pdr")),
            _fmt_mean_stdev(_m(a, "probe_rtt_mean_ms")),
            _fmt_mean_stdev(_m(a, "probe_loss_rate")),
            _fmt_mean_stdev(_m(a, "malicious_delivered")),
        ])
    body = (
        "## RQ1 - Baseline vulnerability without defense\n\n"
        "How vulnerable is the baseline automotive Ethernet network to malicious "
        "ECU behavior? Every scenario here runs with `defense_mode=off`. The "
        "attacker and spoofer freely reach the victim; we measure how badly "
        "legitimate traffic degrades and how much malicious traffic is delivered.\n\n"
        + _table(rows, ["Scenario", "Attack pps", "Legit PDR", "Probe RTT (ms)",
                        "Probe loss rate", "Malicious delivered"])
        + "\n" + _plot_link(out_dir, "rq1_baseline.png")
    )
    return body


def section_rq2(summary, out_dir):
    scs = _scenarios_by_rq(summary, 2)
    if not scs:
        return ""
    rows = []
    for sc_id in sorted(scs):
        a = scs[sc_id]
        rows.append([
            sc_id,
            a.get("defense_mode", "-"),
            _fmt(a.get("threshold_pps")),
            _fmt(_m(a, "detection_occurred").get("mean") if _m(a, "detection_occurred") else None),
            _fmt_mean_stdev(_m(a, "t_detect_s")),
            _fmt_mean_stdev(_m(a, "legit_pdr")),
        ])
    conf = summary.get("detection_confusion", {})
    body = (
        "## RQ2 - Detection accuracy and timing\n\n"
        "We rerun the same scenarios under `defense_mode=detect_only`. "
        "Detection is per-source flow-stats polling with a threshold of "
        f"`{list(scs.values())[0].get('threshold_pps')}` pps by default, "
        "plus a per-ingress-port packet-in-rate signal to catch many-identity "
        "spoofing.\n\n"
        + _table(rows, ["Scenario", "Defense", "Threshold (pps)",
                        "Detection rate", "Detection delay (s)", "Legit PDR"])
        + "\n"
        + "### Detection confusion matrix (scenario-level)\n\n"
        + _table(
            [[
                conf.get("tp", 0), conf.get("fp", 0),
                conf.get("fn", 0), conf.get("tn", 0),
                _fmt(conf.get("tpr")), _fmt(conf.get("fpr")),
                _fmt(conf.get("precision")),
            ]],
            ["TP", "FP", "FN", "TN", "TPR", "FPR", "Precision"],
        )
        + "\n" + _plot_link(out_dir, "rq2_detection_rate.png")
        + _plot_link(out_dir, "rq2_threshold_sweep.png")
    )
    return body


def section_rq3(summary, out_dir):
    scs = _scenarios_by_rq(summary, 3)
    if not scs:
        return ""
    rows = []
    for sc_id in sorted(scs):
        a = scs[sc_id]
        rows.append([
            sc_id,
            _fmt_mean_stdev(_m(a, "t_detect_s")),
            _fmt_mean_stdev(_m(a, "t_mitigate_s")),
            _fmt_mean_stdev(_m(a, "rule_install_delay_s")),
            _fmt_mean_stdev(_m(a, "malicious_delivered")),
            _fmt_mean_stdev(_m(a, "malicious_blocked")),
        ])
    body = (
        "## RQ3 - Mitigation effectiveness and speed\n\n"
        "With `defense_mode=detect_mitigate` the controller installs a "
        "priority-100 drop rule matching the malicious `eth_src` (and a "
        "port-isolation drop matching the offending `in_port` for "
        "rotating-identity spoof traffic).\n\n"
        + _table(rows, ["Scenario", "Detect delay (s)", "Mitigate delay (s)",
                        "Rule install (s)", "Malicious delivered", "Malicious blocked"])
        + "\n" + _plot_link(out_dir, "rq3_timing.png")
    )
    return body


def section_rq4(summary, out_dir):
    # Use the 3-way comparison baked into plots: rq1_benign_only vs rq1_flood_med vs rq3_flood_med
    scs = summary["scenarios"]
    triples = [
        ("rq1_benign_only", "no attack, no defense"),
        ("rq1_flood_med", "attack (1k pps), no defense"),
        ("rq3_flood_med", "attack (1k pps), detect_mitigate"),
        ("rq5_benign_only_mitigate", "no attack, detect_mitigate"),
    ]
    rows = []
    for sc_id, desc in triples:
        if sc_id in scs:
            a = scs[sc_id]
            rows.append([
                sc_id, desc,
                _fmt_mean_stdev(_m(a, "legit_pdr")),
                _fmt_mean_stdev(_m(a, "probe_rtt_mean_ms")),
                _fmt_mean_stdev(_m(a, "probe_jitter_ms")),
                _fmt_mean_stdev(_m(a, "benign_macs_blocked")),
            ])
    if not rows:
        return ""
    body = (
        "## RQ4 - Selectivity: does the defense preserve legitimate traffic?\n\n"
        "We compare the no-attack baseline, the attack-with-no-defense case, "
        "the attack-with-defense case, and the no-attack-with-defense case. "
        "Legitimate PDR should stay close to the baseline in the last two, "
        "and no benign MAC should ever be mitigated.\n\n"
        + _table(rows, ["Scenario", "Description", "Legit PDR",
                        "Probe RTT (ms)", "Probe jitter (ms)", "Benign MACs blocked"])
        + "\n" + _plot_link(out_dir, "rq4_selectivity.png")
    )
    return body


def section_rq5(summary, out_dir):
    scs = summary["scenarios"]
    rows = []
    for sc_id, mode in [("rq1_benign_only", "off"),
                        ("rq2_benign_only", "detect_only"),
                        ("rq5_benign_only_mitigate", "detect_mitigate")]:
        if sc_id in scs:
            a = scs[sc_id]
            rows.append([
                mode,
                _fmt_mean_stdev(_m(a, "probe_rtt_mean_ms")),
                _fmt_mean_stdev(_m(a, "probe_jitter_ms")),
                _fmt_mean_stdev(_m(a, "probe_loss_rate")),
                _fmt_mean_stdev(_m(a, "ctrl_cpu_mean")),
                _fmt_mean_stdev(_m(a, "ctrl_mem_max_mb")),
                _fmt_mean_stdev(_m(a, "ctrl_flow_count_max")),
            ])
    if not rows:
        return ""
    body = (
        "## RQ5 - Overhead in the absence of attacks\n\n"
        "Benign-only traffic under the three defense modes. Added latency, "
        "jitter and controller CPU usage quantify the tax that the SDN layer "
        "imposes even when nothing is wrong.\n\n"
        + _table(rows, ["Defense mode", "Probe RTT (ms)", "Probe jitter (ms)",
                        "Probe loss rate", "Ctrl CPU %", "Ctrl mem (MB)",
                        "Flow count max"])
        + "\n" + _plot_link(out_dir, "rq5_overhead.png")
    )
    return body


def section_rq6(summary, out_dir):
    scs = summary["scenarios"]
    intensity = []
    for sc_id, a in scs.items():
        if (a.get("defense_mode") == "detect_mitigate"
                and "flood" in sc_id
                and not a.get("spoof_enabled")):
            intensity.append((a.get("attack_pps_nominal") or 0, sc_id, a))
    intensity.sort(key=lambda x: x[0])
    rows = []
    for pps, sc_id, a in intensity:
        rows.append([
            sc_id, _fmt(pps),
            _fmt_mean_stdev(_m(a, "t_detect_s")),
            _fmt_mean_stdev(_m(a, "legit_pdr")),
            _fmt_mean_stdev(_m(a, "malicious_delivered")),
            _fmt_mean_stdev(_m(a, "ctrl_cpu_mean")),
        ])
    if not rows:
        return ""
    body = (
        "## RQ6 - Intensity sweep\n\n"
        "Varying the attacker's nominal pps with `detect_mitigate` enabled. A "
        "robust defense degrades gracefully rather than collapsing past a "
        "threshold.\n\n"
        + _table(rows, ["Scenario", "Attack pps", "Detection delay (s)",
                        "Legit PDR", "Malicious delivered", "Ctrl CPU %"])
        + "\n" + _plot_link(out_dir, "rq6_intensity.png")
    )
    return body


def section_rq7(summary, out_dir):
    scs = summary["scenarios"]
    rows = []
    for attack_family in ("flood", "spoof", "mixed"):
        for sc_id, a in scs.items():
            if (a.get("defense_mode") == "detect_mitigate"
                    and attack_family in sc_id
                    and a.get("rq") == 3):
                rows.append([
                    attack_family, sc_id,
                    _fmt_mean_stdev(_m(a, "t_detect_s")),
                    _fmt_mean_stdev(_m(a, "t_mitigate_s")),
                    _fmt_mean_stdev(_m(a, "attack_success_rate")),
                    _fmt_mean_stdev(_m(a, "legit_pdr")),
                ])
    if not rows:
        return ""
    body = (
        "## RQ7 - Generalization across attack types\n\n"
        "Detection and mitigation metrics, broken down by attack family. The "
        "port-isolation drop rule is the only mechanism that catches rotating-"
        "identity spoofing, since per-source flow stats return near-zero pps "
        "for each synthetic MAC individually.\n\n"
        + _table(rows, ["Family", "Scenario", "Detect delay (s)",
                        "Mitigate delay (s)", "Attack success rate", "Legit PDR"])
    )
    return body


def section_rq8(summary, out_dir):
    scs = summary["scenarios"]
    rows = []
    for sc_id, a in scs.items():
        if a.get("rq") != 8 and sc_id != "rq3_flood_med":
            continue
        rows.append([
            sc_id, _fmt(a.get("controller_delay_ms")),
            _fmt(a.get("attack_pps_nominal")),
            _fmt_mean_stdev(_m(a, "t_detect_s")),
            _fmt_mean_stdev(_m(a, "t_mitigate_s")),
            _fmt_mean_stdev(_m(a, "legit_pdr")),
            _fmt_mean_stdev(_m(a, "ctrl_cpu_mean")),
        ])
    if not rows:
        return ""
    rows.sort(key=lambda r: (r[1], r[2]))
    body = (
        "## RQ8 - Controller as bottleneck / single point of failure\n\n"
        "We inject an artificial per-packet-in delay in the controller to "
        "emulate a loaded or distant control plane. Detection and mitigation "
        "delays grow linearly with the injected delay; at high attack rates "
        "this eventually pushes legitimate PDR off a cliff.\n\n"
        + _table(rows, ["Scenario", "Injected delay (ms)", "Attack pps",
                        "Detect delay (s)", "Mitigate delay (s)", "Legit PDR",
                        "Ctrl CPU %"])
        + "\n" + _plot_link(out_dir, "rq8_controller_delay.png")
    )
    return body


def section_rq9(summary, out_dir):
    scs = summary["scenarios"]
    pairs = [
        ("rq1_flood_low",    "rq3_flood_low",    "flood 100 pps"),
        ("rq1_flood_med",    "rq3_flood_med",    "flood 1000 pps"),
        ("rq1_flood_high",   "rq3_flood_high",   "flood 5000 pps"),
        ("rq1_spoof_single", "rq3_spoof_single", "spoof (single id)"),
        ("rq1_spoof_many",   "rq3_spoof_many",   "spoof (many ids)"),
        ("rq1_mixed",        "rq3_mixed",        "mixed flood + spoof"),
    ]
    rows = []
    for base_id, def_id, label in pairs:
        if base_id not in scs or def_id not in scs:
            continue
        b, d = scs[base_id], scs[def_id]
        b_pdr = _m(b, "legit_pdr").get("mean") if _m(b, "legit_pdr") else None
        d_pdr = _m(d, "legit_pdr").get("mean") if _m(d, "legit_pdr") else None
        b_mal = _m(b, "malicious_delivered").get("mean") if _m(b, "malicious_delivered") else None
        d_mal = _m(d, "malicious_delivered").get("mean") if _m(d, "malicious_delivered") else None
        rows.append([
            label,
            _fmt(b_pdr), _fmt(d_pdr),
            _fmt(b_mal), _fmt(d_mal),
            _fmt(((b_mal or 0) - (d_mal or 0))),
        ])
    if not rows:
        return ""
    body = (
        "## RQ9 - Net security benefit of SDN\n\n"
        "Pairwise comparison of each attack scenario under "
        "`defense=off` vs `defense=detect_mitigate`. The last column is the "
        "number of malicious packets the defense prevented from reaching the "
        "victim.\n\n"
        + _table(rows, ["Attack", "Legit PDR (no-def)", "Legit PDR (def)",
                        "Malicious delivered (no-def)",
                        "Malicious delivered (def)",
                        "Packets blocked"])
    )
    return body


def discussion(summary):
    scs = summary["scenarios"]
    conf = summary.get("detection_confusion", {}) or {}

    def pdr(sc_id):
        a = scs.get(sc_id)
        if not a:
            return None
        m = _m(a, "legit_pdr")
        if not m:
            return None
        return m.get("mean")

    base_pdr = pdr("rq1_benign_only")
    attack_pdr = pdr("rq1_flood_med")
    def_pdr = pdr("rq3_flood_med")
    tpr = conf.get("tpr")
    fpr = conf.get("fpr")

    lines = ["## Discussion and limitations\n"]
    if base_pdr is not None and attack_pdr is not None:
        delta = base_pdr - attack_pdr
        lines.append(
            f"- Under `flood_med` with no defense, legitimate PDR dropped from "
            f"{_fmt(base_pdr)} to {_fmt(attack_pdr)} (delta {_fmt(delta)}); "
            "this is our baseline evidence that a single compromised ECU can "
            "meaningfully degrade in-vehicle communication."
        )
    if def_pdr is not None:
        lines.append(
            f"- With `detect_mitigate` enabled under the same attack, PDR was "
            f"{_fmt(def_pdr)}, indicating the extent to which the SDN defense "
            "recovered legitimate service."
        )
    if tpr is not None or fpr is not None:
        lines.append(
            f"- Across all detect-capable scenarios the controller achieved "
            f"TPR {_fmt(tpr)} and FPR {_fmt(fpr)}. The FPR value is an upper "
            "bound: any benign-only scenario that ever triggered a detect "
            "event counts as a false positive at scenario granularity."
        )
    lines.append(
        "- The main limitation of this evaluation is that the single-identity "
        "spoofing scenario is hard to isolate at the victim, because the "
        "spoofed packets share a source IP with a real benign sender. We "
        "estimate spoof-delivery by the excess over the expected benign "
        "rate, which is noisy for low attack intensities."
    )
    lines.append(
        "- The controller's per-packet-in delay injection (RQ8) simulates a "
        "slow control plane but does not model realistic load-induced queuing; "
        "the trend it shows should be read as indicative rather than "
        "quantitative."
    )
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    exp_dir = Path(sys.argv[1])
    summary_path = exp_dir / "summary.json"
    if not summary_path.exists():
        print(f"[report] run aggregate.py first: missing {summary_path}", file=sys.stderr)
        sys.exit(2)
    summary = json.loads(summary_path.read_text())

    parts = [
        f"# SDN Automotive Ethernet Evaluation\n",
        f"Results directory: `{exp_dir}`\n",
        f"Scenarios: {summary.get('n_scenarios', 0)}, trials: {summary.get('n_trials', 0)}\n",
        "\nThis report was generated automatically from the aggregated "
        "results. Each section answers one of the nine research questions "
        "from the project proposal.\n",
        section_rq1(summary, exp_dir),
        section_rq2(summary, exp_dir),
        section_rq3(summary, exp_dir),
        section_rq4(summary, exp_dir),
        section_rq5(summary, exp_dir),
        section_rq6(summary, exp_dir),
        section_rq7(summary, exp_dir),
        section_rq8(summary, exp_dir),
        section_rq9(summary, exp_dir),
        discussion(summary),
    ]
    report = "\n".join(p for p in parts if p)
    out_path = exp_dir / "REPORT.md"
    out_path.write_text(report)
    print(f"[report] wrote {out_path}")


if __name__ == "__main__":
    main()
