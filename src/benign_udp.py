#!/usr/bin/env python3
"""Low-rate benign UDP sender. Run alongside udp_flood.py to measure
collateral damage from rate-based DROP rules installed by the controller.

Reads the ``benign:`` section of ``src/config.yaml``. Writes samples to
``<output_dir>/<run_id>/benign_rate.csv`` using the same run_id as the
attacker if exported via the ``BENIGN_RUN_ID`` environment variable;
otherwise it creates its own.
"""

import csv
import os
import signal
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
CONFIG_PATH = Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))


def die(msg):
    print(f"[benign] config error: {msg}", file=sys.stderr)
    sys.exit(2)


def main():
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    b = cfg.get("benign") or {}
    if not b.get("enabled"):
        print("[benign] benign.enabled is false; exiting")
        return 0
    for k in ("target_port", "source_port", "pps", "payload_size"):
        if b.get(k, 0) <= 0 and k != "source_port":
            die(f"benign.{k} must be > 0")
    dst = cfg["network"]["victim_ip"]
    pps = b["pps"]
    payload = b"B" * b["payload_size"]
    duration = cfg["attack"].get("duration", 10)

    run_id = os.environ.get("BENIGN_RUN_ID") or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-benign-" + uuid.uuid4().hex[:4]
    )
    exp_log_dir = os.environ.get("EXP_LOG_DIR")
    if exp_log_dir:
        out_dir = Path(exp_log_dir)
    else:
        repo_root = Path(__file__).resolve().parent.parent
        out_dir = repo_root / cfg.get("logging", {}).get("output_dir", "logs") / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    host_tag = os.environ.get("BENIGN_HOST_TAG", "benign")
    csv_path = out_dir / f"{host_tag}_rate.csv"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Use a unique source port per host to avoid conflicts when two benign
    # senders run on different Mininet hosts but share the same namespace view
    # when EXP_LOG_DIR is unset.
    try:
        sock.bind(("", b["source_port"]))
    except OSError:
        sock.bind(("", 0))

    stop = {"v": False}

    def on_sigint(*_):
        stop["v"] = True

    signal.signal(signal.SIGINT, on_sigint)

    interval = 1.0 / pps
    t_start = time.monotonic()
    next_send = t_start
    sent = 0

    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["t_mono_s", "sent"])
        last_sample = 0.0
        while not stop["v"]:
            now = time.monotonic()
            t_off = now - t_start
            if t_off >= duration:
                break
            if now < next_send:
                time.sleep(next_send - now)
            try:
                sock.sendto(payload, (dst, b["target_port"]))
                sent += 1
            except OSError as e:
                print(f"[benign] send error: {e}", file=sys.stderr)
            next_send += interval
            if t_off - last_sample >= 0.5:
                w.writerow([f"{t_off:.4f}", sent])
                fh.flush()
                last_sample = t_off
        w.writerow([f"{time.monotonic() - t_start:.4f}", sent])

    print(f"[benign] run_id={run_id} sent={sent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
