#!/usr/bin/env python3
"""Victim ECU: UDP sink + probe-echo server.

Runs two sockets:

* ``victim.listen_port`` (default 30490): application/attack traffic. Each
  packet is logged to ``<EXP_LOG_DIR>/victim_rx.csv`` with its source
  address so the aggregator can compute legitimate vs. malicious
  delivery ratios.
* ``probe.port`` (default 30491): echoes probe packets back to the
  sender so ``latency_probe.py`` can measure legitimate RTT.

Config read from ``src/config.yaml`` (override path via ``EE122_CONFIG``).
Output dir taken from ``EXP_LOG_DIR`` if set, otherwise
``<logging.output_dir>/victim_run``.
"""

import csv
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def _config_path():
    return Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))


def _load_config():
    with open(_config_path()) as f:
        return yaml.safe_load(f) or {}


def _log_dir(cfg):
    v = os.environ.get("EXP_LOG_DIR")
    if v:
        return Path(v)
    base = cfg.get("logging", {}).get("output_dir", "logs")
    return Path(base) / "victim_run"


def _rx_serve(rx_sock, rx_w, rx_fh, rx_lock, stop, t_start, log_interval):
    """Receive loop for application/attack traffic."""
    count = 0
    per_src = {}
    while not stop.is_set():
        try:
            data, addr = rx_sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        now = time.monotonic() - t_start
        count += 1
        src_ip = addr[0]
        per_src[src_ip] = per_src.get(src_ip, 0) + 1
        with rx_lock:
            rx_w.writerow([f"{now:.4f}", src_ip, len(data), count])
            if count % 200 == 0:
                rx_fh.flush()
        if count % log_interval == 0:
            print(f"[victim] rx={count} per_src={per_src}", flush=True)


def _probe_serve(probe_sock, stop):
    """Echo loop for latency probe packets."""
    while not stop.is_set():
        try:
            data, addr = probe_sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            probe_sock.sendto(data, addr)
        except OSError:
            pass


def main():
    cfg = _load_config()
    listen_ip = cfg.get("victim", {}).get("bind_ip", "0.0.0.0")
    listen_port = int(cfg.get("victim", {}).get("listen_port", 30490))
    probe_port = int((cfg.get("probe") or {}).get("port", 30491))
    log_interval = int(cfg.get("victim", {}).get("log_interval", 1000))

    log_dir = _log_dir(cfg)
    log_dir.mkdir(parents=True, exist_ok=True)

    rx_path = log_dir / "victim_rx.csv"
    rx_fh = rx_path.open("w", newline="")
    rx_w = csv.writer(rx_fh)
    rx_w.writerow(["t_mono_s", "src_ip", "bytes", "cumulative_count"])
    rx_lock = threading.Lock()

    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    rx_sock.settimeout(0.5)
    rx_sock.bind((listen_ip, listen_port))

    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe_sock.settimeout(0.5)
    probe_sock.bind((listen_ip, probe_port))

    stop = threading.Event()

    def _sigint(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    t_start = time.monotonic()

    print(f"[victim] rx={listen_ip}:{listen_port} probe={listen_ip}:{probe_port} out={log_dir}")

    rx_thread = threading.Thread(
        target=_rx_serve,
        args=(rx_sock, rx_w, rx_fh, rx_lock, stop, t_start, log_interval),
        daemon=True,
    )
    probe_thread = threading.Thread(
        target=_probe_serve, args=(probe_sock, stop), daemon=True,
    )
    rx_thread.start()
    probe_thread.start()

    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        stop.set()
        try:
            rx_sock.close()
        except Exception:
            pass
        try:
            probe_sock.close()
        except Exception:
            pass
        with rx_lock:
            rx_fh.flush()
            rx_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
