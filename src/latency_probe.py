#!/usr/bin/env python3
"""Latency probe for legitimate-traffic measurement.

Periodically sends small UDP packets to the victim's probe port and
waits for an echo. Records per-packet RTT to
``<EXP_LOG_DIR>/probe_rtt.csv`` so the aggregator can compute legitimate
end-to-end latency, jitter, loss and delivery ratio during each
scenario.

Config (``probe:`` section of ``config.yaml``, override path via
``EE122_CONFIG``):

* ``enabled``        - run only if true
* ``pps``            - probe packet rate (default 20)
* ``port``           - victim echo port (default 30491)
* ``payload_size``   - bytes (default 32, plus 20-byte header)
* ``duration``       - seconds (defaults to attack.duration + a bit)

Each probe packet carries ``(seq_u32, t_send_mono_f64)`` so the victim
echoes the same timestamp back and we compute the RTT locally.
"""

import csv
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
_HEADER_STRUCT = struct.Struct("!If")  # seq u32 + t_send_mono f32


def _config_path():
    return Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))


def _load_config():
    with open(_config_path()) as f:
        return yaml.safe_load(f) or {}


def main():
    cfg = _load_config()
    probe = cfg.get("probe") or {}
    if not probe.get("enabled", False):
        print("[probe] probe.enabled is false; exiting")
        return 0

    net = cfg.get("network", {}) or {}
    dst_ip = net.get("victim_ip") or "10.0.0.2"
    dst_port = int(probe.get("port", 30491))
    src_port = int(probe.get("source_port", 40001))
    pps = float(probe.get("pps", 20))
    if pps <= 0:
        print("[probe] probe.pps must be > 0", file=sys.stderr)
        return 2
    payload_size = int(probe.get("payload_size", 32))
    duration = float(probe.get(
        "duration",
        cfg.get("attack", {}).get("duration", 10) + 4,
    ))

    log_dir = Path(os.environ.get("EXP_LOG_DIR") or (Path.cwd() / "logs" / "probe_run"))
    log_dir.mkdir(parents=True, exist_ok=True)
    csv_path = log_dir / "probe_rtt.csv"
    fh = csv_path.open("w", newline="")
    w = csv.writer(fh)
    w.writerow(["seq", "t_send_mono_s", "t_recv_mono_s", "rtt_ms", "lost"])

    pad = b"P" * max(payload_size - _HEADER_STRUCT.size, 0)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", src_port))
    except OSError as e:
        print(f"[probe] bind({src_port}) failed: {e}", file=sys.stderr)
        # Fall back to an ephemeral port.
        sock.bind(("", 0))
    sock.settimeout(0.2)

    stop = threading.Event()
    in_flight = {}  # seq -> t_send_mono
    lock = threading.Lock()

    def receiver():
        while not stop.is_set():
            try:
                data, _addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < _HEADER_STRUCT.size:
                continue
            seq, t_send_echo = _HEADER_STRUCT.unpack(data[: _HEADER_STRUCT.size])
            t_recv = time.monotonic()
            with lock:
                t_send = in_flight.pop(seq, None)
            if t_send is None:
                # Late reply (already counted as lost) - still log with rtt if available.
                rtt_ms = (t_recv - float(t_send_echo)) * 1000.0
                w.writerow([seq, f"{t_send_echo:.6f}", f"{t_recv:.6f}", f"{rtt_ms:.3f}", 2])
            else:
                rtt_ms = (t_recv - t_send) * 1000.0
                w.writerow([seq, f"{t_send:.6f}", f"{t_recv:.6f}", f"{rtt_ms:.3f}", 0])
            fh.flush()

    rx_thread = threading.Thread(target=receiver, daemon=True)
    rx_thread.start()

    def _sigint(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, _sigint)

    interval = 1.0 / pps
    t_start = time.monotonic()
    next_send = t_start
    seq = 0
    print(f"[probe] dst={dst_ip}:{dst_port} pps={pps:.0f} duration={duration:.1f}s out={csv_path}")

    try:
        while not stop.is_set():
            now = time.monotonic()
            t_off = now - t_start
            if t_off >= duration:
                break
            if now < next_send:
                time.sleep(next_send - now)
            t_send_mono = time.monotonic()
            header = _HEADER_STRUCT.pack(seq & 0xFFFFFFFF, float(t_send_mono))
            payload = header + pad
            with lock:
                in_flight[seq] = t_send_mono
            try:
                sock.sendto(payload, (dst_ip, dst_port))
            except OSError as e:
                print(f"[probe] send error: {e}", file=sys.stderr)
            seq += 1
            next_send += interval

            # Sweep stale in-flight (> 200 ms old) as lost.
            cutoff = time.monotonic() - 0.2
            with lock:
                expired = [s for s, ts in in_flight.items() if ts < cutoff]
                for s in expired:
                    ts = in_flight.pop(s)
                    w.writerow([s, f"{ts:.6f}", "", "", 1])
            if expired:
                fh.flush()
    finally:
        stop.set()
        time.sleep(0.25)
        # Anything still outstanding is lost.
        with lock:
            for s, ts in list(in_flight.items()):
                w.writerow([s, f"{ts:.6f}", "", "", 1])
        fh.flush()
        fh.close()
        try:
            sock.close()
        except Exception:
            pass
    print(f"[probe] sent={seq}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
