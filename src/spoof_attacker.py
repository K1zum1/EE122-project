#!/usr/bin/env python3
"""Spoofing attacker for the automotive SDN evaluation.

Sends UDP packets to the victim while impersonating other ECUs. Two
identity-rotation modes, selected by ``spoof.many_identities`` in
``config.yaml`` (override path via ``EE122_CONFIG``):

* ``false`` (default) - impersonate a single trusted ECU (src_ip / src_mac
                        taken from ``spoof.fake_src_ip`` /
                        ``spoof.fake_src_mac``).
* ``true``            - cycle through ``spoof.num_identities`` distinct
                        synthetic (ip, mac) pairs, one per packet. This
                        reliably stresses learning switches / flow tables
                        and forces the controller to rely on per-port
                        signals rather than per-eth_src signals.

Log layout matches :mod:`udp_flood` for uniform aggregation:
``<EXP_LOG_DIR>/spoof_*.csv`` and ``spoof_summary.json``.
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

# #region agent log
_DBG_LOG = str(Path(__file__).resolve().parent.parent / ".cursor" / "debug-70ad8e.log")
def _dbg(location, message, data=None, hypothesisId=None, runId="initial"):
    try:
        os.makedirs(os.path.dirname(_DBG_LOG), exist_ok=True)
        with open(_DBG_LOG, "a") as _f:
            _f.write(json.dumps({
                "sessionId": "70ad8e",
                "runId": runId,
                "hypothesisId": hypothesisId,
                "location": location,
                "message": message,
                "data": data or {},
                "timestamp": int(time.time() * 1000),
            }) + "\n")
    except Exception:
        pass

_dbg(
    "src/spoof_attacker.py:entry",
    "spoof_attacker process started",
    data={
        "sys_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "pid": os.getpid(),
    },
    hypothesisId="H1_python_env",
)
# #endregion

import yaml
try:
    from scapy.all import Ether, IP, UDP, Raw, sendp
    # #region agent log
    _dbg(
        "src/spoof_attacker.py:scapy_import",
        "scapy imported successfully",
        data={"scapy_available": True},
        hypothesisId="H2_scapy_missing",
    )
    # #endregion
except ImportError as _e:
    # #region agent log
    _dbg(
        "src/spoof_attacker.py:scapy_import",
        "scapy import FAILED",
        data={"error": str(_e)},
        hypothesisId="H2_scapy_missing",
    )
    # #endregion
    raise


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def die(msg):
    print(f"[spoofer] config error: {msg}", file=sys.stderr)
    sys.exit(2)


def _config_path():
    return Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))


def _load_config():
    with open(_config_path()) as f:
        return yaml.safe_load(f) or {}


def _iface():
    # Mininet host interfaces are usually '<hostname>-eth0'.
    return os.environ.get("SPOOF_IFACE", "spoofer-eth0")


def _make_identities(n):
    """Deterministic synthetic (ip, mac) pairs."""
    ids = []
    for i in range(n):
        # Reserve 10.0.66.0/24 for synthetic spoofed identities.
        ip = f"10.0.66.{1 + (i % 250)}"
        mac = f"02:00:00:00:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}"
        ids.append((ip, mac))
    return ids


def _git_sha():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).parent,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return None


def main():
    cfg = _load_config()
    spoof = cfg.get("spoof") or {}
    if not spoof.get("enabled", False):
        print("[spoofer] spoof.enabled is false; exiting")
        return 0

    net = cfg.get("network", {}) or {}
    dst_ip = net.get("victim_ip") or die("network.victim_ip missing")
    dst_mac = spoof.get("victim_mac") or net.get("victim_mac") or "00:00:00:00:00:02"

    target_port = int(spoof.get("target_port", cfg.get("attack", {}).get("target_port", 30490)))
    src_port = int(spoof.get("source_port", 23456))
    pps = float(spoof.get("pps", 100))
    if pps <= 0:
        die("spoof.pps must be > 0")
    duration = float(spoof.get("duration", cfg.get("attack", {}).get("duration", 10)))
    payload_size = int(spoof.get("payload_size", 128))

    many = bool(spoof.get("many_identities", False))
    if many:
        n_ids = int(spoof.get("num_identities", 20))
        if n_ids <= 0:
            die("spoof.num_identities must be > 0 when many_identities is true")
        identities = _make_identities(n_ids)
    else:
        fake_ip = spoof.get("fake_src_ip", "10.0.0.10")   # benign1 by default
        fake_mac = spoof.get("fake_src_mac", "00:00:00:00:00:10")
        identities = [(fake_ip, fake_mac)]

    log_dir = Path(os.environ.get("EXP_LOG_DIR") or (Path.cwd() / "logs" / "spoof_run"))
    log_dir.mkdir(parents=True, exist_ok=True)
    run_id = log_dir.name

    rate_path = log_dir / "spoofer_rate.csv"
    rate_fh = rate_path.open("w", newline="")
    rate_w = csv.writer(rate_fh)
    rate_w.writerow(["t_mono_s", "sent", "bytes_sent", "achieved_pps", "distinct_identities"])

    payload = b"S" * payload_size
    iface = _iface()

    manifest = {
        "run_id": run_id,
        "t_start_wall_iso": datetime.now(timezone.utc).isoformat(),
        "git_sha": _git_sha(),
        "host": os.uname().nodename,
        "iface": iface,
        "many_identities": many,
        "num_identities": len(identities),
        "target_pps": pps,
        "duration": duration,
        "victim": {"ip": dst_ip, "mac": dst_mac, "port": target_port},
        "config_snapshot": {"spoof": spoof, "network": net},
    }
    (log_dir / "spoofer_manifest.json").write_text(json.dumps(manifest, indent=2, default=str))

    exit_reason = {"v": "duration_elapsed"}

    def _sigint(signum, frame):
        exit_reason["v"] = "sigint"
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _sigint)

    print(f"[spoofer] run_id={run_id} iface={iface} ids={len(identities)} pps={pps:.0f}")

    interval = 1.0 / pps
    t_start = time.monotonic()
    next_send = t_start
    sent = 0
    bytes_sent = 0
    last_sample_t = 0.0
    last_sample_sent = 0

    try:
        i = 0
        while True:
            now = time.monotonic()
            t_off = now - t_start
            if t_off >= duration:
                break
            if now < next_send:
                time.sleep(next_send - now)

            src_ip, src_mac = identities[i % len(identities)]
            i += 1
            pkt = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(src=src_ip, dst=dst_ip)
                / UDP(sport=src_port, dport=target_port)
                / Raw(load=payload)
            )
            try:
                sendp(pkt, iface=iface, verbose=False)
            except OSError as e:
                print(f"[spoofer] sendp error: {e}", file=sys.stderr)
                break
            sent += 1
            bytes_sent += len(payload) + 42  # rough Ethernet + IP + UDP overhead
            next_send += interval

            # Avoid catch-up spiral.
            drift_limit = time.monotonic() - 0.5
            if next_send < drift_limit:
                next_send = time.monotonic()

            if t_off - last_sample_t >= 0.1:
                dt = t_off - last_sample_t
                achieved = (sent - last_sample_sent) / dt if dt > 0 else 0.0
                rate_w.writerow([
                    f"{t_off:.4f}", sent, bytes_sent,
                    f"{achieved:.2f}", len(identities),
                ])
                rate_fh.flush()
                last_sample_t = t_off
                last_sample_sent = sent
    except KeyboardInterrupt:
        pass
    finally:
        t_stop = time.monotonic()
        elapsed = t_stop - t_start
        rate_w.writerow([f"{elapsed:.4f}", sent, bytes_sent, "0.00", len(identities)])
        rate_fh.flush()
        rate_fh.close()
        mean_pps = sent / elapsed if elapsed > 0 else 0.0
        (log_dir / "spoofer_summary.json").write_text(json.dumps({
            "run_id": run_id,
            "mode": "many_identities" if many else "single_identity",
            "duration_s": elapsed,
            "sent": sent,
            "bytes_sent": bytes_sent,
            "mean_pps": mean_pps,
            "distinct_identities": len(identities),
            "exit_reason": exit_reason["v"],
        }, indent=2))
        print(
            f"[spoofer] sent={sent} bytes={bytes_sent} "
            f"elapsed={elapsed:.2f}s mean_pps={mean_pps:.2f} "
            f"exit={exit_reason['v']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
