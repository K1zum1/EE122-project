#!/usr/bin/env python3
"""Mininet topology for the automotive-Ethernet SDN evaluation.

Six hosts attached to a single OVS (OpenFlow 1.3) switch s1 over TCLinks:

    victim   10.0.0.2   safety-critical ECU
    attacker 10.0.0.1   flooding ECU
    spoofer  10.0.0.3   spoofing ECU
    benign1  10.0.0.10  normal ECU (low-rate UDP telemetry)
    benign2  10.0.0.11  normal ECU (low-rate UDP telemetry)
    probe    10.0.0.20  latency-probe ECU (RTT echo)

Two run modes, selected via the ``TOPO_MODE`` env var:

* ``cli`` (default)   - drop into the mininet CLI for manual testing
* ``harness``         - orchestrate an experiment: spawn victim, benign,
                         probe, attacker and spoofer on their hosts
                         according to ``config.yaml``, wait the attack
                         duration, tear down, and exit

Env overrides respected by both modes:

* ``EE122_CONFIG``    - alternate path to the scenario config
* ``EXP_LOG_DIR``     - destination directory for per-host logs
* ``CONTROLLER_IP``   - remote controller host (default 127.0.0.1)
* ``CONTROLLER_PORT`` - remote controller port (default 6653)
"""

import os
import sys
import time
from pathlib import Path

import yaml

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_CONFIG = HERE / "config.yaml"


HOSTS = [
    {"name": "victim",   "ip": "10.0.0.2/24",  "mac": "00:00:00:00:00:02"},
    {"name": "attacker", "ip": "10.0.0.1/24",  "mac": "00:00:00:00:00:01"},
    {"name": "spoofer",  "ip": "10.0.0.3/24",  "mac": "00:00:00:00:00:03"},
    {"name": "benign1",  "ip": "10.0.0.10/24", "mac": "00:00:00:00:00:10"},
    {"name": "benign2",  "ip": "10.0.0.11/24", "mac": "00:00:00:00:00:11"},
    {"name": "probe",    "ip": "10.0.0.20/24", "mac": "00:00:00:00:00:20"},
]


def _config_path():
    return Path(os.environ.get("EE122_CONFIG", str(DEFAULT_CONFIG)))


def _load_config():
    with open(_config_path()) as f:
        return yaml.safe_load(f) or {}


def _build_net(cfg):
    topo = cfg.get("topology") or {}
    bw = topo.get("link_bw_mbps", 10)
    delay = f"{topo.get('link_delay_ms', 1)}ms"

    ctrl_ip = os.environ.get("CONTROLLER_IP", "127.0.0.1")
    ctrl_port = int(os.environ.get("CONTROLLER_PORT", 6653))

    net = Mininet(
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
        waitConnected=True,
        autoSetMacs=False,
    )
    net.addController(
        "c0",
        controller=RemoteController,
        ip=ctrl_ip,
        port=ctrl_port,
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    hosts = {}
    for h in HOSTS:
        hosts[h["name"]] = net.addHost(
            h["name"], ip=h["ip"], mac=h["mac"]
        )

    for h in HOSTS:
        net.addLink(hosts[h["name"]], s1, bw=bw, delay=delay)

    return net, hosts


def _run_harness(net, hosts, cfg):
    """Start per-host workloads for a single scenario, wait, stop."""
    log_dir = Path(os.environ.get("EXP_LOG_DIR", str(REPO_ROOT / "logs" / "harness_run")))
    log_dir.mkdir(parents=True, exist_ok=True)

    duration = float(cfg.get("attack", {}).get("duration", 10))
    benign_enabled = bool((cfg.get("benign") or {}).get("enabled", False))
    spoof_enabled = bool((cfg.get("spoof") or {}).get("enabled", False))
    flood_enabled = bool((cfg.get("attack") or {}).get("enabled", True))
    probe_enabled = bool((cfg.get("probe") or {}).get("enabled", False))

    env = os.environ.copy()
    env["EE122_CONFIG"] = str(_config_path())
    env["EXP_LOG_DIR"] = str(log_dir)
    env["BENIGN_RUN_ID"] = log_dir.name

    host_log = lambda name: (log_dir / f"{name}.stdout").open("w")

    victim = hosts["victim"]
    probe = hosts["probe"]
    attacker = hosts["attacker"]
    spoofer = hosts["spoofer"]
    benign1 = hosts["benign1"]
    benign2 = hosts["benign2"]

    victim_py = str(REPO_ROOT / "src" / "victim_server.py")
    probe_py = str(REPO_ROOT / "src" / "latency_probe.py")
    benign_py = str(REPO_ROOT / "src" / "benign_udp.py")
    flood_py = str(REPO_ROOT / "src" / "udp_flood.py")
    spoof_py = str(REPO_ROOT / "src" / "spoof_attacker.py")

    procs = []

    # Victim must start first so probes/floods have somewhere to land.
    info("*** harness: starting victim\n")
    victim_proc = victim.popen(
        ["python3", "-u", victim_py],
        env=env,
        stdout=host_log("victim"),
        stderr=host_log("victim_err"),
    )
    procs.append(("victim", victim_proc))

    time.sleep(0.5)

    if probe_enabled:
        info("*** harness: starting probe\n")
        procs.append((
            "probe",
            probe.popen(
                ["python3", "-u", probe_py],
                env=env,
                stdout=host_log("probe"),
                stderr=host_log("probe_err"),
            ),
        ))

    if benign_enabled:
        info("*** harness: starting benign1/benign2\n")
        benign_env = env.copy()
        benign_env["BENIGN_HOST_TAG"] = "benign1"
        procs.append((
            "benign1",
            benign1.popen(
                ["python3", "-u", benign_py],
                env=benign_env,
                stdout=host_log("benign1"),
                stderr=host_log("benign1_err"),
            ),
        ))
        benign_env2 = env.copy()
        benign_env2["BENIGN_HOST_TAG"] = "benign2"
        procs.append((
            "benign2",
            benign2.popen(
                ["python3", "-u", benign_py],
                env=benign_env2,
                stdout=host_log("benign2"),
                stderr=host_log("benign2_err"),
            ),
        ))

    # Give legitimate traffic a moment to warm up so we can observe baseline
    # before the attacker starts.
    warmup = float(cfg.get("attack", {}).get("warmup_s", 2))
    time.sleep(warmup)

    attack_started_mono = None
    if flood_enabled:
        info("*** harness: starting attacker (flood)\n")
        procs.append((
            "attacker",
            attacker.popen(
                ["python3", "-u", flood_py],
                env=env,
                stdout=host_log("attacker"),
                stderr=host_log("attacker_err"),
            ),
        ))
        attack_started_mono = time.monotonic()

    if spoof_enabled:
        info("*** harness: starting spoofer\n")
        procs.append((
            "spoofer",
            spoofer.popen(
                ["python3", "-u", spoof_py],
                env=env,
                stdout=host_log("spoofer"),
                stderr=host_log("spoofer_err"),
            ),
        ))
        if attack_started_mono is None:
            attack_started_mono = time.monotonic()

    # Record the attack start wall-clock inside the run dir so the aggregator
    # can align attacker-local time series with controller events.
    if attack_started_mono is not None:
        (log_dir / "attack_start.txt").write_text(
            f"attack_start_mono_s={attack_started_mono}\n"
            f"attack_start_wall={time.time()}\n"
        )

    # Wait for the attacker to finish (or for duration if no attack).
    wait_s = duration + warmup + 2
    info(f"*** harness: waiting {wait_s:.1f}s for scenario to complete\n")
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        time.sleep(0.5)
        # Exit early if the attacker terminated (duration_elapsed) AND we've
        # given benign traffic a chance to settle.
        attacker_done = all(
            p.poll() is not None
            for name, p in procs
            if name in ("attacker", "spoofer")
        )
        if attacker_done and time.monotonic() > deadline - 1.0:
            break

    # Stop everything gracefully.
    info("*** harness: terminating workloads\n")
    for name, p in procs:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    time.sleep(0.5)
    for name, p in procs:
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass

    info("*** harness: scenario complete\n")


def car_network():
    cfg = _load_config()
    net, hosts = _build_net(cfg)

    info("*** starting network\n")
    net.start()

    mode = os.environ.get("TOPO_MODE", "cli").strip()

    if mode == "harness":
        try:
            _run_harness(net, hosts, cfg)
        finally:
            info("*** stopping network\n")
            net.stop()
        return

    # Interactive mode: quick connectivity check, then CLI.
    info("*** testing connectivity\n")
    try:
        net.pingAll()
    except Exception as e:
        info(f"*** pingAll error: {e}\n")

    info("*** entering CLI (type 'exit' to quit)\n")
    CLI(net)

    info("*** stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    car_network()
