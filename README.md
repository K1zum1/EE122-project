# EE122-project: SDN-protected Automotive Ethernet

Team members: Jay Chong, Qamil Mirza

This repository implements and evaluates an SDN-based defense against a
compromised ECU on an in-vehicle Ethernet network. The network is
emulated in Mininet, traffic is generated with Scapy + Python sockets,
and the SDN controller is built on [os-ken](https://github.com/os-ken/os-ken).

The evaluation answers nine research questions covering baseline
vulnerability, detection accuracy, mitigation speed, selectivity,
overhead, intensity robustness, cross-attack generalization, controller
bottleneck behavior, and net security benefit.

## Topology

```
  attacker ---+
  spoofer  ---+
  benign1  ---+---> s1 (OVS, OpenFlow 1.3) <---> os-ken controller
  benign2  ---+
  probe    ---+
  victim   ---+
```

Each link is a TCLink with `topology.link_bw_mbps` / `topology.link_delay_ms`
from `src/config.yaml`.

## Quick start (on the Linux host)

```bash
# 1. one-time environment setup (requires apt + pip)
sudo apt install -y mininet openvswitch-switch python3-pip
pip3 install -r requirements.txt

# 2. verify everything is installed
scripts/check_env.sh

# 3. run the full matrix (~60-90 min, 30 scenarios x 3 trials)
sudo -E scripts/run_all.sh

# 4. produce plots, metrics.csv, and REPORT.md
python3 scripts/aggregate.py logs/<exp_id>
python3 scripts/generate_report.py logs/<exp_id>
```

The default `exp_id` is a UTC timestamp; override it as
`sudo -E scripts/run_all.sh my_exp 3`.

## Layout

```
src/
  controller.py       os-ken app: L2 learning + detection + mitigation
  topology.py         Mininet topology + in-process experiment harness
  udp_flood.py        flood attacker (constant / burst / ramp)
  spoof_attacker.py   spoofing attacker (single or many identities)
  benign_udp.py       low-rate benign UDP sender
  latency_probe.py    legitimate-traffic RTT probe
  victim_server.py    UDP sink + probe echo server
  config.yaml         base config (deep-merged with per-scenario overlays)
scripts/
  check_env.sh        environment verification
  gen_scenarios.py    regenerates scripts/scenarios/*.yaml
  merge_config.py     merges a scenario overlay into config.yaml
  run_scenario.sh     runs one scenario-trial (needs sudo)
  run_all.sh          runs the full matrix (needs sudo)
  aggregate.py        turns raw logs into metrics.csv + summary.json + plots/
  generate_report.py  assembles REPORT.md from summary.json
  scenarios/          one YAML per scenario, organized by research question
logs/
  <exp_id>/<scenario>/trial<k>/     one run's raw logs
  <exp_id>/metrics.csv              tidy long-format metrics
  <exp_id>/summary.json             aggregated means/stdevs per scenario
  <exp_id>/plots/*.png              per-RQ figures
  <exp_id>/REPORT.md                final write-up
```

## Per-run log files

Every scenario trial writes to its own directory. The aggregator tolerates
missing files so a partial run still produces a useful report.

- `config.effective.yaml`   base config + scenario overrides actually used
- `attacker_rate.csv`       per-sample flood rate
- `attacker_manifest.json`  flood attacker run metadata
- `attacker_summary.json`   flood attacker totals (sent, bytes, mean pps)
- `spoofer_rate.csv`        per-sample spoof rate (if spoof enabled)
- `spoofer_summary.json`    spoof attacker totals
- `benign1_rate.csv`,       benign sender send rates
- `benign2_rate.csv`
- `probe_rtt.csv`           per-probe RTT (seq, t_send, t_recv, rtt_ms, lost)
- `victim_rx.csv`           per-packet arrivals at the victim
- `controller_stats.csv`    per-poll controller stats (CPU, flows, pps)
- `controller_events.csv`   detection / mitigation event log
- `controller_config.json`  config snapshot as seen by the controller
- `attack_start.txt`        wall clock / monotonic at attack start
- `*.stdout` / `*_err`      per-host stdout / stderr (diagnostic)

## Defense modes

Change `sdn.defense_mode` in `config.yaml` or the scenario overlay:

- `off` - plain L2 learning switch; no detection, no mitigation
- `detect_only` - L2 learning + per-source pps detection, logs events but
  does not install drop flows
- `detect_mitigate` - as above, plus installs priority-100 drop flows on
  offending `eth_src` and offending `in_port`

Detection parameters live under `sdn.*`:

- `poll_interval_ms` - how often the controller polls flow stats
- `threshold_pps`    - per-source (or per-port) trigger
- `consecutive_windows` - number of consecutive windows above threshold
  before a detection fires
- `inject_controller_delay_ms` - artificial per-packet-in delay for RQ8

## Reproducing a single scenario

```bash
sudo -E scripts/run_scenario.sh scripts/scenarios/rq3_flood_med.yaml my_exp 0
python3 scripts/plot_run.py logs/my_exp/rq3_flood_med/trial0
```

## Project timeline

- 3/11 Proposal submission
- 4/08 Baseline network emulation + attacker testing
- 4/28 IDS performance poster presentation
- 5/10 Final extended abstract + code submission
