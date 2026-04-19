#!/usr/bin/env python3
"""SDN controller for automotive-Ethernet experiments.

Provides three operational modes, selected via ``sdn.defense_mode`` in
``config.yaml`` (or overridden through the ``EE122_CONFIG`` env var):

* ``off``              - plain L2 learning switch (baseline scenarios)
* ``detect_only``      - L2 learning + detection, but no mitigation
* ``detect_mitigate``  - L2 learning + detection + install drop rules

Detection is flow-stats + packet-in based: every ``poll_interval_ms`` we
aggregate per-``eth_src`` pps (flow stat deltas + unflooded packet-ins)
and per-``in_port`` packet-in rate. A source exceeding
``threshold_pps`` for ``consecutive_windows`` consecutive windows is
marked malicious. For ``detect_mitigate`` we install a priority-100
drop flow matching ``eth_src``, plus a port-isolation drop flow on the
offending ``in_port`` (this catches many-identity spoofing).

Logs written under ``$EXP_LOG_DIR`` (or ``<output_dir>/controller_run``):

* ``controller_stats.csv``   - one row per poll interval
* ``controller_events.csv``  - switch_connected / detect / mitigate events
"""

import csv
import json
import os
import time
from collections import defaultdict
from pathlib import Path

import yaml

try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, packet


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def _load_config():
    path = Path(os.environ.get("EE122_CONFIG", str(_DEFAULT_CONFIG_PATH)))
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _match_get(match, key):
    """Best-effort extraction of a field from an OFPMatch across os-ken versions."""
    try:
        return match.get(key)
    except Exception:
        pass
    try:
        for k, v in match.items():
            if k == key:
                return v
    except Exception:
        pass
    return None


class SDNDefense(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cfg = _load_config()
        sdn = cfg.get("sdn") or {}

        self.defense_mode = str(sdn.get("defense_mode", "off")).strip()
        if self.defense_mode not in ("off", "detect_only", "detect_mitigate"):
            self.logger.warning(
                "[sdn] unknown defense_mode=%r; falling back to 'off'",
                self.defense_mode,
            )
            self.defense_mode = "off"

        self.poll_interval_s = float(sdn.get("poll_interval_ms", 500)) / 1000.0
        self.threshold_pps = float(sdn.get("threshold_pps", 500))
        self.consecutive_windows = int(sdn.get("consecutive_windows", 2))
        self.inject_controller_delay_s = (
            float(sdn.get("inject_controller_delay_ms", 0)) / 1000.0
        )
        self.drop_priority = int(sdn.get("drop_priority", 100))
        # Many-identity spoof detection: if more than this many distinct
        # source MACs arrive on the same ingress port within the sliding
        # window, flag the port. One ECU has one MAC, so 5+ distinct MACs
        # is a strong spoofing signal regardless of pps.
        self.novel_mac_window_s = float(sdn.get("novel_mac_window_s", 3.0))
        self.novel_mac_threshold = int(sdn.get("novel_mac_threshold", 5))

        # L2 learning state.
        self.mac_to_port = {}
        self.datapaths = {}

        # Accounting state.
        self.prev_flow_pkts_by_src = defaultdict(int)
        self.prev_flow_pkts_by_port = defaultdict(int)  # (dpid, in_port) -> packets
        self.pktin_count_by_src = defaultdict(int)
        self.prev_pktin_count_by_src = defaultdict(int)
        self.pktin_count_by_port = defaultdict(int)
        self.prev_pktin_count_by_port = defaultdict(int)
        self.pktin_total = 0
        self.prev_pktin_total = 0
        self.last_poll_mono = None

        # Detection bookkeeping.
        self.violation_count = defaultdict(int)
        self.t_first_violation = {}
        self.t_detect = {}
        self.t_rule_installed = {}
        self.mitigated_macs = set()
        self.mitigated_ports = set()  # (dpid, in_port)
        # Sliding-window tracking of MACs per port for novel-MAC detection.
        # (dpid, in_port) -> list of (mono_ts, mac)
        self.port_mac_history = defaultdict(list)

        # Output directory.
        exp_log_dir = os.environ.get("EXP_LOG_DIR")
        if exp_log_dir:
            self.run_dir = Path(exp_log_dir)
        else:
            base = cfg.get("logging", {}).get("output_dir", "logs")
            self.run_dir = Path(base) / "controller_run"
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.stats_path = self.run_dir / "controller_stats.csv"
        self.events_path = self.run_dir / "controller_events.csv"
        self._stats_fh = self.stats_path.open("w", newline="")
        self._events_fh = self.events_path.open("w", newline="")
        self._stats_w = csv.writer(self._stats_fh)
        self._events_w = csv.writer(self._events_fh)
        self._stats_w.writerow([
            "t_mono_s", "t_wall_iso",
            "flow_count", "total_flow_pkts", "total_flow_bytes",
            "packet_in_rate", "per_src_pps_json", "per_port_pktin_rate_json",
            "per_port_flow_pps_json", "distinct_mac_per_port_json",
            "cpu_percent", "mem_rss_mb",
        ])
        self._events_w.writerow([
            "t_mono_s", "event", "eth_src", "dpid", "in_port", "extra",
        ])
        self._stats_fh.flush()
        self._events_fh.flush()

        self._proc = psutil.Process() if _HAS_PSUTIL else None
        if self._proc is not None:
            try:
                self._proc.cpu_percent(None)  # prime the interval sampler
            except Exception:
                pass

        self.t_start_mono = time.monotonic()

        # Snapshot config into the run dir so results are self-describing.
        (self.run_dir / "controller_config.json").write_text(
            json.dumps(
                {
                    "defense_mode": self.defense_mode,
                    "poll_interval_s": self.poll_interval_s,
                    "threshold_pps": self.threshold_pps,
                    "consecutive_windows": self.consecutive_windows,
                    "inject_controller_delay_s": self.inject_controller_delay_s,
                    "drop_priority": self.drop_priority,
                },
                indent=2,
            )
        )

        self.logger.info(
            "[sdn] mode=%s threshold_pps=%.0f poll=%.3fs windows=%d run_dir=%s",
            self.defense_mode, self.threshold_pps, self.poll_interval_s,
            self.consecutive_windows, self.run_dir,
        )

        self._monitor_thread = hub.spawn(self._monitor)

    # ---------- logging helpers ----------

    def _now_off(self):
        return time.monotonic() - self.t_start_mono

    def _log_event(self, event, eth_src="", dpid="", in_port="", extra=""):
        self._events_w.writerow(
            [f"{self._now_off():.4f}", event, eth_src, dpid, in_port, extra]
        )
        self._events_fh.flush()

    # ---------- switch lifecycle ----------

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.datapaths[dp.id] = dp
                self._log_event("switch_up", dpid=dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self._log_event("switch_down", dpid=dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 0, match, actions)
        self._log_event("switch_connected", dpid=datapath.id)

    def _add_flow(self, datapath, priority, match, actions, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def _add_drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    # ---------- packet-in / L2 learning ----------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if self.inject_controller_delay_s > 0:
            hub.sleep(self.inject_controller_delay_s)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        self.pktin_total += 1
        self.pktin_count_by_src[src] += 1
        self.pktin_count_by_port[(dpid, in_port)] += 1
        self.port_mac_history[(dpid, in_port)].append((time.monotonic(), src))

        # If the source or the port has already been quarantined, install a
        # short-lived drop to cover any racing packet-ins and bail out.
        if src in self.mitigated_macs:
            self._add_drop_flow(
                datapath, self.drop_priority, parser.OFPMatch(eth_src=src)
            )
            return
        if (dpid, in_port) in self.mitigated_ports:
            self._add_drop_flow(
                datapath, self.drop_priority, parser.OFPMatch(in_port=in_port)
            )
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst, eth_src=src
            )
            self._add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # ---------- monitoring / detection ----------

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.poll_interval_s)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        now_mono = time.monotonic()
        now_off = now_mono - self.t_start_mono

        curr_pkts_by_src = defaultdict(int)
        curr_pkts_by_port = defaultdict(int)  # (dpid, in_port) -> total packets
        dpid = datapath.id
        flow_count = 0
        total_pkts = 0
        total_bytes = 0
        for stat in body:
            flow_count += 1
            total_pkts += stat.packet_count
            total_bytes += stat.byte_count
            src = _match_get(stat.match, "eth_src")
            if src is not None:
                curr_pkts_by_src[src] += stat.packet_count
            in_port = _match_get(stat.match, "in_port")
            if in_port is not None:
                curr_pkts_by_port[(dpid, int(in_port))] += stat.packet_count

        dt = (now_mono - self.last_poll_mono) if self.last_poll_mono else 0.0
        per_src_pps = {}
        per_port_pktin_rate = {}
        per_port_flow_pps = {}  # aggregate pps per ingress port, from flow stats
        packet_in_rate = 0.0
        if dt > 0:
            for src, pkts in curr_pkts_by_src.items():
                flow_delta = pkts - self.prev_flow_pkts_by_src.get(src, 0)
                if flow_delta < 0:
                    flow_delta = pkts
                pktin_curr = self.pktin_count_by_src.get(src, 0)
                pktin_delta = pktin_curr - self.prev_pktin_count_by_src.get(src, 0)
                if pktin_delta < 0:
                    pktin_delta = 0
                per_src_pps[src] = (flow_delta + pktin_delta) / dt
            # include sources that only show up in packet-ins (e.g. rotating spoof macs)
            for src, cnt in self.pktin_count_by_src.items():
                if src in per_src_pps:
                    continue
                pktin_delta = cnt - self.prev_pktin_count_by_src.get(src, 0)
                if pktin_delta > 0:
                    per_src_pps[src] = pktin_delta / dt
            for (d, port), cnt in self.pktin_count_by_port.items():
                delta = cnt - self.prev_pktin_count_by_port.get((d, port), 0)
                if delta > 0:
                    per_port_pktin_rate[f"{d}:{port}"] = delta / dt
            # Aggregate flow-stat pps per ingress port. This is the signal
            # that survives after per-flow rules install, so it catches
            # many-identity spoofing where pktin rate collapses to ~0.
            for (d, port), pkts in curr_pkts_by_port.items():
                prev = self.prev_flow_pkts_by_port.get((d, port), 0)
                delta = pkts - prev
                if delta < 0:
                    delta = pkts
                if delta > 0:
                    per_port_flow_pps[f"{d}:{port}"] = delta / dt
            packet_in_rate = (
                (self.pktin_total - self.prev_pktin_total) / dt
            )

        # Snapshot prev state AFTER we've computed deltas.
        self.prev_flow_pkts_by_src = dict(curr_pkts_by_src)
        self.prev_flow_pkts_by_port = dict(curr_pkts_by_port)
        self.prev_pktin_count_by_src = dict(self.pktin_count_by_src)
        self.prev_pktin_count_by_port = dict(self.pktin_count_by_port)
        self.prev_pktin_total = self.pktin_total
        self.last_poll_mono = now_mono

        # ----- detection -----
        if self.defense_mode in ("detect_only", "detect_mitigate"):
            # Per source MAC
            for src, pps in per_src_pps.items():
                if pps > self.threshold_pps:
                    self.violation_count[src] += 1
                    self.t_first_violation.setdefault(src, now_off)
                    if (
                        src not in self.t_detect
                        and self.violation_count[src] >= self.consecutive_windows
                    ):
                        self.t_detect[src] = now_off
                        self._log_event(
                            "detect",
                            eth_src=src,
                            dpid=datapath.id,
                            extra=f"pps={pps:.1f}",
                        )
                        if self.defense_mode == "detect_mitigate":
                            self._mitigate_mac(src, datapath)
                else:
                    if self.violation_count[src] > 0:
                        self.violation_count[src] -= 1

            # Novel-MAC-count per port: cheap signal for many-identity
            # spoofing, works regardless of pps.
            cutoff = now_mono - self.novel_mac_window_s
            for (d, port), entries in list(self.port_mac_history.items()):
                # Drop history older than the sliding window.
                pruned = [(t, m) for (t, m) in entries if t >= cutoff]
                self.port_mac_history[(d, port)] = pruned
                distinct = {m for (_, m) in pruned}
                if len(distinct) > self.novel_mac_threshold:
                    vkey = f"novelmac:{d}:{port}"
                    if vkey not in self.t_detect:
                        self.t_detect[vkey] = now_off
                        self._log_event(
                            "detect_port",
                            dpid=d,
                            in_port=port,
                            extra=(
                                f"novel_macs={len(distinct)}"
                                f" window_s={self.novel_mac_window_s:.1f}"
                            ),
                        )
                        if self.defense_mode == "detect_mitigate":
                            self._mitigate_port(d, port, datapath)

            # Per ingress port (catches many-identity spoofing). Combine
            # pktin rate (novel-MAC surface) and aggregate flow-stat rate
            # (bulk traffic after rules install). Whichever is higher wins.
            port_keys = set(per_port_pktin_rate) | set(per_port_flow_pps)
            for key in port_keys:
                rate = max(
                    per_port_pktin_rate.get(key, 0.0),
                    per_port_flow_pps.get(key, 0.0),
                )
                vkey = f"port:{key}"
                if rate > self.threshold_pps:
                    self.violation_count[vkey] += 1
                    if (
                        vkey not in self.t_detect
                        and self.violation_count[vkey] >= self.consecutive_windows
                    ):
                        self.t_detect[vkey] = now_off
                        dpid_s, port_s = key.split(":")
                        self._log_event(
                            "detect_port",
                            dpid=dpid_s,
                            in_port=port_s,
                            extra=(
                                f"port_pps={rate:.1f}"
                                f" pktin={per_port_pktin_rate.get(key,0.0):.1f}"
                                f" flow={per_port_flow_pps.get(key,0.0):.1f}"
                            ),
                        )
                        if self.defense_mode == "detect_mitigate":
                            self._mitigate_port(int(dpid_s), int(port_s), datapath)
                else:
                    if self.violation_count[vkey] > 0:
                        self.violation_count[vkey] -= 1

        # ----- stats row -----
        if self._proc is not None:
            try:
                cpu = self._proc.cpu_percent(None)
                mem = self._proc.memory_info().rss / (1024 * 1024)
            except Exception:
                cpu, mem = -1.0, -1.0
        else:
            cpu, mem = -1.0, -1.0

        distinct_mac_per_port = {
            f"{d}:{p}": len({m for (_, m) in entries})
            for (d, p), entries in self.port_mac_history.items()
            if entries
        }
        self._stats_w.writerow([
            f"{now_off:.4f}",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            flow_count, total_pkts, total_bytes,
            f"{packet_in_rate:.2f}",
            json.dumps({k: round(v, 2) for k, v in per_src_pps.items()}),
            json.dumps({k: round(v, 2) for k, v in per_port_pktin_rate.items()}),
            json.dumps({k: round(v, 2) for k, v in per_port_flow_pps.items()}),
            json.dumps(distinct_mac_per_port),
            f"{cpu:.2f}", f"{mem:.2f}",
        ])
        self._stats_fh.flush()

    # ---------- mitigation ----------

    def _mitigate_mac(self, eth_src, datapath):
        if eth_src in self.mitigated_macs:
            return
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=eth_src)
        self._add_drop_flow(datapath, self.drop_priority, match)
        self.mitigated_macs.add(eth_src)
        self.t_rule_installed[eth_src] = self._now_off()
        self._log_event(
            "mitigate_mac",
            eth_src=eth_src,
            dpid=datapath.id,
            extra=f"priority={self.drop_priority}",
        )

    def _mitigate_port(self, dpid, in_port, datapath):
        if (dpid, in_port) in self.mitigated_ports:
            return
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        self._add_drop_flow(datapath, self.drop_priority, match)
        self.mitigated_ports.add((dpid, in_port))
        key = f"port:{dpid}:{in_port}"
        self.t_rule_installed[key] = self._now_off()
        self._log_event(
            "mitigate_port",
            dpid=dpid,
            in_port=in_port,
            extra=f"priority={self.drop_priority}",
        )
