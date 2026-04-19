from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet
from os_ken.lib import hub
import time

class IDSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats = {} #track stats
        
        self.POLL_INTERVAL = 2 #seconds
        self.PPS_THRESHOLD = 150 #dos threshold
        self.BLOCK_DURATION = 30 #block time

        self.monitor_thread = hub.spawn(self._monitor) #background thread

    def add_flow(self, datapath, priority, match, actions, hard_timeout=0):
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
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath #register datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"*** Switch connected: {datapath.id} ***")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions) #standard forward

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.POLL_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        current_time = time.time()

        for stat in body:
            if stat.priority in [0, 100]:
                continue #ignore default or blocked

            match_str = str(stat.match)
            flow_key = (dpid, match_str)
            packet_count = stat.packet_count

            if flow_key in self.flow_stats:
                prev_count, prev_time = self.flow_stats[flow_key]
                time_diff = current_time - prev_time

                if time_diff > 0:
                    pps = (packet_count - prev_count) / time_diff

                    if pps > self.PPS_THRESHOLD:
                        self.logger.warning(f"\n[ALERT] Volumetric DoS Detected! Rate: {pps:.2f} pps")
                        self.logger.warning(f"[ALERT] Compromised Flow: {match_str}")
                        self._mitigate_attack(datapath, stat.match)
                        
                        del self.flow_stats[flow_key] #stop tracking
                        continue

            self.flow_stats[flow_key] = (packet_count, current_time)

    def _mitigate_attack(self, datapath, match):
        parser = datapath.ofproto_parser
        
        inst = [] #drop packet
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst,
            hard_timeout=self.BLOCK_DURATION
        )
        datapath.send_msg(mod)
        self.logger.info(f"[DEFENSE] Flow isolated and dropped for {self.BLOCK_DURATION} seconds.\n")