from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as inet
from ryu.lib import dpid as dpid_lib

from threading import Thread, Lock
import os
import time
import json


class Controller(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")

    IP_FIELDS = ["ip_proto", "ipv4_src", "ipv4_dst"]
    ICMP_FIELDS = ["icmpv4_type", "icmpv4_code"]
    TCP_FIELDS = ["tcp_src", "tcp_dst"]
    UDP_FIELDS = ["udp_src", "udp_dst"]

    MAX_SYN = 20
    SYN_WINDOW_SECONDS = 10
    SYN_BAN_SECONDS = 60
    SYN_MUTEX = Lock()

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.parsed_rule_file = {}
        self.syn_track = {}

        self.parse_rules()

        # Background thread for Task 4 SYN flood defence
        self.clean_thread = Thread(target=self.cleanup_syntrack, daemon=True)
        self.clean_thread.start()

        # Background thread for Task 3 flow statistics
        self.stats_thread = Thread(target=self.poll_flow_stats, daemon=True)
        self.stats_thread.start()

    ###
    # Event Handlers
    ###

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_features_request(self, ev):
        ''' Handle OF Features Request '''
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.install_entry_miss_mod(datapath)

        if datapath.id == 2:
            if not self.parsed_rule_file:
                self.parse_rules()
            self.install_firewall_rules(datapath)

        self.logger.info("Datapath Added")
        self.logger.debug("-- DPID : {}".format(dpid_lib.dpid_to_str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        ''' Handle OF Packet In Event '''
        self.logger.debug("Packet In Event")

        datapath = ev.msg.datapath
        dpid = datapath.id
        in_port = ev.msg.match["in_port"]
        data = ev.msg.data
        buffer_id = ev.msg.buffer_id

        if dpid == 2:
            self.firewall(datapath, in_port, data, buffer_id)
        else:
            self.switch(datapath, in_port, data, buffer_id)

    # Task 3:
    # This handler should process the statistics replies returned by the switch
    # after a flow statistics request has been sent.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def handle_stats_response(self, ev):
        ''' Handle the OF Flow Stats Response '''
        dpid = dpid_lib.dpid_to_str(ev.msg.datapath.id)
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue

            if hasattr(stat.match, "items"):
                match_dict = dict(stat.match.items())
            else:
                match_dict = {}

            self.logger.info(
                "Flow stats dpid=%s match=%s packets=%d bytes=%d",
                dpid,
                match_dict,
                stat.packet_count,
                stat.byte_count,
            )

    ###
    # Shared Functions
    ###

    def install_flow_mod(self, datapath, priority, match, actions=None, i_timeout=60, h_timeout=0):
        if actions is None:
            actions = []
        instructions = [datapath.ofproto_parser.OFPInstructionActions(
                            datapath.ofproto.OFPIT_APPLY_ACTIONS,
                            actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=instructions, idle_timeout=i_timeout,
                                hard_timeout=h_timeout)
        datapath.send_msg(mod)
        self.logger.debug("Flow-Mod Written")

    def install_entry_miss_mod(self, datapath):
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(
                        datapath.ofproto.OFPP_CONTROLLER,
                        datapath.ofproto.OFPCML_NO_BUFFER)]
        self.install_flow_mod(datapath, 0, match, actions, 0, 0)

    def add_l2_mapping(self, datapath_id, pkt, in_port):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        self.mac_to_port.setdefault(datapath_id, {})
        self.mac_to_port[datapath_id][eth_header.src] = in_port

    def use_l2_mapping(self, datapath, pkt):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        out_port = datapath.ofproto.OFPP_FLOOD
        install = False
        if eth_header.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth_header.dst]
            install = True
        return [datapath.ofproto_parser.OFPActionOutput(out_port)], install

    def send_packet_out(self, datapath, in_port, actions, data, buffer_id):
        packet_data = data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=packet_data,
        )
        datapath.send_msg(out)

    def l2_match_from_packet(self, datapath, pkt, in_port):
        eth_h = pkt.get_protocol(ethernet.ethernet)
        return datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            eth_type=eth_h.ethertype,
            eth_src=eth_h.src,
            eth_dst=eth_h.dst,
        )

    def packet_fields_from_packet(self, pkt):
        fields = {}
        eth_h = pkt.get_protocol(ethernet.ethernet)
        if eth_h is None:
            return fields

        fields["eth_type"] = eth_h.ethertype
        fields["eth_src"] = eth_h.src
        fields["eth_dst"] = eth_h.dst

        if eth_h.ethertype != ether_types.ETH_TYPE_IP:
            return fields

        ip_h = pkt.get_protocol(ipv4.ipv4)
        if ip_h is None:
            return fields

        fields["ip_proto"] = ip_h.proto
        fields["ipv4_src"] = ip_h.src
        fields["ipv4_dst"] = ip_h.dst

        if ip_h.proto == inet.IPPROTO_TCP:
            tcp_h = pkt.get_protocol(tcp.tcp)
            if tcp_h is not None:
                fields["tcp_src"] = tcp_h.src_port
                fields["tcp_dst"] = tcp_h.dst_port
        elif ip_h.proto == inet.IPPROTO_UDP:
            udp_h = pkt.get_protocol(udp.udp)
            if udp_h is not None:
                fields["udp_src"] = udp_h.src_port
                fields["udp_dst"] = udp_h.dst_port
        elif ip_h.proto == inet.IPPROTO_ICMP:
            icmp_h = pkt.get_protocol(icmp.icmp)
            if icmp_h is not None:
                fields["icmpv4_type"] = icmp_h.type
                fields["icmpv4_code"] = icmp_h.code

        return fields

    ###
    # Layer 4 Switch Functions
    ###

    def switch(self, datapath, in_port, data, buffer_id):
        '''Handles L4 Switch Packet In Events'''
        pkt = packet.Packet(data)
        eth_h = pkt.get_protocol(ethernet.ethernet)
        if eth_h is None or eth_h.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.add_l2_mapping(datapath.id, pkt, in_port)
        actions, install = self.use_l2_mapping(datapath, pkt)

        if install:
            match = self.ofmatch_from_packet(datapath, pkt, in_port)
            self.install_flow_mod(datapath, 10, match, actions)

        self.send_packet_out(datapath, in_port, actions, data, buffer_id)


    def ofmatch_from_packet(self, datapath, pkt, in_port):
        match_dict = {}
        match_dict["in_port"] = in_port
        eth_h = pkt.get_protocol(ethernet.ethernet)
        match_dict["eth_type"] = eth_h.ethertype
        match_dict["eth_src"] = eth_h.src
        match_dict["eth_dst"] = eth_h.dst
        if eth_h.ethertype == ether_types.ETH_TYPE_IP:
            ip_h = pkt.get_protocol(ipv4.ipv4)
            match_dict["ip_proto"] = ip_h.proto
            match_dict["ipv4_src"] = ip_h.src
            match_dict["ipv4_dst"] = ip_h.dst
            if ip_h.proto == inet.IPPROTO_TCP:
                tcp_h = pkt.get_protocol(tcp.tcp)
                match_dict["tcp_src"] = tcp_h.src_port
                match_dict["tcp_dst"] = tcp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_UDP:
                udp_h = pkt.get_protocol(udp.udp)
                match_dict["udp_src"] = udp_h.src_port
                match_dict["udp_dst"] = udp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_ICMP:
                icmp_h = pkt.get_protocol(icmp.icmp)
                match_dict["icmpv4_type"] = icmp_h.type
                match_dict["icmpv4_code"] = icmp_h.code
        return datapath.ofproto_parser.OFPMatch(**match_dict)

    ###
    # Firewall Functions
    ###

    def firewall(self, datapath, in_port, data, buffer_id):
        ''' Handles Firewall Packet In Events '''
        pkt = packet.Packet(data)
        eth_h = pkt.get_protocol(ethernet.ethernet)
        if eth_h is None or eth_h.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.add_l2_mapping(datapath.id, pkt, in_port)
        packet_fields = self.packet_fields_from_packet(pkt)

        ip_src = packet_fields.get("ipv4_src")
        ip_proto = packet_fields.get("ip_proto")

        # (1) SYN flood ban check and tracking
        if ip_src is not None and ip_proto == inet.IPPROTO_TCP:
            tcp_h = pkt.get_protocol(tcp.tcp)
            now = time.time()

            with self.SYN_MUTEX:
                state = self.syn_track.setdefault(ip_src, {"timestamps": [], "ban_until": 0})

                if state["ban_until"] > now:
                    remaining = max(1, int(state["ban_until"] - now))
                    match = datapath.ofproto_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_src,
                    )
                    self.install_flow_mod(
                        datapath,
                        300,
                        match,
                        actions=[],
                        i_timeout=0,
                        h_timeout=remaining,
                    )
                    return

                state["timestamps"] = [
                    ts for ts in state["timestamps"] if now - ts <= self.SYN_WINDOW_SECONDS
                ]

                is_syn = (tcp_h.bits & tcp.TCP_SYN) and not (tcp_h.bits & tcp.TCP_ACK)
                if is_syn:
                    state["timestamps"].append(now)
                    if len(state["timestamps"]) > self.MAX_SYN:
                        state["ban_until"] = now + self.SYN_BAN_SECONDS
                        state["timestamps"] = []
                        match = datapath.ofproto_parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_src,
                        )
                        self.install_flow_mod(
                            datapath,
                            300,
                            match,
                            actions=[],
                            i_timeout=0,
                            h_timeout=self.SYN_BAN_SECONDS,
                        )
                        self.logger.warning(
                            "SYN flood ban applied to %s for %ss",
                            ip_src,
                            self.SYN_BAN_SECONDS,
                        )
                        return

        # (2) Firewall deny rules
        dpid = dpid_lib.dpid_to_str(datapath.id)
        rules = self.parsed_rule_file.get(dpid, {}).get("rules", [])

        for rule in rules:
            if all(packet_fields.get(key) == value for key, value in rule.items()):
                match = self.ofmatch_from_dict(rule)
                self.install_flow_mod(datapath, 200, match, actions=[], i_timeout=0, h_timeout=0)
                self.logger.info("Firewall denied packet by rule on dpid=%s: %s", dpid, rule)
                return

        # (3) Not denied -> learning forward
        actions, _ = self.use_l2_mapping(datapath, pkt)
        self.send_packet_out(datapath, in_port, actions, data, buffer_id)

    # Students should decide where to call parse_rules(), for example
    # when the controller starts or when the firewall datapath connects.
    def parse_rules(self):
        '''parse the rule file into the self.parsed_rule_file'''
        try:
            with open(self.RULES_FILE, "r", encoding="utf-8") as rule_file:
                parsed = json.load(rule_file)
            self.parsed_rule_file = parsed.get("datapath", {})
            self.logger.info("Loaded firewall rules from %s", self.RULES_FILE)
        except Exception as exc:
            self.parsed_rule_file = {}
            self.logger.error("Failed to parse firewall rules file %s: %s", self.RULES_FILE, exc)

    def install_firewall_rules(self, datapath):
        dpid = dpid_lib.dpid_to_str(datapath.id)
        rules = self.parsed_rule_file.get(dpid, {}).get("rules", [])
        for rule in rules:
            match = self.ofmatch_from_dict(rule)
            self.install_flow_mod(datapath, 200, match, actions=[], i_timeout=0, h_timeout=0)
        if rules:
            self.logger.info("Installed %d firewall deny rules on dpid=%s", len(rules), dpid)

    def ofmatch_from_dict(self, match_dict):
        ''' convert a dict/json rule to a match '''
        ## Converts a Python dictionary from JSON into an OpenFlow match ##
        return OFPMatch(**match_dict)

    def cleanup_syntrack(self):
        while True:
            now = time.time()
            with self.SYN_MUTEX:
                for src_ip in list(self.syn_track.keys()):
                    state = self.syn_track[src_ip]
                    state["timestamps"] = [
                        ts for ts in state["timestamps"] if now - ts <= self.SYN_WINDOW_SECONDS
                    ]
                    if state["ban_until"] <= now:
                        state["ban_until"] = 0
                    if not state["timestamps"] and state["ban_until"] == 0:
                        del self.syn_track[src_ip]
            time.sleep(1)

    def poll_flow_stats(self):
        while True:
            for dpid in (1, 2, 3):
                datapath = self.datapaths.get(dpid)
                if datapath is not None:
                    self.request_flow_stats(datapath, datapath.ofproto_parser.OFPMatch())
            time.sleep(5)

    # Task 3:
    # Students should decide when flow statistics requests are sent.
    # A simple approach is to send requests periodically during runtime.
    def request_flow_stats(self, datapath, ofmatch):
        ## Make and send the Flow Stats Request for Task 3 ##
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        req = parser.OFPFlowStatsRequest(
            datapath=datapath,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=ofmatch,
        )
        datapath.send_msg(req)
