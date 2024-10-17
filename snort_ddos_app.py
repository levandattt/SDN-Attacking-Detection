import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import socket
import json
import threading
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway

from collections import defaultdict

class SnortDDoSApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Prometheus metrics registry
    registry = CollectorRegistry()

    # General attack metrics
    attacks_detected = Counter(
        'ddos_attacks_detected', 'Number of DDoS attacks detected', registry=registry
    )
    tcp_attacks = Counter(
        'tcp_attacks_detected', 'Number of TCP-based attacks detected', registry=registry
    )
    icmp_attacks = Counter(
        'icmp_attacks_detected', 'Number of ICMP-based attacks detected', registry=registry
    )
    blocked_ips = Counter(
        'ips_blocked', 'Number of IP addresses blocked', registry=registry
    )
    current_blocked_ips = Gauge(
        'current_blocked_ips', 'Number of currently blocked IPs', registry=registry
    )
    top_source_ips = Counter(
        'top_source_ips', 'Attack count per source IP', ['src_ip'], registry=registry
    )

    def __init__(self, *args, **kwargs):
        super(SnortDDoSApp, self).__init__(*args, **kwargs)
        self.snort_listener_thread = threading.Thread(target=self.listen_to_snort)
        self.snort_listener_thread.start()

        # Track blocked IPs and data paths
        self.blocked_ips_dict = defaultdict(int)
        self.datapaths = {}
        self.pushgateway_url= 'localhost:9001'

    def listen_to_snort(self):
        log_file_path = "alert_json.txt"
        with open(log_file_path, "r") as f:
            f.seek(0, 2)  # Move to the end of the file

            while True:
                line = f.readline()
                if line:
                    try:
                        alert_info = json.loads(line.strip())
                        self.handle_alert(alert_info)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"JSON decoding failed: {e}, data: {line.strip()}")
                else:
                    time.sleep(1)

    def handle_alert(self, alert_info):
        # Increment general attack counter
        self.attacks_detected.inc()

        # Track top source IPs
        src_ip = alert_info.get("src_addr", "unknown")
        self.top_source_ips.labels(src_ip).inc()

        # Detect and increment protocol-specific counters
        protocol = alert_info.get("proto", "").lower()
        if protocol == "tcp":
            self.tcp_attacks.inc()
        elif protocol == "icmp":
            self.icmp_attacks.inc()

        # Block IP if needed
        if "attack" in alert_info.get("msg", "").lower() and src_ip not in self.blocked_ips_dict:
            self.logger.info(f"DDoS attack detected from {src_ip}. Blocking source...")
            self.block_ip(src_ip)
            self.blocked_ips.inc()
            self.blocked_ips_dict[src_ip] = True
            self.current_blocked_ips.set(len(self.blocked_ips_dict))

        self.push_metrics()

    def block_ip(self, src_ip):
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            mod = parser.OFPFlowMod(
                datapath=dp, priority=100, match=match,
                instructions=[parser.OFPInstructionActions(dp.ofproto.OFPIT_CLEAR_ACTIONS, [])]
            )
            dp.send_msg(mod)

    def push_metrics(self):
        try:
            push_to_gateway(self.pushgateway_url, job='snort_ddos_app', registry=self.registry)
            self.logger.info("Metrics pushed to Prometheus Pushgateway")
        except Exception as e:
            self.logger.error(f"Failed to push metrics: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == 'DEAD':
            del self.datapaths[datapath.id]
