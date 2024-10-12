import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp
import socket
import json
import threading

class SnortDDoSApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SnortDDoSApp, self).__init__(*args, **kwargs)
        self.snort_socket_path = "/tmp/snort_alert"
        self.snort_listener_thread = threading.Thread(target=self.listen_to_snort)
        self.snort_listener_thread.start()

    # def listen_to_snort(self):
    #     # Create a UNIX socket for listening to Snort alerts
    #     sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    #     print("socket", self.snort_socket_path, "listening")
        
    #     sock.bind(self.snort_socket_path)
        
    #     while True:
    #         data = sock.recv(2048)
    #         if data:
    #             self.logger.info(f"Snort alert received: {data}")
    #             alert_info = json.loads(data.decode('utf-8',  errors='ignore'))
    #             self.handle_alert(alert_info)
    

    def listen_to_snort(self):
        log_file_path = "/tmp/snort_alert.log"
        
        # Open the log file in read mode and seek to the end to get only new entries
        with open(log_file_path, "r") as f:
            f.seek(0, 2)  # Move to the end of the file
            
            while True:
                line = f.readline()
                if line:
                    self.logger.info(f"Snort alert received: {line.strip()}")
                    try:
                        # Assuming Snort logs alerts in JSON format; adjust if the format is different
                        alert_info = json.loads(line.strip())
                        self.handle_alert(alert_info)
                        time.sleep(1)  # Wait before reading the next line
                    except json.JSONDecodeError as e:
                        self.logger.error(f"JSON decoding failed: {e}, data: {line.strip()}")
                else:
                    time.sleep(1)  # No new data; wait before trying again


    def handle_alert(self, alert_info):
        # This function processes the alert and takes action if needed
        if "attack" in alert_info.get("msg", "").lower():
            src_ip = alert_info.get("src_ip")
            self.logger.info(f"DDoS attack detected from {src_ip}. Blocking source...")
            self.block_ip(src_ip)

    def block_ip(self, src_ip):
        # Blocking traffic from the source IP detected as malicious
        datapaths = list(self.datapaths.values())
        for dp in datapaths:
            parser = dp.ofproto_parser
            match = parser.OFPMatch(ipv4_src=src_ip)
            actions = []
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_CLEAR_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst)
            dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.logger.info(f"Registering datapath: {datapath.id}")
            self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            self.logger.info(f"Unregistering datapath: {datapath.id}")
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
