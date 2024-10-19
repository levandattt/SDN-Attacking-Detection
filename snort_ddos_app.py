import time
import json
import threading
from collections import defaultdict
import requests  # For sending logs to Loki
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway, Histogram, Summary


class SnortDDoSApp:
    registry = CollectorRegistry()

    # Prometheus metrics
    attacks_detected = Counter('ddos_attacks_detected', 'Total number of DDoS attacks', registry=registry)
    protocol_attacks = Counter('protocol_attacks', 'Number of attacks by protocol', ['proto'], registry=registry)
    attack_messages = Counter('attack_messages', 'Count of attack messages', ['msg'], registry=registry)
    blocked_ips = Counter('ips_blocked', 'Number of IPs blocked', registry=registry)
    current_blocked_ips = Gauge('current_blocked_ips', 'Currently blocked IPs', registry=registry)
    top_source_ips = Counter('top_source_ips', 'Attack count by source IP', ['src_ip'], registry=registry)
    top_destination_ips = Counter('top_destination_ips', 'Attack count by destination IP', ['dst_ip'],
                                  registry=registry)
    active_source_ips = Gauge('active_source_ips', 'Number of currently active attacking source IPs', registry=registry)

    # Histograms and Summaries
    packet_size_histogram = Histogram('packet_size_bytes', 'Packet size distribution in bytes',
                                      buckets=[100, 500, 1000, 5000, 10000, 50000], registry=registry)
    attack_duration_histogram = Histogram('attack_duration_seconds', 'Attack duration in seconds',
                                          buckets=[0.5, 1, 5, 10, 30, 60, 120], registry=registry)
    alert_handling_latency = Summary('alert_handling_latency_seconds', 'Latency of alert handling in seconds',
                                     registry=registry)
    attack_message_summary = Summary('attack_message_summary', 'Summary of attack message distribution', ['msg'],
                                     registry=registry)

    def __init__(self, pushgateway_url='localhost:9001', loki_url="http://localhost:3100", log_file="alert_json.txt"):
        self.pushgateway_url = pushgateway_url
        self.loki_url = loki_url  # Loki URL
        self.log_file = log_file
        self.blocked_ips_dict = defaultdict(int)
        self.active_ips = set()
        self.attack_start_times = {}

        # Start Snort listener thread
        self.snort_listener_thread = threading.Thread(target=self.listen_to_snort)
        self.snort_listener_thread.start()

    def listen_to_snort(self):
        with open(self.log_file, "r") as f:
            f.seek(0, 2)  # Move to the end of the file
            while True:
                line = f.readline()
                if line:
                    try:
                        alert_info = json.loads(line.strip())
                        self.handle_alert(alert_info)
                    except json.JSONDecodeError as e:
                        print(f"JSON decoding failed: {e}, data: {line.strip()}")
                else:
                    time.sleep(1)

    def handle_alert(self, alert_info):
        start_time = time.time()  # Start latency measurement

        # Extract necessary information
        src_ip = alert_info.get("src_addr", "unknown")
        dst_ip = alert_info.get("dst_addr", "unknown")
        msg = alert_info.get("msg", "unknown")
        proto = alert_info.get("proto", "unknown").lower()
        packet_size = alert_info.get("pkt_len", 0)

        # Update metrics
        self.attacks_detected.inc()
        self.top_source_ips.labels(src_ip).inc()
        self.top_destination_ips.labels(dst_ip).inc()
        self.protocol_attacks.labels(proto).inc()
        self.attack_messages.labels(msg).inc()
        self.packet_size_histogram.observe(packet_size)

        # Log to Loki
        self.log_to_loki(f"Alert received: {msg}", src_ip, dst_ip, proto, packet_size)

        # Block IP if necessary
        if "attack" in msg.lower() and src_ip not in self.blocked_ips_dict:
            print(f"Blocking IP: {src_ip}")
            self.blocked_ips.inc()
            self.blocked_ips_dict[src_ip] = True
            self.current_blocked_ips.set(len(self.blocked_ips_dict))

        if src_ip not in self.active_ips:
            print(f"New attack detected from {src_ip}")
            self.active_ips.add(src_ip)
            self.active_source_ips.inc()

        latency = time.time() - start_time
        self.alert_handling_latency.observe(latency)
        self.attack_message_summary.labels(msg).observe(1)
        self.push_metrics()

    def log_to_loki(self, message, src_ip, dst_ip, proto, packet_size):
        """Send log messages to Loki."""
        log_entry = {
            "streams": [
                {
                    "stream": {
                        "job": "alert-job",
                        "level": "info"
                    },
                    "values": [
                        [str(int(time.time() * 1e9)),
                         message + ", src ip: " + str(src_ip) + ", dest ip: " + str(dst_ip)]
                    ]
                }
            ]
        }

        print(log_entry)
        try:
            response = requests.post(f"{self.loki_url}/loki/api/v1/push", json=log_entry)
            if response.status_code == 204:
                print("Log successfully sent to Loki")
            else:
                print(f"Failed to send log to Loki: {response.text}")
        except Exception as e:
            print(f"Error sending log to Loki: {e}")

    def end_attack(self, src_ip):
        """Record the duration of an attack when it ends."""
        if src_ip in self.attack_start_times:
            start_time = self.attack_start_times.pop(src_ip)
            duration = time.time() - start_time
            self.attack_duration_histogram.observe(duration)
            print(f"Attack from {src_ip} ended. Duration: {duration} seconds")

            if src_ip in self.active_ips:
                self.active_ips.remove(src_ip)
                self.active_source_ips.dec()

    def push_metrics(self):
        """Push metrics to Prometheus Pushgateway."""
        try:
            push_to_gateway(self.pushgateway_url, job='attack_alert', registry=self.registry)
            print("Metrics successfully pushed to Prometheus Pushgateway")
        except Exception as e:
            print(f"Failed to push metrics: {e}")


# Usage
if __name__ == "__main__":
    app = SnortDDoSApp()
    print("Aggregator has started")
