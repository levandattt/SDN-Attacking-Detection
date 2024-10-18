import time
import json
import threading
from collections import defaultdict
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway

class SnortDDoSApp:
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

    def __init__(self, pushgateway_url='localhost:9001', log_file="alert_json.txt"):
        self.pushgateway_url = pushgateway_url
        self.log_file = log_file

        # Track blocked IPs
        self.blocked_ips_dict = defaultdict(int)

        # Start thread to listen to Snort alerts
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
            print(f"DDoS attack detected from {src_ip}. Blocking source...")
            self.blocked_ips.inc()
            self.blocked_ips_dict[src_ip] = True
            self.current_blocked_ips.set(len(self.blocked_ips_dict))

        # Push metrics to Prometheus Pushgateway
        self.push_metrics()

    def push_metrics(self):
        try:
            push_to_gateway(self.pushgateway_url, job='snort_ddos_app', registry=self.registry)
            print("Metrics successfully pushed to Prometheus Pushgateway")
        except Exception as e:
            print(f"Failed to push metrics: {e}")


# Usage
if __name__ == "__main__":
    app = SnortDDoSApp()
    print("Aggregator has started")
