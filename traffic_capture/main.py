import json
import os
import sys
from datetime import datetime

from parso.normalizer import Rule
from scapy.arch import L2Socket
from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP
from scapy.layers.dhcp import DHCP

from sigma_rules.sigma_engine import SigmaEngine
from sniff_arp import extractARP
from sniff_dhcp import extractDHCP

LOG_DIR="traffic_logs"
RULE_DIR="sigma_rules"

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

def save_log(data, filename):
    filepath = os.path.join(LOG_DIR, filename)
    logs = []

    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                logs = json.load(f)
        except:
            logs = []

    logs.append(data)
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=4)

def packet_handler(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(DHCP):
        data = extractDHCP(packet)
        if data:
            data["timestamp"] = timestamp
            print(f"[{timestamp}] DHCP capture")
            save_log(data, "dhcp_logs.json")

    elif packet.haslayer(ARP):
        data = extractARP(packet)
        if data:
            data["timestamp"] = timestamp
            print(f"[{timestamp}] ARP capture")
            save_log(data, "arp_logs.json")


if __name__ == "__main__":
    print("Starting monitoring ..")

    engine = SigmaEngine(RULE_DIR)
    engine.load_rules(RULE_DIR)
    engine.print_rules()
    sniff(
        iface="ens4",
        filter="arp or (udp and (port 67 or port 68))",
        prn=packet_handler,
        store=0,
        promisc=True,
        L2socket=L2Socket
    )
