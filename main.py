from datetime import datetime

from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from sigma_processing.sigma_backend import SigmaBackend
from traffic_capture.logs import save_log
from traffic_capture.sniff_arp import extractARP
from traffic_capture.sniff_dhcp import extractDHCP

detector=SigmaBackend("sigma_rules")

def packet_handler(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = None
    filename = ""

    if packet.haslayer(DHCP):
        data = extractDHCP(packet)
        filename = "dhcp_logs.json"

    elif packet.haslayer(ARP):
        data = extractARP(packet)
        filename = "arp_logs.json"

    if data:
        data["timestamp"] = timestamp

        is_alert = detector.analyze(data)

        if is_alert:
            print(f"\n[!!!] ALERT: {data.get('sigma_rule_name')} [!!!]")

        save_log(data, filename)
        print(f"[{timestamp}] {data['protocol']} captured")

if __name__=="__main__":

    print("Starting ..")

    # sniff(
    #     iface="ens7",
    #     filter="arp or (udp and( port 67 or port 68))",
    #     prn=packet_handler,
    #     store=0,
    #     promisc=True,
    #     L2socket=L2Socket
    # )
    sniff(offline="data_sets/atac_dhcp.pcap",
          filter="udp and (port 67 or port 68)",
          prn=packet_handler,
          store=0
    )