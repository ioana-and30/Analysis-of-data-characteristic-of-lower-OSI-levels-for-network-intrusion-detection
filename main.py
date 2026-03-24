from datetime import datetime

from scapy.arch import L2Socket
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from sigma_backend.sigma_detector import SigmaDetector
from traffic_capture.logs import save_log
from traffic_capture.sniff_arp import extractARP
from traffic_capture.sniff_dhcp import extractDHCP

detector=SigmaDetector("sigma_rules")

def packet_handler(packet):
    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data=None
    filename=""

    if packet.haslayer(DHCP):
        data=extractDHCP(packet)
        if data:
            data["protocol"]="DHCP"
            filename="dhcp_logs.json"

    elif packet.haslayer(ARP):
        data=extractARP(packet)
        if data:
            data["protocol"]="ARP"
            filename="arp_logs.json"

    if data:
        data["timestamp"]=timestamp
        detector.analyze(data)
        save_log(data,filename)

        print(f"[{timestamp}] {data['protocol']} captured")

if __name__=="__main__":

    print("Starting ..")

    sniff(
        iface="ens7",
        filter="arp or (udp and( port 67 or port 68))",
        prn=packet_handler,
        store=0,
        promisc=True,
        L2socket=L2Socket
    )

