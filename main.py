from datetime import datetime

from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from sigma_processing.sigma_backend import SigmaBackend
from traffic_capture.logs import save_log
from traffic_capture.sniff_arp import extractARP
from traffic_capture.sniff_dhcp import extractDHCP

detector=SigmaBackend("sigma_rules")
packet_id=1
def packet_handler(packet):

    global packet_id
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    data = None
    filename = ""

    if packet.haslayer(DHCP):
        data = extractDHCP(packet)
        filename = "dhcp_logs.json"
        data["id"]='DHCP'+str(packet_id)
        packet_id+=1

    elif packet.haslayer(ARP):
        data = extractARP(packet)
        filename = "arp_logs.json"
        data["id"] = 'ARP'+str(packet_id)
        packet_id += 1

    if data:
        data["timestamp"] = timestamp

        is_alert = detector.analyze(data)

        if not is_alert:
            print(f"[{timestamp}] Packet {data['id']} captured")

        save_log(data, filename)

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

    #
    # sniff(offline="data_sets/atac_arp.pcap",
    #       filter="arp",
    #       prn=packet_handler,
    #       store=0
    #       )