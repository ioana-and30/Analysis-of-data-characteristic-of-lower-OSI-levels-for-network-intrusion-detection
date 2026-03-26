from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import wrpcap
import random

def generate_dhcp_discover(filename="atac_dhcp.pcap", count=105):
    packets = []
    for i in range(count):
        rand_mac = "00:11:22:33:44:%02x" % (i % 255)
        ether = Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=rand_mac.replace(':', '').lower()[:12].encode(), xid=random.randint(1, 10 ** 8))
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        packets.append(ether / ip / udp / bootp / dhcp)

    wrpcap(filename, packets)


def generate_arp_requests(filename="atac_arp.pcap", count=30):
    packets = []
    source_mac = "00:0c:29:4f:8b:35"
    source_ip = "192.168.1.50"

    for i in range(count):
        target_ip = f"192.168.1.{i + 1}"

        ether = Ether(src=source_mac, dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(
            op=1,
            hwsrc=source_mac,
            psrc=source_ip,
            hwdst="00:00:00:00:00:00",
            pdst=target_ip
        )

        packets.append(ether / arp)
    wrpcap(filename, packets)
if __name__ == "__main__":
    generate_dhcp_discover()
    generate_arp_requests()