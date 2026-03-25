from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import wrpcap
import random

def generate_dhcp_attack(filename="data_sets/atac_dhcp.pcap", count=150):
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
    print(f"Creat {filename} cu {count} pachete.")


if __name__ == "__main__":
    generate_dhcp_attack()