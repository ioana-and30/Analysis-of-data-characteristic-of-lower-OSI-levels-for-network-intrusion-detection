import random
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import wrpcap
import time


def generate_attack(filename="data_sets/licenta.pcap"):
    packets = []

    GATEWAY_MAC = "aa:bb:cc:00:00:01"
    GATEWAY_IP = "192.168.10.1"
    ATTACKER_MAC = "de:ad:be:ef:00:01"
    VICTIM_MAC = "00:11:22:33:44:01"
    VICTIM_IP = "192.168.10.101"

    packets.append(
        Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=VICTIM_MAC, psrc=VICTIM_IP, pdst=GATEWAY_IP))
    packets.append(
        Ether(src=GATEWAY_MAC, dst=VICTIM_MAC) / IP(src=GATEWAY_IP, dst=VICTIM_IP) / UDP(sport=67, dport=68) / BOOTP(
            op=2, chaddr=bytes.fromhex(VICTIM_MAC.replace(':', ''))) / DHCP(options=[("message-type", "offer"), "end"]))

    rogue_mac = "de:ad:be:ef:00:02"
    packets.append(Ether(src=rogue_mac, dst=VICTIM_MAC) / IP(src="192.168.10.250", dst=VICTIM_IP) / UDP(sport=67,
                                                                                                        dport=68) / BOOTP(
        op=2, chaddr=bytes.fromhex(VICTIM_MAC.replace(':', ''))) / DHCP(options=[("message-type", "offer"), "end"]))

    packets.append(
        Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GATEWAY_IP, hwdst=VICTIM_MAC,
                                                      pdst=VICTIM_IP))

    for i in range(25):
        target_ip = f"192.168.10.{i + 2}"
        packets.append(
            Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=ATTACKER_MAC, psrc="192.168.10.200",
                                                                   pdst=target_ip))

    starve_mac = "00:aa:bb:cc:dd:ee"
    for i in range(110):
        packets.append(
            Ether(src=starve_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68,
                                                                                                            dport=67) / BOOTP(
                chaddr=bytes.fromhex(starve_mac.replace(':', ''))) / DHCP(
                options=[("message-type", "discover"), "end"]))

    curr_time = time.time()
    for i, p in enumerate(packets):
        p.time = curr_time + (i * 0.01)

    wrpcap(filename, packets)

if __name__ == "__main__":
    generate_attack()