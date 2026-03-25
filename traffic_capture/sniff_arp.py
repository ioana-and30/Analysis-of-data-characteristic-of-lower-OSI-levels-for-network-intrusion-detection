import json
from scapy.sendrecv import sniff
from scapy.layers.l2 import Ether, ARP


ARP_OPTIONS={
    1:"REQUEST",
    2:"REPLY"
}

def extractARP(packet):
    extracted_data = {}

    arp_layer = packet.getlayer(ARP)
    operation = "REQUEST" if arp_layer.op == 1 else "REPLY"
    extracted_data = {
        "protocol": "ARP",
        "operation": "request" if arp_layer.op == 1 else "REPLY",
        "src_mac": arp_layer.hwsrc,
        "src_ip": arp_layer.psrc,
        "dst_mac": arp_layer.hwdst,
        "dst_ip": arp_layer.pdst
    }
    return extracted_data
