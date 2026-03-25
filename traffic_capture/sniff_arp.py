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
        "network.protocol":"arp",
        "arp.opcode": "request" if arp_layer.op == 1 else "REPLY",
        "source.mac": arp_layer.hwsrc,
        "source.ip": arp_layer.psrc,
        "destination.mac": arp_layer.hwdst,
        "destination.ip": arp_layer.pdst
    }
    return extracted_data
