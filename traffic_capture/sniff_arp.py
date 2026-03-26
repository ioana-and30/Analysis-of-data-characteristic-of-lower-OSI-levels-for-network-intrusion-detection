from scapy.layers.l2 import ARP

ARP_OPTIONS={
    1:"REQUEST",
    2:"REPLY"
}

def extractARP(packet):

    arp_layer = packet.getlayer(ARP)
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
