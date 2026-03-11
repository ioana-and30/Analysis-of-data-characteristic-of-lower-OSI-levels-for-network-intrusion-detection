import json
from scapy.sendrecv import sniff
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import DHCP, BOOTP

DHCP_OPTIONS = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}

def extractDHCP(packet):
    extracted_data = {}

    bootp_layer = packet.getlayer(BOOTP)
    dhcp_layer = packet.getlayer(DHCP)

    msg_type_id = None
    clean_options =[]

    for opt in dhcp_layer.options:
        if isinstance(opt, tuple):
            if opt[0] == 'message-type':
                msg_type_id = opt[1]

            clean_options.append(f"{opt[0]}: {opt[1]}")

        elif isinstance(opt, str):
            clean_options.append(opt)

    extracted_data = {
        "protocol": "DHCP",
        "message_type_name": DHCP_OPTIONS.get(msg_type_id, "UNKNOWN"),
        "transaction_id": hex(bootp_layer.xid),
        "client_mac_chaddr": bootp_layer.chaddr.hex(':')[:17],
        "options": clean_options
    }
    return extracted_data
