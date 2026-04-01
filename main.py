import os
from datetime import datetime

from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff

from sigma_processing.sigma_backend import SigmaBackend
from traffic_capture.logs import save_log
from traffic_capture.sniff_arp import extractARP
from traffic_capture.sniff_dhcp import extractDHCP
import ui.terminal_ui as ui

sys_info = ui.get_sys_info()
trusted_mac = sys_info.get('trusted_dhcp')

detector=SigmaBackend("sigma_rules", trusted_mac)
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


def live_capture(interface, ):
    ui.show_message(f"[*] Starting lice capture on {interface}...", style="bold green")
    try:
        sniff(
            iface=interface,
            filter="arp or (udp and (port 67 or port 68))",
            prn=packet_handler,
            store=0,
            promisc=True
            # L2socket=L2Socket
        )
    except Exception as e:
        ui.show_message(f"[!] Error: {e}", style="bold red")


def offline_analysis(pcap_path):
    if os.path.exists(pcap_path):
        ui.show_message(f"[*] Analyzing file: {pcap_path}...", style="bold green")
        try:
            sniff(
                offline=pcap_path,
                filter="arp or (udp and (port 67 or port 68))",
                prn=packet_handler,
                store=0
            )
        except Exception as e:
            ui.show_message(f"[!] Error processing pcap: {e}", style="bold red")
    else:
        ui.show_message(f"[!] File '{pcap_path}' not found", style="bold red")


def main():
    global packet_id

    while True:
        packet_id = 1

        info = ui.display_header()

        choice = ui.get_user_choice()

        if choice == 1:
            live_capture(info['iface'])
            ui.wait_for_input("\n[dim]Live capture finished. Press enter to go back to the menu...[/]")

        elif choice == 2:
            pcap_path = ui.ask_for_pcap_path()
            offline_analysis(pcap_path)
            ui.wait_for_input("\n[dim]Offline analysis complete. Press enter to go back to the menu...[/]")

        elif choice == 0:
            ui.show_message("Shutting down..", style="bold")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ui.show_message("\n[!] Keyboard interrupt", style="bold red")
        exit(0)