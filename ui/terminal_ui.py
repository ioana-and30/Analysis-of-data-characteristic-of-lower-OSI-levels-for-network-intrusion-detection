import os
import socket
from getpass import getuser
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import IntPrompt, Prompt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(BASE_DIR, "config", ".env")

load_dotenv(dotenv_path=env_path)
console = Console()

def get_sys_info():
    return {
        "user": getuser(),
        "hostname": socket.gethostname(),
        "iface": os.getenv("INTERFACE", "ens7"),
        "trusted_dhcp": os.getenv("DHCP_AUTHORIZED_MAC", "UNKOWN")
    }

def display_header():
    info = get_sys_info()
    console.clear()

    table = Table(show_header=False, box=None)
    table.add_row("👤 [bold cyan]Current user:[/]", info['user'])
    table.add_row("💻  [bold cyan]Hostname:[/]", info['hostname'])
    table.add_row("🔌 [bold cyan]Network interface:[/]", f"[yellow]{info['iface']}[/]")
    table.add_row("🛡️ [bold cyan]Authorized MAC:[/]", f"[bold green]{info['trusted_dhcp']}[/]")

    panel = Panel(
        table,
        title="[bold blue]IDS Agent - Security Monitor v1.0[/]",
        subtitle="[dim]Configuration via .env[/]",
        expand=False,
        border_style="blue"
    )
    console.print(panel)
    console.print()
    return info


def get_user_choice():
    console.print("[bold]Select the operating mode:[/]")
    console.print("  [bold green]1.[/] ⚡ Sniffing")
    console.print("  [bold yellow]2.[/] 📁 Offline Analysis (Load .pcap file) ")
    console.print("  [bold red]0.[/] ❌ Exit")

    return IntPrompt.ask("\nYour option", choices=["1", "2", "0"], show_choices=False)


def ask_for_pcap_path():
    return Prompt.ask("\n[bold yellow][?][/] The path to the .pcap file",
                      default="data_sets/atac_dhcp.pcap")


def show_message(msg, style="bold green"):
    console.print(f"\n[{style}]{msg}[/]")


def wait_for_input(msg="[dim]Enter to continue...[/]"):
    input(f"\n{msg}")