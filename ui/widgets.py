import socket
import threading
from datetime import datetime

from textual.widgets import DataTable, RichLog

from models import Device, PortInfo, PacketRecord, Connection


# Thread-safe reverse DNS cache for 3rd party hostname resolution
_dns_cache: dict[str, str] = {}
_dns_lock = threading.Lock()


def _reverse_dns(ip: str) -> str:
    """Cached reverse DNS lookup. Returns hostname or empty string."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
    # Do the lookup outside the lock
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ""
    with _dns_lock:
        _dns_cache[ip] = hostname
    return hostname


class DeviceTable(DataTable):
    """Table displaying discovered network devices."""

    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns("IP Address", "MAC Address", "Hostname", "Vendor", "Last Seen")

    def load_devices(self, devices: list[Device], filter_text: str = ""):
        self.clear()
        ft = filter_text.lower()
        for dev in devices:
            if ft and not any(ft in field.lower() for field in [
                dev.ip, dev.mac, dev.hostname, dev.vendor,
            ]):
                continue
            self.add_row(
                dev.ip,
                dev.mac,
                dev.hostname or "-",
                dev.vendor or "-",
                dev.last_seen.strftime("%H:%M:%S"),
                key=dev.ip,
            )


class PortTable(DataTable):
    """Table displaying port scan results."""

    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns("Port", "State", "Service", "Banner")

    def load_ports(self, ports: list[PortInfo]):
        self.clear()
        for p in ports:
            self.add_row(
                str(p.port),
                p.state,
                p.service_name or "-",
                p.banner[:80] if p.banner else "-",
                key=str(p.port),
            )


class TrafficLog(RichLog):
    """Scrolling log of captured packets.

    Format: TARGET:port  > or <  REMOTE (hostname):port  PROTO  SIZE
    Target is always on the left. > = outgoing, < = incoming.
    """

    def __init__(self, target_ip: str = "", **kwargs):
        super().__init__(**kwargs)
        self.target_ip = target_ip

    def append_packet(self, pkt: PacketRecord):
        ts = pkt.timestamp.strftime("%H:%M:%S.%f")[:-3]
        proto_colors = {"TCP": "cyan", "UDP": "green", "ICMP": "yellow"}
        color = proto_colors.get(pkt.protocol, "white")

        # Determine direction: outgoing (target → remote) or incoming (remote → target)
        if pkt.src_ip == self.target_ip:
            # Outgoing: target sent this packet
            arrow = "[bold bright_red]>[/]"
            target_port = pkt.src_port
            remote_ip = pkt.dst_ip
            remote_port = pkt.dst_port
        else:
            # Incoming: target received this packet
            arrow = "[bold bright_green]<[/]"
            target_port = pkt.dst_port
            remote_ip = pkt.src_ip
            remote_port = pkt.src_port

        # Resolve 3rd party hostname
        hostname = _reverse_dns(remote_ip)
        if hostname:
            remote_label = f"{remote_ip} [dim]({hostname})[/]"
        else:
            remote_label = remote_ip

        # Format ports
        tp = f":{target_port}" if target_port else ""
        rp = f":{remote_port}" if remote_port else ""

        # Column-aligned output:
        # TIME  |  TARGET:port  |  >/<  |  REMOTE:port (hostname)  |  PROTO  |  SIZE
        line = (
            f"[dim]{ts}[/]  "
            f"{self.target_ip}{tp:<7s}  "
            f"{arrow}  "
            f"{remote_label}{rp}  "
            f"[{color}]{pkt.protocol:<5}[/]  "
            f"[dim]{_format_bytes(pkt.size)}[/]"
        )
        self.write(line)


class ConnectionTable(DataTable):
    """Table displaying aggregated connections."""

    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns(
            "Remote IP", "Hostname", "Port", "Protocol", "Packets", "Bytes",
            "First Seen", "Last Seen",
        )

    def load_connections(self, connections: list[Connection]):
        self.clear()
        for c in connections:
            hostname = _reverse_dns(c.remote_ip)
            self.add_row(
                c.remote_ip,
                hostname or "-",
                str(c.remote_port),
                c.protocol,
                str(c.packet_count),
                _format_bytes(c.bytes_total),
                c.first_seen.strftime("%H:%M:%S"),
                c.last_seen.strftime("%H:%M:%S"),
                key=f"{c.remote_ip}:{c.remote_port}:{c.protocol}",
            )


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / (1024 * 1024):.1f} MB"
