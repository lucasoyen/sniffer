import socket
import threading
from datetime import datetime

from rich.text import Text
from textual.widgets import DataTable, RichLog, Static

from models import Device, PortInfo, PacketRecord, Connection


# Thread-safe reverse DNS cache for 3rd party hostname resolution
_dns_cache: dict[str, str] = {}
_dns_lock = threading.Lock()


def _reverse_dns(ip: str) -> str:
    """Cached reverse DNS lookup. Returns hostname or empty string."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
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
                Text(dev.mac),
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

    Format: TIME  TARGET:port  >/<  REMOTE (hostname):port  PROTO  SIZE  INFO
    Target always on left. > = outgoing (red), < = incoming (green).
    """

    def __init__(self, target_ip: str = "", **kwargs):
        super().__init__(**kwargs)
        self.target_ip = target_ip

    def append_packet(self, pkt: PacketRecord):
        ts = pkt.timestamp.strftime("%H:%M:%S.%f")[:-3]
        proto_colors = {"TCP": "cyan", "UDP": "green", "ICMP": "yellow"}
        color = proto_colors.get(pkt.protocol, "white")

        if pkt.src_ip == self.target_ip:
            arrow = "[bold bright_red]>[/]"
            target_port = pkt.src_port
            remote_ip = pkt.dst_ip
            remote_port = pkt.dst_port
        else:
            arrow = "[bold bright_green]<[/]"
            target_port = pkt.dst_port
            remote_ip = pkt.src_ip
            remote_port = pkt.src_port

        hostname = _reverse_dns(remote_ip)
        if hostname:
            remote_label = f"{remote_ip} [dim]({hostname})[/]"
        else:
            remote_label = remote_ip

        tp = f":{target_port}" if target_port else ""
        rp = f":{remote_port}" if remote_port else ""

        # Info column: show TLS SNI, DNS query, TCP flags, etc.
        info_part = ""
        if pkt.info:
            info_part = f"  [italic]{pkt.info}[/]"

        line = (
            f"[dim]{ts}[/]  "
            f"{self.target_ip}{tp:<7s}  "
            f"{arrow}  "
            f"{remote_label}{rp}  "
            f"[{color}]{pkt.protocol:<5}[/]  "
            f"[dim]{_format_bytes(pkt.size)}[/]"
            f"{info_part}"
        )
        self.write(line)


class ConnectionTable(DataTable):
    """Table displaying aggregated connections with domain identification."""

    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns(
            "Remote IP", "Hostname", "Domain", "Port", "Protocol",
            "Packets", "Bytes", "First Seen", "Last Seen",
        )

    def load_connections(self, connections: list[Connection]):
        self.clear()
        for c in connections:
            hostname = _reverse_dns(c.remote_ip)
            self.add_row(
                c.remote_ip,
                hostname or "-",
                c.domain or "-",
                str(c.remote_port),
                c.protocol,
                str(c.packet_count),
                _format_bytes(c.bytes_total),
                c.first_seen.strftime("%H:%M:%S"),
                c.last_seen.strftime("%H:%M:%S"),
                key=f"{c.remote_ip}:{c.remote_port}:{c.protocol}",
            )


class PacketDetailView(RichLog):
    """Shows detailed packet inspection: hex dump + decoded info."""

    def show_packet(self, pkt: PacketRecord):
        """Display full details for a single packet."""
        self.clear()

        ts = pkt.timestamp.strftime("%H:%M:%S.%f")[:-3]
        self.write(f"[bold]Packet Detail[/]  {ts}")
        self.write(f"  {pkt.src_ip}:{pkt.src_port} > {pkt.dst_ip}:{pkt.dst_port}  [{pkt.protocol}]  {pkt.size} bytes")
        self.write("")

        if pkt.tls_sni:
            self.write(f"  [cyan]TLS Server Name:[/] {pkt.tls_sni}")
        if pkt.dns_query:
            self.write(f"  [green]DNS Query:[/] {pkt.dns_query}")
        if pkt.info:
            self.write(f"  [yellow]Info:[/] {pkt.info}")

        if pkt.payload:
            self.write("")
            self.write("[bold]Payload[/]")
            self._write_hexdump(pkt.payload)
            self.write("")
            self._write_ascii(pkt.payload)
        else:
            self.write("")
            self.write("[dim]No payload data[/]")

    def show_connection_packets(self, packets: list[PacketRecord], target_ip: str):
        """Display a summary of all packets for a connection."""
        self.clear()
        if not packets:
            self.write("[dim]No packets captured for this connection[/]")
            return

        self.write(f"[bold]{len(packets)} packet(s)[/]")
        self.write("")

        for pkt in packets[-50:]:  # Show last 50
            ts = pkt.timestamp.strftime("%H:%M:%S.%f")[:-3]
            if pkt.src_ip == target_ip:
                arrow = "[bold bright_red]>[/]"
            else:
                arrow = "[bold bright_green]<[/]"

            info = f"  [italic]{pkt.info}[/]" if pkt.info else ""
            self.write(
                f"[dim]{ts}[/]  {arrow}  {pkt.size:>5} B  "
                f"[dim]{pkt.protocol}[/]{info}"
            )

            # Show payload preview for packets that have one
            if pkt.payload:
                preview = pkt.payload[:64]
                text = preview.decode("utf-8", errors="replace")
                # Only show if it has printable content
                printable = "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
                if any(c.isprintable() for c in text):
                    self.write(f"         [dim]{printable[:100]}[/]")

    def _write_hexdump(self, data: bytes, width: int = 16):
        """Write hex dump of payload."""
        for offset in range(0, min(len(data), 256), width):
            chunk = data[offset:offset + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.write(f"  [dim]{offset:04x}[/]  {hex_part:<{width * 3}}  {ascii_part}")

    def _write_ascii(self, data: bytes):
        """Write printable ASCII content."""
        text = data[:256].decode("utf-8", errors="replace")
        printable = "".join(c if c.isprintable() or c in "\r\n\t " else "." for c in text)
        if any(c.isprintable() for c in text):
            self.write("[bold]ASCII[/]")
            for line in printable.split("\n")[:20]:
                if line.strip():
                    self.write(f"  {line.rstrip()}")


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / (1024 * 1024):.1f} MB"
