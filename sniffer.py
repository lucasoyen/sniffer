import threading
from collections import deque
from datetime import datetime

from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

from models import PacketRecord, Connection

# Max payload bytes to store per packet
MAX_PAYLOAD = 512


def _extract_tls_sni(payload: bytes) -> str:
    """Extract Server Name Indication from a TLS ClientHello."""
    try:
        if len(payload) < 6:
            return ""
        if payload[0] != 0x16:  # TLS handshake
            return ""
        if payload[5] != 0x01:  # ClientHello
            return ""
        # Skip: handshake_type(1) + length(3) + version(2) + random(32)
        pos = 5 + 1 + 3 + 2 + 32
        if pos >= len(payload):
            return ""
        # Session ID
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return ""
        # Cipher suites
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(payload):
            return ""
        # Compression methods
        cm_len = payload[pos]
        pos += 1 + cm_len
        if pos + 2 > len(payload):
            return ""
        # Extensions
        ext_total = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_total
        while pos + 4 < end and pos + 4 < len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # SNI
                if pos + 5 <= len(payload):
                    name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                    if pos + 5 + name_len <= len(payload):
                        return payload[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return ""


def _extract_dns_query(pkt) -> str:
    """Extract the queried domain name from a DNS packet."""
    try:
        if pkt.haslayer(DNSQR):
            name = pkt[DNSQR].qname
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            return name.rstrip(".")
    except Exception:
        pass
    return ""


def _extract_payload(pkt) -> bytes:
    """Extract raw payload bytes from a packet."""
    try:
        if pkt.haslayer(Raw):
            return bytes(pkt[Raw].load[:MAX_PAYLOAD])
    except Exception:
        pass
    return b""


def _build_info(pkt, protocol: str, tls_sni: str, dns_query: str) -> str:
    """Build a human-readable info string for the packet."""
    parts = []
    if tls_sni:
        parts.append(f"TLS SNI: {tls_sni}")
    if dns_query:
        qtype = ""
        try:
            if pkt.haslayer(DNSQR):
                qt = pkt[DNSQR].qtype
                qtype_map = {1: "A", 5: "CNAME", 28: "AAAA", 12: "PTR", 15: "MX", 16: "TXT", 33: "SRV", 65: "HTTPS"}
                qtype = qtype_map.get(qt, str(qt))
        except Exception:
            pass
        parts.append(f"DNS {qtype} {dns_query}")
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        flag_str = str(flags)
        parts.append(f"[{flag_str}]")
    if not parts and pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
        parts.append(type_map.get(icmp.type, f"Type {icmp.type}"))
    return "  ".join(parts)


class PacketSniffer:
    """Captures packets for a target IP in a background thread."""

    def __init__(self, max_packets: int = 5000):
        self._packets: deque[PacketRecord] = deque(maxlen=max_packets)
        self._connections: dict[tuple, Connection] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._target_ip: str = ""
        self._interface: str | None = None
        self.running = False
        self.error: str = ""

    def start(self, target_ip: str, interface: str | None = None):
        """Start capturing packets involving target_ip."""
        if self.running:
            self.stop()

        self._target_ip = target_ip
        self._interface = interface
        self._stop_event.clear()
        self._packets.clear()
        self._connections.clear()
        self.error = ""
        self.running = True

        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name=f"sniffer-{target_ip}",
        )
        self._thread.start()

    def stop(self):
        """Stop the capture thread."""
        self._stop_event.set()
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    def _capture_loop(self):
        """Run scapy sniff, trying BPF filter first, then falling back to software filter."""
        bpf = f"host {self._target_ip}"

        # Try with BPF filter first (faster, kernel-level)
        try:
            scapy_sniff(
                iface=self._interface,
                filter=bpf,
                prn=self._process_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
            return
        except Exception:
            if self._stop_event.is_set():
                return

        # Fallback: capture all packets, filter in _process_packet
        try:
            scapy_sniff(
                iface=self._interface,
                prn=self._process_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as e:
            self.error = str(e)
            self.running = False

    def _process_packet(self, pkt):
        """Extract info from a packet and store it."""
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Software filter: only keep packets involving our target
        if src_ip != self._target_ip and dst_ip != self._target_ip:
            return

        size = len(pkt)
        protocol = "OTHER"
        src_port = 0
        dst_port = 0

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        # Deep inspection
        payload = _extract_payload(pkt)
        tls_sni = _extract_tls_sni(payload) if protocol == "TCP" else ""
        dns_query = _extract_dns_query(pkt) if pkt.haslayer(DNS) else ""
        info = _build_info(pkt, protocol, tls_sni, dns_query)

        summary = pkt.sprintf("%IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport%") if pkt.haslayer(TCP) else pkt.summary()

        record = PacketRecord(
            timestamp=datetime.now(),
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            size=size,
            summary=summary,
            payload=payload,
            tls_sni=tls_sni,
            dns_query=dns_query,
            info=info,
        )

        # Determine the remote end
        if src_ip == self._target_ip:
            remote_ip = dst_ip
            remote_port = dst_port
        else:
            remote_ip = src_ip
            remote_port = src_port

        # Use domain from TLS SNI or DNS query
        domain = tls_sni or dns_query

        conn_key = (remote_ip, remote_port, protocol)

        with self._lock:
            self._packets.append(record)

            if conn_key in self._connections:
                conn = self._connections[conn_key]
                conn.packet_count += 1
                conn.bytes_total += size
                conn.last_seen = record.timestamp
                if domain and not conn.domain:
                    conn.domain = domain
            else:
                self._connections[conn_key] = Connection(
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    packet_count=1,
                    bytes_total=size,
                    first_seen=record.timestamp,
                    last_seen=record.timestamp,
                    domain=domain,
                )

    def get_packets(self, n: int = 100) -> list[PacketRecord]:
        """Return the last n packets."""
        with self._lock:
            items = list(self._packets)
            return items[-n:]

    def get_packets_for_connection(self, remote_ip: str, remote_port: int, protocol: str) -> list[PacketRecord]:
        """Return all packets matching a specific connection."""
        with self._lock:
            return [
                p for p in self._packets
                if (
                    (p.src_ip == remote_ip and p.src_port == remote_port and p.protocol == protocol)
                    or (p.dst_ip == remote_ip and p.dst_port == remote_port and p.protocol == protocol)
                )
            ]

    def get_connections(self) -> list[Connection]:
        """Return all tracked connections sorted by packet count descending."""
        with self._lock:
            conns = list(self._connections.values())
        conns.sort(key=lambda c: c.packet_count, reverse=True)
        return conns

    def get_packet_count(self) -> int:
        with self._lock:
            return len(self._packets)
