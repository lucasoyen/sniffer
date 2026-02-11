import threading
from collections import deque
from datetime import datetime

from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP

from models import PacketRecord, Connection


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

    def start(self, target_ip: str, interface: str | None = None):
        """Start capturing packets involving target_ip."""
        if self.running:
            self.stop()

        self._target_ip = target_ip
        self._interface = interface
        self._stop_event.clear()
        self._packets.clear()
        self._connections.clear()
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
        """Run scapy sniff in a loop, stopping when the event is set."""
        bpf = f"host {self._target_ip}"
        try:
            scapy_sniff(
                iface=self._interface,
                filter=bpf,
                prn=self._process_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception:
            # Capture may fail if interface is invalid or permissions are lacking
            self.running = False

    def _process_packet(self, pkt):
        """Extract info from a packet and store it."""
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
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
        )

        # Determine the remote end (the side that isn't our target)
        if src_ip == self._target_ip:
            remote_ip = dst_ip
            remote_port = dst_port
        else:
            remote_ip = src_ip
            remote_port = src_port

        conn_key = (remote_ip, remote_port, protocol)

        with self._lock:
            self._packets.append(record)

            if conn_key in self._connections:
                conn = self._connections[conn_key]
                conn.packet_count += 1
                conn.bytes_total += size
                conn.last_seen = record.timestamp
            else:
                self._connections[conn_key] = Connection(
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    packet_count=1,
                    bytes_total=size,
                    first_seen=record.timestamp,
                    last_seen=record.timestamp,
                )

    def get_packets(self, n: int = 100) -> list[PacketRecord]:
        """Return the last n packets."""
        with self._lock:
            items = list(self._packets)
            return items[-n:]

    def get_connections(self) -> list[Connection]:
        """Return all tracked connections sorted by packet count descending."""
        with self._lock:
            conns = list(self._connections.values())
        conns.sort(key=lambda c: c.packet_count, reverse=True)
        return conns

    def get_packet_count(self) -> int:
        with self._lock:
            return len(self._packets)
