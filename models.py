from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PortInfo:
    port: int
    state: str  # "open", "closed", "filtered"
    service_name: str = ""
    banner: str = ""


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    ports: list[PortInfo] = field(default_factory=list)


@dataclass
class PacketRecord:
    timestamp: datetime
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    size: int
    summary: str


@dataclass
class Connection:
    remote_ip: str
    remote_port: int
    protocol: str
    packet_count: int = 0
    bytes_total: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
