import socket
import struct
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import (
    ARP, Ether, IP, TCP, sr1, srp, conf, get_if_addr, get_if_list,
    IFACES,
)

from models import Device, PortInfo

# Common ports to scan by default
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 8888,
    27017,
]

WELL_KNOWN_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 5901: "vnc-1",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    27017: "mongodb",
}


def get_default_interface():
    """Auto-detect the active network interface and subnet.
    Returns (interface_name, subnet_cidr) or raises RuntimeError.
    """
    try:
        # On Windows, scapy uses IFACES to list interfaces
        for iface_name, iface in IFACES.items():
            try:
                ip = iface.ip
                if ip and ip != "127.0.0.1" and not ip.startswith("169.254."):
                    # Derive /24 subnet from the interface IP
                    parts = ip.split(".")
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    return iface_name, subnet
            except Exception:
                continue
    except Exception:
        pass

    # Fallback: iterate scapy's get_if_list
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != "127.0.0.1" and not ip.startswith("169.254."):
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                return iface, subnet
        except Exception:
            continue

    raise RuntimeError("Could not detect a usable network interface")


def _resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup, returns empty string on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _resolve_vendor(mac: str) -> str:
    """Look up vendor from MAC OUI database."""
    try:
        from mac_vendor_lookup import MacLookup
        return MacLookup().lookup(mac)
    except Exception:
        return ""


def discover_devices(interface: str, subnet: str, timeout: int = 3) -> list[Device]:
    """ARP scan the subnet and return discovered devices."""
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        iface=interface,
        timeout=timeout,
        verbose=False,
    )

    devices = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc.upper()
        hostname = _resolve_hostname(ip)
        vendor = _resolve_vendor(mac)
        devices.append(Device(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
        ))
    return devices


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Connect to ip:port and try to read a banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Some services send a banner immediately
            s.sendall(b"\r\n")
            data = s.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def _scan_single_port(ip: str, port: int, timeout: float) -> PortInfo | None:
    """Scan a single port using TCP connect scan."""
    service = WELL_KNOWN_SERVICES.get(port, "")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port, timeout)
                return PortInfo(
                    port=port,
                    state="open",
                    service_name=service,
                    banner=banner,
                )
    except Exception:
        pass
    return None


def scan_ports(
    ip: str,
    port_range: list[int] | None = None,
    timeout: float = 1.5,
    max_workers: int = 50,
    progress_callback=None,
) -> list[PortInfo]:
    """Scan ports on target IP. Returns list of open PortInfo.

    progress_callback(scanned, total) is called after each port completes.
    """
    ports = port_range or COMMON_PORTS
    results: list[PortInfo] = []
    scanned = 0
    total = len(ports)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_single_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            scanned += 1
            info = future.result()
            if info is not None:
                results.append(info)
            if progress_callback:
                progress_callback(scanned, total)

    results.sort(key=lambda p: p.port)
    return results


def guess_os(ip: str, timeout: float = 2.0) -> str:
    """Send a TCP SYN probe and guess OS from TTL value."""
    try:
        pkt = IP(dst=ip) / TCP(dport=80, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(IP):
            ttl = resp[IP].ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
    except Exception:
        pass
    return ""
