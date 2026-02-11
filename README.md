# Sniffer

A terminal-based network scanner and traffic analyzer. Discover devices on your LAN, scan ports, and watch live traffic — all from a TUI.

Built with [Scapy](https://scapy.net/) and [Textual](https://textual.textualize.io/).

## Features

- **Device Discovery** — ARP scan to find all devices on your subnet with MAC vendor lookup and hostname resolution
- **Port Scanning** — TCP connect scan across common ports with banner grabbing
- **Live Traffic Capture** — Real-time packet log with directional arrows (incoming/outgoing) and 3rd-party hostname resolution
- **Connection Tracking** — Aggregated view of all connections by remote IP, port, and protocol
- **Search & Filter** — Filter the device list by IP, MAC, hostname, or vendor

## Prerequisites

### Windows
- **Python 3.11+**
- **[Npcap](https://npcap.com/)** — required by Scapy for raw socket access on Windows
  - During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
- **Administrator privileges** — required for raw sockets and packet capture

### Linux / macOS
- **Python 3.11+**
- **libpcap** — usually pre-installed; if not: `sudo apt install libpcap-dev` (Debian/Ubuntu) or `brew install libpcap` (macOS)
- **Root privileges** — run with `sudo`

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/sniffer.git
cd sniffer
python -m venv .venv
```

Activate the venv:

```bash
# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run as admin/root:

```bash
# Windows (from an admin terminal, or with gsudo)
gsudo python main.py

# Linux / macOS
sudo python main.py
```

## Keybindings

### Device List

| Key | Action |
|-----|--------|
| `s` | Scan network |
| `/` | Search / filter devices |
| `Enter` | Select device |
| `q` | Quit |

### Target View

| Key | Action |
|-----|--------|
| `p` | Run port scan |
| `t` | Toggle live traffic capture |
| `c` | Switch to connections tab |
| `Esc` | Back to device list |

## Project Structure

```
sniffer/
├── main.py          # Entry point
├── models.py        # Data classes (Device, PortInfo, PacketRecord, Connection)
├── scanner.py       # ARP discovery, port scanning, banner grabbing
├── sniffer.py       # Live packet capture & connection tracking
└── ui/
    ├── app.py       # Textual App, startup checks
    ├── screens.py   # Device list and target detail screens
    └── widgets.py   # Table and log widgets
```
