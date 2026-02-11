from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    DataTable, Footer, Header, Input, Label, Static, TabbedContent, TabPane,
)

from models import Device
from scanner import discover_devices, scan_ports, guess_os
from sniffer import PacketSniffer
from ui.widgets import DeviceTable, PortTable, TrafficLog, ConnectionTable


class DeviceListScreen(Screen):
    """Main screen showing discovered network devices."""

    BINDINGS = [
        Binding("s", "scan", "Scan Network"),
        Binding("slash", "search", "Search"),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    #search-bar {
        dock: top;
        height: 3;
        padding: 0 1;
        display: none;
    }
    #search-bar.visible {
        display: block;
    }
    #search-input {
        width: 100%;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }
    DeviceTable {
        height: 1fr;
    }
    """

    def __init__(self, interface: str, subnet: str):
        super().__init__()
        self.interface = interface
        self.subnet = subnet
        self.devices: list[Device] = []
        self.filter_text = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical():
            with Horizontal(id="search-bar"):
                yield Input(placeholder="Filter by IP, MAC, hostname, vendor...", id="search-input")
            yield DeviceTable(id="device-table")
            yield Static("Ready — press [b]s[/b] to scan", id="status-bar")
        yield Footer()

    def on_mount(self):
        self.action_scan()

    def action_scan(self):
        self._run_discovery()

    @work(thread=True, exclusive=True, group="discovery")
    def _run_discovery(self):
        status = self.query_one("#status-bar", Static)
        table = self.query_one("#device-table", DeviceTable)

        self.app.call_from_thread(status.update, f"Scanning {self.subnet} ...")
        devices = discover_devices(self.interface, self.subnet)
        self.devices = devices
        self.app.call_from_thread(table.load_devices, devices, self.filter_text)
        self.app.call_from_thread(
            status.update,
            f"Found {len(devices)} device(s) on {self.subnet}",
        )

    def action_search(self):
        bar = self.query_one("#search-bar")
        bar.toggle_class("visible")
        if bar.has_class("visible"):
            self.query_one("#search-input", Input).focus()

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "search-input":
            self.filter_text = event.value
            table = self.query_one("#device-table", DeviceTable)
            table.load_devices(self.devices, self.filter_text)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        # Find the device by IP (stored as row key)
        ip = str(event.row_key.value)
        device = next((d for d in self.devices if d.ip == ip), None)
        if device:
            self.app.push_screen(TargetScreen(device, self.interface))


class TargetScreen(Screen):
    """Detail screen for a selected device with Ports / Traffic / Connections tabs."""

    BINDINGS = [
        Binding("p", "port_scan", "Port Scan"),
        Binding("t", "toggle_traffic", "Toggle Traffic"),
        Binding("c", "show_connections", "Connections"),
        Binding("escape", "go_back", "Back"),
    ]

    CSS = """
    #target-header {
        dock: top;
        height: 3;
        padding: 0 2;
        background: $primary-background;
    }
    #target-status {
        dock: bottom;
        height: 1;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }
    PortTable {
        height: 1fr;
    }
    TrafficLog {
        height: 1fr;
    }
    ConnectionTable {
        height: 1fr;
    }
    """

    def __init__(self, device: Device, interface: str):
        super().__init__()
        self.device = device
        self.interface = interface
        self.sniffer = PacketSniffer()
        self._last_packet_count = 0
        self._traffic_timer = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        info = (
            f"[b]{self.device.ip}[/b]  "
            f"MAC: {self.device.mac}  "
            f"Host: {self.device.hostname or '-'}  "
            f"Vendor: {self.device.vendor or '-'}"
        )
        yield Static(info, id="target-header")
        with TabbedContent("Ports", "Traffic", "Connections"):
            with TabPane("Ports", id="tab-ports"):
                yield PortTable(id="port-table")
            with TabPane("Traffic", id="tab-traffic"):
                yield TrafficLog(target_ip=self.device.ip, id="traffic-log", highlight=True, markup=True)
            with TabPane("Connections", id="tab-connections"):
                yield ConnectionTable(id="conn-table")
        yield Static("Press [b]p[/b] port scan | [b]t[/b] toggle traffic | [b]c[/b] connections | [b]Esc[/b] back", id="target-status")
        yield Footer()

    def action_port_scan(self):
        self._run_port_scan()

    @work(thread=True, exclusive=True, group="portscan")
    def _run_port_scan(self):
        status = self.query_one("#target-status", Static)
        table = self.query_one("#port-table", PortTable)

        def on_progress(scanned, total):
            self.app.call_from_thread(
                status.update,
                f"Port scanning {self.device.ip}: {scanned}/{total}",
            )

        self.app.call_from_thread(status.update, f"Scanning ports on {self.device.ip} ...")
        ports = scan_ports(self.device.ip, progress_callback=on_progress)
        self.device.ports = ports
        self.app.call_from_thread(table.load_ports, ports)
        self.app.call_from_thread(
            status.update,
            f"Port scan complete — {len(ports)} open port(s)",
        )

    def action_toggle_traffic(self):
        if self.sniffer.running:
            self.sniffer.stop()
            if self._traffic_timer:
                self._traffic_timer.stop()
                self._traffic_timer = None
            status = self.query_one("#target-status", Static)
            status.update("Traffic capture stopped")
        else:
            self.sniffer.start(self.device.ip, self.interface)
            self._traffic_timer = self.set_interval(1.0, self._poll_traffic)
            status = self.query_one("#target-status", Static)
            status.update(f"Capturing traffic for {self.device.ip} ...")

            # Switch to Traffic tab
            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-traffic"

    def _poll_traffic(self):
        """Periodically pull new packets into the traffic log and update connections."""
        current_count = self.sniffer.get_packet_count()
        if current_count > self._last_packet_count:
            new_count = current_count - self._last_packet_count
            packets = self.sniffer.get_packets(new_count)
            # Only get the truly new ones
            new_packets = packets[-(new_count):]
            log = self.query_one("#traffic-log", TrafficLog)
            for pkt in new_packets:
                log.append_packet(pkt)
            self._last_packet_count = current_count

        # Also refresh connections table
        conn_table = self.query_one("#conn-table", ConnectionTable)
        conn_table.load_connections(self.sniffer.get_connections())

    def action_show_connections(self):
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-connections"
        # Refresh immediately
        conn_table = self.query_one("#conn-table", ConnectionTable)
        conn_table.load_connections(self.sniffer.get_connections())

    def action_go_back(self):
        if self.sniffer.running:
            self.sniffer.stop()
        if self._traffic_timer:
            self._traffic_timer.stop()
        self.app.pop_screen()
