from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from rich.text import Text
from textual.widgets import (
    DataTable, Footer, Header, Input, LoadingIndicator,
    Static, TabbedContent, TabPane,
)

from models import Device
from scanner import discover_devices, scan_ports, guess_os
from sniffer import PacketSniffer
from ui.widgets import (
    DeviceTable, PortTable, TrafficLog, ConnectionTable, PacketDetailView,
)


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
    #scan-loader {
        height: 3;
        display: none;
    }
    #scan-loader.visible {
        display: block;
    }
    #scan-hint {
        text-align: center;
        color: $text-muted;
        display: none;
    }
    #scan-hint.visible {
        display: block;
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
            yield LoadingIndicator(id="scan-loader")
            yield Static("Discovering devices on your network — this can take a few seconds", id="scan-hint")
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
        loader = self.query_one("#scan-loader", LoadingIndicator)

        hint = self.query_one("#scan-hint", Static)
        self.app.call_from_thread(loader.add_class, "visible")
        self.app.call_from_thread(hint.add_class, "visible")
        self.app.call_from_thread(status.update, f"Scanning {self.subnet} ...")
        try:
            devices = discover_devices(self.interface, self.subnet)
            self.devices = devices
            self.app.call_from_thread(table.load_devices, devices, self.filter_text)
            self.app.call_from_thread(
                status.update,
                f"Found {len(devices)} device(s) on {self.subnet}",
            )
        except Exception as e:
            self.app.call_from_thread(status.update, f"Scan failed: {e}")
        finally:
            self.app.call_from_thread(loader.remove_class, "visible")
            self.app.call_from_thread(hint.remove_class, "visible")

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
        ip = str(event.row_key.value)
        device = next((d for d in self.devices if d.ip == ip), None)
        if device:
            self.app.push_screen(TargetScreen(device, self.interface))


class TargetScreen(Screen):
    """Detail screen for a selected device with Ports / Traffic / Connections / Inspect tabs."""

    BINDINGS = [
        Binding("p", "port_scan", "Port Scan"),
        Binding("t", "toggle_traffic", "Traffic OFF"),
        Binding("c", "show_connections", "Connections"),
        Binding("i", "show_inspect", "Inspect"),
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
    #port-loader {
        height: 3;
        display: none;
    }
    #port-loader.visible {
        display: block;
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
    PacketDetailView {
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
        info = Text.assemble(
            (self.device.ip, "bold"), "  ",
            "MAC: ", Text(self.device.mac), "  ",
            f"Host: {self.device.hostname or '-'}  ",
            f"Vendor: {self.device.vendor or '-'}",
        )
        yield Static(info, id="target-header")
        with TabbedContent("Ports", "Traffic", "Connections", "Inspect"):
            with TabPane("Ports", id="tab-ports"):
                yield LoadingIndicator(id="port-loader")
                yield PortTable(id="port-table")
            with TabPane("Traffic", id="tab-traffic"):
                yield TrafficLog(target_ip=self.device.ip, id="traffic-log", highlight=True, markup=True)
            with TabPane("Connections", id="tab-connections"):
                yield ConnectionTable(id="conn-table")
            with TabPane("Inspect", id="tab-inspect"):
                yield PacketDetailView(id="packet-detail", highlight=True, markup=True)
        yield Static("", id="target-status")
        yield Footer()

    def _update_traffic_binding(self):
        """Update the traffic key binding label and color based on sniffer state."""
        if self.sniffer.running:
            desc = "[green bold]Traffic ON[/]"
        else:
            desc = "Traffic OFF"
        self._bindings.bind("t", "toggle_traffic", desc, show=True)
        try:
            self.refresh_bindings()
        except Exception:
            pass

    def action_port_scan(self):
        self._run_port_scan()

    @work(thread=True, exclusive=True, group="portscan")
    def _run_port_scan(self):
        status = self.query_one("#target-status", Static)
        table = self.query_one("#port-table", PortTable)
        loader = self.query_one("#port-loader", LoadingIndicator)

        self.app.call_from_thread(loader.add_class, "visible")

        def on_progress(scanned, total):
            self.app.call_from_thread(
                status.update,
                f"Port scanning {self.device.ip}: {scanned}/{total}",
            )

        self.app.call_from_thread(status.update, f"Scanning ports on {self.device.ip} ...")
        try:
            ports = scan_ports(self.device.ip, progress_callback=on_progress)
            self.device.ports = ports
            self.app.call_from_thread(table.load_ports, ports)
            if ports:
                msg = f"Port scan complete — {len(ports)} open port(s)"
            else:
                msg = "Port scan complete — no open ports found (firewall may be blocking)"
            self.app.call_from_thread(status.update, msg)
        except Exception as e:
            self.app.call_from_thread(status.update, f"Port scan failed: {e}")
        finally:
            self.app.call_from_thread(loader.remove_class, "visible")

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

            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-traffic"

        self._update_traffic_binding()

    def _poll_traffic(self):
        """Periodically pull new packets into the traffic log and update connections."""
        if self.sniffer.error:
            status = self.query_one("#target-status", Static)
            status.update(f"[red]Capture failed: {self.sniffer.error}[/]")
            if self._traffic_timer:
                self._traffic_timer.stop()
                self._traffic_timer = None
            self.sniffer.running = False
            self._update_traffic_binding()
            return

        if not self.sniffer.running and self._traffic_timer:
            status = self.query_one("#target-status", Static)
            status.update("[red]Capture stopped unexpectedly[/]")
            self._traffic_timer.stop()
            self._traffic_timer = None
            self._update_traffic_binding()
            return

        current_count = self.sniffer.get_packet_count()
        if current_count > self._last_packet_count:
            new_count = current_count - self._last_packet_count
            packets = self.sniffer.get_packets(new_count)
            new_packets = packets[-new_count:]
            log = self.query_one("#traffic-log", TrafficLog)
            for pkt in new_packets:
                log.append_packet(pkt)
            self._last_packet_count = current_count

        conn_table = self.query_one("#conn-table", ConnectionTable)
        conn_table.load_connections(self.sniffer.get_connections())

    def action_show_connections(self):
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-connections"
        conn_table = self.query_one("#conn-table", ConnectionTable)
        conn_table.load_connections(self.sniffer.get_connections())

    def action_show_inspect(self):
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-inspect"

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        """When a connection is selected, inspect its packets."""
        # Only handle selections from the connection table
        if event.data_table.id != "conn-table":
            return

        key = str(event.row_key.value)
        # Key format: "remote_ip:remote_port:protocol"
        parts = key.rsplit(":", 2)
        if len(parts) != 3:
            return

        remote_ip, remote_port_str, protocol = parts
        try:
            remote_port = int(remote_port_str)
        except ValueError:
            return

        packets = self.sniffer.get_packets_for_connection(remote_ip, remote_port, protocol)
        detail = self.query_one("#packet-detail", PacketDetailView)
        detail.show_connection_packets(packets, self.device.ip)

        # Switch to inspect tab
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-inspect"

        conns = self.sniffer.get_connections()
        conn = next((c for c in conns if c.remote_ip == remote_ip and c.remote_port == remote_port and c.protocol == protocol), None)
        if conn:
            domain = conn.domain or ""
            label = f"{remote_ip}:{remote_port} ({domain})" if domain else f"{remote_ip}:{remote_port}"
            status = self.query_one("#target-status", Static)
            status.update(f"Inspecting {label} — {len(packets)} packet(s)")

    def action_go_back(self):
        if self.sniffer.running:
            self.sniffer.stop()
        if self._traffic_timer:
            self._traffic_timer.stop()
        self.app.pop_screen()
