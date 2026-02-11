import ctypes
import os
import sys

from textual.app import App

from scanner import get_default_interface
from ui.screens import DeviceListScreen


def _is_admin() -> bool:
    """Check if the process has admin/root privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Unix fallback
        return os.geteuid() == 0


def _npcap_installed() -> bool:
    """Check if Npcap (or WinPcap) is installed on Windows."""
    if sys.platform != "win32":
        return True  # Not needed on non-Windows
    npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
    wpcap_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll")
    return os.path.isdir(npcap_dir) or os.path.isfile(wpcap_dll)


class SnifferApp(App):
    """Network Scanner TUI."""

    TITLE = "Sniffer"
    SUB_TITLE = "Network Scanner & Traffic Analyzer"

    CSS = """
    Screen {
        background: $background;
    }
    """

    def __init__(self):
        super().__init__()
        self.interface: str = ""
        self.subnet: str = ""

    def on_mount(self):
        # Pre-flight checks
        if sys.platform == "win32" and not _is_admin():
            self.notify(
                "Not running as Administrator — raw sockets may fail.\n"
                "Restart terminal as Admin for full functionality.",
                severity="warning",
                timeout=8,
            )

        if sys.platform == "win32" and not _npcap_installed():
            self.notify(
                "Npcap not detected! Scapy requires Npcap on Windows.\n"
                "Download from https://npcap.com — install with WinPcap API compatibility.",
                severity="error",
                timeout=10,
            )

        # Detect interface
        try:
            self.interface, self.subnet = get_default_interface()
        except RuntimeError as e:
            self.notify(str(e), severity="error", timeout=10)
            self.interface = ""
            self.subnet = ""

        self.push_screen(DeviceListScreen(self.interface, self.subnet))
