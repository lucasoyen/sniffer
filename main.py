#!/usr/bin/env python3
"""Sniffer — Network Scanner TUI.

Run with admin/root privileges for full functionality:
    python main.py
"""

import sys
import os

# Ensure the project root is on the path so relative imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.app import SnifferApp


def main():
    app = SnifferApp()
    app.run()


if __name__ == "__main__":
    main()
