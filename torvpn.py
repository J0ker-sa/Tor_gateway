#!/usr/bin/env python3
"""
torvpn.py — Entry Point
=========================
System-wide transparent Tor proxy for Linux.

Routes all TCP and DNS traffic through Tor using nftables,
with full footprint hardening and a kill-switch firewall.

Usage:
    sudo python3 torvpn.py

Requirements:
    - Root privileges (sudo)
    - Python 3.9+
    - tor, nftables, ip, hostnamectl, timedatectl, sysctl, chattr

See README.md for full documentation.
"""

from src.main import run

if __name__ == "__main__":
    run()
