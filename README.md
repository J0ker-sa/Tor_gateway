# TorVPN — System-Wide Transparent Tor Proxy

A production-grade Python application that routes **100% of system TCP and DNS traffic** through a locally managed Tor daemon using `nftables` transparent proxying, with comprehensive footprint hardening and a fail-safe kill-switch.

## Features

- **Transparent Proxy** — All TCP and DNS traffic automatically routed through Tor via nftables
- **Kill-Switch Firewall** — If Tor dies, ALL internet traffic is blocked (no clear-text leaks)
- **Self-Healing Watchdog** — Automatically restarts Tor up to 3 times on crash
- **MAC Address Spoofing** — Random locally-administered MAC on every run
- **Hostname Scrubbing** — System hostname set to "localhost"
- **Timezone Normalization** — Forced to UTC to prevent fingerprinting
- **TTL Normalization** — Set to 64 (most common across OSes)
- **IPv6 Disabled** — Prevents dual-stack routing leaks
- **DNS Lock** — `resolv.conf` made immutable to prevent NetworkManager overrides
- **Clean Teardown** — All changes fully reversed on Ctrl+C / SIGTERM

## Requirements

- **OS:** Linux with systemd and nftables
- **Python:** 3.9+
- **Privileges:** Root (sudo)
- **System packages:**
  - `tor` — The onion router daemon
  - `nftables` — Netfilter tables firewall
  - `iproute2` — The `ip` command
  - `e2fsprogs` — The `chattr` command

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install tor nftables iproute2 e2fsprogs
```

### Install dependencies (Arch Linux)

```bash
sudo pacman -S tor nftables iproute2 e2fsprogs
```

## Usage

```bash
# Start the Tor VPN
sudo python3 torvpn.py

# Verify you're on Tor
curl https://check.torproject.org/api/ip

# Stop and restore system (press Ctrl+C in the running terminal)
```

## Project Structure

```
├── torvpn.py              # Entry point
├── src/
│   ├── __init__.py
│   ├── main.py            # Orchestrator, watchdog, signal handling
│   ├── footprint.py       # MAC, hostname, timezone, TTL, IPv6 hardening
│   ├── tor.py             # Tor daemon lifecycle management
│   ├── firewall.py        # nftables ruleset generation & management
│   └── dns.py             # resolv.conf locking & backup
├── requirements.txt       # Empty (stdlib only)
└── README.md              # This file
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
│                   (any process)                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│   TCP traffic ──→ nftables DNAT ──→ 127.0.0.1:9040  │
│   DNS traffic ──→ nftables DNAT ──→ 127.0.0.1:9053  │
│   Other traffic ──→ DROPPED (kill-switch)            │
│                                                      │
├─────────────────────────────────────────────────────┤
│                  Tor Daemon                           │
│              (torvpn-worker user)                     │
│                                                      │
│   TransPort 9040 ──→ Tor Network ──→ Internet        │
│   DNSPort   9053 ──→ Tor Network ──→ DNS Resolution  │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Security Notes

> ⚠️ **Test in a VM first.** This application modifies critical system settings including firewall rules, DNS, MAC address, hostname, and timezone. Always test in a disposable environment.

> ⚠️ **Kill-switch is intentional.** If Tor fails and cannot be restarted, the kill-switch blocks ALL internet access. This is by design to prevent clear-text traffic leaks.

> ⚠️ **Not a replacement for Tails/Whonix.** While this provides system-wide Tor routing, a dedicated OS like Tails or Whonix provides stronger isolation guarantees (e.g., separate VMs for the gateway and workstation).


# Tor_gateway
# Tor_gateway
