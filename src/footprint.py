"""
src/footprint.py — Footprint Hardening Module
===============================================
Neutralizes system-level identifiers that can be used for fingerprinting
or deanonymization. All changes are reversible; original state is backed
up in a module-level dataclass and restored during teardown.

Functions are executed *before* internet connectivity is established so
no traffic ever leaves the machine with real identifiers.
"""

import logging
import os
import random
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("torvpn.footprint")


# ---------------------------------------------------------------------------
# Original state container — populated during harden(), consumed by restore()
# ---------------------------------------------------------------------------
@dataclass
class _OriginalState:
    """Stores the original system values so they can be restored on teardown."""
    mac_address: Optional[str] = None
    interface: Optional[str] = None
    hostname: Optional[str] = None
    timezone: Optional[str] = None
    ttl: Optional[int] = None
    ipv6_all: Optional[int] = None
    ipv6_default: Optional[int] = None


_state = _OriginalState()


# ---------------------------------------------------------------------------
# Helper: run a subprocess and return stdout, raising on failure
# ---------------------------------------------------------------------------
def _run(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Execute a command with full error handling and logging.

    Args:
        cmd:     Command tokens (no shell=True, ever).
        check:   Raise CalledProcessError on non-zero exit.
        capture: Capture stdout/stderr.

    Returns:
        CompletedProcess instance.
    """
    log.debug("exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# 1. Network interface detection
# ---------------------------------------------------------------------------
def _detect_interface() -> str:
    """Detect the primary network interface from the default route.

    Parses `ip route show default` for the first line containing 'dev <iface>'.

    Returns:
        Interface name string (e.g. "eth0", "wlan0", "enp3s0").

    Raises:
        RuntimeError: If no default route / interface can be determined.
    """
    result = _run(["ip", "route", "show", "default"])
    # Typical output: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    match = re.search(r"dev\s+(\S+)", result.stdout)
    if not match:
        raise RuntimeError(
            "Cannot detect primary network interface — no default route found. "
            "Output was: " + repr(result.stdout)
        )
    iface = match.group(1)
    log.info("Detected primary interface: %s", iface)
    return iface


# ---------------------------------------------------------------------------
# 2. MAC address spoofing
# ---------------------------------------------------------------------------
def _generate_random_mac() -> str:
    """Generate a random locally-administered unicast MAC address.

    The first octet has the locally-administered bit set (bit 1) and the
    multicast bit cleared (bit 0), giving a pattern of x2:xx:xx:xx:xx:xx,
    x6:xx:xx:xx:xx:xx, xA:xx:xx:xx:xx:xx, or xE:xx:xx:xx:xx:xx.

    Returns:
        MAC address string in colon-separated hex (e.g. "a2:b4:c6:d8:e0:f2").
    """
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    # Set locally-administered bit (bit 1 of first octet)
    octets[0] |= 0x02
    # Clear multicast bit (bit 0 of first octet)
    octets[0] &= 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def _get_current_mac(iface: str) -> str:
    """Read the current MAC address of the given interface.

    Args:
        iface: Network interface name.

    Returns:
        Current MAC as a colon-separated hex string.

    Raises:
        RuntimeError: If MAC cannot be parsed from `ip link show`.
    """
    result = _run(["ip", "link", "show", iface])
    # Typical:  "link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
    match = re.search(r"link/ether\s+([\da-fA-F:]{17})", result.stdout)
    if not match:
        raise RuntimeError(f"Cannot read MAC for {iface}: {result.stdout!r}")
    return match.group(1).lower()


def spoof_mac() -> None:
    """Spoof the MAC address on the primary network interface.

    Sequence:
        1. Detect interface & back up current MAC.
        2. Bring interface down.
        3. Apply random locally-administered MAC.
        4. Bring interface back up.

    The brief connectivity interruption is intentional — it guarantees
    no packet ever leaves with the real hardware MAC.
    """
    iface = _detect_interface()
    original_mac = _get_current_mac(iface)

    _state.interface = iface
    _state.mac_address = original_mac

    # Changing the MAC of an authenticated Wi-Fi connection breaks WPA/WPA2.
    # The access point will drop all traffic from the new MAC.
    is_wireless = iface.startswith("wl") or os.path.exists(f"/sys/class/net/{iface}/wireless")
    if is_wireless:
        log.warning("Skipping MAC spoofing on wireless interface '%s' (would break Wi-Fi authentication)", iface)
        return

    new_mac = _generate_random_mac()
    log.info("Spoofing MAC on %s: %s → %s", iface, original_mac, new_mac)

    _run(["ip", "link", "set", iface, "down"])
    _run(["ip", "link", "set", iface, "address", new_mac])
    _run(["ip", "link", "set", iface, "up"])

    log.info("[OK] MAC address spoofed successfully")


def restore_mac() -> None:
    """Restore the original MAC address and bring the interface back up."""
    if _state.mac_address is None or _state.interface is None:
        log.debug("No MAC backup — skipping restore")
        return

    iface = _state.interface
    original = _state.mac_address
    log.info("Restoring MAC on %s → %s", iface, original)

    _run(["ip", "link", "set", iface, "down"])
    _run(["ip", "link", "set", iface, "address", original])
    _run(["ip", "link", "set", iface, "up"])

    log.info("[OK] MAC address restored")


# ---------------------------------------------------------------------------
# 3. Hostname scrubbing
# ---------------------------------------------------------------------------
def scrub_hostname() -> None:
    """Replace the system hostname with 'localhost' to prevent leaking
    the machine's real identity via DHCP, mDNS, or other broadcast protocols.
    """
    _state.hostname = socket.gethostname()
    log.info("Scrubbing hostname: '%s' → 'localhost'", _state.hostname)

    _run(["hostnamectl", "set-hostname", "localhost"])
    log.info("[OK] Hostname set to 'localhost'")


def restore_hostname() -> None:
    """Restore the original hostname."""
    if _state.hostname is None:
        log.debug("No hostname backup — skipping restore")
        return

    log.info("Restoring hostname → '%s'", _state.hostname)
    _run(["hostnamectl", "set-hostname", _state.hostname])
    log.info("[OK] Hostname restored")


# ---------------------------------------------------------------------------
# 4. Timezone normalization
# ---------------------------------------------------------------------------
def normalize_timezone() -> None:
    """Force the system timezone to UTC.

    Many websites and services can fingerprint users by their timezone.
    Setting UTC neutralizes this vector.
    """
    result = _run(["timedatectl", "show", "-p", "Timezone", "--value"])
    _state.timezone = result.stdout.strip()

    log.info("Normalizing timezone: '%s' → 'UTC'", _state.timezone)
    _run(["timedatectl", "set-timezone", "UTC"])
    log.info("[OK] Timezone set to UTC")


def restore_timezone() -> None:
    """Restore the original timezone."""
    if _state.timezone is None:
        log.debug("No timezone backup — skipping restore")
        return

    log.info("Restoring timezone → '%s'", _state.timezone)
    _run(["timedatectl", "set-timezone", _state.timezone])
    log.info("[OK] Timezone restored")


# ---------------------------------------------------------------------------
# 5. TTL manipulation
# ---------------------------------------------------------------------------
def _read_sysctl(key: str) -> str:
    """Read a sysctl value.

    Args:
        key: Sysctl key (e.g. "net.ipv4.ip_default_ttl").

    Returns:
        The current value as a string.
    """
    result = _run(["sysctl", "-n", key])
    return result.stdout.strip()


def set_ttl() -> None:
    """Set the default IPv4 TTL to 64.

    A TTL of 64 is the most common default across operating systems
    (Linux, macOS, iOS, Android), making it the hardest to fingerprint.
    Non-standard TTLs can reveal the OS or the fact that traffic is tunneled.
    """
    current = _read_sysctl("net.ipv4.ip_default_ttl")
    _state.ttl = int(current)

    log.info("Setting TTL: %s → 64", current)
    _run(["sysctl", "-w", "net.ipv4.ip_default_ttl=64"])
    log.info("[OK] TTL set to 64")


def restore_ttl() -> None:
    """Restore the original TTL value."""
    if _state.ttl is None:
        log.debug("No TTL backup — skipping restore")
        return

    log.info("Restoring TTL → %d", _state.ttl)
    _run(["sysctl", "-w", f"net.ipv4.ip_default_ttl={_state.ttl}"])
    log.info("[OK] TTL restored")


# ---------------------------------------------------------------------------
# 6. IPv6 disabling
# ---------------------------------------------------------------------------
def disable_ipv6() -> None:
    """Completely disable IPv6 to prevent dual-stack routing leaks.

    Even with Tor routing all IPv4, an active IPv6 stack can bypass the
    tunnel entirely if the destination supports v6. This is a critical
    anonymity leak vector.
    """
    _state.ipv6_all = int(_read_sysctl("net.ipv6.conf.all.disable_ipv6"))
    _state.ipv6_default = int(_read_sysctl("net.ipv6.conf.default.disable_ipv6"))

    log.info("Disabling IPv6 globally")
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
    log.info("[OK] IPv6 disabled")


def restore_ipv6() -> None:
    """Restore original IPv6 configuration."""
    if _state.ipv6_all is None:
        log.debug("No IPv6 backup — skipping restore")
        return

    log.info("Restoring IPv6 settings")
    _run(["sysctl", "-w", f"net.ipv6.conf.all.disable_ipv6={_state.ipv6_all}"])
    _run(["sysctl", "-w", f"net.ipv6.conf.default.disable_ipv6={_state.ipv6_default}"])
    log.info("[OK] IPv6 restored")


# ---------------------------------------------------------------------------
# 7. DNS Cache Flushing
# ---------------------------------------------------------------------------
def flush_dns_cache() -> None:
    """Flush the system DNS cache to prevent leaking previous DNS queries.

    Attempts to flush caches for systemd-resolved and nscd if they exist.
    """
    log.info("Flushing system DNS caches")

    # Try systemd-resolved
    try:
        if shutil.which("resolvectl"):
            _run(["resolvectl", "flush-caches"], capture=True)
            log.info("[OK] systemd-resolved cache flushed")
        elif shutil.which("systemd-resolve"):
            _run(["systemd-resolve", "--flush-caches"], capture=True)
            log.info("[OK] systemd-resolved cache flushed")
    except Exception as exc:
        log.debug("Failed to flush systemd-resolved: %s", exc)

    # Try nscd
    try:
        if shutil.which("nscd"):
            _run(["nscd", "-i", "hosts"], capture=True)
            log.info("[OK] nscd hosts cache flushed")
    except Exception as exc:
        log.debug("Failed to flush nscd: %s", exc)


# ---------------------------------------------------------------------------
# Public API — aggregate harden / restore
# ---------------------------------------------------------------------------
def harden() -> None:
    """Execute the full footprint hardening sequence.

    Order matters: MAC spoofing brings the interface down, so it must
    happen first. Hostname and timezone are independent. TTL and IPv6
    are network-stack level and don't depend on interface state.
    """
    log.info("=" * 50)
    log.info("FOOTPRINT HARDENING — BEGIN")
    log.info("=" * 50)

    spoof_mac()
    scrub_hostname()
    normalize_timezone()
    set_ttl()
    disable_ipv6()
    flush_dns_cache()

    log.info("=" * 50)
    log.info("FOOTPRINT HARDENING — COMPLETE")
    log.info("=" * 50)


def restore() -> None:
    """Reverse all footprint changes. Errors are logged but do not halt
    the teardown — we attempt to restore as much as possible.
    """
    log.info("=" * 50)
    log.info("FOOTPRINT RESTORE — BEGIN")
    log.info("=" * 50)

    for fn in (restore_ipv6, restore_ttl, restore_timezone, restore_hostname, restore_mac):
        try:
            fn()
        except Exception as exc:
            log.error("Failed to restore (%s): %s", fn.__name__, exc)

    log.info("=" * 50)
    log.info("FOOTPRINT RESTORE — COMPLETE")
    log.info("=" * 50)
