"""
src/backup.py — Persistent Backup & State Recovery
=====================================================
Before any system settings are modified, this module queries and persists
the original machine state to a JSON file at ``/var/lib/torvpn/backup_state.json``.

If the application is interrupted (crash, OOM kill, power loss) the backup
file survives on disk. On the next startup, ``disaster_recovery()`` detects
the stale backup, restores every recorded setting, deletes the file, and
only then allows a fresh session to begin.

JSON schema (v1)::

    {
        "version": 1,
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "interface": "eth0",
        "hostname": "myhost",
        "timezone": "America/New_York",
        "resolv_conf": "nameserver 8.8.8.8\\nnameserver 8.8.4.4\\n"
    }
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from src.exitcodes import ExitCode

log = logging.getLogger("torvpn.backup")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BACKUP_DIR = Path("/var/lib/torvpn")
BACKUP_PATH = BACKUP_DIR / "backup_state.json"
BACKUP_VERSION = 1

RESOLV_CONF = Path("/etc/resolv.conf")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """Execute a command with logging and error propagation.

    Args:
        cmd:   Command tokens (no shell=True).
        check: Raise CalledProcessError on non-zero exit.

    Returns:
        CompletedProcess instance.
    """
    log.debug("exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Gather current system state
# ---------------------------------------------------------------------------
def _detect_interface() -> Optional[str]:
    """Detect the primary network interface from the default route.

    Returns:
        Interface name string, or None if no default route is found.
    """
    try:
        result = _run(["ip", "route", "show", "default"])
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception as exc:
        log.warning("Could not detect interface for backup: %s", exc)
    return None


def _get_mac(iface: str) -> Optional[str]:
    """Read the current MAC address of the given interface.

    Returns:
        MAC as colon-separated hex, or None on failure.
    """
    try:
        result = _run(["ip", "link", "show", iface])
        match = re.search(r"link/ether\s+([\da-fA-F:]{17})", result.stdout)
        if match:
            return match.group(1).lower()
    except Exception as exc:
        log.warning("Could not read MAC for %s: %s", iface, exc)
    return None


def _get_hostname() -> str:
    """Return the current system hostname."""
    return socket.gethostname()


def _get_timezone() -> Optional[str]:
    """Read the current timezone string via timedatectl.

    Returns:
        Timezone string (e.g. "America/New_York"), or None on failure.
    """
    try:
        result = _run(["timedatectl", "show", "-p", "Timezone", "--value"])
        return result.stdout.strip()
    except Exception as exc:
        log.warning("Could not read timezone for backup: %s", exc)
    return None


def _read_resolv_conf() -> str:
    """Read and return the complete contents of /etc/resolv.conf.

    Returns:
        File contents as a string, or empty string if unreadable.
    """
    try:
        return RESOLV_CONF.read_text()
    except OSError as exc:
        log.warning("Could not read %s for backup: %s", RESOLV_CONF, exc)
        return ""


# ---------------------------------------------------------------------------
# Public API: save / load / delete
# ---------------------------------------------------------------------------
def save() -> dict[str, Any]:
    """Query the current system state and persist it to the backup file.

    This function MUST be called BEFORE any mutations are applied.

    Returns:
        The backup data dict that was written.
    """
    log.info("Collecting original system state for backup...")

    iface = _detect_interface()
    mac = _get_mac(iface) if iface else None

    is_symlink = RESOLV_CONF.is_symlink() if RESOLV_CONF.exists() else False
    symlink_target = os.readlink(str(RESOLV_CONF)) if is_symlink else None

    data: dict[str, Any] = {
        "version": BACKUP_VERSION,
        "mac_address": mac,
        "interface": iface,
        "hostname": _get_hostname(),
        "timezone": _get_timezone(),
        "resolv_conf": _read_resolv_conf(),
        "resolv_conf_is_symlink": is_symlink,
        "resolv_conf_target": symlink_target,
    }

    # Ensure the backup directory exists.
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # Write atomically: write to a temp file then rename.
    tmp_path = BACKUP_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data, indent=2) + "\n")
    tmp_path.rename(BACKUP_PATH)

    log.info("[OK] Backup saved → %s", BACKUP_PATH)
    log.debug("Backup contents: %s", json.dumps(data, indent=2))
    return data


def load() -> Optional[dict[str, Any]]:
    """Read and parse the backup file if it exists.

    Returns:
        Parsed dict, or None if no backup file exists.
    """
    if not BACKUP_PATH.exists():
        return None

    try:
        raw = BACKUP_PATH.read_text()
        data = json.loads(raw)
        log.info("Loaded existing backup from %s", BACKUP_PATH)
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to parse backup file %s: %s", BACKUP_PATH, exc)
        return None


def delete() -> None:
    """Remove the backup file (idempotent)."""
    try:
        BACKUP_PATH.unlink(missing_ok=True)
        log.info("Deleted backup file: %s", BACKUP_PATH)
    except OSError as exc:
        log.warning("Could not delete backup file: %s", exc)


# ---------------------------------------------------------------------------
# Disaster Recovery
# ---------------------------------------------------------------------------
def disaster_recovery() -> None:
    """Detect and recover from a stale backup left by a previous crash.

    If ``/var/lib/torvpn/backup_state.json`` exists when this function is
    called, it means a previous session was terminated abnormally (crash,
    OOM, power loss) and the system may be in a partially mutated state.

    Recovery sequence:
        1. Parse the backup file.
        2. Restore MAC address on the recorded interface.
        3. Restore hostname via hostnamectl.
        4. Restore timezone via timedatectl.
        5. Unlock and restore /etc/resolv.conf.
        6. Delete the stale backup file.

    If any step fails, log the error and exit with
    ``ExitCode.ERROR_BACKUP_RESTORE_FAILURE`` — it is unsafe to proceed
    with a partially restored system.
    """
    data = load()
    if data is None:
        log.debug("No stale backup found — clean start")
        return

    log.warning("=" * 60)
    log.warning("DISASTER RECOVERY — stale backup detected!")
    log.warning("A previous session did not shut down cleanly.")
    log.warning("Restoring original system state before proceeding...")
    log.warning("=" * 60)

    try:
        # -- Restore MAC address --
        iface = data.get("interface")
        mac = data.get("mac_address")
        if iface and mac:
            log.info("Restoring MAC on %s → %s", iface, mac)
            _run(["ip", "link", "set", iface, "down"])
            _run(["ip", "link", "set", iface, "address", mac])
            _run(["ip", "link", "set", iface, "up"])
            log.info("[OK] MAC restored")

        # -- Restore hostname --
        hostname = data.get("hostname")
        if hostname:
            log.info("Restoring hostname → '%s'", hostname)
            _run(["hostnamectl", "set-hostname", hostname])
            log.info("[OK] Hostname restored")

        # -- Restore timezone --
        tz = data.get("timezone")
        if tz:
            log.info("Restoring timezone → '%s'", tz)
            _run(["timedatectl", "set-timezone", tz])
            log.info("[OK] Timezone restored")

        # -- Restore /etc/resolv.conf --
        resolv = data.get("resolv_conf")
        is_symlink = data.get("resolv_conf_is_symlink", False)
        symlink_target = data.get("resolv_conf_target")
        if resolv or is_symlink:
            log.info("Restoring /etc/resolv.conf")
            # Remove immutable flag first (may have been set by dns.lock).
            try:
                _run(["chattr", "-i", str(RESOLV_CONF)])
            except subprocess.CalledProcessError:
                pass  # Flag wasn't set — that's fine.

            if is_symlink and symlink_target:
                RESOLV_CONF.unlink(missing_ok=True)
                os.symlink(symlink_target, str(RESOLV_CONF))
                log.info("[OK] resolv.conf symlink restored to %s", symlink_target)
            elif resolv:
                RESOLV_CONF.write_text(resolv)
                log.info("[OK] resolv.conf restored")

        # -- Clean up --
        delete()

        log.info("=" * 60)
        log.info("DISASTER RECOVERY — COMPLETE")
        log.info("System restored to pre-torvpn state.")
        log.info("=" * 60)

    except Exception as exc:
        log.critical(
            "DISASTER RECOVERY FAILED: %s — system may be in an "
            "inconsistent state. Manual intervention required.", exc
        )
        sys.exit(ExitCode.ERROR_BACKUP_RESTORE_FAILURE)
