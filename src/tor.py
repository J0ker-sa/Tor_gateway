"""
src/tor.py — Tor Process Lifecycle Manager
============================================
Handles the complete lifecycle of a dedicated Tor daemon instance:
    1. System user creation (torvpn-worker)
    2. Data directory provisioning
    3. torrc configuration generation
    4. Process launch and bootstrap monitoring
    5. Health checking and graceful termination

The Tor daemon runs as a subprocess owned by Python (RunAsDaemon 0),
allowing direct process control via poll(), terminate(), and kill().
"""

import logging
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("torvpn.tor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOR_USER = "torvpn-worker"
TOR_DATA_DIR = Path("/var/lib/torvpn")
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053
TOR_LISTEN_ADDR = "127.0.0.1"
BOOTSTRAP_TIMEOUT = 120  # seconds to wait for 100% bootstrap
TORRC_TEMPLATE = """\
## Auto-generated torrc for torvpn — do not edit manually.
## This file is deleted on shutdown.

# Let Python manage the process lifecycle directly.
RunAsDaemon 0

# Transparent proxy port with stream isolation per destination.
# IsolateDestAddr ensures different destinations use different circuits.
# IsolateDestPort ensures different ports on the same destination are isolated.
TransPort {listen}:{trans_port} IsolateDestAddr IsolateDestPort

# DNS resolver port — all UDP/53 traffic is redirected here by nftables.
DNSPort {listen}:{dns_port}

# Disable SOCKS — we only use transparent proxying.
SocksPort 0

# Dedicated data directory for this instance.
DataDirectory {data_dir}

# Log to stdout so Python can capture and parse bootstrap progress.
Log notice stdout
"""


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------
class _TorState:
    """Holds references to the running Tor process and configuration."""

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.torrc_path: Optional[str] = None
        self.uid: Optional[int] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._bootstrapped = threading.Event()
        self._bootstrap_pct: int = 0
        self._output_lines: list[str] = []


_tor = _TorState()


# ---------------------------------------------------------------------------
# 1. System user management
# ---------------------------------------------------------------------------
def _ensure_user() -> int:
    """Create the dedicated torvpn-worker system user if it doesn't exist.

    The user is created with:
        - No login shell (/usr/sbin/nologin)
        - No home directory
        - System account flag (low UID range)

    Returns:
        The numeric UID of the torvpn-worker user.
    """
    try:
        pw = pwd.getpwnam(TOR_USER)
        uid = pw.pw_uid
        log.info("System user '%s' already exists (UID %d)", TOR_USER, uid)
        return uid
    except KeyError:
        pass  # User doesn't exist — create it

    log.info("Creating system user '%s'", TOR_USER)

    # Determine the correct nologin path for this distribution
    nologin = "/usr/sbin/nologin"
    if not os.path.exists(nologin):
        nologin = "/sbin/nologin"

    subprocess.run(
        [
            "useradd",
            "--system",              # System account (low UID, no aging)
            "--no-create-home",      # No home directory needed
            "--shell", nologin,      # No interactive login
            TOR_USER,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )

    pw = pwd.getpwnam(TOR_USER)
    log.info("[OK] Created system user '%s' (UID %d)", TOR_USER, pw.pw_uid)
    return pw.pw_uid


# ---------------------------------------------------------------------------
# 2. Data directory provisioning
# ---------------------------------------------------------------------------
def _ensure_data_dir(uid: int) -> None:
    """Create and permission the Tor data directory.

    Args:
        uid: The UID of the torvpn-worker user (owner of the directory).
    """
    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    pw = pwd.getpwnam(TOR_USER)
    gid = pw.pw_gid

    # Tor requires the data directory to be owned by the running user
    # and have restrictive permissions (mode 0700).
    os.chown(TOR_DATA_DIR, uid, gid)
    os.chmod(TOR_DATA_DIR, 0o700)

    log.info("[OK] Data directory ready: %s (owner=%d:%d, mode=0700)", TOR_DATA_DIR, uid, gid)


# ---------------------------------------------------------------------------
# 3. torrc generation
# ---------------------------------------------------------------------------
def _write_torrc() -> str:
    """Generate and write the torrc configuration file.

    Returns:
        Absolute path to the generated torrc file.
    """
    content = TORRC_TEMPLATE.format(
        listen=TOR_LISTEN_ADDR,
        trans_port=TOR_TRANS_PORT,
        dns_port=TOR_DNS_PORT,
        data_dir=TOR_DATA_DIR,
    )

    # Write to a secure temporary file
    fd, path = tempfile.mkstemp(prefix="torvpn_", suffix="_torrc")
    with os.fdopen(fd, "w") as f:
        f.write(content)

    # Make readable by the tor user
    os.chmod(path, 0o644)

    log.info("[OK] torrc written to %s", path)
    log.debug("torrc contents:\n%s", content)
    return path


# ---------------------------------------------------------------------------
# 4. Bootstrap monitor (runs in a dedicated thread)
# ---------------------------------------------------------------------------
def _monitor_output(process: subprocess.Popen) -> None:
    """Read Tor's stdout/stderr line by line, parse bootstrap progress,
    and set the bootstrapped event when 100% is reached.

    This runs in a background thread so the main thread can implement
    a timeout via Event.wait(timeout=...).

    Args:
        process: The running Tor subprocess with stdout=PIPE.
    """
    try:
        for raw_line in iter(process.stdout.readline, ""):
            line = raw_line.strip()
            if not line:
                continue

            _tor._output_lines.append(line)

            # Parse bootstrap progress messages
            # Example: "Jan 01 00:00:00.000 [notice] Bootstrapped 50% (loading_descriptors): ..."
            match = re.search(r"Bootstrapped\s+(\d+)%", line)
            if match:
                pct = int(match.group(1))
                _tor._bootstrap_pct = pct
                log.info("[BOOTSTRAP] %d%%: %s", pct, line.split(":", 1)[-1].strip() if ":" in line else "")

                if pct >= 100:
                    _tor._bootstrapped.set()
            elif "err" in line.lower() or "warn" in line.lower():
                # Surface Tor warnings/errors to our log
                log.warning("[TOR] %s", line)
            else:
                log.debug("[TOR] %s", line)
    except (ValueError, OSError):
        # Pipe closed — process is terminating
        pass


# ---------------------------------------------------------------------------
# 5. Public API
# ---------------------------------------------------------------------------
def get_uid() -> Optional[int]:
    """Return the UID of the torvpn-worker user, or None if not yet created."""
    return _tor.uid


def is_alive() -> bool:
    """Check if the Tor process is still running.

    Returns:
        True if the process exists and has not exited.
    """
    if _tor.process is None:
        return False
    return _tor.process.poll() is None


def start() -> int:
    """Execute the full Tor startup sequence.

    Sequence:
        1. Ensure system user exists.
        2. Provision data directory.
        3. Generate torrc.
        4. Launch Tor subprocess.
        5. Wait for 100% bootstrap.

    Returns:
        The UID of the torvpn-worker user (needed by the firewall module).

    Raises:
        RuntimeError: If Tor fails to bootstrap within the timeout.
        FileNotFoundError: If the `tor` binary is not installed.
    """
    log.info("=" * 50)
    log.info("TOR LIFECYCLE — STARTING")
    log.info("=" * 50)

    # Check that tor is installed
    tor_bin = shutil.which("tor")
    if tor_bin is None:
        raise FileNotFoundError(
            "The 'tor' binary was not found on this system. "
            "Install it with: sudo apt install tor  (Debian/Ubuntu) or "
            "sudo pacman -S tor  (Arch)."
        )
    log.info("Found Tor binary: %s", tor_bin)

    # Step 1: User
    uid = _ensure_user()
    _tor.uid = uid

    # Step 2: Data directory
    _ensure_data_dir(uid)

    # Step 3: torrc
    torrc_path = _write_torrc()
    _tor.torrc_path = torrc_path

    # Step 4: Launch Tor as torvpn-worker
    log.info("Launching Tor process as user '%s' (UID %d)...", TOR_USER, uid)

    pw = pwd.getpwnam(TOR_USER)

    def _demote():
        """Pre-exec function to drop privileges to torvpn-worker."""
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    _tor.process = subprocess.Popen(
        [tor_bin, "-f", torrc_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Merge stderr into stdout for unified parsing
        text=True,
        preexec_fn=_demote,
    )

    log.info("Tor process launched (PID %d)", _tor.process.pid)

    # Step 5: Monitor bootstrap in a background thread
    _tor._reader_thread = threading.Thread(
        target=_monitor_output,
        args=(_tor.process,),
        daemon=True,
        name="tor-bootstrap-monitor",
    )
    _tor._reader_thread.start()

    # Wait for bootstrap completion
    log.info("Waiting for Tor to bootstrap (timeout=%ds)...", BOOTSTRAP_TIMEOUT)
    if not _tor._bootstrapped.wait(timeout=BOOTSTRAP_TIMEOUT):
        # Timeout — Tor didn't reach 100%
        log.error("Tor bootstrap timed out at %d%%", _tor._bootstrap_pct)
        stop()
        raise RuntimeError(
            f"Tor failed to bootstrap within {BOOTSTRAP_TIMEOUT}s. "
            f"Reached {_tor._bootstrap_pct}%. Check network connectivity."
        )

    log.info("=" * 50)
    log.info("[OK] TOR FULLY BOOTSTRAPPED — 100%%")
    log.info("=" * 50)
    return uid


def stop() -> None:
    """Gracefully terminate the Tor process.

    Sends SIGTERM first and waits up to 10 seconds. If the process
    doesn't exit, escalates to SIGKILL.
    """
    if _tor.process is None:
        log.debug("No Tor process to stop")
        return

    pid = _tor.process.pid
    log.info("Stopping Tor process (PID %d)...", pid)

    if _tor.process.poll() is None:
        # Process is still running — request graceful shutdown
        _tor.process.terminate()
        try:
            _tor.process.wait(timeout=10)
            log.info("[OK] Tor exited gracefully")
        except subprocess.TimeoutExpired:
            log.warning("Tor did not exit after SIGTERM — sending SIGKILL")
            _tor.process.kill()
            _tor.process.wait(timeout=5)
            log.info("[OK] Tor killed")
    else:
        log.info("Tor process already exited (code=%d)", _tor.process.returncode)

    # Clean up the temporary torrc
    if _tor.torrc_path and os.path.exists(_tor.torrc_path):
        os.unlink(_tor.torrc_path)
        log.debug("Removed temporary torrc: %s", _tor.torrc_path)

    _tor.process = None
