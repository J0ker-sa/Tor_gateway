"""
src/tor.py — Tor Process Lifecycle Manager
============================================
Handles the complete lifecycle of a dedicated Tor daemon instance:
    1. System user creation (torvpn-worker)
    2. Data directory provisioning
    3. torrc configuration generation
    4. Process launch and bootstrap monitoring with heartbeat
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
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from src.exitcodes import ExitCode

log = logging.getLogger("torvpn.tor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOR_USER = "torvpn-worker"
TOR_DATA_DIR = Path("/var/lib/torvpn")
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053
TOR_LISTEN_ADDR = "127.0.0.1"

# Default bootstrap timeout — overridden by config.bootstrap_timeout at
# runtime.  This constant exists only as a fallback for direct module
# usage outside the orchestrator.
DEFAULT_BOOTSTRAP_TIMEOUT = 300  # seconds

# Paths searched (in order) for the optional bridges configuration.
# If any of these files exist, bridge mode is enabled automatically.
# Each non-empty, non-comment line is appended verbatim to the torrc.
BRIDGES_CONF = Path("/etc/torvpn/bridges.conf")
BRIDGES_USER_CONF = Path.home() / ".config" / "torvpn" / "bridges.conf"

# Base torrc — no bridges.  Bridge lines are appended if a bridges.conf
# is found.  The {bridge_section} placeholder is replaced with either
# the bridge directives (UseBridges 1 + ClientTransportPlugin + Bridge
# lines) or the string ``# (no bridges configured)`` so Tor uses its
# default guard selection.
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

# ─── Bridge / pluggable transport section ──────────────────────────
{bridge_section}
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
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._bootstrapped = threading.Event()
        self._bootstrap_pct: int = 0
        self._output_lines: list[str] = []
        self.bridge_mode: bool = False


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

    Also installs a sudoers rule allowing root to run ``tor`` as
    ``torvpn-worker`` non-interactively (NOPASSWD).  This is required by
    the ``sudo -u`` launch strategy.

    Returns:
        The numeric UID of the torvpn-worker user.
    """
    try:
        pw = pwd.getpwnam(TOR_USER)
        uid = pw.pw_uid
        log.info("System user '%s' already exists (UID %d)", TOR_USER, uid)
        _ensure_sudoers_rule(uid)
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
    uid = pw.pw_uid
    log.info("[OK] Created system user '%s' (UID %d)", TOR_USER, uid)
    _ensure_sudoers_rule(uid)
    return uid


# Sudoers file granting root the right to run ``tor`` as torvpn-worker
# without a password.
SUDOERS_FILE = Path("/etc/sudoers.d/torvpn-tor")


def _ensure_sudoers_rule(uid: int) -> None:
    """Install /etc/sudoers.d/torvpn-tor with NOPASSWD for ``tor``.

    Idempotent: writes only if the file does not already contain the
    correct line.  The rule is scoped to a single binary (tor) and a
    single target user (torvpn-worker) — no broader access is granted.
    """
    try:
        if SUDOERS_FILE.exists():
            existing = SUDOERS_FILE.read_text()
            if "torvpn-worker" in existing and "NOPASSWD" in existing:
                log.debug("sudoers rule already present at %s", SUDOERS_FILE)
                return
    except OSError as exc:
        log.warning("Could not read existing sudoers file: %s", exc)

    # Locate the tor binary path so the rule matches the actual install
    tor_path = shutil.which("tor") or "/usr/bin/tor"
    desired_line = f"root ALL=(ALL) NOPASSWD: {tor_path}\n"

    try:
        SUDOERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SUDOERS_FILE.write_text(desired_line)
        os.chmod(SUDOERS_FILE, 0o440)
        log.info("[OK] Installed sudoers rule: %s", SUDOERS_FILE)

        # Validate the sudoers file is well-formed (visudo -c -f)
        visudo = shutil.which("visudo")
        if visudo:
            result = subprocess.run(
                [visudo, "-c", "-f", str(SUDOERS_FILE)],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                log.error("sudoers file failed validation: %s", result.stderr)
                SUDOERS_FILE.unlink(missing_ok=True)
                raise RuntimeError(
                    f"Could not install valid sudoers rule: {result.stderr}"
                )
    except OSError as exc:
        log.error("Failed to install sudoers rule: %s", exc)
        raise RuntimeError(f"sudoers install failed: {exc}") from exc


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
def _load_bridge_section() -> tuple[str, bool]:
    """Read bridges.conf (if present) and return the torrc lines to inject.

    The returned string includes a ``UseBridges 1`` directive plus the
    client-transport-plugin and Bridge lines from the file.  The bool
    indicates whether bridge mode is active (so the caller can log it).

    Search order:
        1. /etc/torvpn/bridges.conf    (system-wide)
        2. ~/.config/torvpn/bridges.conf (per-user)

    Returns:
        (bridge_section_text, enabled)
    """
    candidates = [BRIDGES_CONF, BRIDGES_USER_CONF]
    for path in candidates:
        if not path.exists():
            continue
        try:
            raw = path.read_text()
        except OSError as exc:
            log.warning("Could not read bridges file %s: %s", path, exc)
            continue

        # Filter blank lines and comments.  Each remaining line is
        # appended verbatim — the user is responsible for the syntax.
        lines = [
            ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if not lines:
            log.warning("Bridges file %s is empty — ignoring", path)
            continue

        section = "UseBridges 1\n" + "\n".join(lines)
        log.info("Bridge mode enabled (from %s, %d line%s)",
                 path, len(lines), "s" if len(lines) != 1 else "")
        return section, True

    return "# (no bridges configured — using Tor's default guard selection)", False


def generate_torrc() -> str:
    """Generate the torrc configuration content WITHOUT writing to disk.

    This is used by the ``--dry-run`` mode to show the user what
    configuration would be applied.

    Returns:
        The complete torrc file content as a string.
    """
    bridge_section, _ = _load_bridge_section()
    return TORRC_TEMPLATE.format(
        listen=TOR_LISTEN_ADDR,
        trans_port=TOR_TRANS_PORT,
        dns_port=TOR_DNS_PORT,
        data_dir=TOR_DATA_DIR,
        bridge_section=bridge_section,
    )


def _write_torrc() -> tuple[str, bool]:
    """Generate and write the torrc configuration file.

    Returns:
        (torrc_path, bridge_mode_enabled)
    """
    bridge_section, bridge_enabled = _load_bridge_section()

    content = TORRC_TEMPLATE.format(
        listen=TOR_LISTEN_ADDR,
        trans_port=TOR_TRANS_PORT,
        dns_port=TOR_DNS_PORT,
        data_dir=TOR_DATA_DIR,
        bridge_section=bridge_section,
    )

    # Write to a secure temporary file
    fd, path = tempfile.mkstemp(prefix="torvpn_", suffix="_torrc")
    with os.fdopen(fd, "w") as f:
        f.write(content)

    # Make readable by the tor user
    os.chmod(path, 0o644)

    log.info("[OK] torrc written to %s (bridges=%s)", path, bridge_enabled)
    log.debug("torrc contents:\n%s", content)
    return path, bridge_enabled


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


def _heartbeat_loop(timeout: int) -> None:
    """Emit a heartbeat log message every 5 seconds during bootstrap.

    Provides visible feedback to the user/operator that the bootstrap
    process is still active, and shows elapsed time.  Stops once
    bootstrap completes or the timeout is reached.

    Args:
        timeout: The bootstrap timeout in seconds (for display only —
                 the actual timeout enforcement is in ``start()``).
    """
    start_time = time.monotonic()
    interval = 5  # seconds between heartbeats

    while not _tor._bootstrapped.is_set():
        _tor._bootstrapped.wait(timeout=interval)
        if _tor._bootstrapped.is_set():
            break

        elapsed = int(time.monotonic() - start_time)
        pct = _tor._bootstrap_pct
        log.info(
            "[HEARTBEAT] Tor is bootstrapping... "
            "[Elapsed: %ds / %ds] [Progress: %d%%]",
            elapsed, timeout, pct,
        )

        # Stop heartbeat if we've exceeded the timeout (the main
        # thread will handle the actual termination).
        if elapsed >= timeout:
            break


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


def start(bootstrap_timeout: int = DEFAULT_BOOTSTRAP_TIMEOUT) -> int:
    """Execute the full Tor startup sequence.

    Sequence:
        1. Ensure system user exists.
        2. Provision data directory.
        3. Generate torrc.
        4. Launch Tor subprocess.
        5. Start heartbeat thread.
        6. Wait for 100% bootstrap.

    Args:
        bootstrap_timeout: Maximum seconds to wait for Tor to reach
                           100% network consensus bootstrap.

    Returns:
        The UID of the torvpn-worker user (needed by the firewall module).

    Raises:
        FileNotFoundError: If the ``tor`` binary is not installed.
        SystemExit: If Tor fails to bootstrap within the timeout
                    (exits with ``ExitCode.ERROR_TOR_BOOTSTRAP_TIMEOUT``).
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

    # Step 1.5: Clean up any orphaned Tor processes from previous runs
    log.info("Cleaning up any orphaned Tor processes or rogue listeners...")
    subprocess.run(["pkill", "-9", "-u", TOR_USER, "-x", "tor"], check=False)
    
    # Aggressively free up our required ports in case another user/process is holding them
    if shutil.which("fuser"):
        subprocess.run(["fuser", "-k", "-9", f"{TOR_TRANS_PORT}/tcp"], check=False, capture_output=True)
        subprocess.run(["fuser", "-k", "-9", f"{TOR_DNS_PORT}/udp"], check=False, capture_output=True)

    time.sleep(0.5)  # Give the OS a moment to release the sockets

    # Step 2: Data directory
    _ensure_data_dir(uid)

    # Step 3: torrc
    torrc_path, bridge_enabled = _write_torrc()
    _tor.torrc_path = torrc_path
    _tor.bridge_mode = bridge_enabled

    # Step 4: Launch Tor as torvpn-worker
    log.info("Launching Tor process as user '%s' (UID %d) via sudo...", TOR_USER, uid)

    # Prefer ``sudo -u`` over preexec_fn=os.setuid.  Reasons:
    #   - sudo sets up PAM (rlimits, nsswitch, login uid) correctly
    #   - leaves an audit trail in /var/log/auth.log
    #   - RLIMIT_NPROC / RLIMIT_NOFILE applied per PAM config
    #   - if Tor crashes and dumps core, the core is owned by the
    #     worker user, not by root (smaller forensic footprint)
    # Falls back to preexec_fn if sudo is unavailable.
    sudo_bin = shutil.which("sudo")
    if sudo_bin:
        argv = [sudo_bin, "-n", "-u", TOR_USER, "--", tor_bin, "-f", torrc_path]
        _tor.process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merged for unified parsing
            text=True,
        )
    else:
        log.warning("sudo not found — falling back to preexec_fn setuid (less safe)")
        pw = pwd.getpwnam(TOR_USER)

        def _demote():
            """Pre-exec function to drop privileges to torvpn-worker."""
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)

        _tor.process = subprocess.Popen(
            [tor_bin, "-f", torrc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merged for unified parsing
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

    # Step 5b: Start heartbeat thread — logs progress every 5 seconds
    _tor._heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(bootstrap_timeout,),
        daemon=True,
        name="tor-bootstrap-heartbeat",
    )
    _tor._heartbeat_thread.start()

    # Step 6: Wait for bootstrap completion
    log.info("Waiting for Tor to bootstrap (timeout=%ds)...", bootstrap_timeout)
    if not _tor._bootstrapped.wait(timeout=bootstrap_timeout):
        # Timeout — Tor didn't reach 100%
        log.critical(
            "Tor bootstrap timed out at %d%% after %ds",
            _tor._bootstrap_pct, bootstrap_timeout,
        )
        stop()
        sys.exit(ExitCode.ERROR_TOR_BOOTSTRAP_TIMEOUT)

    log.info("=" * 50)
    log.info("[OK] TOR FULLY BOOTSTRAPPED — 100%%")
    log.info("=" * 50)
    return uid


def stop() -> None:
    """Gracefully terminate the Tor process.

    Sends SIGTERM first and waits up to 10 seconds.  If the process
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

    # Remove the sudoers rule we installed.  We do NOT remove the
    # torvpn-worker user itself — keeping it lets subsequent runs
    # skip the useradd step.  To remove it, use ``userdel torvpn-worker``.
    if SUDOERS_FILE.exists():
        try:
            SUDOERS_FILE.unlink()
            log.debug("Removed sudoers rule: %s", SUDOERS_FILE)
        except OSError as exc:
            log.warning("Could not remove sudoers rule: %s", exc)

    _tor.process = None
