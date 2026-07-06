"""
src/main.py — Orchestrator, Watchdog & Fail-Safe
===================================================
Central coordination module that ties together all subsystems into a
clean startup → monitor → teardown lifecycle.

Responsibilities:
    1. CLI argument parsing (--dry-run, --bootstrap-timeout)
    2. Root privilege verification (bypassed in --dry-run)
    3. Disaster recovery from stale backup files
    4. Persistent backup of original system state
    5. Ordered startup sequence (footprint → tor → firewall → dns)
    6. Watchdog thread for Tor process health monitoring
    7. Signal handling (SIGINT, SIGTERM) for graceful shutdown
    8. Ordered teardown sequence (reverse of startup)
    9. Emergency panic mode if Tor dies unexpectedly
    10. Dry-run mode: print planned config and exit
"""

import logging
import os
import signal
import sys
import threading
import time

from src import backup, dns, firewall, footprint, tor
from src.config import Config, parse_args
from src.exitcodes import ExitCode

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
def _setup_logging() -> None:
    """Configure the logging system with a clean, readable format.

    Uses color-coded level names when outputting to a terminal.
    """
    # Custom formatter with optional ANSI colors
    class _ColorFormatter(logging.Formatter):
        """Formatter that adds ANSI color codes when writing to a TTY."""

        COLORS = {
            "DEBUG":    "\033[90m",       # Gray
            "INFO":     "\033[36m",       # Cyan
            "WARNING":  "\033[33m",       # Yellow
            "ERROR":    "\033[31m",       # Red
            "CRITICAL": "\033[1;31m",     # Bold red
        }
        RESET = "\033[0m"

        def __init__(self, use_color: bool = True):
            super().__init__(
                fmt="%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
                datefmt="%H:%M:%S",
            )
            self.use_color = use_color

        def format(self, record: logging.LogRecord) -> str:
            if self.use_color:
                color = self.COLORS.get(record.levelname, "")
                record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_ColorFormatter(use_color=sys.stdout.isatty()))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


log = logging.getLogger("torvpn.main")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ████████╗ ██████╗ ██████╗   ██╗   ██╗██████╗ ███╗   ██╗   ║
║   ╚══██╔══╝██╔═══██╗██╔══██╗  ██║   ██║██╔══██╗████╗  ██║   ║
║      ██║   ██║   ██║██████╔╝  ██║   ██║██████╔╝██╔██╗ ██║   ║
║      ██║   ██║   ██║██╔══██╗  ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║   ║
║      ██║   ╚██████╔╝██║  ██║   ╚████╔╝ ██║     ██║ ╚████║   ║
║      ╚═╝    ╚═════╝ ╚═╝  ╚═╝    ╚═══╝  ╚═╝     ╚═╝  ╚═══╝   ║
║                                                              ║
║  System-Wide Transparent Tor Proxy via nftables/iptables     ║
║  ─────────────────────────────────────────────               ║
║  All TCP + DNS traffic routed through Tor                    ║
║  Kill-switch active • IPv6 disabled • MAC spoofed            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------
_shutdown_event = threading.Event()   # Signals the main thread to begin teardown
_is_tearing_down = False              # Guard against double teardown
_tor_uid: int = 0                     # Populated after Tor starts
_config: Config = Config()            # Populated by run()
_maintenance_mode = False             # Set to True when intentionally stopping Tor for maintenance


# ---------------------------------------------------------------------------
# Transactional startup tracking
# ---------------------------------------------------------------------------
# Each step that modifies system state registers itself here when it
# succeeds.  Teardown walks this set in REVERSE order, so an early
# failure (e.g., Tor can't bootstrap) doesn't try to undo steps that
# never ran.  The keys are stable strings; the values are the bound
# restore functions.
#
# Example: if footprint.harden() raises, no entry is added and
# teardown() will only run footprint.restore() if the MAC-spoof
# sub-step was the one that completed.
_RESTORE_REGISTRY: list[tuple[str, callable]] = []


def _register_restore(label: str, fn) -> None:
    """Append a teardown step.  Order of registration = order of undo
    (reverse at teardown time)."""
    _RESTORE_REGISTRY.append((label, fn))


def _registered_restore() -> None:
    """Undo everything that was registered, in reverse order.

    Idempotent: each registered function is itself safe to call when
    its corresponding state isn't present (the modules return early).
    Errors are logged, never raised, so a single failed step doesn't
    leave the rest of the teardown undone.
    """
    log.info("Registered restore steps (in reverse):")
    for label, _fn in reversed(_RESTORE_REGISTRY):
        log.info("  ↻ %s", label)
    log.info("")
    for label, fn in reversed(_RESTORE_REGISTRY):
        try:
            fn()
        except Exception as exc:
            log.error("Restore step %r failed: %s", label, exc)
    _RESTORE_REGISTRY.clear()


# ---------------------------------------------------------------------------
# Watchdog thread
# ---------------------------------------------------------------------------
WATCHDOG_INTERVAL = 5     # seconds between health checks
WATCHDOG_MAX_RESTARTS = 3 # maximum Tor restart attempts before permanent lockdown


def _watchdog_loop() -> None:
    """Continuously monitor Tor's health.  If Tor crashes, activate the
    kill-switch and attempt to restart it.

    This runs as a daemon thread so it dies automatically if the main
    thread exits (e.g., during teardown).

    Recovery strategy:
        1. Detect Tor death via process.poll()
        2. Immediately activate kill-switch (firewall.panic())
        3. Attempt to restart Tor up to WATCHDOG_MAX_RESTARTS times
        4. If restart succeeds, re-apply firewall rules
        5. If all restarts fail, keep kill-switch active (full lockdown)
           and exit with ERROR_FIREWALL_FAILURE
    """
    global _maintenance_mode
    restart_count = 0

    while not _shutdown_event.is_set():
        time.sleep(WATCHDOG_INTERVAL)

        # Don't check during shutdown
        if _shutdown_event.is_set():
            break

        if not tor.is_alive():
            if _maintenance_mode:
                # Tor is intentionally stopped for maintenance (e.g., IP rotation).
                # Do not panic or attempt restart; just wait for it to come back.
                log.debug("Watchdog: Tor is temporarily stopped for maintenance (IP rotation)")
                continue

            log.critical("=" * 60)
            log.critical("WATCHDOG: Tor process has died unexpectedly!")
            log.critical("=" * 60)

            # Immediately block all traffic.  Pass the known tor_uid so
            # the kill-switch's Tor-UID exemption matches the (now
            # dead) Tor process.
            firewall.panic(tor_uid=tor.get_uid() or 0)

            if restart_count >= WATCHDOG_MAX_RESTARTS:
                log.critical(
                    "WATCHDOG: Maximum restart attempts (%d) exhausted",
                    WATCHDOG_MAX_RESTARTS,
                )
                log.critical(
                    "WATCHDOG: System is in FULL LOCKDOWN — no internet access"
                )
                log.critical(
                    "WATCHDOG: Restart torvpn manually or press Ctrl+C to exit"
                )
                # Signal shutdown and exit with the appropriate code.
                _shutdown_event.set()
                # Give the main thread a moment to begin teardown,
                # then force exit if it hasn't.
                time.sleep(2)
                sys.exit(ExitCode.ERROR_FIREWALL_FAILURE)

            restart_count += 1
            log.warning(
                "WATCHDOG: Attempting Tor restart (%d/%d)...",
                restart_count,
                WATCHDOG_MAX_RESTARTS,
            )

            try:
                new_uid = tor.start(bootstrap_timeout=_config.bootstrap_timeout)
                # Re-apply firewall with (potentially) the same UID
                firewall.apply(new_uid)
                log.info("WATCHDOG: Tor restarted successfully — resuming normal operation")
                restart_count = 0  # Reset counter on success
            except Exception as exc:
                log.error("WATCHDOG: Tor restart failed: %s", exc)
                log.error("WATCHDOG: Kill-switch remains active")

    log.debug("Watchdog thread exiting")


def _ip_rotator_loop() -> None:
    """Periodically restart Tor to obtain a new IP address.

    This runs as a daemon thread and restarts Tor every 5 minutes (300 seconds)
    to rotate the exit node and thus the public IP address.
    """
    global _maintenance_mode
    while not _shutdown_event.is_set():
        # Sleep for 5 minutes (300 seconds) but check for shutdown every second
        # to allow timely termination.
        for _ in range(300):
            if _shutdown_event.is_set():
                break
            time.sleep(1)

        if _shutdown_event.is_set():
            break

        # Only attempt rotation if Tor is alive (otherwise watchdog will handle restart)
        if tor.is_alive():
            log.info("IP rotator: Restarting Tor to obtain a new IP address...")
            try:
                # Enter maintenance mode so watchdog does not panic or attempt restart
                _maintenance_mode = True
                # Stop Tor
                tor.stop()
                # Start Tor again with the same bootstrap timeout
                new_uid = tor.start(bootstrap_timeout=_config.bootstrap_timeout)
                # Re-apply firewall with the same UID (should be same as before)
                firewall.apply(new_uid)
                log.info("IP rotator: Tor restarted successfully with new IP")
            except Exception as exc:
                log.error("IP rotator: Failed to restart Tor: %s", exc)
                # If restart fails, we leave Tor stopped; the watchdog will detect
                # the dead process and attempt recovery (but note we are in maintenance mode)
            finally:
                # Exit maintenance mode
                _maintenance_mode = False
        else:
            log.debug("IP rotator: Tor is not alive, skipping rotation (watchdog will handle)")

    log.debug("IP rotator thread exiting")


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
def _signal_handler(signum: int, frame) -> None:
    """Handle SIGINT (Ctrl+C) and SIGTERM for graceful shutdown.

    Sets the shutdown event which unblocks the main thread to run
    the teardown sequence.
    """
    sig_name = signal.Signals(signum).name
    log.info("")  # Blank line after ^C
    log.info("Received %s — initiating graceful shutdown...", sig_name)
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
def _teardown() -> None:
    """Execute the registered teardown steps in reverse order.

    Each startup step that succeeded registered its undo function via
    _register_restore().  This function walks them in reverse, so:
        - only completed steps are undone (no half-attempts at things
          that never ran)
        - each step is independently try/except'd so one failure
          doesn't prevent the rest
        - the registry is cleared after a successful run, so the
          function is idempotent (calling _teardown() twice does
          nothing the second time).

    Also deletes the persistent backup file on clean shutdown.
    """
    global _is_tearing_down

    if _is_tearing_down:
        log.warning("Teardown already in progress — ignoring duplicate call")
        return

    _is_tearing_down = True

    log.info("")
    log.info("╔══════════════════════════════════════════════════╗")
    log.info("║           TEARDOWN — RESTORING SYSTEM           ║")
    log.info("╚══════════════════════════════════════════════════╝")
    log.info("")

    # Run all registered undo steps (reverse order of registration).
    _registered_restore()

    # Delete the persistent backup file — the system is now restored.
    backup.delete()

    log.info("")
    log.info("╔══════════════════════════════════════════════════╗")
    log.info("║        ALL SYSTEMS RESTORED — GOODBYE           ║")
    log.info("╚══════════════════════════════════════════════════╝")
    log.info("")


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------
def _dry_run() -> None:
    """Execute dry-run mode: print planned configuration and exit.

    Does NOT:
        - Check root privileges
        - Modify any system settings
        - Launch any processes
        - Apply any firewall rules

    DOES:
        - Print the planned torrc configuration
        - Print the planned firewall ruleset (nftables or iptables)
        - Exit with ExitCode.SUCCESS
    """
    log.info("DRY-RUN MODE — no system modifications will be made")
    log.info("")

    # Generate torrc content
    torrc_content = tor.generate_torrc()

    # Generate firewall ruleset (use UID 0 as placeholder)
    ruleset_content = firewall.generate_ruleset(tor_uid=0)

    # Print to stdout
    print("=" * 70)
    print("  PLANNED TORRC CONFIGURATION")
    print("=" * 70)
    print(torrc_content)
    print()
    print("=" * 70)
    print("  PLANNED FIREWALL RULESET")
    print("=" * 70)
    print(ruleset_content)
    print()
    print("=" * 70)
    print(f"  Bootstrap timeout: {_config.bootstrap_timeout}s")
    print("=" * 70)

    log.info("Dry-run complete — exiting")
    sys.exit(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run() -> None:
    """Execute the full torvpn lifecycle.

    Startup sequence:
        0. Parse CLI arguments
        1. Check root privileges (skip in --dry-run)
        2. Run disaster recovery if stale backup exists
        3. Save persistent backup of original state
        4. Harden system footprint
        5. Start Tor daemon and wait for bootstrap
        6. Apply firewall rules
        7. Lock DNS to Tor resolver
        8. Start watchdog thread
        9. Block until signal (Ctrl+C or SIGTERM)

    On signal → teardown in reverse order.
    """
    global _tor_uid, _config

    _setup_logging()

    # ── Step 0: Parse CLI arguments ──
    _config = parse_args()

    # ── Banner ──
    print(BANNER)

    # ── Dry-run check (before root check) ──
    if _config.dry_run:
        _dry_run()
        # _dry_run() calls sys.exit() — this line is never reached.

    # ── Step 1: Root check ──
    if os.geteuid() != 0:
        log.critical("This application requires root privileges.")
        log.critical("Please run with: sudo python3 torvpn.py")
        sys.exit(ExitCode.ERROR_NOT_ROOT)

    log.info("Running as root (UID 0) ✓")

    # ── Register signal handlers ──
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        # ── Step 2: Disaster recovery ──
        # If a previous session crashed and left a stale backup file,
        # restore the system to its original state before proceeding.
        backup.disaster_recovery()

        # ── Step 3: Save persistent backup ──
        # Capture original system state BEFORE any mutations.
        backup.save()

        # ── Step 4: Footprint hardening ──
        # The individual sub-steps register their own undo functions
        # so a partial harden() (e.g., MAC success, hostname fail)
        # still unwinds cleanly.
        _register_restore("footprint", footprint.restore)
        footprint.harden()

        # ── Step 5: Start Tor ──
        # Tor's stop() is itself idempotent and safe to call when
        # start() never produced a live process.
        _tor_uid = tor.start(bootstrap_timeout=_config.bootstrap_timeout)
        _register_restore("tor", tor.stop)

        # ── Step 6: Apply firewall ──
        firewall.apply(_tor_uid)
        _register_restore("firewall", firewall.teardown)

        # ── Step 7: Lock DNS ──
        dns.lock()
        _register_restore("dns", dns.restore)

        # ── Step 8: Start watchdog ──
        watchdog_thread = threading.Thread(
            target=_watchdog_loop,
            daemon=True,
            name="tor-watchdog",
        )
        watchdog_thread.start()
        log.info("[OK] Watchdog thread started (interval=%ds)", WATCHDOG_INTERVAL)

        # ── Step 9: Start IP rotator (rotates exit node every 5 minutes) ──
        ip_rotator_thread = threading.Thread(
            target=_ip_rotator_loop,
            daemon=True,
            name="ip-rotator",
        )
        ip_rotator_thread.start()
        log.info("[OK] IP rotator thread started (interval=300s)")

        # ── All systems go ──
        log.info("")
        log.info("╔══════════════════════════════════════════════════╗")
        log.info("║         TOR VPN IS ACTIVE — ALL TRAFFIC         ║")
        log.info("║         IS NOW ROUTED THROUGH TOR               ║")
        log.info("║                                                  ║")
        log.info("║  Verify: curl https://check.torproject.org       ║")
        log.info("║  Press Ctrl+C to disconnect and restore system   ║")
        log.info("╚══════════════════════════════════════════════════╝")
        log.info("")

        # ── Block until shutdown signal ──
        # Event.wait() is signal-safe and releases the GIL,
        # allowing the signal handler to set() it.
        _shutdown_event.wait()

    except SystemExit:
        # Re-raise SystemExit so ExitCode-based exits propagate cleanly
        # through the finally block.
        raise
    except FileNotFoundError as exc:
        log.critical("Missing dependency: %s", exc)
        log.critical("Install required packages and try again.")
        sys.exit(ExitCode.ERROR_MISSING_DEPENDENCIES)
    except RuntimeError as exc:
        log.critical("Startup failed: %s", exc)
        sys.exit(ExitCode.ERROR_GENERIC)
    except Exception as exc:
        log.critical("Unexpected error during startup: %s", exc, exc_info=True)
        sys.exit(ExitCode.ERROR_GENERIC)
    finally:
        # Always attempt teardown, regardless of how we got here
        _teardown()
