"""
src/main.py — Orchestrator, Watchdog & Fail-Safe
===================================================
Central coordination module that ties together all subsystems into a
clean startup → monitor → teardown lifecycle.

Responsibilities:
    1. Root privilege verification
    2. Ordered startup sequence (footprint → tor → firewall → dns)
    3. Watchdog thread for Tor process health monitoring
    4. Signal handling (SIGINT, SIGTERM) for graceful shutdown
    5. Ordered teardown sequence (reverse of startup)
    6. Emergency panic mode if Tor dies unexpectedly
"""

import logging
import os
import signal
import sys
import threading
import time

from src import dns, firewall, footprint, tor

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
║  System-Wide Transparent Tor Proxy via nftables              ║
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


# ---------------------------------------------------------------------------
# Transactional startup tracking
# ---------------------------------------------------------------------------
# Each step that modifies system state registers itself here when it
# succeeds. Teardown walks this set in REVERSE order, so an early
# failure (e.g., Tor can't bootstrap) doesn't try to undo steps that
# never ran. The keys are stable strings; the values are the bound
# restore functions.
#
# Example: if footprint.harden() raises, no entry is added and
# teardown() will only run footprint.restore() if the MAC-spoof
# sub-step was the one that completed.
_RESTORE_REGISTRY: list[tuple[str, callable]] = []


def _register_restore(label: str, fn) -> None:
    """Append a teardown step. Order of registration = order of undo
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
    """Continuously monitor Tor's health. If Tor crashes, activate the
    kill-switch and attempt to restart it.

    This runs as a daemon thread so it dies automatically if the main
    thread exits (e.g., during teardown).

    Recovery strategy:
        1. Detect Tor death via process.poll()
        2. Immediately activate kill-switch (firewall.panic())
        3. Attempt to restart Tor up to WATCHDOG_MAX_RESTARTS times
        4. If restart succeeds, re-apply firewall rules
        5. If all restarts fail, keep kill-switch active (full lockdown)
    """
    restart_count = 0

    while not _shutdown_event.is_set():
        time.sleep(WATCHDOG_INTERVAL)

        # Don't check during shutdown
        if _shutdown_event.is_set():
            break

        if not tor.is_alive():
            log.critical("=" * 60)
            log.critical("WATCHDOG: Tor process has died unexpectedly!")
            log.critical("=" * 60)

            # Immediately block all traffic. Pass the known tor_uid so
            # the kill-switch's Tor-UID exemption matches the (now
            # dead) Tor process. If we don't know it, the kill-switch
            # blocks everything (safest).
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
                # Stay in the loop to keep logging but don't try to restart
                while not _shutdown_event.is_set():
                    time.sleep(WATCHDOG_INTERVAL)
                break

            restart_count += 1
            log.warning(
                "WATCHDOG: Attempting Tor restart (%d/%d)...",
                restart_count,
                WATCHDOG_MAX_RESTARTS,
            )

            try:
                new_uid = tor.start()
                # Re-apply firewall with (potentially) the same UID
                firewall.apply(new_uid)
                log.info("WATCHDOG: Tor restarted successfully — resuming normal operation")
                restart_count = 0  # Reset counter on success
            except Exception as exc:
                log.error("WATCHDOG: Tor restart failed: %s", exc)
                log.error("WATCHDOG: Kill-switch remains active")

    log.debug("Watchdog thread exiting")


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
    _register_restore(). This function walks them in reverse, so:
        - only completed steps are undone (no half-attempts at things
          that never ran)
        - each step is independently try/except'd so one failure
          doesn't prevent the rest
        - the registry is cleared after a successful run, so the
          function is idempotent (calling _teardown() twice does
          nothing the second time).
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

    log.info("")
    log.info("╔══════════════════════════════════════════════════╗")
    log.info("║        ALL SYSTEMS RESTORED — GOODBYE           ║")
    log.info("╚══════════════════════════════════════════════════╝")
    log.info("")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run() -> None:
    """Execute the full torvpn lifecycle.

    Startup sequence:
        1. Check root privileges
        2. Harden system footprint
        3. Start Tor daemon and wait for bootstrap
        4. Apply nftables firewall rules
        5. Lock DNS to Tor resolver
        6. Start watchdog thread
        7. Block until signal (Ctrl+C or SIGTERM)

    On signal → teardown in reverse order.
    """
    global _tor_uid

    _setup_logging()

    # ── Banner ──
    print(BANNER)

    # ── Step 0: Root check ──
    if os.geteuid() != 0:
        log.error("This application requires root privileges.")
        log.error("Please run with: sudo python3 torvpn.py")
        sys.exit(1)

    log.info("Running as root (UID 0) ✓")

    # ── Register signal handlers ──
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        # ── Step 1: Footprint hardening ──
        # The individual sub-steps register their own undo functions
        # so a partial harden() (e.g., MAC success, hostname fail)
        # still unwinds cleanly.
        _register_restore("footprint", footprint.restore)
        footprint.harden()

        # ── Step 2: Start Tor ──
        # Tor's stop() is itself idempotent and safe to call when
        # start() never produced a live process.
        _tor_uid = tor.start()
        _register_restore("tor", tor.stop)

        # ── Step 3: Apply firewall ──
        firewall.apply(_tor_uid)
        _register_restore("firewall", firewall.teardown)

        # ── Step 4: Lock DNS ──
        dns.lock()
        _register_restore("dns", dns.restore)

        # ── Step 5: Start watchdog ──
        watchdog_thread = threading.Thread(
            target=_watchdog_loop,
            daemon=True,
            name="tor-watchdog",
        )
        watchdog_thread.start()
        log.info("[OK] Watchdog thread started (interval=%ds)", WATCHDOG_INTERVAL)

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

    except FileNotFoundError as exc:
        log.error("Missing dependency: %s", exc)
        log.error("Install required packages and try again.")
    except RuntimeError as exc:
        log.error("Startup failed: %s", exc)
    except Exception as exc:
        log.error("Unexpected error during startup: %s", exc, exc_info=True)
    finally:
        # Always attempt teardown, regardless of how we got here
        _teardown()
