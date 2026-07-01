"""
src/config.py — CLI Configuration & Argument Parsing
=======================================================
Centralises all runtime configuration into a single ``Config`` dataclass
populated from CLI flags and environment variables.

Precedence for --bootstrap-timeout:
    1. CLI flag (highest)
    2. Environment variable ``TOR_BOOTSTRAP_TIMEOUT``
    3. Built-in default (300 seconds)

Usage:
    from src.config import parse_args, Config
    cfg = parse_args()        # uses sys.argv
    cfg = parse_args([...])   # explicit args (for testing)
"""

import argparse
import os
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_BOOTSTRAP_TIMEOUT = 300  # seconds


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration container.

    Attributes:
        dry_run:            When True, skip all system-modifying actions.
                            Instead, print the planned torrc and firewall
                            ruleset to stdout and exit successfully.
        bootstrap_timeout:  Maximum number of seconds to wait for Tor
                            to reach 100% network consensus bootstrap.
    """

    dry_run: bool = False
    bootstrap_timeout: int = DEFAULT_BOOTSTRAP_TIMEOUT


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> Config:
    """Parse command-line arguments and environment overrides.

    Args:
        argv: Explicit argument list. ``None`` means ``sys.argv[1:]``
              (the default argparse behaviour). Pass an explicit list
              in unit tests to avoid touching the real CLI.

    Returns:
        A frozen ``Config`` instance.
    """
    parser = argparse.ArgumentParser(
        prog="torvpn",
        description=(
            "System-wide transparent Tor proxy for Linux. "
            "Routes all TCP and DNS traffic through a locally managed "
            "Tor daemon using nftables/iptables transparent proxying, "
            "with comprehensive footprint hardening and a fail-safe "
            "kill-switch."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "Do not modify the system. Print the planned torrc "
            "configuration and firewall ruleset to stdout and exit."
        ),
    )

    parser.add_argument(
        "--bootstrap-timeout",
        type=int,
        default=None,  # None so we can detect "not provided"
        metavar="SECONDS",
        help=(
            f"Maximum seconds to wait for Tor bootstrap "
            f"(default: {DEFAULT_BOOTSTRAP_TIMEOUT}). "
            f"Can also be set via the TOR_BOOTSTRAP_TIMEOUT "
            f"environment variable; the CLI flag takes precedence."
        ),
    )

    args = parser.parse_args(argv)

    # Resolve bootstrap_timeout with precedence:
    #   CLI flag  >  env var  >  built-in default
    if args.bootstrap_timeout is not None:
        # Explicit CLI flag — highest priority.
        timeout = args.bootstrap_timeout
    else:
        env_val = os.environ.get("TOR_BOOTSTRAP_TIMEOUT")
        if env_val is not None:
            try:
                timeout = int(env_val)
            except ValueError:
                # Malformed env var — fall back to default with a warning.
                # (We can't use the logging module here because it hasn't
                # been configured yet.)
                print(
                    f"[WARN] TOR_BOOTSTRAP_TIMEOUT='{env_val}' is not a "
                    f"valid integer — using default ({DEFAULT_BOOTSTRAP_TIMEOUT}s)"
                )
                timeout = DEFAULT_BOOTSTRAP_TIMEOUT
        else:
            timeout = DEFAULT_BOOTSTRAP_TIMEOUT

    return Config(
        dry_run=args.dry_run,
        bootstrap_timeout=timeout,
    )
