"""
src/exitcodes.py — Global Exit Code Definitions
===================================================
Defines a canonical set of exit codes as an IntEnum so that systemd unit
wrappers, parent monitoring scripts, and CI pipelines can programmatically
react to distinct failure modes.

Usage:
    from src.exitcodes import ExitCode
    sys.exit(ExitCode.ERROR_NOT_ROOT)

Every module that calls sys.exit() MUST import from here — never use
bare integer literals for exit codes.
"""

import enum


class ExitCode(enum.IntEnum):
    """Application exit codes.

    Each value maps to a distinct failure category, enabling external
    tooling (systemd, monitoring, wrapper scripts) to differentiate
    between recoverable and fatal conditions without parsing log output.

    Attributes:
        SUCCESS:                    Clean shutdown, no errors.
        ERROR_GENERIC:              Unclassified / unexpected failure.
        ERROR_NOT_ROOT:             Application was not run as root (UID 0).
        ERROR_MISSING_DEPENDENCIES: A required system binary (nft, iptables,
                                    tor, chattr, etc.) was not found.
        ERROR_TOR_BOOTSTRAP_TIMEOUT: Tor failed to reach 100% consensus
                                     bootstrap within the configured timeout.
        ERROR_FIREWALL_FAILURE:     Firewall rules could not be applied, or
                                    the watchdog detected an unrecoverable
                                    Tor crash with kill-switch active.
        ERROR_BACKUP_RESTORE_FAILURE: The disaster-recovery module failed to
                                      restore the system from a stale backup
                                      file left by a previous crashed session.
    """

    SUCCESS = 0
    ERROR_GENERIC = 1
    ERROR_NOT_ROOT = 2
    ERROR_MISSING_DEPENDENCIES = 3
    ERROR_TOR_BOOTSTRAP_TIMEOUT = 4
    ERROR_FIREWALL_FAILURE = 5
    ERROR_BACKUP_RESTORE_FAILURE = 6
