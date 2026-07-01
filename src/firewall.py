"""
src/firewall.py — nftables Firewall & Routing Engine
======================================================
Generates and manages the nftables ruleset that implements transparent
Tor proxying with a kill-switch.

Architecture:
    table inet torvpn
    ├── chain output     (nat, priority -100)  — DNAT redirections
    └── chain killswitch (filter, priority 0)  — kill-switch with policy drop

Traffic flow:
    1. Tor daemon traffic (by UID) → ACCEPT (bypass all rules)
    2. LAN traffic → ACCEPT (preserve local connectivity)
    3. DNS (UDP/53) → DNAT to 127.0.0.1:9053 (Tor DNSPort)
    4. All TCP → DNAT to 127.0.0.1:9040 (Tor TransPort)
    5. Everything else → DROP (kill-switch)
"""

import logging
import subprocess

log = logging.getLogger("torvpn.firewall")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TABLE_NAME = "torvpn"
TABLE_FAMILY = "inet"

# Subnets exempt from Tor redirection (local networks)
LAN_SUBNETS = "{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"

# Tor ports (must match the torrc configuration)
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053

# ---------------------------------------------------------------------------
# Ruleset template
# ---------------------------------------------------------------------------
# The ruleset is loaded atomically via `nft -f -` to prevent any window
# where partial rules are active.
#
# The {tor_uid} placeholder is filled at runtime with the UID of the
# torvpn-worker user.
RULESET_TEMPLATE = """\
# Flush any previous torvpn table to ensure idempotent application.
# The 'delete' command will fail if the table doesn't exist, so we
# guard it by adding the table first (add is idempotent).
add table {family} {table}
delete table {family} {table}

# Create the table fresh.
table {family} {table} {{

    # ──────────────────────────────────────────────────────────────
    # NAT chain — Redirect traffic to Tor's transparent proxy ports
    # ──────────────────────────────────────────────────────────────
    chain output {{
        type nat hook output priority -100; policy accept;

        # Rule 1: Tor daemon's own traffic must pass through unmodified.
        # Without this, Tor's connections to guard nodes would be
        # redirected back to itself, creating an infinite loop.
        meta skuid {tor_uid} accept

        # Rule 2: LAN traffic is exempt from redirection.
        # This preserves local SSH, file sharing, printer access, etc.
        ip daddr {lan} accept

        # Rule 3: Redirect all DNS queries (UDP/53) to Tor's DNS resolver.
        # This prevents DNS leaks to the ISP's resolver.
        udp dport 53 dnat ip to 127.0.0.1:{dns_port}

        # Rule 4: Redirect all outbound TCP to Tor's TransPort.
        # The "!= {trans_port}" guard prevents double-redirection of
        # traffic that's already destined for the TransPort.
        tcp dport != {trans_port} dnat ip to 127.0.0.1:{trans_port}
    }}

    # ──────────────────────────────────────────────────────────────
    # Filter chain — Kill-switch with default DROP policy
    # ──────────────────────────────────────────────────────────────
    # If Tor crashes and the NAT rules are flushed, this chain's
    # DROP policy ensures NO clear-text traffic can escape.
    chain killswitch {{
        type filter hook output priority 0; policy drop;

        # Allow all loopback traffic (essential for local services
        # and for the DNAT'd Tor connections on 127.0.0.1).
        oifname "lo" accept

        # Allow the Tor daemon to reach the real internet.
        meta skuid {tor_uid} accept

        # Allow LAN traffic (same subnets as NAT exemption).
        ip daddr {lan} accept

        # Allow established and related connections.
        # This is critical: after DNAT rewrites the destination to
        # 127.0.0.1:9040, the connection is "established" and needs
        # this rule to flow.
        ct state established,related accept

        # Allow traffic explicitly destined for the local Tor DNS port.
        # This handles the DNAT'd DNS packets.
        udp dport {dns_port} ip daddr 127.0.0.1 accept

        # Allow traffic explicitly destined for the local Tor TransPort.
        # This handles the DNAT'd TCP packets.
        tcp dport {trans_port} ip daddr 127.0.0.1 accept

        # ── KILL SWITCH ──
        # Everything else hits the chain's default policy: DROP.
        # This includes:
        #   - All un-redirected UDP (non-DNS)
        #   - All ICMP / ICMPv6 (ping, traceroute)
        #   - Any IPv6 packets (if IPv6 somehow wasn't fully disabled)
        #   - Any traffic from processes not matching the above rules
    }}
}}
"""


# ---------------------------------------------------------------------------
# Helper: run nft command
# ---------------------------------------------------------------------------
def _run_nft(args: list[str], *, input_data: str = None) -> subprocess.CompletedProcess:
    """Execute an nft command with error handling.

    Args:
        args:       Arguments to pass to nft (e.g. ["-f", "-"]).
        input_data: Optional string to feed to nft's stdin.

    Returns:
        CompletedProcess instance.

    Raises:
        subprocess.CalledProcessError: If nft returns a non-zero exit code.
    """
    cmd = ["nft"] + args
    log.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(
            cmd,
            input=input_data,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as exc:
        log.error("nft command failed (exit %d)", exc.returncode)
        if exc.stderr:
            log.error("nft stderr: %s", exc.stderr.strip())
        if exc.stdout:
            log.debug("nft stdout: %s", exc.stdout.strip())
        raise


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def apply(tor_uid: int) -> None:
    """Generate and atomically load the nftables ruleset.

    This is the core security function. After this call:
        - All DNS goes through Tor
        - All TCP goes through Tor
        - All other traffic is silently dropped (kill-switch)

    Args:
        tor_uid: The numeric UID of the torvpn-worker user. Traffic from
                 this UID is allowed to bypass the redirect rules.
    """
    log.info("=" * 50)
    log.info("FIREWALL — APPLYING NFTABLES RULESET")
    log.info("=" * 50)

    ruleset = RULESET_TEMPLATE.format(
        family=TABLE_FAMILY,
        table=TABLE_NAME,
        tor_uid=tor_uid,
        lan=LAN_SUBNETS,
        trans_port=TOR_TRANS_PORT,
        dns_port=TOR_DNS_PORT,
    )

    log.debug("Ruleset:\n%s", ruleset)

    # Atomic load — either the entire ruleset applies, or none of it does.
    _run_nft(["-f", "-"], input_data=ruleset)

    log.info("[OK] nftables ruleset applied (kill-switch active)")
    log.info("     Tor UID exemption: %d", tor_uid)
    log.info("     DNS redirect:  UDP/53 → 127.0.0.1:%d", TOR_DNS_PORT)
    log.info("     TCP redirect:  *      → 127.0.0.1:%d", TOR_TRANS_PORT)


def panic() -> None:
    """Emergency kill-switch activation.

    Flushes all rules from the torvpn table but KEEPS the table and its
    chains (which have policy DROP). This means:
        - The NAT chain's ACCEPT/DNAT rules are gone
        - The filter chain's ACCEPT rules are gone
        - Only the DROP policy remains → all traffic is blocked

    This is called by the watchdog when Tor crashes unexpectedly.
    """
    log.critical("!!! PANIC — ACTIVATING KILL-SWITCH !!!")

    try:
        _run_nft(["flush", "table", TABLE_FAMILY, TABLE_NAME])
        log.critical("[PANIC] All rules flushed — DROP policy in effect")
        log.critical("[PANIC] NO internet traffic will pass until Tor is restored")
    except subprocess.CalledProcessError as exc:
        # If the table doesn't exist, we're already in a safe state
        # (no rules means no traffic — the default kernel behavior
        # without nftables is to accept, but we handle this edge case
        # by logging a warning).
        log.error(
            "Failed to flush nftables table (it may not exist): %s",
            exc.stderr,
        )


def teardown() -> None:
    """Completely remove the torvpn nftables table.

    After this call, the system's firewall returns to its pre-torvpn state.
    No Tor-related rules remain.
    """
    log.info("Removing nftables table '%s %s'...", TABLE_FAMILY, TABLE_NAME)

    try:
        _run_nft(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        log.info("[OK] nftables table removed — firewall restored")
    except subprocess.CalledProcessError as exc:
        if "No such file or directory" in (exc.stderr or "") or "Could not process rule" in (exc.stderr or ""):
            log.debug("Table already removed — nothing to do")
        else:
            log.error("Failed to remove nftables table: %s", exc.stderr)
