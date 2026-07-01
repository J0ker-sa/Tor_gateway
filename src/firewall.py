"""
src/firewall.py — Firewall & Fallback Routing Engine
=======================================================
Generates and manages the firewall ruleset that implements transparent
Tor proxying with a kill-switch.  Supports both ``nftables`` (preferred)
and ``iptables`` (legacy fallback).

Backend detection order:
    1. ``nft`` binary → use nftables atomically loaded ruleset.
    2. ``iptables-legacy`` or ``iptables`` → use iptables chain commands.
    3. Neither found → exit with ERROR_MISSING_DEPENDENCIES.

Architecture (nftables):
    table inet torvpn
    ├── chain output     (nat, priority -100)  — DNAT redirections
    └── chain killswitch (filter, priority 0)  — kill-switch with policy drop

Architecture (iptables):
    nat    OUTPUT  — DNAT redirections
    filter OUTPUT  — kill-switch with policy DROP

Traffic flow (both backends):
    1. Tor daemon traffic (by UID) → ACCEPT (bypass all rules)
    2. LAN traffic → ACCEPT (preserve local connectivity)
    3. DNS (UDP/53) → DNAT to 127.0.0.1:9053 (Tor DNSPort)
    4. All TCP → DNAT to 127.0.0.1:9040 (Tor TransPort)
    5. Explicit DROP: non-DNS UDP, ICMP, SCTP, DCCP
    6. Everything else → DROP (kill-switch policy)
"""

import logging
import shutil
import subprocess
import sys
from typing import Optional

from src.exitcodes import ExitCode

log = logging.getLogger("torvpn.firewall")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TABLE_NAME = "torvpn"
TABLE_FAMILY = "inet"

# Subnets exempt from Tor redirection (local networks)
LAN_SUBNETS_NFT = "{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"
LAN_SUBNETS_LIST = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

LAN6_SUBNETS_NFT = "{ ::1/128, fe80::/10, fc00::/7 }"
LAN6_SUBNETS_LIST = ["::1/128", "fe80::/10", "fc00::/7"]

# Tor ports (must match the torrc configuration)
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053

# Detected backend — set by _detect_backend()
_backend: Optional[str] = None      # "nft" or "iptables"
_iptables_bin: Optional[str] = None  # path to iptables/iptables-legacy
_ip6tables_bin: Optional[str] = None # path to ip6tables/ip6tables-legacy


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
def _detect_backend() -> str:
    """Detect the available packet-filtering backend.

    Search order:
        1. ``nft`` → modern nftables (preferred).
        2. ``iptables-legacy`` → legacy iptables (pre-nft systems).
        3. ``iptables`` → could be nft-backed or standalone iptables.
        4. None found → fatal error.

    Returns:
        ``"nft"`` or ``"iptables"``.

    Side effects:
        Sets module-level ``_backend`` and ``_iptables_bin``.
    """
    global _backend, _iptables_bin, _ip6tables_bin

    # Try nft first (preferred)
    if shutil.which("nft"):
        _backend = "nft"
        log.info("Firewall backend: nftables (nft)")
        return "nft"

    # Try iptables-legacy (explicit legacy binary on nft-defaulting systems)
    legacy = shutil.which("iptables-legacy")
    if legacy:
        _backend = "iptables"
        _iptables_bin = legacy
        _ip6tables_bin = shutil.which("ip6tables-legacy") or shutil.which("ip6tables")
        log.info("Firewall backend: iptables-legacy (%s)", legacy)
        return "iptables"

    # Try standard iptables
    ipt = shutil.which("iptables")
    if ipt:
        _backend = "iptables"
        _iptables_bin = ipt
        _ip6tables_bin = shutil.which("ip6tables")
        log.info("Firewall backend: iptables (%s)", ipt)
        return "iptables"

    # No compatible backend found — fatal
    log.critical(
        "No compatible packet-filtering backend found. "
        "Install nftables (preferred) or iptables. "
        "Debian/Ubuntu: sudo apt install nftables  |  "
        "Arch: sudo pacman -S nftables"
    )
    sys.exit(ExitCode.ERROR_MISSING_DEPENDENCIES)


# ===========================================================================
# NFTABLES BACKEND
# ===========================================================================

# ---------------------------------------------------------------------------
# nftables ruleset template
# ---------------------------------------------------------------------------
# The ruleset is loaded atomically via ``nft -f -`` to prevent any window
# where partial rules are active.
#
# The {tor_uid} placeholder is filled at runtime with the UID of the
# torvpn-worker user.
NFTABLES_RULESET_TEMPLATE = """\
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

        # Rule 2: Redirect all DNS queries (UDP/TCP port 53) to Tor's DNS resolver.
        # This prevents DNS leaks to the ISP's resolver.
        # Must be placed BEFORE LAN/loopback exemptions so DNS queries to 127.0.0.1
        # (defined in resolv.conf) are redirected to the Tor DNS port instead
        # of hitting the loopback exemption rule.
        udp dport 53 dnat ip to 127.0.0.1:{dns_port}
        tcp dport 53 dnat ip to 127.0.0.1:{dns_port}

        # Rule 3: LAN traffic is exempt from redirection.
        # This preserves local SSH, file sharing, printer access, etc.
        ip daddr {lan} accept
        ip6 daddr {lan6} accept

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
        ip6 daddr {lan6} accept

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

        # ── EXPLICIT MULTI-PROTOCOL DROP RULES ──
        # These rules ensure that protocols which cannot be safely
        # tunnelled through Tor are unconditionally blocked, regardless
        # of the chain's default policy.  This provides defence-in-depth
        # and makes audit/logging explicit.

        # Drop ALL ICMP (ping, traceroute, etc.) — prevents path discovery.
        meta l4proto icmp drop
        meta l4proto icmpv6 drop

        # Drop ALL non-DNS UDP — Tor cannot tunnel raw UDP.
        udp dport != {dns_port} drop

        # Drop SCTP (protocol 132) — cannot be tunnelled through Tor.
        meta l4proto sctp drop

        # Drop DCCP (protocol 33) — cannot be tunnelled through Tor.
        meta l4proto dccp drop

        # ── KILL SWITCH ──
        # Everything else hits the chain's default policy: DROP.
    }}
}}
"""


def _generate_nftables_ruleset(tor_uid: int) -> str:
    """Render the nftables ruleset template with runtime values.

    Args:
        tor_uid: The numeric UID of the torvpn-worker user.

    Returns:
        Complete nftables ruleset as a string.
    """
    return NFTABLES_RULESET_TEMPLATE.format(
        family=TABLE_FAMILY,
        table=TABLE_NAME,
        tor_uid=tor_uid,
        lan=LAN_SUBNETS_NFT,
        lan6=LAN6_SUBNETS_NFT,
        trans_port=TOR_TRANS_PORT,
        dns_port=TOR_DNS_PORT,
    )


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


def _apply_nftables(tor_uid: int) -> None:
    """Generate and atomically load the nftables ruleset.

    Args:
        tor_uid: The numeric UID of the torvpn-worker user.
    """
    ruleset = _generate_nftables_ruleset(tor_uid)
    log.debug("Ruleset:\n%s", ruleset)

    # Atomic load — either the entire ruleset applies, or none of it does.
    _run_nft(["-f", "-"], input_data=ruleset)

    log.info("[OK] nftables ruleset applied (kill-switch active)")
    log.info("     Tor UID exemption: %d", tor_uid)
    log.info("     DNS redirect:  UDP/53 → 127.0.0.1:%d", TOR_DNS_PORT)
    log.info("     TCP redirect:  *      → 127.0.0.1:%d", TOR_TRANS_PORT)


def _teardown_nftables() -> None:
    """Completely remove the torvpn nftables table."""
    log.info("Removing nftables table '%s %s'...", TABLE_FAMILY, TABLE_NAME)
    try:
        _run_nft(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        log.info("[OK] nftables table removed — firewall restored")
    except subprocess.CalledProcessError as exc:
        if "No such file or directory" in (exc.stderr or "") or "Could not process rule" in (exc.stderr or ""):
            log.debug("Table already removed — nothing to do")
        else:
            log.error("Failed to remove nftables table: %s", exc.stderr)


def _panic_nftables(tor_uid: int) -> None:
    """Emergency kill-switch via nftables.

    Replaces the torvpn table with a minimal ruleset that DROPs
    everything except Tor-UID and LAN traffic.
    """
    if tor_uid <= 0:
        # No UID — block EVERYTHING (safest during a crash).
        panic_rules = (
            f"add table {TABLE_FAMILY} {TABLE_NAME}\n"
            f"delete table {TABLE_FAMILY} {TABLE_NAME}\n"
            f"table {TABLE_FAMILY} {TABLE_NAME} {{\n"
            f"    chain killswitch {{\n"
            f"        type filter hook output priority 0; policy drop;\n"
            f"        drop\n"
            f"    }}\n"
            f"}}\n"
        )
    else:
        panic_rules = (
            f"add table {TABLE_FAMILY} {TABLE_NAME}\n"
            f"delete table {TABLE_FAMILY} {TABLE_NAME}\n"
            f"table {TABLE_FAMILY} {TABLE_NAME} {{\n"
            f"    chain killswitch {{\n"
            f"        type filter hook output priority 0; policy drop;\n"
            f"        meta skuid {tor_uid} accept\n"
            f"        ip daddr {LAN_SUBNETS_NFT} accept\n"
            f"        ip6 daddr {LAN6_SUBNETS_NFT} accept\n"
            f"        drop\n"
            f"    }}\n"
            f"}}\n"
        )

    try:
        _run_nft(["-f", "-"], input_data=panic_rules)
        log.critical("[PANIC] Kill-switch engaged — all outbound traffic DROPped")
    except subprocess.CalledProcessError as exc:
        log.error("[PANIC] Failed to install kill-switch rules: %s", exc.stderr)
        # Last-ditch effort
        try:
            _run_nft(["add", "table", TABLE_FAMILY, TABLE_NAME])
            _run_nft([
                "add", "chain", TABLE_FAMILY, TABLE_NAME, "killswitch",
                "{", "type", "filter", "hook", "output", "priority", "0",
                ";", "policy", "drop", ";", "}",
            ])
            log.critical("[PANIC] Bare kill-switch chain installed")
        except subprocess.CalledProcessError as exc2:
            log.critical("[PANIC] Could not install kill-switch: %s", exc2.stderr)
            log.critical("[PANIC] SYSTEM MAY LEAK — investigate immediately")


# ===========================================================================
# IPTABLES BACKEND (Legacy Fallback)
# ===========================================================================

def _run_ipt(args: list[str], *, check: bool = True, is_ip6: bool = False) -> subprocess.CompletedProcess:
    """Execute an iptables command with error handling.

    Uses the detected iptables binary (``iptables`` or ``iptables-legacy``).

    Args:
        args:  Arguments to pass after the iptables binary.
        check: Raise on non-zero exit.
        is_ip6: If True, run ip6tables instead of iptables.

    Returns:
        CompletedProcess instance.
    """
    bin_path = _ip6tables_bin if is_ip6 else _iptables_bin
    if bin_path is None:
        if is_ip6:
             log.debug("ip6tables binary not found, skipping IPv6 rule.")
             return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        else:
             raise RuntimeError("iptables binary not detected — call _detect_backend() first")

    cmd = [bin_path] + args
    log.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as exc:
        log.error("iptables command failed (exit %d): %s", exc.returncode, exc.stderr.strip())
        if check:
            raise
        return exc


def generate_iptables_commands(tor_uid: int) -> list[str]:
    """Generate the list of iptables commands for transparent Tor proxying.

    This is used by ``--dry-run`` to show the user what would be executed,
    and by ``_apply_iptables()`` for actual application.

    Args:
        tor_uid: The numeric UID of the torvpn-worker user.

    Returns:
        List of complete iptables command strings (without the binary name).
    """
    ipt = _iptables_bin or "iptables"
    commands = []

    # ── Create custom chains ──
    commands.append(f"{ipt} -t nat -N TORVPN_NAT 2>/dev/null || true")
    commands.append(f"{ipt} -t filter -N TORVPN_KILL 2>/dev/null || true")

    # ── Flush existing rules in our chains ──
    commands.append(f"{ipt} -t nat -F TORVPN_NAT")
    commands.append(f"{ipt} -t filter -F TORVPN_KILL")

    # ── NAT OUTPUT chain rules ──
    # Rule 1: Tor daemon bypasses redirection (by owner UID).
    commands.append(
        f"{ipt} -t nat -A TORVPN_NAT -m owner --uid-owner {tor_uid} -j RETURN"
    )

    # Rule 2: Redirect DNS (UDP/53 and TCP/53) to Tor's DNSPort.
    # Must be placed BEFORE LAN/loopback exemptions so DNS queries to 127.0.0.1
    # (defined in resolv.conf) are redirected to the Tor DNS port instead
    # of hitting the loopback exemption rule.
    commands.append(
        f"{ipt} -t nat -A TORVPN_NAT -p udp --dport 53 "
        f"-j DNAT --to-destination 127.0.0.1:{TOR_DNS_PORT}"
    )
    commands.append(
        f"{ipt} -t nat -A TORVPN_NAT -p tcp --dport 53 "
        f"-j DNAT --to-destination 127.0.0.1:{TOR_DNS_PORT}"
    )

    # Rule 3: LAN subnets bypass redirection.
    for subnet in LAN_SUBNETS_LIST:
        commands.append(
            f"{ipt} -t nat -A TORVPN_NAT -d {subnet} -j RETURN"
        )

    # Rule 4: Redirect all TCP to Tor's TransPort.
    commands.append(
        f"{ipt} -t nat -A TORVPN_NAT -p tcp --dport != 53 "
        f"-j DNAT --to-destination 127.0.0.1:{TOR_TRANS_PORT}"
    )

    # ── Filter OUTPUT chain rules (kill-switch) ──
    # Allow loopback.
    commands.append(f"{ipt} -A TORVPN_KILL -o lo -j ACCEPT")

    # Allow Tor daemon traffic.
    commands.append(
        f"{ipt} -A TORVPN_KILL -m owner --uid-owner {tor_uid} -j ACCEPT"
    )

    # Allow LAN traffic.
    for subnet in LAN_SUBNETS_LIST:
        commands.append(f"{ipt} -A TORVPN_KILL -d {subnet} -j ACCEPT")

    # Allow established/related connections.
    commands.append(
        f"{ipt} -A TORVPN_KILL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )

    # Allow DNAT'd Tor DNS traffic.
    commands.append(
        f"{ipt} -A TORVPN_KILL -p udp -d 127.0.0.1 --dport {TOR_DNS_PORT} -j ACCEPT"
    )

    # Allow DNAT'd Tor TransPort traffic.
    commands.append(
        f"{ipt} -A TORVPN_KILL -p tcp -d 127.0.0.1 --dport {TOR_TRANS_PORT} -j ACCEPT"
    )

    # ── EXPLICIT MULTI-PROTOCOL DROP RULES ──
    # Drop ALL ICMP.
    commands.append(f"{ipt} -A TORVPN_KILL -p icmp -j DROP")

    # Drop ALL non-DNS UDP.
    commands.append(
        f"{ipt} -A TORVPN_KILL -p udp ! --dport {TOR_DNS_PORT} -j DROP"
    )

    # Drop SCTP (protocol 132).
    commands.append(f"{ipt} -A TORVPN_KILL -p sctp -j DROP")

    # Drop DCCP (protocol 33).
    commands.append(f"{ipt} -A TORVPN_KILL -p dccp -j DROP")

    # Default DROP for everything else.
    commands.append(f"{ipt} -A TORVPN_KILL -j DROP")

    # ── Jump from built-in OUTPUT chains to our custom chains ──
    commands.append(f"{ipt} -t nat -A OUTPUT -j TORVPN_NAT")
    commands.append(f"{ipt} -A OUTPUT -j TORVPN_KILL")

    # ── IPv6 Anti-Leak (ip6tables) ──
    if _ip6tables_bin:
        ip6t = "ip6tables"  # Placeholder string, actual execution uses is_ip6 flag
        commands.append(f"{ip6t} -t filter -N TORVPN_KILL 2>/dev/null || true")
        commands.append(f"{ip6t} -t filter -F TORVPN_KILL")
        commands.append(f"{ip6t} -A TORVPN_KILL -o lo -j ACCEPT")
        commands.append(f"{ip6t} -A TORVPN_KILL -m owner --uid-owner {tor_uid} -j ACCEPT")
        for subnet in LAN6_SUBNETS_LIST:
            commands.append(f"{ip6t} -A TORVPN_KILL -d {subnet} -j ACCEPT")
        commands.append(f"{ip6t} -A TORVPN_KILL -j DROP")
        commands.append(f"{ip6t} -A OUTPUT -j TORVPN_KILL")

    return commands


def _apply_iptables(tor_uid: int) -> None:
    """Apply iptables rules for transparent Tor proxying.

    Creates custom chains (TORVPN_NAT, TORVPN_KILL) and inserts
    jump rules into the built-in OUTPUT chains.

    Args:
        tor_uid: The numeric UID of the torvpn-worker user.
    """
    log.info("Applying iptables ruleset (legacy fallback)...")

    commands = generate_iptables_commands(tor_uid)
    for cmd_str in commands:
        # Parse the command string into tokens (strip shell-isms like 2>/dev/null).
        # For actual execution, we run each iptables command directly.
        parts = cmd_str.split()

        # Handle the "|| true" idiom: just run with check=False.
        check = "||" not in cmd_str
        # Strip shell redirects and boolean operators.
        clean_parts = [p for p in parts if p not in ("||", "true", "2>/dev/null")]

        is_ip6 = clean_parts[0] == "ip6tables"
        _run_ipt(clean_parts[1:], check=check, is_ip6=is_ip6)  # [1:] strips the binary name

    log.info("[OK] iptables ruleset applied (kill-switch active)")
    log.info("     Tor UID exemption: %d", tor_uid)
    log.info("     DNS redirect:  UDP/53 → 127.0.0.1:%d", TOR_DNS_PORT)
    log.info("     TCP redirect:  *      → 127.0.0.1:%d", TOR_TRANS_PORT)


def _teardown_iptables() -> None:
    """Remove all torvpn iptables rules and chains."""
    log.info("Removing iptables rules and chains...")

    # Remove jumps from built-in OUTPUT chains.
    _run_ipt(["-t", "nat", "-D", "OUTPUT", "-j", "TORVPN_NAT"], check=False)
    _run_ipt(["-D", "OUTPUT", "-j", "TORVPN_KILL"], check=False)

    # Flush and delete custom chains.
    _run_ipt(["-t", "nat", "-F", "TORVPN_NAT"], check=False)
    _run_ipt(["-t", "nat", "-X", "TORVPN_NAT"], check=False)
    _run_ipt(["-F", "TORVPN_KILL"], check=False)
    _run_ipt(["-X", "TORVPN_KILL"], check=False)

    if _ip6tables_bin:
        _run_ipt(["-D", "OUTPUT", "-j", "TORVPN_KILL"], check=False, is_ip6=True)
        _run_ipt(["-F", "TORVPN_KILL"], check=False, is_ip6=True)
        _run_ipt(["-X", "TORVPN_KILL"], check=False, is_ip6=True)

    log.info("[OK] iptables rules removed — firewall restored")


def _panic_iptables(tor_uid: int) -> None:
    """Emergency kill-switch via iptables.

    Flushes existing rules and replaces them with a blanket DROP.
    """
    # Remove existing jump rules (ignore errors).
    _run_ipt(["-t", "nat", "-D", "OUTPUT", "-j", "TORVPN_NAT"], check=False)
    _run_ipt(["-D", "OUTPUT", "-j", "TORVPN_KILL"], check=False)

    # Flush and re-populate the kill chain with a single DROP.
    _run_ipt(["-F", "TORVPN_KILL"], check=False)
    _run_ipt(["-A", "TORVPN_KILL", "-j", "DROP"], check=False)

    # Re-add the jump.
    _run_ipt(["-A", "OUTPUT", "-j", "TORVPN_KILL"], check=False)

    if _ip6tables_bin:
        _run_ipt(["-D", "OUTPUT", "-j", "TORVPN_KILL"], check=False, is_ip6=True)
        _run_ipt(["-F", "TORVPN_KILL"], check=False, is_ip6=True)
        _run_ipt(["-A", "TORVPN_KILL", "-j", "DROP"], check=False, is_ip6=True)
        _run_ipt(["-A", "OUTPUT", "-j", "TORVPN_KILL"], check=False, is_ip6=True)

    log.critical("[PANIC] iptables kill-switch engaged — all outbound DROPped")


# ===========================================================================
# PUBLIC API (backend-agnostic)
# ===========================================================================

def generate_ruleset(tor_uid: int) -> str:
    """Generate the firewall ruleset/commands WITHOUT applying them.

    Used by ``--dry-run`` mode to show the user what would be applied.

    Args:
        tor_uid: The numeric UID (0 for dry-run placeholder).

    Returns:
        A human-readable string of the full ruleset.
    """
    backend = _detect_backend()

    if backend == "nft":
        return _generate_nftables_ruleset(tor_uid)
    else:
        # iptables: join the command list into a readable script.
        commands = generate_iptables_commands(tor_uid)
        header = (
            "#!/bin/bash\n"
            "# Auto-generated iptables ruleset for torvpn\n"
            "# Backend: iptables (legacy fallback)\n"
            f"# Tor UID: {tor_uid}\n"
            "#\n"
        )
        return header + "\n".join(commands) + "\n"


def apply(tor_uid: int) -> None:
    """Detect the backend and apply the firewall ruleset.

    This is the core security function.  After this call:
        - All DNS goes through Tor
        - All TCP goes through Tor
        - ICMP, non-DNS UDP, SCTP, DCCP are explicitly DROPped
        - All other traffic is silently dropped (kill-switch)

    Args:
        tor_uid: The numeric UID of the torvpn-worker user.  Traffic from
                 this UID is allowed to bypass the redirect rules.
    """
    log.info("=" * 50)
    log.info("FIREWALL — APPLYING RULESET")
    log.info("=" * 50)

    backend = _detect_backend()

    if backend == "nft":
        _apply_nftables(tor_uid)
    else:
        _apply_iptables(tor_uid)


def teardown() -> None:
    """Remove all torvpn firewall rules using the detected backend.

    After this call, the system's firewall returns to its pre-torvpn state.
    """
    if _backend == "nft" or (_backend is None and shutil.which("nft")):
        _teardown_nftables()
    elif _backend == "iptables" or (_backend is None and (shutil.which("iptables-legacy") or shutil.which("iptables"))):
        _teardown_iptables()
    else:
        log.warning("No firewall backend detected during teardown — nothing to clean up")


def panic(tor_uid: int = 0) -> None:
    """Emergency kill-switch activation.

    Replaces the active ruleset with a minimal DROP-everything rule.
    Called by the watchdog when Tor crashes unexpectedly.

    Args:
        tor_uid: The torvpn-worker UID (0 = block everything including Tor).
    """
    log.critical("!!! PANIC — ACTIVATING KILL-SWITCH !!!")

    if _backend == "nft":
        _panic_nftables(tor_uid)
    elif _backend == "iptables":
        _panic_iptables(tor_uid)
    else:
        # Try nftables first, then iptables as a last resort.
        if shutil.which("nft"):
            _panic_nftables(tor_uid)
        elif shutil.which("iptables-legacy") or shutil.which("iptables"):
            _panic_iptables(tor_uid)
        else:
            log.critical("[PANIC] No firewall backend available — CANNOT ACTIVATE KILL-SWITCH")
            log.critical("[PANIC] SYSTEM IS UNPROTECTED — DISCONNECT NETWORK IMMEDIATELY")
