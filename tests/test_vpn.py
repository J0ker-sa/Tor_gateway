"""
tests/test_vpn.py — Comprehensive Unit Test Suite
====================================================
Covers three categories mandated by the specification:

1. MAC address generation (``_generate_random_mac``)
   - Valid format (regex)
   - Locally-administered bit set
   - Unicast bit cleared
   - Statistical confidence (100 iterations)

2. Firewall ruleset template generation
   - TCP redirect to TransPort 9040
   - DNS redirect to DNSPort 9053
   - Explicit ICMP DROP rule
   - Explicit SCTP/DCCP DROP rules
   - LAN subnet exemptions
   - Tor UID exemption
   - Both nftables and iptables backends

3. DNS lock/restore
   - Mocked file I/O and subprocess calls
   - chattr -i/+i call verification
   - File content verification
   - Backup / restore lifecycle

All tests are fully self-contained and do NOT require root privileges,
network access, or any system binaries — every external dependency is
mocked.
"""

import re
import subprocess
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so ``src.*`` imports work
# when pytest is invoked from the project root directory.
# ---------------------------------------------------------------------------
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================================
# Category 1: MAC Address Generation
# ============================================================================

from src.footprint import _generate_random_mac

# Strict regex for a colon-separated MAC address with lowercase hex.
MAC_REGEX = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class TestGenerateRandomMac:
    """Test suite for _generate_random_mac()."""

    def test_format_valid(self):
        """Generated MAC must match xx:xx:xx:xx:xx:xx format."""
        mac = _generate_random_mac()
        assert MAC_REGEX.match(mac), f"MAC '{mac}' does not match expected format"

    def test_locally_administered_bit_set(self):
        """The locally-administered bit (bit 1 of octet 0) must be set."""
        mac = _generate_random_mac()
        first_octet = int(mac.split(":")[0], 16)
        assert (first_octet & 0x02) == 0x02, (
            f"Locally-administered bit not set in first octet 0x{first_octet:02x}"
        )

    def test_unicast_bit_cleared(self):
        """The multicast bit (bit 0 of octet 0) must be cleared (unicast)."""
        mac = _generate_random_mac()
        first_octet = int(mac.split(":")[0], 16)
        assert (first_octet & 0x01) == 0x00, (
            f"Multicast bit is set in first octet 0x{first_octet:02x} — should be unicast"
        )

    def test_format_100_iterations(self):
        """Run 100 iterations for statistical confidence on format correctness."""
        for i in range(100):
            mac = _generate_random_mac()
            assert MAC_REGEX.match(mac), (
                f"Iteration {i}: MAC '{mac}' does not match expected format"
            )

    def test_locally_administered_100_iterations(self):
        """Run 100 iterations to verify the locally-administered bit is always set."""
        for i in range(100):
            mac = _generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert (first_octet & 0x02) == 0x02, (
                f"Iteration {i}: locally-administered bit not set in 0x{first_octet:02x}"
            )

    def test_unicast_100_iterations(self):
        """Run 100 iterations to verify the multicast bit is always cleared."""
        for i in range(100):
            mac = _generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert (first_octet & 0x01) == 0x00, (
                f"Iteration {i}: multicast bit set in 0x{first_octet:02x}"
            )

    def test_randomness(self):
        """Multiple calls should produce different MACs (with overwhelming probability)."""
        macs = {_generate_random_mac() for _ in range(50)}
        # With 48 random bits, collisions in 50 samples are astronomically unlikely.
        assert len(macs) >= 45, (
            f"Only {len(macs)} unique MACs in 50 — possible RNG issue"
        )

    def test_length(self):
        """MAC string must be exactly 17 characters (6*2 hex digits + 5 colons)."""
        mac = _generate_random_mac()
        assert len(mac) == 17, f"MAC length is {len(mac)}, expected 17"

    def test_six_octets(self):
        """MAC must contain exactly 6 colon-separated octets."""
        mac = _generate_random_mac()
        octets = mac.split(":")
        assert len(octets) == 6, f"Expected 6 octets, got {len(octets)}"


# ============================================================================
# Category 2: Firewall Ruleset Template Generation
# ============================================================================

from src.firewall import (
    _generate_nftables_ruleset,
    generate_iptables_commands,
    TOR_TRANS_PORT,
    TOR_DNS_PORT,
    LAN_SUBNETS_LIST,
)


class TestNftablesRuleset:
    """Test the nftables ruleset template generation."""

    @pytest.fixture
    def ruleset(self):
        """Generate a ruleset with a test UID."""
        return _generate_nftables_ruleset(tor_uid=1234)

    def test_tcp_redirect_present(self, ruleset):
        """The ruleset must redirect TCP traffic to the TransPort."""
        assert f"dnat ip to 127.0.0.1:{TOR_TRANS_PORT}" in ruleset

    def test_dns_redirect_present(self, ruleset):
        """The ruleset must redirect DNS (UDP/53) to the DNSPort."""
        assert f"udp dport 53 dnat ip to 127.0.0.1:{TOR_DNS_PORT}" in ruleset

    def test_tor_uid_exemption(self, ruleset):
        """The ruleset must exempt the Tor daemon's UID from redirection."""
        assert "meta skuid 1234 accept" in ruleset

    def test_lan_subnet_exemptions(self, ruleset):
        """The ruleset must exempt all LAN subnets from redirection."""
        for subnet in LAN_SUBNETS_LIST:
            assert subnet in ruleset, f"LAN subnet {subnet} not found in ruleset"

    def test_icmp_drop_explicit(self, ruleset):
        """The ruleset must explicitly DROP ICMP packets."""
        assert "meta l4proto icmp drop" in ruleset

    def test_icmpv6_drop_explicit(self, ruleset):
        """The ruleset must explicitly DROP ICMPv6 packets."""
        assert "meta l4proto icmpv6 drop" in ruleset

    def test_sctp_drop_explicit(self, ruleset):
        """The ruleset must explicitly DROP SCTP packets."""
        assert "meta l4proto sctp drop" in ruleset

    def test_dccp_drop_explicit(self, ruleset):
        """The ruleset must explicitly DROP DCCP packets."""
        assert "meta l4proto dccp drop" in ruleset

    def test_non_dns_udp_drop(self, ruleset):
        """The ruleset must explicitly DROP non-DNS UDP traffic."""
        assert f"udp dport != {TOR_DNS_PORT} drop" in ruleset

    def test_killswitch_policy_drop(self, ruleset):
        """The killswitch chain must have a default DROP policy."""
        assert "policy drop;" in ruleset

    def test_loopback_accept(self, ruleset):
        """Loopback traffic must be accepted."""
        assert 'oifname "lo" accept' in ruleset

    def test_established_related(self, ruleset):
        """Established/related connections must be accepted."""
        assert "ct state established,related accept" in ruleset

    def test_different_uids_produce_different_rulesets(self):
        """Different Tor UIDs must produce different rulesets."""
        rs1 = _generate_nftables_ruleset(tor_uid=1000)
        rs2 = _generate_nftables_ruleset(tor_uid=2000)
        assert rs1 != rs2
        assert "1000" in rs1
        assert "2000" in rs2


class TestIptablesCommands:
    """Test the iptables command generation."""

    @pytest.fixture
    def commands(self):
        """Generate iptables commands with a test UID."""
        # Temporarily set the module-level _iptables_bin for command generation.
        import src.firewall as fw
        old_bin = fw._iptables_bin
        fw._iptables_bin = "iptables"
        cmds = generate_iptables_commands(tor_uid=5678)
        fw._iptables_bin = old_bin
        return cmds

    @pytest.fixture
    def commands_text(self, commands):
        """Join all commands into a single string for easy searching."""
        return "\n".join(commands)

    def test_tcp_redirect_present(self, commands_text):
        """iptables commands must include TCP DNAT to TransPort."""
        assert f"--to-destination 127.0.0.1:{TOR_TRANS_PORT}" in commands_text

    def test_dns_redirect_present(self, commands_text):
        """iptables commands must include DNS DNAT to DNSPort."""
        assert f"--to-destination 127.0.0.1:{TOR_DNS_PORT}" in commands_text

    def test_tor_uid_exemption(self, commands_text):
        """iptables commands must exempt Tor UID via --uid-owner."""
        assert "--uid-owner 5678" in commands_text

    def test_lan_subnet_exemptions(self, commands_text):
        """iptables commands must include RETURN rules for all LAN subnets."""
        for subnet in LAN_SUBNETS_LIST:
            assert subnet in commands_text, (
                f"LAN subnet {subnet} not found in iptables commands"
            )

    def test_icmp_drop_explicit(self, commands_text):
        """iptables commands must explicitly DROP ICMP."""
        assert "-p icmp -j DROP" in commands_text

    def test_sctp_drop_explicit(self, commands_text):
        """iptables commands must explicitly DROP SCTP."""
        assert "-p sctp -j DROP" in commands_text

    def test_dccp_drop_explicit(self, commands_text):
        """iptables commands must explicitly DROP DCCP."""
        assert "-p dccp -j DROP" in commands_text

    def test_non_dns_udp_drop(self, commands_text):
        """iptables commands must DROP non-DNS UDP."""
        assert f"! --dport {TOR_DNS_PORT} -j DROP" in commands_text

    def test_final_drop_rule(self, commands_text):
        """iptables commands must end with a catch-all DROP."""
        assert "TORVPN_KILL -j DROP" in commands_text

    def test_chain_creation(self, commands_text):
        """iptables commands must create the custom chains."""
        assert "TORVPN_NAT" in commands_text
        assert "TORVPN_KILL" in commands_text

    def test_jump_rules(self, commands_text):
        """iptables commands must include jump rules to custom chains."""
        assert "-j TORVPN_NAT" in commands_text
        assert "-j TORVPN_KILL" in commands_text

    def test_different_uids_produce_different_commands(self):
        """Different Tor UIDs must produce different command sets."""
        import src.firewall as fw
        old_bin = fw._iptables_bin
        fw._iptables_bin = "iptables"
        cmds1 = "\n".join(generate_iptables_commands(tor_uid=1000))
        cmds2 = "\n".join(generate_iptables_commands(tor_uid=2000))
        fw._iptables_bin = old_bin
        assert cmds1 != cmds2
        assert "1000" in cmds1
        assert "2000" in cmds2


# ============================================================================
# Category 3: DNS Lock/Restore
# ============================================================================

from src import dns as dns_module


class TestDnsLock:
    """Test dns.lock() by mocking file I/O and subprocess calls."""

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.shutil.copy2")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_lock_sequence(self, mock_resolv_path, mock_copy2, mock_run):
        """Verify lock() calls chattr -i, writes the file, then calls chattr +i."""
        # Configure mocks
        mock_resolv_path.exists.return_value = True
        mock_resolv_path.is_symlink.return_value = False
        mock_resolv_path.__str__ = lambda self: "/etc/resolv.conf"

        # Reset module state
        dns_module._backup_created = False

        # Track chattr call order
        call_log = []

        def side_effect_run(cmd, **kwargs):
            if cmd[0] == "chattr":
                call_log.append(cmd[1])  # "+i" or "-i"
            result = mock.MagicMock()
            result.returncode = 0
            return result

        mock_run.side_effect = side_effect_run

        dns_module.lock()

        # Verify chattr was called: first -i (unlock), then +i (lock)
        assert call_log == ["-i", "+i"], (
            f"Expected chattr calls ['-i', '+i'], got {call_log}"
        )

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_lock_writes_nameserver(self, mock_resolv_path, mock_run):
        """Verify lock() writes 'nameserver 127.0.0.1' to resolv.conf."""
        mock_resolv_path.exists.return_value = True
        mock_resolv_path.is_symlink.return_value = False
        mock_resolv_path.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = False
        dns_module.lock()

        # Find the write_text call
        write_calls = mock_resolv_path.write_text.call_args_list
        assert len(write_calls) >= 1, "write_text was never called on resolv.conf"

        written_content = write_calls[-1][0][0]  # First positional arg of last call
        assert "nameserver 127.0.0.1" in written_content, (
            f"Expected 'nameserver 127.0.0.1' in written content, got: {written_content!r}"
        )

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.shutil.copy2")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_lock_backs_up_existing(self, mock_resolv_path, mock_copy2, mock_run):
        """Verify lock() backs up the existing resolv.conf before overwriting."""
        mock_resolv_path.exists.return_value = True
        mock_resolv_path.is_symlink.return_value = False
        mock_resolv_path.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = False
        dns_module.lock()

        # shutil.copy2 should have been called for backup
        mock_copy2.assert_called_once()

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_lock_handles_missing_resolv_conf(self, mock_resolv_path, mock_run):
        """Verify lock() handles a missing resolv.conf gracefully."""
        mock_resolv_path.exists.return_value = False
        mock_resolv_path.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = False
        dns_module.lock()

        # Should still write the locked content
        mock_resolv_path.write_text.assert_called()


class TestDnsRestore:
    """Test dns.restore() by mocking file I/O and subprocess calls."""

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.shutil.copy2")
    @mock.patch("src.dns.RESOLV_BACKUP")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_unlocks_and_restores(self, mock_resolv, mock_backup, mock_copy2, mock_run):
        """Verify restore() calls chattr -i and copies backup back."""
        mock_backup.exists.return_value = True
        mock_backup.__str__ = lambda self: "/etc/resolv.conf.torvpn.bak"
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = True
        dns_module.restore()

        # Verify chattr -i was called
        chattr_calls = [
            call for call in mock_run.call_args_list
            if call[0][0][0] == "chattr" and call[0][0][1] == "-i"
        ]
        assert len(chattr_calls) >= 1, "chattr -i was not called during restore"

        # Verify backup was copied back
        mock_copy2.assert_called_once()

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_BACKUP")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_deletes_backup(self, mock_resolv, mock_backup, mock_run):
        """Verify restore() deletes the backup file after restoring."""
        mock_backup.exists.return_value = True
        mock_backup.__str__ = lambda self: "/etc/resolv.conf.torvpn.bak"
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = True

        with mock.patch("src.dns.shutil.copy2"):
            dns_module.restore()

        # Verify backup file deletion was attempted
        mock_backup.unlink.assert_called_once()

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_BACKUP")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_handles_chattr_failure(self, mock_resolv, mock_backup, mock_run):
        """Verify restore() handles chattr failure gracefully."""
        mock_backup.exists.return_value = True
        mock_backup.__str__ = lambda self: "/etc/resolv.conf.torvpn.bak"
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"

        # Make chattr -i raise an error
        def run_side_effect(cmd, **kwargs):
            if cmd[0] == "chattr" and cmd[1] == "-i":
                raise subprocess.CalledProcessError(1, cmd)
            return mock.MagicMock(returncode=0)

        mock_run.side_effect = run_side_effect
        dns_module._backup_created = True

        with mock.patch("src.dns.shutil.copy2"):
            # Should not raise — restore must be resilient
            dns_module.restore()

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_BACKUP")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_warns_on_missing_backup(self, mock_resolv, mock_backup, mock_run):
        """Verify restore() logs a warning when no backup exists."""
        mock_backup.exists.return_value = False
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module._backup_created = False

        # Should not raise
        dns_module.restore()


class TestDnsRestoreFromBackup:
    """Test dns.restore_from_backup() — the disaster recovery path."""

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_from_backup_writes_content(self, mock_resolv, mock_run):
        """Verify restore_from_backup() writes the provided content."""
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        original_content = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
        dns_module.restore_from_backup(original_content)

        mock_resolv.write_text.assert_called_once_with(original_content)

    @mock.patch("src.dns.subprocess.run")
    @mock.patch("src.dns.RESOLV_CONF")
    def test_restore_from_backup_unlocks_first(self, mock_resolv, mock_run):
        """Verify restore_from_backup() attempts to remove immutable flag first."""
        mock_resolv.__str__ = lambda self: "/etc/resolv.conf"
        mock_run.return_value = mock.MagicMock(returncode=0)

        dns_module.restore_from_backup("nameserver 1.1.1.1\n")

        # Find chattr -i call
        chattr_calls = [
            call for call in mock_run.call_args_list
            if call[0][0][0] == "chattr" and call[0][0][1] == "-i"
        ]
        assert len(chattr_calls) >= 1, "chattr -i was not called"


# ============================================================================
# Category 4: ExitCode Enum Verification
# ============================================================================

from src.exitcodes import ExitCode


class TestExitCodes:
    """Verify the ExitCode enum has all required values."""

    def test_success(self):
        assert ExitCode.SUCCESS == 0

    def test_error_generic(self):
        assert ExitCode.ERROR_GENERIC == 1

    def test_error_not_root(self):
        assert ExitCode.ERROR_NOT_ROOT == 2

    def test_error_missing_dependencies(self):
        assert ExitCode.ERROR_MISSING_DEPENDENCIES == 3

    def test_error_tor_bootstrap_timeout(self):
        assert ExitCode.ERROR_TOR_BOOTSTRAP_TIMEOUT == 4

    def test_error_firewall_failure(self):
        assert ExitCode.ERROR_FIREWALL_FAILURE == 5

    def test_error_backup_restore_failure(self):
        assert ExitCode.ERROR_BACKUP_RESTORE_FAILURE == 6

    def test_all_values_unique(self):
        """All exit code values must be unique."""
        values = [e.value for e in ExitCode]
        assert len(values) == len(set(values)), "Duplicate exit code values found"


# ============================================================================
# Category 5: Config Parsing
# ============================================================================

from src.config import parse_args, Config, DEFAULT_BOOTSTRAP_TIMEOUT


class TestConfigParsing:
    """Test CLI argument parsing."""

    def test_default_values(self):
        """No args → defaults."""
        cfg = parse_args([])
        assert cfg.dry_run is False
        assert cfg.bootstrap_timeout == DEFAULT_BOOTSTRAP_TIMEOUT

    def test_dry_run_flag(self):
        """--dry-run flag sets dry_run=True."""
        cfg = parse_args(["--dry-run"])
        assert cfg.dry_run is True

    def test_bootstrap_timeout_flag(self):
        """--bootstrap-timeout sets the timeout value."""
        cfg = parse_args(["--bootstrap-timeout", "600"])
        assert cfg.bootstrap_timeout == 600

    def test_bootstrap_timeout_env_var(self):
        """TOR_BOOTSTRAP_TIMEOUT env var sets the timeout."""
        with mock.patch.dict(os.environ, {"TOR_BOOTSTRAP_TIMEOUT": "450"}):
            cfg = parse_args([])
            assert cfg.bootstrap_timeout == 450

    def test_cli_overrides_env_var(self):
        """CLI flag takes precedence over env var."""
        with mock.patch.dict(os.environ, {"TOR_BOOTSTRAP_TIMEOUT": "450"}):
            cfg = parse_args(["--bootstrap-timeout", "600"])
            assert cfg.bootstrap_timeout == 600

    def test_invalid_env_var_uses_default(self, capsys):
        """Invalid env var falls back to default."""
        with mock.patch.dict(os.environ, {"TOR_BOOTSTRAP_TIMEOUT": "not_a_number"}):
            cfg = parse_args([])
            assert cfg.bootstrap_timeout == DEFAULT_BOOTSTRAP_TIMEOUT

    def test_config_is_frozen(self):
        """Config instances should be immutable."""
        cfg = parse_args([])
        with pytest.raises(AttributeError):
            cfg.dry_run = True
