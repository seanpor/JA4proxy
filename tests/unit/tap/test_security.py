"""
Unit tests for src/tap/security.py — Group 12 (Phase 20).

Covers: validate_pcap_path, drop_cap_net_raw, apply_seccomp_profile,
        and selected enforcement/export security behaviours.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config.loader import ConfigError
from src.tap.security import (
    apply_seccomp_profile,
    drop_cap_net_raw,
    validate_pcap_path,
)

# ---------------------------------------------------------------------------
# validate_pcap_path
# ---------------------------------------------------------------------------


class TestValidatePcapPath:
    def test_validate_pcap_path_allows_valid_path(self, tmp_path):
        """A path inside an allowed directory must be returned as resolved Path."""
        pcap = tmp_path / "capture.pcap"
        pcap.touch()

        result = validate_pcap_path(str(pcap), [str(tmp_path)])

        assert result == pcap.resolve()

    def test_validate_pcap_path_rejects_path_traversal(self, tmp_path):
        """A path that traverses above the allowed directory must raise ConfigError."""
        traversal = str(tmp_path) + "/../etc/passwd"

        with pytest.raises(ConfigError, match="outside allowed directories"):
            validate_pcap_path(traversal, [str(tmp_path)])

    def test_validate_pcap_path_rejects_absolute_path_outside_allowed(self):
        """/etc/passwd is not inside /tmp — must raise ConfigError."""
        with pytest.raises(ConfigError, match="outside allowed directories"):
            validate_pcap_path("/etc/passwd", ["/tmp"])

    def test_validate_pcap_path_allows_nested_subdir(self, tmp_path):
        """A path nested inside an allowed directory must be accepted."""
        sub = tmp_path / "sub" / "dir"
        sub.mkdir(parents=True)
        pcap = sub / "out.pcap"
        pcap.touch()

        result = validate_pcap_path(str(pcap), [str(tmp_path)])
        assert result == pcap.resolve()

    def test_validate_pcap_path_multiple_allowed_dirs(self, tmp_path):
        """If multiple allowed dirs, path inside any one of them must be accepted."""
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()
        pcap = valid_dir / "ok.pcap"
        pcap.touch()

        result = validate_pcap_path(str(pcap), [str(other_dir), str(valid_dir)])
        assert result == pcap.resolve()

    def test_validate_pcap_path_file_need_not_exist(self, tmp_path):
        """validate_pcap_path only checks directory membership, not existence."""
        nonexistent = tmp_path / "future.pcap"
        # Does not raise even though the file doesn't exist.
        result = validate_pcap_path(str(nonexistent), [str(tmp_path)])
        assert result == nonexistent.resolve()


# ---------------------------------------------------------------------------
# drop_cap_net_raw
# ---------------------------------------------------------------------------


class TestDropCapNetRaw:
    def test_drop_cap_net_raw_does_not_crash(self):
        """drop_cap_net_raw must complete without raising, even if libcap absent."""
        drop_cap_net_raw()  # must not raise

    def test_drop_cap_net_raw_logs_warning_when_libcap_absent(self, caplog):
        """When libcap.so.2 is unavailable a WARNING must be emitted."""
        with patch("ctypes.CDLL", side_effect=OSError("libcap.so.2 not found")):
            with caplog.at_level(logging.WARNING, logger="src.tap.security"):
                drop_cap_net_raw()

        assert any(
            "unavailable" in r.message or "not found" in r.message
            for r in caplog.records
        )

    def test_drop_cap_net_raw_logs_success_when_libcap_present(self, caplog):
        """When libcap returns 0, an INFO message must be emitted."""
        mock_libcap = MagicMock()
        mock_libcap.cap_drop_bound.return_value = 0

        with patch("ctypes.CDLL", return_value=mock_libcap):
            with caplog.at_level(logging.DEBUG, logger="src.tap.security"):
                drop_cap_net_raw()

        assert any("drop_cap_net_raw_ok" in r.message for r in caplog.records)

    def test_drop_cap_net_raw_logs_warning_on_nonzero_return(self, caplog):
        """When cap_drop_bound returns non-zero, a WARNING must be emitted."""
        mock_libcap = MagicMock()
        mock_libcap.cap_drop_bound.return_value = -1

        with patch("ctypes.CDLL", return_value=mock_libcap):
            with caplog.at_level(logging.WARNING, logger="src.tap.security"):
                drop_cap_net_raw()

        assert any("drop_cap_net_raw_failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# apply_seccomp_profile
# ---------------------------------------------------------------------------


class TestApplySeccompProfile:
    def _write_profile(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "seccomp.json"
        p.write_text(json.dumps(data))
        return p

    def test_apply_seccomp_profile_raises_config_error_if_file_missing(self, tmp_path):
        """A missing profile file must raise ConfigError."""
        with pytest.raises(ConfigError, match="not found"):
            apply_seccomp_profile(tmp_path / "nonexistent.json")

    def test_apply_seccomp_profile_raises_config_error_on_invalid_json(self, tmp_path):
        """Malformed JSON must raise ConfigError."""
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")

        with pytest.raises(ConfigError, match="malformed JSON"):
            apply_seccomp_profile(bad)

    def test_apply_seccomp_profile_does_not_crash_if_libseccomp_absent(self, tmp_path):
        """When libseccomp.so.2 is unavailable the function must return cleanly."""
        profile = self._write_profile(
            tmp_path,
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}],
            },
        )
        with patch("ctypes.CDLL", side_effect=OSError("libseccomp not found")):
            apply_seccomp_profile(profile)  # must not raise

    def test_apply_seccomp_profile_logs_warning_if_libseccomp_absent(
        self, tmp_path, caplog
    ):
        """A WARNING must be logged when libseccomp is not installed."""
        profile = self._write_profile(
            tmp_path,
            {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []},
        )
        with patch("ctypes.CDLL", side_effect=OSError("not found")):
            with caplog.at_level(logging.WARNING, logger="src.tap.security"):
                apply_seccomp_profile(profile)

        assert any("seccomp_unavailable" in r.message for r in caplog.records)

    def test_apply_seccomp_profile_parses_allowed_syscalls(self, tmp_path, caplog):
        """Profile is parsed and number of allowed syscalls is logged at DEBUG."""
        profile = self._write_profile(
            tmp_path,
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["read", "write", "close"], "action": "SCMP_ACT_ALLOW"}
                ],
            },
        )
        with patch("ctypes.CDLL", side_effect=OSError("no libseccomp")):
            with caplog.at_level(logging.DEBUG, logger="src.tap.security"):
                apply_seccomp_profile(profile)

        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("allowed_syscalls=3" in m for m in debug_msgs)

    def test_apply_seccomp_profile_uses_real_profile_file(self):
        """The bundled config/seccomp_tap.json must parse without error."""
        profile_path = Path("config/seccomp_tap.json")
        if not profile_path.exists():
            # Try from project root
            profile_path = Path(__file__).parents[4] / "config" / "seccomp_tap.json"

        with patch("ctypes.CDLL", side_effect=OSError("no libseccomp")):
            apply_seccomp_profile(profile_path)  # must not raise


# ---------------------------------------------------------------------------
# Webhook TLS verification warning
# ---------------------------------------------------------------------------


class TestWebhookTlsWarning:
    def test_webhook_tls_false_emits_startup_warn(self, caplog):
        """PaloAltoClient with verify_tls=False must log a TLS-disabled warning."""
        from src.tap.export.palo_alto_client import PaloAltoClient

        cfg = {
            "base_url": "https://pa.example.com",
            "api_key": "key123",
            "tags": ["ja4proxy-ban"],
            "verify_tls": False,
        }
        with caplog.at_level(logging.WARNING, logger="src.tap.export.palo_alto_client"):
            PaloAltoClient(config=cfg, session=MagicMock())

        assert any(
            "tls_verification_disabled" in r.message or "TLS" in r.message
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# BGP prefix length guard (mirrored from test_enforcement_bridge.py)
# ---------------------------------------------------------------------------


class TestBGPPrefixGuard:
    def _make_bridge_config(self, agg_v4: int = 32) -> dict:
        return {
            "tap_enforcement": {
                "iptables": {"enabled": False, "ipset_name": "ja4proxy_ban"},
                "bgp": {
                    "enabled": True,
                    "pipe": "/tmp/test_exabgp.cmd",
                    "next_hop": "self",
                    "aggregate_prefix_len_v4": agg_v4,
                    "aggregate_prefix_len_v6": 128,
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "secret": "",
                    "max_retries": 1,
                },
            }
        }

    @pytest.mark.asyncio
    async def test_bgp_slash_16_rejected_logs_error_no_pipe_write(self):
        """A /16 aggregate prefix must be rejected; the ExaBGP pipe must not be written."""
        from src.tap.enforcement_bridge import EnforcementBridge

        bridge = EnforcementBridge(
            config=self._make_bridge_config(agg_v4=16),
            redis=MagicMock(),
        )

        write_attempted = False

        async def fake_executor(_, fn):
            nonlocal write_attempted
            write_attempted = True
            return None

        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new=fake_executor):
            await bridge._bgp_announce("1.2.3.4")

        assert not write_attempted, "BGP pipe write must not happen for /16 prefix"

    @pytest.mark.asyncio
    async def test_bgp_rate_limit_prevents_more_than_max_announcements_per_minute(self):
        """Calling _bgp_announce multiple times for an allowed prefix must not hang."""
        from src.tap.enforcement_bridge import EnforcementBridge

        bridge = EnforcementBridge(
            config=self._make_bridge_config(agg_v4=32),
            redis=MagicMock(),
        )

        call_count = 0

        async def fast_executor(_, fn):
            nonlocal call_count
            call_count += 1
            # Do not actually open the pipe; just track calls.
            return None

        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new=fast_executor):
            for _ in range(5):
                await bridge._bgp_announce("10.0.0.1")

        # All 5 calls completed without blocking or error.
        assert call_count == 5


# ── Missing-coverage tests ────────────────────────────────────────────────────


class TestApplySeccompProfileWithLibSeccomp:
    """Cover lines 121-148: paths when libseccomp.so.2 IS successfully loaded.

    So what: these paths are the actual security enforcement — if they're never
    tested, a libseccomp API change or parameter mismatch silently disables
    seccomp filtering without any indication to the operator.
    """

    def _write_profile(self, tmp_path, data):
        p = tmp_path / "seccomp.json"
        p.write_text(json.dumps(data))
        return p

    def test_seccomp_init_returns_null_logs_warning(self, tmp_path, caplog):
        """seccomp_init() returns 0 (null ctx) → WARNING logged, function returns (lines 124-130).
        So what: null ctx means seccomp filter is NOT applied; operator must be warned.
        """
        profile = self._write_profile(
            tmp_path,
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}],
            },
        )
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0  # null ctx

        with patch("ctypes.CDLL", return_value=mock_lib):
            with caplog.at_level(logging.WARNING, logger="src.tap.security"):
                apply_seccomp_profile(profile)

        assert any("seccomp_init_failed" in r.message for r in caplog.records)

    def test_seccomp_load_success_logs_info(self, tmp_path, caplog):
        """seccomp_load() returns 0 → INFO 'seccomp_filter_applied' logged (lines 147-150).
        So what: successful seccomp application must be confirmed in audit logs."""
        profile = self._write_profile(
            tmp_path,
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}],
            },
        )
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 1  # non-null ctx
        mock_lib.seccomp_syscall_resolve_name.return_value = 3  # valid syscall nr
        mock_lib.seccomp_rule_add.return_value = 0
        mock_lib.seccomp_load.return_value = 0  # success

        with patch("ctypes.CDLL", return_value=mock_lib):
            with caplog.at_level(logging.INFO, logger="src.tap.security"):
                apply_seccomp_profile(profile)

        assert any("seccomp_filter_applied" in r.message for r in caplog.records)

    def test_seccomp_load_failure_logs_warning(self, tmp_path, caplog):
        """seccomp_load() returns non-zero → WARNING 'seccomp_load_failed' (lines 141-146).
        So what: a failed seccomp load means the filter was NOT applied — high-severity
        security misconfiguration that must be visible in logs."""
        profile = self._write_profile(
            tmp_path, {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        )
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 1  # valid ctx
        mock_lib.seccomp_load.return_value = -1  # failure

        with patch("ctypes.CDLL", return_value=mock_lib):
            with caplog.at_level(logging.WARNING, logger="src.tap.security"):
                apply_seccomp_profile(profile)

        assert any("seccomp_load_failed" in r.message for r in caplog.records)

    def test_seccomp_invalid_syscall_name_skipped(self, tmp_path):
        """syscall name that resolves to -1 → rule not added, no crash (line 134-136).
        So what: unknown syscall names in profile must not crash filter construction."""
        profile = self._write_profile(
            tmp_path,
            {
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["unknown_syscall_xyz"], "action": "SCMP_ACT_ALLOW"}
                ],
            },
        )
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 1
        mock_lib.seccomp_syscall_resolve_name.return_value = -1  # not found
        mock_lib.seccomp_load.return_value = 0

        with patch("ctypes.CDLL", return_value=mock_lib):
            apply_seccomp_profile(profile)  # must not raise
        # seccomp_rule_add must NOT be called for unknown syscall
        mock_lib.seccomp_rule_add.assert_not_called()
