"""Unit tests for TLSEnforcer (Phase 3).

Covers all branches of TLSEnforcer.check() plus from_config() and
on_config_reload() helpers.
"""

import pytest

from src.security.tls_enforcer import (
    SSL3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    WEAK_CIPHERS,
    TLSEnforcer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRONG_CIPHERS = [0xC02B, 0xC02C, 0x1301, 0x1302]  # ECDHE-ECDSA, TLS 1.3


def _make_enforcer(**overrides) -> TLSEnforcer:
    """Build a TLSEnforcer with a baseline config and optional overrides."""
    cfg = {
        "tls_enforcer": {
            "enabled": True,
            "block_ssl3": True,
            "block_tls_10": True,
            "block_tls_11": True,
            "flag_tls_12": False,
            "score": 10,
            "block_weak_ciphers": False,
            "weak_cipher_score": 20,
            "weak_ciphers": [],
        },
        "security_policy": {
            "tls_version_bypass": {"enabled": True},
        },
    }
    cfg["tls_enforcer"].update(overrides.get("tls_enforcer", {}))
    cfg["security_policy"].update(overrides.get("security_policy", {}))
    return TLSEnforcer(cfg)


# ---------------------------------------------------------------------------
# TLS 1.3 — gold standard; no signal
# ---------------------------------------------------------------------------


class TestTLS13:
    def test_tls13_no_signal(self):
        """TLS 1.3 with strong ciphers → empty list, no block."""
        e = _make_enforcer()
        result = e.check(TLS13, _STRONG_CIPHERS)
        assert result == []

    def test_tls13_empty_cipher_list(self):
        """TLS 1.3 with no cipher list → empty list."""
        e = _make_enforcer()
        result = e.check(TLS13, [])
        assert result == []


# ---------------------------------------------------------------------------
# TLS 1.2
# ---------------------------------------------------------------------------


class TestTLS12:
    def test_tls12_flag_false_no_signal(self):
        """TLS 1.2 with flag_tls_12=false → no signal."""
        e = _make_enforcer(tls_enforcer={"flag_tls_12": False})
        result = e.check(TLS12, _STRONG_CIPHERS)
        assert result == []

    def test_tls12_flag_true_emits_signal(self):
        """TLS 1.2 with flag_tls_12=true → tls_version signal at configured score."""
        e = _make_enforcer(tls_enforcer={"flag_tls_12": True, "score": 10})
        result = e.check(TLS12, _STRONG_CIPHERS)
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "tls_version"
        assert result[0].score == 10

    def test_tls12_custom_score(self):
        """Custom score value is respected."""
        e = _make_enforcer(tls_enforcer={"flag_tls_12": True, "score": 7})
        result = e.check(TLS12, [])
        assert result[0].score == 7


# ---------------------------------------------------------------------------
# TLS 1.1
# ---------------------------------------------------------------------------


class TestTLS11:
    def test_tls11_bypass_enabled_hard_block(self):
        """TLS 1.1 + tls_version_bypass enabled → hard block (None)."""
        e = _make_enforcer()  # bypass enabled by default
        result = e.check(TLS11, [])
        assert result is None

    def test_tls11_bypass_disabled_emits_signal(self):
        """TLS 1.1 + bypass disabled → RiskSignal with score=40."""
        e = _make_enforcer(
            security_policy={"tls_version_bypass": {"enabled": False}}
        )
        result = e.check(TLS11, [])
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "tls_version"
        assert result[0].score == 40

    def test_tls11_block_flag_false_bypass_enabled_no_block(self):
        """block_tls_11=false → TLS 1.1 passes even with bypass enabled."""
        e = _make_enforcer(tls_enforcer={"block_tls_11": False})
        result = e.check(TLS11, [])
        assert result == []


# ---------------------------------------------------------------------------
# TLS 1.0
# ---------------------------------------------------------------------------


class TestTLS10:
    def test_tls10_bypass_enabled_hard_block(self):
        """TLS 1.0 + bypass enabled → hard block (None)."""
        e = _make_enforcer()
        result = e.check(TLS10, [])
        assert result is None

    def test_tls10_bypass_disabled_emits_signal(self):
        """TLS 1.0 + bypass disabled → RiskSignal."""
        e = _make_enforcer(
            security_policy={"tls_version_bypass": {"enabled": False}}
        )
        result = e.check(TLS10, [])
        assert result is not None
        assert result[0].name == "tls_version"
        assert result[0].score == 40

    def test_tls10_block_flag_false_no_block(self):
        """block_tls_10=false → TLS 1.0 allowed even with bypass enabled."""
        e = _make_enforcer(tls_enforcer={"block_tls_10": False})
        result = e.check(TLS10, [])
        assert result == []


# ---------------------------------------------------------------------------
# SSLv3
# ---------------------------------------------------------------------------


class TestSSL3:
    def test_ssl3_bypass_enabled_hard_block(self):
        """SSLv3 always hard-blocks regardless of bypass setting."""
        e = _make_enforcer()
        assert e.check(SSL3, []) is None

    def test_ssl3_bypass_disabled_still_hard_block(self):
        """SSLv3 hard-blocks even when tls_version_bypass is disabled."""
        e = _make_enforcer(
            security_policy={"tls_version_bypass": {"enabled": False}}
        )
        assert e.check(SSL3, []) is None

    def test_ssl3_block_flag_false_still_hard_block(self):
        """block_ssl3=false → SSLv3 passes (admin opt-in to allow SSLv3 investigation)."""
        e = _make_enforcer(tls_enforcer={"block_ssl3": False})
        # block_ssl3 disabled → SSLv3 is not blocked
        result = e.check(SSL3, [])
        assert result is not None  # list (possibly empty) — not hard block


# ---------------------------------------------------------------------------
# Weak cipher suite detection
# ---------------------------------------------------------------------------


class TestWeakCiphers:
    def test_weak_cipher_score_signal(self):
        """Weak cipher + block_weak_ciphers=false → RiskSignal at configured score."""
        e = _make_enforcer(
            tls_enforcer={"block_weak_ciphers": False, "weak_cipher_score": 20}
        )
        result = e.check(TLS13, [0x0004])  # RC4_128_MD5
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "weak_cipher"
        assert result[0].score == 20

    def test_weak_cipher_hard_block(self):
        """Weak cipher + block_weak_ciphers=true → hard block (None)."""
        e = _make_enforcer(tls_enforcer={"block_weak_ciphers": True})
        result = e.check(TLS13, [0x0005])  # RC4_128_SHA
        assert result is None

    def test_mixed_cipher_list_one_weak(self):
        """One weak cipher in an otherwise strong list → signal emitted."""
        e = _make_enforcer()
        mixed = _STRONG_CIPHERS + [0x000A]  # adds 3DES
        result = e.check(TLS12, mixed)
        names = [s.name for s in result] if result else []
        assert "weak_cipher" in names

    def test_all_strong_ciphers_no_signal(self):
        """All strong ciphers → no weak_cipher signal."""
        e = _make_enforcer()
        result = e.check(TLS12, _STRONG_CIPHERS)
        assert result is not None
        assert not any(s.name == "weak_cipher" for s in result)

    def test_empty_cipher_list_no_signal(self):
        """Empty cipher list → no weak_cipher signal."""
        e = _make_enforcer()
        result = e.check(TLS12, [])
        assert result == []

    def test_custom_weak_cipher_in_config(self):
        """Config-defined cipher ID is recognised as weak."""
        cfg = {
            "tls_enforcer": {
                "enabled": True,
                "block_ssl3": True,
                "block_tls_10": True,
                "block_tls_11": True,
                "flag_tls_12": False,
                "block_weak_ciphers": False,
                "weak_cipher_score": 20,
                "weak_ciphers": [0xFFFF],  # custom sentinel
            },
            "security_policy": {"tls_version_bypass": {"enabled": True}},
        }
        e = TLSEnforcer(cfg)
        result = e.check(TLS13, [0xFFFF])
        assert result is not None
        assert any(s.name == "weak_cipher" for s in result)

    def test_weak_cipher_custom_score(self):
        """Custom weak_cipher_score value is used in the signal."""
        e = _make_enforcer(tls_enforcer={"weak_cipher_score": 35})
        result = e.check(TLS13, [0x0004])
        assert result is not None
        weak = [s for s in result if s.name == "weak_cipher"]
        assert weak[0].score == 35


# ---------------------------------------------------------------------------
# tls_version=None (unknown version)
# ---------------------------------------------------------------------------


class TestUnknownVersion:
    def test_none_version_no_crash(self):
        """tls_version=None → no crash; no version signal."""
        e = _make_enforcer()
        result = e.check(None, [])
        assert result == []

    def test_none_version_weak_cipher_still_detected(self):
        """tls_version=None with weak cipher → cipher signal still emitted."""
        e = _make_enforcer()
        result = e.check(None, [0x0004])
        assert result is not None
        assert any(s.name == "weak_cipher" for s in result)


# ---------------------------------------------------------------------------
# enabled=false short-circuits everything
# ---------------------------------------------------------------------------


class TestDisabledEnforcer:
    def test_disabled_sslv3_not_blocked(self):
        """enabled=false → SSLv3 passes; no signal; no crash."""
        e = _make_enforcer(tls_enforcer={"enabled": False})
        assert e.check(SSL3, [0x0004]) == []

    def test_disabled_tls11_not_blocked(self):
        """enabled=false → TLS 1.1 passes."""
        e = _make_enforcer(tls_enforcer={"enabled": False})
        assert e.check(TLS11, []) == []


# ---------------------------------------------------------------------------
# from_config() and on_config_reload()
# ---------------------------------------------------------------------------


class TestFromConfigAndReload:
    def test_from_config_creates_instance(self):
        """from_config() returns a TLSEnforcer with correct settings."""
        cfg = {
            "tls_enforcer": {"enabled": True, "flag_tls_12": True, "score": 7},
            "security_policy": {"tls_version_bypass": {"enabled": True}},
        }
        e = TLSEnforcer.from_config(cfg)
        result = e.check(TLS12, [])
        assert result is not None
        assert result[0].score == 7

    def test_on_config_reload_updates_flag_tls_12(self):
        """Hot reload: flag_tls_12 false → true → next call emits signal."""
        cfg_before = {
            "tls_enforcer": {"flag_tls_12": False},
            "security_policy": {"tls_version_bypass": {"enabled": True}},
        }
        e = TLSEnforcer(cfg_before)
        assert e.check(TLS12, []) == []

        cfg_after = {
            "tls_enforcer": {"flag_tls_12": True, "score": 10},
            "security_policy": {"tls_version_bypass": {"enabled": True}},
        }
        e.on_config_reload(cfg_after)
        result = e.check(TLS12, [])
        assert result is not None
        assert any(s.name == "tls_version" for s in result)

    def test_on_config_reload_changes_bypass_enabled(self):
        """Hot reload: bypass enabled→disabled changes TLS 1.1 from block to signal."""
        e = _make_enforcer()
        # Initially bypass enabled → hard block
        assert e.check(TLS11, []) is None

        cfg_no_bypass = {
            "tls_enforcer": {
                "enabled": True,
                "block_tls_11": True,
                "block_ssl3": True,
                "block_tls_10": True,
            },
            "security_policy": {"tls_version_bypass": {"enabled": False}},
        }
        e.on_config_reload(cfg_no_bypass)
        result = e.check(TLS11, [])
        assert result is not None  # signals, not hard block
        assert result[0].name == "tls_version"

    def test_empty_config_uses_safe_defaults(self):
        """Empty config dict uses all default values without crashing."""
        e = TLSEnforcer({})
        # Defaults: block_ssl3=True, bypass enabled → SSLv3 hard block
        assert e.check(SSL3, []) is None
        # Defaults: flag_tls_12=False → no signal for TLS 1.2
        assert e.check(TLS12, _STRONG_CIPHERS) == []


# ---------------------------------------------------------------------------
# WEAK_CIPHERS constant sanity checks
# ---------------------------------------------------------------------------


class TestWeakCiphersConstant:
    def test_rc4_in_weak_ciphers(self):
        assert 0x0004 in WEAK_CIPHERS  # RC4_128_MD5
        assert 0x0005 in WEAK_CIPHERS  # RC4_128_SHA

    def test_null_in_weak_ciphers(self):
        assert 0x0000 in WEAK_CIPHERS

    def test_3des_in_weak_ciphers(self):
        assert 0x000A in WEAK_CIPHERS

    def test_strong_cipher_not_in_weak_ciphers(self):
        assert 0xC02B not in WEAK_CIPHERS  # ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        assert 0x1301 not in WEAK_CIPHERS  # TLS_AES_128_GCM_SHA256 (TLS 1.3)
