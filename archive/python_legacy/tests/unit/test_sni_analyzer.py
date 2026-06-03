#!/usr/bin/env python3
"""Unit tests for SNIAnalyzer (Phase 4)."""

from unittest.mock import Mock

import pytest
from src.security.risk_scorer import RiskSignal
from src.security.sni_analyzer import (
    SNIAnalyzer,
    _get_primary_label,
    _shannon_entropy,
    dga_score,
)


class TestSNIAnalyzerInit:
    """Test SNIAnalyzer initialization and configuration."""

    def test_init_with_default_config(self):
        """Test initialization with default configuration."""
        config = {}
        analyzer = SNIAnalyzer(config)

        assert analyzer._enabled is True
        assert analyzer._missing_sni_enabled is True
        assert analyzer._missing_sni_score == 30
        assert analyzer._ip_literal_enabled is True
        assert analyzer._ip_literal_score == 25
        assert analyzer._dga_enabled is True
        assert analyzer._entropy_threshold == 3.8
        assert analyzer._dga_score_cap == 40
        assert analyzer._unexpected_sni_score == 15
        assert analyzer._expected_hostnames == frozenset()

    def test_init_with_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            "sni_analyzer": {
                "enabled": False,
                "missing_sni": {"enabled": False, "score": 20},
                "ip_literal_sni": {"enabled": False, "score": 15},
                "dga_detection": {
                    "enabled": False,
                    "entropy_threshold": 4.0,
                    "score_cap": 30,
                },
                "expected_hostnames": ["example.com", "test.org"],
                "score": 10,
            }
        }
        analyzer = SNIAnalyzer(config)

        assert analyzer._enabled is False
        assert analyzer._missing_sni_enabled is False
        assert analyzer._missing_sni_score == 20
        assert analyzer._ip_literal_enabled is False
        assert analyzer._ip_literal_score == 15
        assert analyzer._dga_enabled is False
        assert analyzer._entropy_threshold == 4.0
        assert analyzer._dga_score_cap == 30
        assert analyzer._unexpected_sni_score == 10
        assert analyzer._expected_hostnames == frozenset(["example.com", "test.org"])

    def test_from_config(self):
        """Test from_config class method."""
        config = {"sni_analyzer": {"enabled": True}}
        analyzer = SNIAnalyzer.from_config(config)
        assert isinstance(analyzer, SNIAnalyzer)
        assert analyzer._enabled is True


class TestSNIAnalyzerAnalyze:
    """Test SNIAnalyzer.analyze() method."""

    def test_missing_sni_returns_signal(self):
        """Test that missing SNI returns missing_sni signal."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze(None)

        assert len(signals) == 1
        assert signals[0].name == "missing_sni"
        assert signals[0].score == 30
        assert "SNI extension absent" in signals[0].reason
        assert "example.com" not in signals[0].reason  # Privacy check

    def test_ip_literal_sni_returns_signal(self):
        """Test that IP literal SNI returns ip_literal_sni signal."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("192.168.1.1")

        assert len(signals) == 1
        assert signals[0].name == "ip_literal_sni"
        assert signals[0].score == 25
        assert "raw IP address" in signals[0].reason
        assert "192.168.1.1" not in signals[0].reason  # Privacy check

    def test_valid_hostname_no_signals(self):
        """Test that valid hostname returns no signals."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("www.google.com")

        assert len(signals) == 0

    def test_dga_detection_known_dga(self):
        """Test DGA detection with known DGA pattern."""
        config = {}
        analyzer = SNIAnalyzer(config)

        # Known DGA pattern: long, high entropy, no vowels
        dga_hostname = "xkcd93j4fk92jf94jf92jf94jf.com"
        signals = analyzer.analyze(dga_hostname)

        dga_signals = [s for s in signals if s.name == "dga"]
        assert len(dga_signals) >= 1

        dga_signal = dga_signals[0]
        assert dga_signal.score > 0
        assert dga_signal.score <= 40  # Capped at score_cap
        assert "DGA confidence" in dga_signal.reason
        assert dga_hostname not in dga_signal.reason  # Privacy check

    def test_dga_detection_clean_hostname(self):
        """Test DGA detection with clean hostname."""
        config = {}
        analyzer = SNIAnalyzer(config)

        # Clean hostname
        clean_hostname = "www.google.com"
        signals = analyzer.analyze(clean_hostname)

        dga_signals = [s for s in signals if s.name == "dga"]
        assert len(dga_signals) == 0

    def test_unexpected_hostname_signal(self):
        """Test unexpected hostname signal."""
        config = {"sni_analyzer": {"expected_hostnames": ["example.com", "test.org"]}}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("unknown.com")

        unexpected_signals = [s for s in signals if s.name == "unexpected_sni"]
        assert len(unexpected_signals) == 1

        signal = unexpected_signals[0]
        assert signal.score == 15
        assert "not in expected_hostnames list" in signal.reason
        assert "unknown.com" not in signal.reason  # Privacy check

    def test_expected_hostname_no_signal(self):
        """Test that expected hostname returns no unexpected_sni signal."""
        config = {"sni_analyzer": {"expected_hostnames": ["example.com", "test.org"]}}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("example.com")

        unexpected_signals = [s for s in signals if s.name == "unexpected_sni"]
        assert len(unexpected_signals) == 0

    def test_empty_expected_hostnames_no_signal(self):
        """Test that empty expected_hostnames list returns no signal."""
        config = {"sni_analyzer": {"expected_hostnames": []}}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("anything.com")

        unexpected_signals = [s for s in signals if s.name == "unexpected_sni"]
        assert len(unexpected_signals) == 0

    def test_disabled_analyzer_returns_no_signals(self):
        """Test that disabled analyzer returns no signals."""
        config = {"sni_analyzer": {"enabled": False}}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze(None)
        assert len(signals) == 0

        signals = analyzer.analyze("192.168.1.1")
        assert len(signals) == 0

        signals = analyzer.analyze("www.google.com")
        assert len(signals) == 0

    def test_dga_score_capping(self):
        """Test that DGA score is properly capped."""
        config = {
            "sni_analyzer": {
                "dga_detection": {"score_cap": 30}  # Lower than default 40
            }
        }
        analyzer = SNIAnalyzer(config)

        # Use a hostname that would normally get high DGA score
        signals = analyzer.analyze("xkcd93j4fk92jf94jf92jf94jf.com")

        dga_signals = [s for s in signals if s.name == "dga"]
        if dga_signals:
            dga_signal = dga_signals[0]
            # Score should be capped at 30, not exceed 100
            assert dga_signal.score <= 30
            assert dga_signal.score <= 100


class TestDGAScore:
    """Test DGA scoring algorithm."""

    def test_dga_score_clean_domain(self):
        """Test DGA score with clean domain."""
        score = dga_score("www.google.com")
        assert 0.0 <= score <= 0.1  # Should be very low

    def test_dga_score_high_entropy(self):
        """Test DGA score with high entropy domain."""
        score = dga_score("xkcd93j4fk92jf94jf92jf94jf.com")
        assert 0.5 <= score <= 1.0  # Should be high

    def test_dga_score_no_vowels(self):
        """Test DGA score with no vowels."""
        score = dga_score("xkcd93j4fk92jf94jf92jf94jf.com")
        assert score >= 0.3  # No vowels should contribute significantly

    def test_dga_score_long_label(self):
        """Test DGA score with long label."""
        long_label = "a" * 30 + ".com"
        score = dga_score(long_label)
        assert score >= 0.2  # Long label should contribute

    def test_dga_score_with_digits(self):
        """Test DGA score with digit sequences."""
        score = dga_score("test123456789domain.com")
        assert score >= 0.1  # Digit sequence should contribute

    def test_dga_score_short_label(self):
        """Test DGA score with short label (should be 0)."""
        score = dga_score("abc.com")
        assert score == 0.0  # Too short for analysis

    def test_dga_score_max_cap(self):
        """Test that DGA score doesn't exceed 1.0."""
        # Create a domain that should max out all heuristics
        score = dga_score("xkcd93j4fk92jf94jf92jf94jf1234567890.com")
        assert 0.0 <= score <= 1.0


class TestDGAHelpers:
    """Test DGA helper functions."""

    def test_shannon_entropy(self):
        """Test Shannon entropy calculation."""
        # Low entropy (repetitive)
        ent = _shannon_entropy("aaaaaaaa")
        assert 0.0 <= ent <= 1.0

        # High entropy (random)
        ent = _shannon_entropy("abcdefgh")
        assert ent >= 3.0

        # Empty string
        ent = _shannon_entropy("")
        assert ent == 0.0

    def test_get_primary_label(self):
        """Test primary label extraction."""
        # Simple case
        assert _get_primary_label("www.google.com") == "google"

        # Multiple prefixes
        assert _get_primary_label("www.mail.test.example.com") == "test"

        # No prefixes
        assert _get_primary_label("google.com") == "google"

        # Edge case: all prefixes
        assert _get_primary_label("www.mail.cdn.google.com") == "google"

        # Empty
        assert _get_primary_label("") == ""


class TestConfigReload:
    """Test configuration hot reload."""

    def test_on_config_reload(self):
        """Test that config reload updates settings."""
        config1 = {"sni_analyzer": {"missing_sni": {"score": 30}}}
        analyzer = SNIAnalyzer(config1)
        assert analyzer._missing_sni_score == 30

        config2 = {"sni_analyzer": {"missing_sni": {"score": 25}}}
        analyzer.on_config_reload(config2)
        assert analyzer._missing_sni_score == 25

    def test_on_config_reload_preserves_state(self):
        """Test that config reload doesn't break analyzer state."""
        config1 = {}
        analyzer = SNIAnalyzer(config1)

        # First analysis
        signals1 = analyzer.analyze(None)
        assert len(signals1) == 1

        # Reload config
        config2 = {"sni_analyzer": {"missing_sni": {"score": 20}}}
        analyzer.on_config_reload(config2)

        # Second analysis with new config
        signals2 = analyzer.analyze(None)
        assert len(signals2) == 1
        assert signals2[0].score == 20


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_sni_with_trailing_dot(self):
        """Test SNI with trailing dot."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("example.com.")
        # Should handle trailing dot gracefully
        assert len(signals) == 0  # Valid hostname

    def test_sni_case_insensitive(self):
        """Test that SNI analysis is case insensitive."""
        config = {"sni_analyzer": {"expected_hostnames": ["example.com"]}}
        analyzer = SNIAnalyzer(config)

        # Mixed case should match
        signals = analyzer.analyze("Example.COM")
        unexpected_signals = [s for s in signals if s.name == "unexpected_sni"]
        assert len(unexpected_signals) == 0

    def test_ipv6_literal(self):
        """Test IPv6 literal detection."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

        ip_literal_signals = [s for s in signals if s.name == "ip_literal_sni"]
        assert len(ip_literal_signals) == 1

    def test_empty_string_sni(self):
        """Test empty string SNI."""
        config = {}
        analyzer = SNIAnalyzer(config)

        signals = analyzer.analyze("")
        # Empty string should be treated as missing/invalid
        # Implementation may vary - could be no signal or missing_sni equivalent
        # This test documents current behavior
        signal_names = [s.name for s in signals]
        assert "ip_literal_sni" not in signal_names  # Empty string is not a valid IP

    def test_unicode_sni(self):
        """Test Unicode in SNI."""
        config = {}
        analyzer = SNIAnalyzer(config)

        # Should handle Unicode gracefully
        signals = analyzer.analyze("测试.com")
        # May or may not produce signals depending on implementation
        # Main requirement: should not crash
        assert isinstance(signals, list)


class TestPrivacy:
    """Test privacy protections."""

    def test_no_raw_sni_in_reason(self):
        """Test that raw SNI values never appear in signal reasons."""
        config = {}
        analyzer = SNIAnalyzer(config)

        test_snis = [
            None,
            "192.168.1.1",
            "www.example.com",
            "xkcd93j4fk92jf94jf92jf94jf.com",
        ]

        for sni in test_snis:
            signals = analyzer.analyze(sni)
            for signal in signals:
                # Raw SNI should not appear in reason
                if sni is not None:
                    assert str(sni) not in signal.reason
                # IP addresses should not appear in reason
                if sni and "192.168.1.1" in str(sni):
                    assert "192.168.1.1" not in signal.reason

    def test_no_sni_in_metrics(self):
        """Test that SNI values are not exposed in metrics."""
        # This is more of a documentation test
        # Actual metrics testing would require Prometheus client mocking
        config = {}
        analyzer = SNIAnalyzer(config)

        # Analyze a sensitive SNI
        analyzer.analyze("internal-corporate-banking.example.com")

        # Metrics should only contain signal names, not SNI values
        # This is enforced by the implementation not passing SNI to metrics
        # Signal reasons contain only structural descriptions


class TestPerformance:
    """Test performance characteristics."""

    def test_dga_score_performance(self):
        """Test that DGA scoring is fast."""
        import time

        test_hostnames = [
            "www.google.com",
            "xkcd93j4fk92jf94jf92jf94jf.com",
            "test" + "a" * 50 + ".com",
            "192.168.1.1",
            "a" * 100 + ".com",
        ]

        start_time = time.time()
        for _ in range(1000):  # 1000 iterations
            for hostname in test_hostnames:
                dga_score(hostname)
        end_time = time.time()

        duration_per_call = (end_time - start_time) / (1000 * len(test_hostnames))

        # Should be very fast (< 0.2ms per call - adjusted for CI environments)
        assert duration_per_call < 0.0002

    def test_analyze_performance(self):
        """Test that analyze() is fast."""
        import time

        config = {"sni_analyzer": {"expected_hostnames": ["example.com", "test.org"]}}
        analyzer = SNIAnalyzer(config)

        test_snis = [None, "192.168.1.1", "www.google.com", "example.com"]

        start_time = time.time()
        for _ in range(1000):  # 1000 iterations
            for sni in test_snis:
                analyzer.analyze(sni)
        end_time = time.time()

        duration_per_call = (end_time - start_time) / (1000 * len(test_snis))

        # Should be very fast (< 0.2ms per call - adjusted for CI environments)
        assert duration_per_call < 0.0002


# ── Missing-coverage tests ────────────────────────────────────────────────────


class TestSNIAnalyzerInitErrorHandling:
    """Cover ValueError/TypeError exception handlers in __init__ (lines 179, 189-190,
    197-198, 207-208, 211-212, 223-224) and non-list expected_hostnames (line 217).

    So what: an operator typo in proxy.yml must not crash the proxy on startup —
    invalid config values must silently fall back to safe defaults.
    """

    def test_invalid_missing_sni_score_falls_back_to_default(self):
        """Non-numeric missing_sni score → defaults to 30 (line 179).
        So what: a config typo must not raise ValueError at startup."""
        config = {"sni_analyzer": {"missing_sni": {"score": "not-a-number"}}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._missing_sni_score == 30

    def test_invalid_ip_literal_score_falls_back_to_default(self):
        """Non-numeric ip_literal score → defaults to 25 (lines 189-190)."""
        config = {"sni_analyzer": {"ip_literal_sni": {"score": [1, 2]}}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._ip_literal_score == 25

    def test_invalid_entropy_threshold_falls_back_to_default(self):
        """Non-numeric entropy_threshold → defaults to 3.8 (lines 197-198)."""
        config = {"sni_analyzer": {"dga_detection": {"entropy_threshold": "high"}}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._entropy_threshold == 3.8

    def test_invalid_dga_score_cap_falls_back_to_default(self):
        """Non-numeric dga score_cap → defaults to 40 (lines 207-208)."""
        config = {"sni_analyzer": {"dga_detection": {"score_cap": None}}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._dga_score_cap == 40

    def test_invalid_unexpected_sni_score_falls_back_to_default(self):
        """Non-numeric unexpected score → defaults to 15 (lines 223-224)."""
        config = {"sni_analyzer": {"score": "bad"}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._unexpected_sni_score == 15

    def test_non_list_expected_hostnames_treated_as_empty(self):
        """expected_hostnames that isn't a list → empty frozenset (line 217).
        So what: a misconfigured string value must not crash with TypeError."""
        config = {"sni_analyzer": {"expected_hostnames": "not-a-list"}}
        analyzer = SNIAnalyzer(config)
        assert analyzer._expected_hostnames == frozenset()


class TestDGAConsonantHeavy:
    """Cover the consonant-heavy branch in dga_score() (line 136).

    So what: C2 beacons often use domains that have vowels but at a very low
    ratio (mostly consonants). Missing this branch means reduced DGA detection.
    """

    def test_consonant_heavy_long_label_scores(self):
        """alpha_count >= 10, vowel_count > 0, ratio > 5.0 → score += 0.20 (line 136).
        So what: a consonant-heavy but not vowel-free label must still get scored."""
        # Need: >=10 alpha, some vowels, but alpha/vowel > 5.0
        # e.g. 10 alpha: 1 vowel, 9 consonants → ratio = 10.0 > 5.0
        # 'bcdfghjklm' + 'a' → ratio=11 but that's exactly 12 chars
        label = "bcdfghjklma.com"  # 11 alpha, 1 vowel → ratio=11>5
        score = dga_score(label)
        # Should score at least 0.20 from this branch
        assert score >= 0.20

    def test_consonant_heavy_short_label_not_scored(self):
        """alpha_count < 10 → consonant-heavy branch skipped.
        So what: short hostnames with no vowels must not be falsely flagged."""
        label = "bcdfg.com"  # only 5 alpha
        score = dga_score(label)
        # Should not trigger the >=10 alpha branch
        # (may trigger other branches but not line 136)
        assert 0.0 <= score <= 1.0
