#!/usr/bin/env python3
"""Unit tests for TCPAnalyzer (Phase 5)."""

import pytest
from unittest.mock import Mock
from src.security.tcp_analyzer import TCPAnalyzer, TrustSignal
from src.security.risk_scorer import RiskSignal


class TestTCPAnalyzerInit:
    """Test TCPAnalyzer initialization."""

    def test_init_with_default_config(self):
        """Test initialization with default configuration."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        assert analyzer._enabled is True
        assert analyzer._ja4t_enabled is True
        assert analyzer._ja4t_score == 30
        assert analyzer._resumption_enabled is True
        assert analyzer._resumption_score == 15
        assert analyzer._lifespan_enabled is True
        assert analyzer._lifespan_score == 20
        assert analyzer._concurrent_enabled is True
        assert analyzer._return_visitor_enabled is True
        assert analyzer._tls_alerts_enabled is True
        assert analyzer._alert_score == 20

    def test_init_with_custom_config(self):
        """Test initialization with custom configuration."""
        config = {
            'tcp_analyzer': {
                'enabled': True,
                'tcp_fingerprinting': {'enabled': True, 'score': 25},
                'session_resumption': {'enabled': False, 'score': 10},
                'connection_lifespan': {'enabled': True, 'threshold_ms': 300, 'score': 15},
                'concurrent_connections': {'enabled': True, 'thresholds': {'moderate': 10, 'high': 30, 'severe': 60}},
                'return_visitor': {'enabled': False, 'trusted_days': 14, 'score_reduction_pct': 15},
                'tls_alerts': {'enabled': True, 'rate_threshold': 10, 'score': 25}
            }
        }
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        assert analyzer._ja4t_score == 25
        assert analyzer._resumption_enabled is False
        assert analyzer._lifespan_threshold_ms == 300
        assert analyzer._concurrent_thresholds['moderate'] == 10
        assert analyzer._return_visitor_enabled is False
        assert analyzer._alert_score == 25

    def test_init_disabled(self):
        """Test initialization with analyzer disabled."""
        config = {'tcp_analyzer': {'enabled': False}}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        assert analyzer._enabled is False


class TestJA4TMismatch:
    """Test JA4T fingerprinting functionality."""

    def test_ja4t_mismatch_detection(self):
        """Test JA4T OS mismatch detection."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with mismatched OS indicators
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = '65535,64,sackOK,TS,nop,WS'  # Linux pattern
                self.ja4 = 't13d1516h2_8daaf6152771_02713d6af862'  # Windows pattern (h2)
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should detect mismatch
        ja4t_signals = [s for s in signals if s.name == 'ja4t_mismatch']
        assert len(ja4t_signals) == 1
        assert ja4t_signals[0].score == 30
        assert 'linux' in ja4t_signals[0].reason
        assert 'windows' in ja4t_signals[0].reason

    def test_ja4t_no_mismatch(self):
        """Test JA4T with matching OS."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with matching OS indicators
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = '65535,64,sackOK,TS,nop,WS'  # Linux pattern
                self.ja4 = 't12d151415_deadbeef1337_attackertools'  # Linux pattern
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should not detect mismatch
        ja4t_signals = [s for s in signals if s.name == 'ja4t_mismatch']
        assert len(ja4t_signals) == 0

    def test_ja4t_missing_data(self):
        """Test JA4T with missing data."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with missing data
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = ''
                self.ja4 = ''
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should not crash, should return empty signals
        assert len(signals) == 0
        assert len(trust_signals) == 0

    def test_ja4t_os_mapping(self):
        """Test JA4T to OS mapping logic."""
        # Test Linux pattern
        assert TCPAnalyzer._map_ja4t_to_os('65535,64,sackOK,TS,nop,WS') == 'linux'
        
        # Test Windows pattern
        assert TCPAnalyzer._map_ja4t_to_os('65535,128,sackOK,TS,nop,WS') == 'windows'
        
        # Test macOS pattern
        assert TCPAnalyzer._map_ja4t_to_os('65535,255,sackOK,TS,nop,WS') == 'macos'
        
        # Test unknown pattern
        assert TCPAnalyzer._map_ja4t_to_os('12345,99,unknown') == 'unknown'
        assert TCPAnalyzer._map_ja4t_to_os('') == 'unknown'

    def test_ja4_os_mapping(self):
        """Test JA4 to OS mapping logic."""
        # Test Windows pattern (TLS 1.3 with h2)
        assert TCPAnalyzer._map_ja4_to_implied_os('t13d1516h2_8daaf6152771_02713d6af862') == 'windows'
        
        # Test macOS pattern (TLS 1.3 with h1)
        assert TCPAnalyzer._map_ja4_to_implied_os('t13d1516h1_8daaf6152771_02713d6af862') == 'macos'
        
        # Test Linux pattern (TLS 1.2)
        assert TCPAnalyzer._map_ja4_to_implied_os('t12d151415_deadbeef1337_attackertools') == 'linux'
        
        # Test unknown pattern
        assert TCPAnalyzer._map_ja4_to_implied_os('') == 'unknown'
        assert TCPAnalyzer._map_ja4_to_implied_os('invalid') == 'unknown'


class TestDisabledAnalyzer:
    """Test analyzer behavior when disabled."""

    def test_analyzer_disabled(self):
        """Test that disabled analyzer returns no signals."""
        config = {'tcp_analyzer': {'enabled': False}}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = '65535,64,sackOK,TS,nop,WS'
                self.ja4 = 't13d1516h2_8daaf6152771_02713d6af862'
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        assert len(signals) == 0
        assert len(trust_signals) == 0

    def test_module_disabled(self):
        """Test individual module disable."""
        config = {
            'tcp_analyzer': {
                'enabled': True,
                'tcp_fingerprinting': {'enabled': False}
            }
        }
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = '65535,64,sackOK,TS,nop,WS'
                self.ja4 = 't13d1516h2_8daaf6152771_02713d6af862'
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should not generate JA4T signals when module disabled
        ja4t_signals = [s for s in signals if s.name == 'ja4t_mismatch']
        assert len(ja4t_signals) == 0


class TestConfigReload:
    """Test configuration hot reload."""

    def test_config_reload(self):
        """Test that config reload updates settings."""
        config1 = {
            'tcp_analyzer': {
                'tcp_fingerprinting': {'score': 30}
            }
        }
        redis_client = Mock()
        analyzer = TCPAnalyzer(config1, redis_client)
        assert analyzer._ja4t_score == 30
        
        config2 = {
            'tcp_analyzer': {
                'tcp_fingerprinting': {'score': 25}
            }
        }
        analyzer.on_config_reload(config2)
        assert analyzer._ja4t_score == 25


class TestErrorHandling:
    """Test error handling and resilience."""

    def test_analyze_with_exception(self):
        """Test that analyze handles exceptions gracefully."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Context that might cause issues
        class ProblematicContext:
            def __init__(self):
                # No TCP data - should handle gracefully
                pass
        
        ctx = ProblematicContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should not crash, should return empty or valid signals
        assert isinstance(signals, list)
        assert isinstance(trust_signals, list)

    def test_ja4t_parsing_errors(self):
        """Test JA4T parsing handles malformed data."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        class MockContext:
            def __init__(self):
                self.tcp_ja4t = 'malformed,data,here'  # Malformed JA4T
                self.ja4 = 'valid_ja4_string'
        
        ctx = MockContext()
        signals, trust_signals = analyzer.analyze(ctx)
        
        # Should not crash
        assert isinstance(signals, list)
        assert isinstance(trust_signals, list)


class TestTrustSignals:
    """Test trust signal generation."""

    def test_trust_signal_structure(self):
        """Test that trust signals have correct structure."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create a trust signal manually to test structure
        trust_signal = TrustSignal(
            reduction_pct=20,
            reason="Trusted visitor: 14.0 days, 95% allow rate"
        )
        
        assert trust_signal.reduction_pct == 20
        assert "Trusted visitor" in trust_signal.reason
        assert "95%" in trust_signal.reason


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
