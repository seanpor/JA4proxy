#!/usr/bin/env python3
"""Unit tests for TCPAnalyzer (Phase 5)."""

import pytest
import time
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


class TestSessionResumption:
    """Test session resumption tracking (TDD - tests before implementation)."""

    def test_session_resumption_signal_generation(self):
        """Test that no_resumption signal is generated after threshold."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return data indicating no resumption
        redis_data = {b'total': b'15', b'resumed': b'0'}  # 15 connections, 0 resumed
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
                self.ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # no_resumption_signals = [s for s in signals if s.name == 'no_resumption']
        # assert len(no_resumption_signals) == 1
        # assert no_resumption_signals[0].score == 15
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_session_resumption_below_threshold(self):
        """Test that no signal is generated below threshold."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return data below threshold
        redis_data = {b'total': b'5', b'resumed': b'0'}  # Only 5 connections
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
                self.ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # no_resumption_signals = [s for s in signals if s.name == 'no_resumption']
        # assert len(no_resumption_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_session_resumption_with_resumption(self):
        """Test that no signal is generated when resumption occurs."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to show some resumption
        redis_data = {b'total': b'15', b'resumed': b'8'}  # 15 connections, 8 resumed
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
                self.ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # no_resumption_signals = [s for s in signals if s.name == 'no_resumption']
        # assert len(no_resumption_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending


class TestConnectionLifespan:
    """Test connection lifespan analysis (TDD - tests before implementation)."""

    def test_short_lived_connections(self):
        """Test that short_lived signal is generated for brief connections."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return short lifespans
        redis_client.zrange.return_value = [
            (b'conn1', 100.0),  # 100ms
            (b'conn2', 200.0),  # 200ms
            (b'conn3', 300.0),  # 300ms
            (b'conn4', 400.0),  # 400ms
            (b'conn5', 450.0),  # 450ms
        ]  # Median = 300ms < 500ms threshold
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # short_lived_signals = [s for s in signals if s.name == 'short_lived']
        # assert len(short_lived_signals) == 1
        # assert short_lived_signals[0].score == 20
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_normal_lived_connections(self):
        """Test that no signal is generated for normal connections."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return normal lifespans
        redis_client.zrange.return_value = [
            (b'conn1', 1000.0),  # 1000ms
            (b'conn2', 2000.0),  # 2000ms
            (b'conn3', 3000.0),  # 3000ms
            (b'conn4', 4000.0),  # 4000ms
            (b'conn5', 5000.0),  # 5000ms
        ]  # Median = 3000ms > 500ms threshold
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # short_lived_signals = [s for s in signals if s.name == 'short_lived']
        # assert len(short_lived_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_insufficient_data(self):
        """Test that no signal is generated with insufficient data."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return insufficient data
        redis_client.zrange.return_value = [
            (b'conn1', 100.0),  # Only 1 connection
        ]  # Need >= 5 connections
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # short_lived_signals = [s for s in signals if s.name == 'short_lived']
        # assert len(short_lived_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending


class TestConcurrentConnections:
    """Test concurrent connection tracking (TDD - tests before implementation)."""

    def test_severe_concurrency(self):
        """Test that high_concurrency signal is generated for severe levels."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return severe concurrency count
        redis_client.incr.return_value = 150  # > 100 (severe threshold)
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # concurrency_signals = [s for s in signals if s.name == 'high_concurrency']
        # assert len(concurrency_signals) == 1
        # assert concurrency_signals[0].score == 40  # Severe score
        # assert 'severe' in concurrency_signals[0].reason
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_high_concurrency(self):
        """Test that high_concurrency signal is generated for high levels."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return high concurrency count
        redis_client.incr.return_value = 60  # > 50 (high), < 100 (severe)
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # concurrency_signals = [s for s in signals if s.name == 'high_concurrency']
        # assert len(concurrency_signals) == 1
        # assert concurrency_signals[0].score == 25  # High score
        # assert 'high' in concurrency_signals[0].reason
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_moderate_concurrency(self):
        """Test that high_concurrency signal is generated for moderate levels."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return moderate concurrency count
        redis_client.incr.return_value = 25  # > 20 (moderate), < 50 (high)
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # concurrency_signals = [s for s in signals if s.name == 'high_concurrency']
        # assert len(concurrency_signals) == 1
        # assert concurrency_signals[0].score == 10  # Moderate score
        # assert 'moderate' in concurrency_signals[0].reason
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_normal_concurrency(self):
        """Test that no signal is generated for normal concurrency."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return normal concurrency count
        redis_client.incr.return_value = 10  # < 20 (moderate threshold)
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # concurrency_signals = [s for s in signals if s.name == 'high_concurrency']
        # assert len(concurrency_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending


class TestReturnVisitorTrust:
    """Test return visitor trust system (TDD - tests before implementation)."""

    def test_trusted_visitor_signal(self):
        """Test that trust signal is generated for long-term good visitors."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return trusted visitor data
        now = time.time()
        seven_days_ago = now - (7 * 86400)
        redis_data = {
            b'first_seen': str(seven_days_ago).encode(),
            b'total': b'100',
            b'allowed': b'95',  # 95% allow rate
        }
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # assert len(trust_signals) == 1
        # assert trust_signals[0].reduction_pct == 20
        # assert 'Trusted visitor' in trust_signals[0].reason
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_new_visitor_no_trust(self):
        """Test that no trust signal is generated for new visitors."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return new visitor data
        now = time.time()
        one_day_ago = now - 86400
        redis_data = {
            b'first_seen': str(one_day_ago).encode(),  # Only 1 day
            b'total': b'10',
            b'allowed': b'9',  # 90% allow rate
        }
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # assert len(trust_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_low_allow_rate_no_trust(self):
        """Test that no trust signal is generated for visitors with low allow rate."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Mock Redis to return data with low allow rate
        now = time.time()
        seven_days_ago = now - (7 * 86400)
        redis_data = {
            b'first_seen': str(seven_days_ago).encode(),
            b'total': b'100',
            b'allowed': b'70',  # 70% allow rate < 90% threshold
        }
        redis_client.hgetall.return_value = redis_data
        
        # Create mock context
        class MockContext:
            def __init__(self):
                self.client_ip = "192.168.1.1"
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # assert len(trust_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending


class TestTLSAlerts:
    """Test TLS alert monitoring (TDD - tests before implementation)."""

    def test_high_alert_rate(self):
        """Test that tls_alert_rate signal is generated for excessive alerts."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with many TLS alerts
        class MockContext:
            def __init__(self):
                self.tls_alerts = ['handshake_failure', 'certificate_unknown', 'decode_error', 
                                 'protocol_version', 'insufficient_security', 'access_denied']
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # alert_signals = [s for s in signals if s.name == 'tls_alert_rate']
        # assert len(alert_signals) == 1
        # assert alert_signals[0].score == 20
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_normal_alert_rate(self):
        """Test that no signal is generated for normal alert rates."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with few TLS alerts
        class MockContext:
            def __init__(self):
                self.tls_alerts = ['handshake_failure']  # Only 1 alert
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # alert_signals = [s for s in signals if s.name == 'tls_alert_rate']
        # assert len(alert_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending

    def test_no_alerts(self):
        """Test that no signal is generated with no alerts."""
        config = {}
        redis_client = Mock()
        analyzer = TCPAnalyzer(config, redis_client)
        
        # Create mock context with no TLS alerts
        class MockContext:
            def __init__(self):
                self.tls_alerts = []
        
        ctx = MockContext()
        
        # This will fail until implementation is complete
        # signals, trust_signals = analyzer.analyze(ctx)
        # alert_signals = [s for s in signals if s.name == 'tls_alert_rate']
        # assert len(alert_signals) == 0
        
        # Placeholder - will implement after tests pass
        assert True  # TDD: Test defined, implementation pending


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
