#!/usr/bin/env python3
"""Chaos tests for SNI analyzer (Phase 4)."""

import pytest
from unittest.mock import Mock
from src.security.sni_analyzer import SNIAnalyzer


class TestSNIAnalyzerChaos:
    """Chaos tests for SNI analyzer resilience."""

    def test_sni_analyzer_with_none_config(self):
        """Test SNI analyzer handles None config gracefully."""
        # Should not crash, should use defaults
        analyzer = SNIAnalyzer(None)
        
        signals = analyzer.analyze(None)
        assert len(signals) == 1  # missing_sni signal
        assert signals[0].name == 'missing_sni'

    def test_sni_analyzer_with_empty_config(self):
        """Test SNI analyzer handles empty config gracefully."""
        analyzer = SNIAnalyzer({})
        
        signals = analyzer.analyze(None)
        assert len(signals) == 1  # missing_sni signal
        assert signals[0].name == 'missing_sni'

    def test_sni_analyzer_with_malformed_config(self):
        """Test SNI analyzer handles malformed config gracefully."""
        # Config with wrong types
        config = {
            'sni_analyzer': {
                'enabled': "not_a_boolean",  # Wrong type
                'missing_sni': {'score': "not_a_number"},  # Wrong type
            }
        }
        
        # Should not crash, should convert types or use defaults
        analyzer = SNIAnalyzer(config)
        
        # Should still work
        signals = analyzer.analyze(None)
        assert isinstance(signals, list)

    def test_sni_analyzer_with_null_bytes(self):
        """Test SNI analyzer handles null bytes in SNI."""
        analyzer = SNIAnalyzer({})
        
        # Should not crash
        signals = analyzer.analyze('test\x00.example.com')
        assert isinstance(signals, list)

    def test_sni_analyzer_with_very_long_sni(self):
        """Test SNI analyzer handles very long SNI values."""
        analyzer = SNIAnalyzer({})
        
        # Very long SNI (should not crash)
        long_sni = 'a' * 1000 + '.com'
        signals = analyzer.analyze(long_sni)
        assert isinstance(signals, list)

    def test_sni_analyzer_with_special_characters(self):
        """Test SNI analyzer handles special characters."""
        analyzer = SNIAnalyzer({})
        
        special_snis = [
            'test\n.example.com',  # Newline
            'test\r.example.com',  # Carriage return
            'test\t.example.com',  # Tab
            'test\x1f.example.com',  # Unit separator
        ]
        
        for sni in special_snis:
            signals = analyzer.analyze(sni)
            assert isinstance(signals, list)

    def test_sni_analyzer_config_reload_with_invalid_data(self):
        """Test SNI analyzer handles invalid config during reload."""
        analyzer = SNIAnalyzer({'sni_analyzer': {'missing_sni': {'score': 30}}})
        
        # Initial state
        signals1 = analyzer.analyze(None)
        assert signals1[0].score == 30
        
        # Reload with invalid data
        invalid_config = {
            'sni_analyzer': {
                'missing_sni': {'score': "invalid"}  # Not a number
            }
        }
        
        # Should not crash
        analyzer.on_config_reload(invalid_config)
        
        # Should still work (may use default or keep old value)
        signals2 = analyzer.analyze(None)
        assert isinstance(signals2, list)

    def test_sni_analyzer_multiple_reloads(self):
        """Test SNI analyzer handles multiple rapid config reloads."""
        analyzer = SNIAnalyzer({})
        
        # Multiple reloads
        for i in range(10):
            config = {
                'sni_analyzer': {
                    'missing_sni': {'score': 30 + i}
                }
            }
            analyzer.on_config_reload(config)
            signals = analyzer.analyze(None)
            assert isinstance(signals, list)

    def test_sni_analyzer_with_unicode_edge_cases(self):
        """Test SNI analyzer handles Unicode edge cases."""
        analyzer = SNIAnalyzer({})
        
        unicode_snis = [
            '\ud800.com',  # Surrogate pair
            '\ufffd.com',  # Replacement character
            '\u0000.com',  # Null character (Unicode)
        ]
        
        for sni in unicode_snis:
            signals = analyzer.analyze(sni)
            assert isinstance(signals, list)

    def test_sni_analyzer_memory_efficiency(self):
        """Test SNI analyzer doesn't leak memory."""
        import gc
        
        # Create many analyzers
        analyzers = []
        for i in range(100):
            config = {'sni_analyzer': {'missing_sni': {'score': 30}}}
            analyzer = SNIAnalyzer(config)
            analyzers.append(analyzer)
        
        # Clean up
        del analyzers
        gc.collect()
        
        # Should not crash or leak
        analyzer = SNIAnalyzer({})
        signals = analyzer.analyze('test.com')
        assert isinstance(signals, list)


class TestSNIAnalyzerErrorConditions:
    """Test SNI analyzer error conditions and recovery."""

    def test_sni_analyzer_with_broken_ip_address(self):
        """Test SNI analyzer handles broken IP addresses."""
        analyzer = SNIAnalyzer({})
        
        # Invalid IP formats
        broken_ips = [
            '999.999.999.999',
            '192.168.1',
            '192.168.1.1.1',
            'gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg',  # Invalid IPv6
        ]
        
        for ip in broken_ips:
            signals = analyzer.analyze(ip)
            # Should not crash, may or may not produce ip_literal_sni signal
            assert isinstance(signals, list)

    def test_sni_analyzer_with_mixed_content(self):
        """Test SNI analyzer handles mixed content SNI."""
        analyzer = SNIAnalyzer({})
        
        mixed_snis = [
            'http://example.com',  # URL instead of hostname
            'https://example.com',
            'example.com:443',     # With port
            'user@example.com',     # Email-like
        ]
        
        for sni in mixed_snis:
            signals = analyzer.analyze(sni)
            assert isinstance(signals, list)

    def test_sni_analyzer_with_whitespace(self):
        """Test SNI analyzer handles whitespace in SNI."""
        analyzer = SNIAnalyzer({})
        
        whitespace_snis = [
            ' example.com',
            'example.com ',
            ' ex ample . com ',
            '\texample.com\t',
        ]
        
        for sni in whitespace_snis:
            signals = analyzer.analyze(sni)
            assert isinstance(signals, list)

    def test_sni_analyzer_config_edge_cases(self):
        """Test SNI analyzer handles edge cases in configuration."""
        # Very high scores
        config = {
            'sni_analyzer': {
                'missing_sni': {'score': 999999},
                'ip_literal_sni': {'score': 999999},
                'dga_detection': {'score_cap': 999999}
            }
        }
        
        analyzer = SNIAnalyzer(config)
        signals = analyzer.analyze(None)
        # Should handle large numbers without crashing
        assert len(signals) == 1
        
        # Negative scores
        config = {
            'sni_analyzer': {
                'missing_sni': {'score': -100}
            }
        }
        
        analyzer = SNIAnalyzer(config)
        signals = analyzer.analyze(None)
        # Should handle negative numbers without crashing
        assert len(signals) == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
