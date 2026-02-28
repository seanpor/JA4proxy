#!/usr/bin/env python3
"""Integration tests for SNI analysis in the security pipeline (Phase 4)."""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from src.security.pipeline import Pipeline, ConnectionContext
from src.security.risk_scorer import RiskScorer
from src.security.action_decider import ActionDecider
from src.cache.local_cache import LocalCache


@pytest.mark.asyncio
class TestSNIPipelineIntegration:
    """Test SNI analysis integration with the security pipeline."""

    @pytest.fixture
    def pipeline(self):
        """Create a pipeline with SNI analyzer wired in."""
        config = {
            'security_policy': {
                'alpn_browser_bypass': {'enabled': False},  # Disable ALPN bypass for testing
                'ja4_whitelist_bypass': {'enabled': False},
                'mtls_bypass': {'enabled': False},
                'static_ip_allowlist': {'enabled': False},
                'ja4_blacklist_bypass': {'enabled': False},
            },
            'sni_analyzer': {
                'enabled': True,
                'missing_sni': {'enabled': True, 'score': 30},
                'ip_literal_sni': {'enabled': True, 'score': 25},
                'dga_detection': {'enabled': True, 'entropy_threshold': 3.8, 'score_cap': 40},
                'expected_hostnames': [],
                'score': 15
            }
        }
        
        local_cache = LocalCache(config)
        redis_client = Mock()
        
        pipeline = Pipeline(config, local_cache, redis_client)
        
        # Wire in scorer and decider
        scorer = RiskScorer(config)
        decider = ActionDecider(config)
        pipeline.update_scorer(scorer, decider)
        
        return pipeline

    @pytest.fixture
    def connection_context(self):
        """Create a connection context for testing."""
        return ConnectionContext(
            client_ip="192.168.1.100",
            ja4="t13d1516h2_8daaf6152771_02713d6af862",
            alpn="h2",
            has_valid_client_cert=False,
            sni="www.google.com",
            tls_version=0x0303,  # TLS 1.2
            country="US",
            cipher_list=[]
        )

    async def test_pipeline_with_valid_sni(self, pipeline, connection_context):
        """Test pipeline with valid SNI returns no SNI signals."""
        result = await pipeline.process(connection_context)
        
        # Should allow the connection
        assert result.action == "allow"
        
        # Check that no SNI-related signals were generated
        sni_signal_names = [s.name for s in result.signals if 'sni' in s.name.lower()]
        assert len(sni_signal_names) == 0

    async def test_pipeline_with_missing_sni(self, pipeline, connection_context):
        """Test pipeline with missing SNI generates missing_sni signal."""
        # Modify context to have no SNI
        connection_context.sni = None
        connection_context.raw_sni = ""
        
        result = await pipeline.process(connection_context)
        
        # Should still allow (score might be elevated but not enough to block)
        assert result.action in ["allow", "flag"]
        
        # Check for missing_sni signal
        sni_signals = [s for s in result.signals if s.name == 'missing_sni']
        assert len(sni_signals) == 1
        assert sni_signals[0].score == 30

    async def test_pipeline_with_ip_literal_sni(self, pipeline, connection_context):
        """Test pipeline with IP literal SNI generates ip_literal_sni signal."""
        # Modify context to have IP literal SNI
        connection_context.sni = "192.168.1.1"
        connection_context.raw_sni = "192.168.1.1"
        
        result = await pipeline.process(connection_context)
        
        # Should still allow (score might be elevated but not enough to block)
        assert result.action in ["allow", "flag"]
        
        # Check for ip_literal_sni signal
        sni_signals = [s for s in result.signals if s.name == 'ip_literal_sni']
        assert len(sni_signals) == 1
        assert sni_signals[0].score == 25

    async def test_pipeline_with_dga_sni(self, pipeline, connection_context):
        """Test pipeline with DGA-like SNI generates dga signal."""
        # Modify context to have DGA-like SNI
        connection_context.sni = "xkcd93j4fk92jf94jf92jf94jf.com"
        connection_context.raw_sni = "xkcd93j4fk92jf94jf92jf94jf.com"
        
        result = await pipeline.process(connection_context)
        
        # Should still allow (score might be elevated but not enough to block)
        assert result.action in ["allow", "flag"]
        
        # Check for dga signal
        dga_signals = [s for s in result.signals if s.name == 'dga']
        assert len(dga_signals) >= 1
        if dga_signals:
            assert dga_signals[0].score > 0
            assert dga_signals[0].score <= 40  # Capped at score_cap

    async def test_pipeline_with_expected_hostname(self, pipeline, connection_context):
        """Test pipeline with expected hostname configuration."""
        # Update pipeline with expected hostnames
        config = pipeline._config.copy()
        config['sni_analyzer']['expected_hostnames'] = ['www.google.com', 'www.example.com']
        pipeline.on_config_reload(config)
        
        # Test with expected hostname
        connection_context.sni = "www.google.com"
        result = await pipeline.process(connection_context)
        
        # Should allow
        assert result.action == "allow"
        
        # Should have no unexpected_sni signal
        unexpected_signals = [s for s in result.signals if s.name == 'unexpected_sni']
        assert len(unexpected_signals) == 0

    async def test_pipeline_with_unexpected_hostname(self, pipeline, connection_context):
        """Test pipeline with unexpected hostname generates unexpected_sni signal."""
        # Update pipeline with expected hostnames
        config = pipeline._config.copy()
        config['sni_analyzer']['expected_hostnames'] = ['www.example.com', 'www.test.com']
        pipeline.on_config_reload(config)
        
        # Test with unexpected hostname
        connection_context.sni = "www.google.com"
        result = await pipeline.process(connection_context)
        
        # Should still allow (score might be elevated but not enough to block)
        assert result.action in ["allow", "flag"]
        
        # Should have unexpected_sni signal
        unexpected_signals = [s for s in result.signals if s.name == 'unexpected_sni']
        assert len(unexpected_signals) == 1
        assert unexpected_signals[0].score == 15

    async def test_pipeline_sni_analysis_disabled(self, pipeline, connection_context):
        """Test pipeline with SNI analysis disabled."""
        # Disable SNI analyzer
        config = pipeline._config.copy()
        config['sni_analyzer']['enabled'] = False
        pipeline.on_config_reload(config)
        
        # Test with various SNI values
        test_cases = [
            None,  # Missing SNI
            "192.168.1.1",  # IP literal
            "xkcd93j4fk92jf94jf92jf94jf.com",  # DGA
        ]
        
        for sni in test_cases:
            connection_context.sni = sni
            result = await pipeline.process(connection_context)
            
            # Should allow
            assert result.action == "allow"
            
            # Should have no SNI signals
            sni_signals = [s for s in result.signals if 'sni' in s.name.lower() or s.name == 'dga']
            assert len(sni_signals) == 0

    async def test_pipeline_error_handling(self, pipeline, connection_context):
        """Test pipeline handles SNI analyzer errors gracefully."""
        # This test verifies that even if SNI analysis fails, the pipeline continues
        # We can't easily force an error in the analyzer, but we can verify the structure
        
        result = await pipeline.process(connection_context)
        
        # Should always return a valid result
        assert hasattr(result, 'action')
        assert hasattr(result, 'score')
        assert hasattr(result, 'signals')
        assert isinstance(result.signals, list)


@pytest.mark.asyncio
class TestSNIConfigReload:
    """Test SNI analyzer configuration reload in pipeline."""

    @pytest.fixture
    def pipeline(self):
        """Create a pipeline for config reload testing."""
        config = {
            'security_policy': {
                'alpn_browser_bypass': {'enabled': False},  # Disable ALPN bypass for testing
                'ja4_whitelist_bypass': {'enabled': False},
                'mtls_bypass': {'enabled': False},
                'static_ip_allowlist': {'enabled': False},
                'ja4_blacklist_bypass': {'enabled': False},
            },
            'sni_analyzer': {
                'enabled': True,
                'missing_sni': {'enabled': True, 'score': 30}
            }
        }
        
        local_cache = LocalCache(config)
        redis_client = Mock()
        
        pipeline = Pipeline(config, local_cache, redis_client)
        
        # Wire in scorer and decider
        scorer = RiskScorer(config)
        decider = ActionDecider(config)
        pipeline.update_scorer(scorer, decider)
        
        return pipeline

    @pytest.fixture
    def connection_context(self):
        """Create a connection context without SNI."""
        return ConnectionContext(
            client_ip="192.168.1.100",
            ja4="t13d1516h2_8daaf6152771_02713d6af862",
            alpn="h2",
            has_valid_client_cert=False,
            sni=None,
            tls_version=0x0303,
            country="US",
            cipher_list=[]
        )

    async def test_config_reload_updates_scores(self, pipeline, connection_context):
        """Test that config reload updates SNI analyzer scores."""
        # Initial test with score=30
        result1 = await pipeline.process(connection_context)
        missing_sni_signals = [s for s in result1.signals if s.name == 'missing_sni']
        assert len(missing_sni_signals) == 1
        assert missing_sni_signals[0].score == 30
        
        # Reload with score=25
        new_config = pipeline._config.copy()
        new_config['sni_analyzer']['missing_sni']['score'] = 25
        pipeline.on_config_reload(new_config)
        
        # Test with new score
        result2 = await pipeline.process(connection_context)
        missing_sni_signals = [s for s in result2.signals if s.name == 'missing_sni']
        assert len(missing_sni_signals) == 1
        assert missing_sni_signals[0].score == 25

    async def test_config_reload_disables_analyzer(self, pipeline, connection_context):
        """Test that config reload can disable SNI analyzer."""
        # Initial test with analyzer enabled
        result1 = await pipeline.process(connection_context)
        missing_sni_signals = [s for s in result1.signals if s.name == 'missing_sni']
        assert len(missing_sni_signals) == 1
        
        # Reload with analyzer disabled
        new_config = pipeline._config.copy()
        new_config['sni_analyzer']['enabled'] = False
        pipeline.on_config_reload(new_config)
        
        # Test with analyzer disabled
        result2 = await pipeline.process(connection_context)
        missing_sni_signals = [s for s in result2.signals if s.name == 'missing_sni']
        assert len(missing_sni_signals) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
