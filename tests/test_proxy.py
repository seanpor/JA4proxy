#!/usr/bin/env python3
"""
Comprehensive test suite for JA4 Proxy
"""

import pytest
import asyncio
import hashlib
import time
from unittest.mock import Mock, patch, AsyncMock
import redis
from proxy import (
    JA4Fingerprint, TLSParser, JA4Generator, ConfigManager, 
    SecurityManager, TarpitManager, ProxyServer
)


class TestJA4Fingerprint:
    """Test JA4Fingerprint data structure."""
    
    def test_fingerprint_creation(self):
        """Test basic fingerprint creation."""
        fp = JA4Fingerprint(
            ja4="t13d1516h2_8daaf6152771_02713d6af862",
            ja4s="t130200_1302_a56c586dc9d7",
            source_ip="192.168.1.100",
            timestamp=time.time()
        )
        
        assert fp.ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
        assert fp.source_ip == "192.168.1.100"
        assert fp.timestamp > 0
    
    def test_fingerprint_defaults(self):
        """Test fingerprint with default values."""
        fp = JA4Fingerprint(ja4="test_fingerprint")
        
        assert fp.ja4 == "test_fingerprint"
        assert fp.ja4s is None
        assert fp.client_hello_hash == ""
        assert fp.timestamp == 0.0


class TestTLSParser:
    """Test TLS packet parsing functionality."""
    
    def setUp(self):
        self.parser = TLSParser()
    
    @patch('proxy.IP')
    def test_parse_client_hello_no_tls(self, mock_ip):
        """Test parsing packet without TLS layer."""
        mock_packet = Mock()
        mock_packet.haslayer.return_value = False
        mock_ip.return_value = mock_packet
        
        result = self.parser.parse_client_hello(mock_packet)
        assert result is None
    
    def test_extract_client_hello_fields(self):
        """Test extraction of Client Hello fields."""
        mock_client_hello = Mock()
        mock_client_hello.version = 0x0303  # TLS 1.2
        mock_client_hello.cipher_suites = [0x1301, 0x1302, 0x1303]
        
        mock_ext = Mock()
        mock_ext.type = 10
        mock_ext.elliptic_curves = [23, 24, 25]
        mock_client_hello.ext = [mock_ext]
        
        fields = self.parser._extract_client_hello_fields(mock_client_hello)
        
        assert fields['version'] == 0x0303
        assert fields['cipher_suites'] == [0x1301, 0x1302, 0x1303]
        assert fields['extensions'] == [10]
        assert fields['supported_groups'] == [23, 24, 25]


class TestJA4Generator:
    """Test JA4 fingerprint generation."""
    
    def setUp(self):
        self.generator = JA4Generator()
    
    def test_generate_ja4_basic(self):
        """Test basic JA4 generation."""
        client_hello_fields = {
            'version': 0x0303,
            'cipher_suites': [0x1301, 0x1302],
            'extensions': [0, 10, 13, 43],
            'supported_groups': [23, 24, 25],
            'signature_algorithms': [0x0401, 0x0501],
            'supported_versions': [0x0304]
        }
        
        ja4 = self.generator.generate_ja4(client_hello_fields)
        
        assert ja4.startswith('t12d')
        assert len(ja4.split('_')) == 3
    
    def test_get_version_string(self):
        """Test TLS version string conversion."""
        assert self.generator._get_version_string(0x0301) == "10"
        assert self.generator._get_version_string(0x0302) == "11"
        assert self.generator._get_version_string(0x0303) == "12"
        assert self.generator._get_version_string(0x0304) == "13"
        assert self.generator._get_version_string(0x9999) == "00"
    
    def test_hash_cipher_suites(self):
        """Test cipher suite hashing."""
        cipher_suites = [0x1301, 0x1302, 0x1303]
        result = self.generator._hash_cipher_suites(cipher_suites)
        
        assert len(result) == 12
        assert result.isalnum()
    
    def test_hash_extensions(self):
        """Test extension hashing."""
        extensions = [10, 13, 43, 51]
        result = self.generator._hash_extensions(extensions)
        
        assert len(result) == 12
        assert result.isalnum()
    
    def test_is_grease(self):
        """Test GREASE value detection."""
        assert self.generator._is_grease(0x0a0a)
        assert self.generator._is_grease(0x1a1a)
        assert not self.generator._is_grease(0x1301)


class TestConfigManager:
    """Test configuration management."""
    
    @patch('builtins.open')
    @patch('yaml.safe_load')
    def test_load_config_success(self, mock_yaml_load, mock_open):
        """Test successful config loading."""
        mock_config = {'proxy': {'bind_port': 8080}}
        mock_yaml_load.return_value = mock_config
        
        manager = ConfigManager("test.yml")
        
        assert manager.config == mock_config
        mock_open.assert_called_once_with("test.yml", 'r')
    
    @patch('builtins.open', side_effect=FileNotFoundError())
    def test_load_config_file_not_found(self, mock_open):
        """Test config loading with missing file."""
        manager = ConfigManager("missing.yml")
        
        assert 'proxy' in manager.config
        assert manager.config['proxy']['bind_port'] == 8080
    
    def test_default_config(self):
        """Test default configuration values."""
        manager = ConfigManager("nonexistent.yml")
        config = manager.config
        
        assert config['proxy']['bind_host'] == '0.0.0.0'
        assert config['proxy']['bind_port'] == 8080
        assert config['redis']['host'] == 'localhost'
        assert config['security']['whitelist_enabled'] is True


class TestSecurityManager:
    """Test security policy enforcement."""
    
    def setUp(self):
        self.mock_redis = Mock()
        self.config = {
            'security': {
                'whitelist_enabled': True,
                'blacklist_enabled': True,
                'rate_limiting': True,
                'max_requests_per_minute': 100,
                'block_unknown_ja4': False
            }
        }
        self.security_manager = SecurityManager(self.config, self.mock_redis)
    
    def test_check_access_allowed(self):
        """Test access check for allowed fingerprint."""
        self.mock_redis.smembers.return_value = {b'allowed_fingerprint'}
        self.mock_redis.incr.return_value = 1
        
        fingerprint = JA4Fingerprint(ja4="allowed_fingerprint")
        allowed, reason = self.security_manager.check_access(fingerprint, "192.168.1.1")
        
        assert allowed is True
        assert reason == "Allowed"
    
    def test_check_access_blacklisted(self):
        """Test access check for blacklisted fingerprint."""
        self.security_manager.blacklist = {b'blocked_fingerprint'}
        
        fingerprint = JA4Fingerprint(ja4="blocked_fingerprint")
        allowed, reason = self.security_manager.check_access(fingerprint, "192.168.1.1")
        
        assert allowed is False
        assert reason == "JA4 blacklisted"
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        self.mock_redis.incr.return_value = 101  # Over limit
        
        result = self.security_manager._check_rate_limit("192.168.1.1")
        
        assert result is False


class TestTarpitManager:
    """Test TARPIT functionality."""
    
    def setUp(self):
        self.config = {
            'security': {
                'tarpit_enabled': True,
                'tarpit_duration': 5
            }
        }
        self.tarpit_manager = TarpitManager(self.config)
    
    @pytest.mark.asyncio
    async def test_tarpit_connection_enabled(self):
        """Test TARPIT delay when enabled."""
        mock_writer = AsyncMock()
        
        start_time = time.time()
        await self.tarpit_manager.tarpit_connection(mock_writer)
        duration = time.time() - start_time
        
        assert duration >= 4.9  # Allow for small timing variations
        mock_writer.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_tarpit_connection_disabled(self):
        """Test TARPIT when disabled."""
        self.config['security']['tarpit_enabled'] = False
        tarpit_manager = TarpitManager(self.config)
        
        mock_writer = AsyncMock()
        
        start_time = time.time()
        await tarpit_manager.tarpit_connection(mock_writer)
        duration = time.time() - start_time
        
        assert duration < 1.0  # Should return quickly


@pytest.mark.asyncio
class TestProxyServer:
    """Test main proxy server functionality."""
    
    def setUp(self):
        with patch('proxy.ConfigManager') as mock_config_manager:
            mock_config_manager.return_value.config = {
                'proxy': {
                    'bind_host': '127.0.0.1',
                    'bind_port': 8080,
                    'backend_host': '127.0.0.1',
                    'backend_port': 80,
                    'buffer_size': 8192,
                    'connection_timeout': 30
                },
                'redis': {
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0,
                    'password': None,
                    'timeout': 5
                },
                'security': {
                    'rate_limiting': True,
                    'max_requests_per_minute': 100
                },
                'metrics': {'enabled': True, 'port': 9090},
                'logging': {'level': 'INFO', 'format': '%(message)s'}
            }
            
            with patch('proxy.redis.Redis'), \
                 patch('proxy.logging.getLogger'):
                self.proxy_server = ProxyServer()
    
    async def test_analyze_tls_handshake(self):
        """Test TLS handshake analysis."""
        test_data = b"test_tls_data"
        client_ip = "192.168.1.100"
        
        with patch.object(self.proxy_server.tls_parser, 'parse_client_hello') as mock_parse, \
             patch.object(self.proxy_server.ja4_generator, 'generate_ja4') as mock_generate, \
             patch.object(self.proxy_server, '_store_fingerprint') as mock_store:
            
            mock_parse.return_value = {'version': 0x0303}
            mock_generate.return_value = "test_ja4_fingerprint"
            
            fingerprint = await self.proxy_server._analyze_tls_handshake(test_data, client_ip)
            
            assert fingerprint.ja4 == "test_ja4_fingerprint"
            assert fingerprint.source_ip == client_ip
            mock_store.assert_called_once()
    
    async def test_store_fingerprint(self):
        """Test fingerprint storage in Redis."""
        fingerprint = JA4Fingerprint(
            ja4="test_fingerprint",
            source_ip="192.168.1.100",
            timestamp=time.time(),
            client_hello_hash="abcd1234"
        )
        
        await self.proxy_server._store_fingerprint(fingerprint)
        
        # Verify Redis calls were made
        self.proxy_server.redis_client.hset.assert_called()
        self.proxy_server.redis_client.expire.assert_called()


class TestIntegration:
    """Integration tests for complete proxy functionality."""
    
    @pytest.mark.asyncio
    async def test_full_request_flow(self):
        """Test complete request processing flow."""
        # This would be a more complex integration test
        # Testing the full flow from connection to backend forwarding
        pass
    
    def test_redis_integration(self):
        """Test Redis integration."""
        # Test with actual Redis instance if available
        try:
            r = redis.Redis(host='localhost', port=6379, db=15)  # Use test DB
            r.ping()
            
            # Test whitelist/blacklist operations
            r.sadd('ja4:whitelist', 'test_fingerprint')
            assert b'test_fingerprint' in r.smembers('ja4:whitelist')
            
            # Cleanup
            r.delete('ja4:whitelist')
            
        except redis.ConnectionError:
            pytest.skip("Redis not available for integration testing")


if __name__ == "__main__":
    pytest.main(["-v", __file__])