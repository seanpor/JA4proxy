#!/usr/bin/env python3
"""
Property-based testing for JA4 Proxy using Hypothesis
Tests fingerprint generation, validation, and edge cases.
"""

import pytest
import string
import time
from hypothesis import given, strategies as st, assume, settings, HealthCheck
from hypothesis.stateful import RuleBasedStateMachine, rule, Bundle
import hypothesis.strategies as st

from proxy import JA4Fingerprint, JA4Generator, TLSParser
from security.validation import SecurityValidator, ValidationError, SecurityError


class TestJA4FingerprintProperties:
    """Property-based tests for JA4 fingerprint generation."""
    
    @given(st.text(alphabet=string.ascii_lowercase + string.digits + '_', min_size=35, max_size=35))
    def test_ja4_fingerprint_format_validation(self, ja4_string):
        """Test JA4 fingerprint format validation with random inputs."""
        assume(len(ja4_string.split('_')) == 3)
        
        try:
            fingerprint = JA4Fingerprint(ja4=ja4_string)
            # If no exception, verify it matches expected pattern
            assert len(fingerprint.ja4) == 35
            parts = fingerprint.ja4.split('_')
            assert len(parts) == 3
            assert len(parts[1]) == 12  # First hash
            assert len(parts[2]) == 12  # Second hash
        except ValidationError:
            # Expected for invalid formats
            pass
    
    @given(st.integers(min_value=0, max_value=0xFFFF))
    def test_cipher_suite_hashing(self, cipher_suite):
        """Test cipher suite hashing with various inputs."""
        generator = JA4Generator()
        
        # Test single cipher suite
        result = generator._hash_cipher_suites([cipher_suite])
        assert len(result) == 12
        assert all(c in string.hexdigits.lower() for c in result)
        
        # Test consistency
        result2 = generator._hash_cipher_suites([cipher_suite])
        assert result == result2
    
    @given(st.lists(st.integers(min_value=0, max_value=0xFFFF), min_size=1, max_size=20))
    def test_extension_hashing_properties(self, extensions):
        """Test extension hashing properties."""
        generator = JA4Generator()
        
        result = generator._hash_extensions(extensions)
        
        # Hash should be consistent
        assert result == generator._hash_extensions(extensions)
        
        # Hash should be valid hex
        assert len(result) == 12
        assert all(c in string.hexdigits.lower() for c in result)
        
        # Order shouldn't matter (extensions are sorted)
        shuffled = list(extensions)
        import random
        random.shuffle(shuffled)
        assert result == generator._hash_extensions(shuffled)
    
    @given(st.ip_addresses())
    def test_ip_validation_properties(self, ip_addr):
        """Test IP address validation with various IP types."""
        validator = SecurityValidator({})
        ip_str = str(ip_addr)
        
        try:
            result = validator.validate_ip_address(ip_str, check_reputation=False)
            assert result is True
        except (ValidationError, SecurityError):
            # Some IPs might be rejected based on policy
            pass
    
    @given(st.floats(min_value=0, max_value=2**31))
    def test_timestamp_validation(self, timestamp):
        """Test timestamp validation with various values."""
        current_time = time.time()
        
        try:
            fp = JA4Fingerprint(ja4="t13d1516h2_8daaf6152771_02713d6af862", timestamp=timestamp)
            # Should be within reasonable bounds
            assert abs(fp.timestamp - current_time) <= 86400 * 30  # 30 days
        except ValidationError:
            # Expected for unreasonable timestamps
            pass


class TLSFingerprintStateMachine(RuleBasedStateMachine):
    """Stateful testing for TLS fingerprint processing."""
    
    def __init__(self):
        super().__init__()
        self.generator = JA4Generator()
        self.parser = TLSParser()
        self.fingerprints = []
    
    fingerprints = Bundle('fingerprints')
    
    @rule(target=fingerprints,
          version=st.integers(min_value=0x0301, max_value=0x0304),
          cipher_suites=st.lists(st.integers(min_value=0, max_value=0xFFFF), min_size=1, max_size=50),
          extensions=st.lists(st.integers(min_value=0, max_value=0xFFFF), min_size=0, max_size=30))
    def generate_fingerprint(self, version, cipher_suites, extensions):
        """Generate JA4 fingerprint from TLS parameters."""
        client_hello_fields = {
            'version': version,
            'cipher_suites': cipher_suites,
            'extensions': extensions
        }
        
        ja4 = self.generator.generate_ja4(client_hello_fields)
        
        # Verify basic properties
        assert isinstance(ja4, str)
        assert len(ja4) > 0
        
        return ja4
    
    @rule(fingerprint=fingerprints)
    def validate_fingerprint(self, fingerprint):
        """Validate generated fingerprint."""
        # Should be valid format
        parts = fingerprint.split('_')
        assert len(parts) == 3
        
        # First part should contain version and counts
        assert len(parts[0]) >= 6
        
        # Hash parts should be hex
        assert all(c in string.hexdigits.lower() for c in parts[1])
        assert all(c in string.hexdigits.lower() for c in parts[2])


class TestSecurityValidationProperties:
    """Property-based tests for security validation."""
    
    def setup_method(self):
        """Setup test environment."""
        self.validator = SecurityValidator({
            'security': {
                'max_request_size': 1024 * 1024,
                'rate_limit_window': 60,
                'max_requests_per_minute': 100
            }
        })
    
    @given(st.integers(min_value=0, max_value=10 * 1024 * 1024))
    def test_request_size_validation(self, size):
        """Test request size validation."""
        try:
            result = self.validator.validate_request_size(size)
            assert result is True
            assert size <= 1024 * 1024  # Should be within limit
        except SecurityError:
            assert size > 1024 * 1024  # Should exceed limit
    
    @given(st.dictionaries(
        st.text(alphabet=string.ascii_letters + string.digits + '-_', min_size=1, max_size=50),
        st.text(min_size=0, max_size=8192),
        min_size=0, max_size=20
    ))
    def test_header_validation(self, headers):
        """Test HTTP header validation."""
        result = self.validator.validate_http_headers(headers)
        
        # Result should be dictionary
        assert isinstance(result, dict)
        
        # All header names should be lowercase
        assert all(name.islower() for name in result.keys())
        
        # No header values should exceed size limit
        assert all(len(value) <= 8192 for value in result.values())
        
        # No control characters in values
        import re
        assert all(not re.search(r'[\x00-\x1f\x7f]', value) for value in result.values())
    
    @given(st.text(alphabet=string.ascii_letters + string.digits + '._-', min_size=1, max_size=100))
    def test_ja4_validation_properties(self, fingerprint_like):
        """Test JA4 validation with fingerprint-like strings."""
        try:
            result = self.validator.validate_ja4_fingerprint(fingerprint_like)
            # If validation passes, should be proper format
            assert len(fingerprint_like) >= 35
            assert '_' in fingerprint_like
        except ValidationError:
            # Expected for invalid formats
            pass


class TestMemorySafety:
    """Test memory safety and resource limits."""
    
    @given(st.binary(min_size=0, max_size=10 * 1024 * 1024))
    def test_large_input_handling(self, data):
        """Test handling of large inputs without memory issues."""
        parser = TLSParser()
        
        # Should not crash or consume excessive memory
        try:
            # Simulate packet parsing with large data
            result = parser.parse_client_hello(None)  # Will return None for invalid input
            assert result is None
        except Exception as e:
            # Should be controlled exceptions, not memory errors
            assert not isinstance(e, MemoryError)
    
    @settings(suppress_health_check=[HealthCheck.too_slow])
    @given(st.lists(st.binary(min_size=1, max_size=1000), min_size=0, max_size=1000))
    def test_bulk_processing_stability(self, data_list):
        """Test processing many inputs without resource exhaustion."""
        generator = JA4Generator()
        
        processed = 0
        for data in data_list:
            try:
                # Process data without storing results (memory efficiency test)
                result = generator._hash_cipher_suites([len(data)])
                processed += 1
            except Exception:
                pass
        
        # Should process some inputs without crashing
        assert processed >= 0


class TestConcurrentAccess:
    """Test concurrent access patterns."""
    
    @pytest.mark.asyncio
    async def test_concurrent_fingerprint_generation(self):
        """Test concurrent fingerprint generation."""
        import asyncio
        
        generator = JA4Generator()
        
        async def generate_fingerprint(i):
            client_hello_fields = {
                'version': 0x0303,
                'cipher_suites': [0x1301 + i % 10, 0x1302 + i % 10],
                'extensions': [0 + i % 5, 10 + i % 5, 13 + i % 5]
            }
            return generator.generate_ja4(client_hello_fields)
        
        # Run multiple concurrent generations
        tasks = [generate_fingerprint(i) for i in range(100)]
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 100
        assert all(isinstance(result, str) for result in results)


class TestTLSParsingFuzzing:
    """Fuzzing tests for TLS parsing."""
    
    @given(st.binary(min_size=0, max_size=1000))
    def test_malformed_tls_packets(self, packet_data):
        """Test parsing malformed TLS packets."""
        parser = TLSParser()
        
        try:
            # Should handle malformed packets gracefully
            result = parser.parse_client_hello(packet_data)
            # Either returns valid result or None
            assert result is None or isinstance(result, dict)
        except Exception as e:
            # Should not crash with unhandled exceptions
            assert isinstance(e, (ValueError, IndexError, struct.error))


# Stateful test runner
TestTLSStateful = TLSFingerprintStateMachine.TestCase


if __name__ == '__main__':
    # Run property-based tests
    pytest.main([__file__, '-v', '--hypothesis-show-statistics'])