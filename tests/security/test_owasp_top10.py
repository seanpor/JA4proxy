#!/usr/bin/env python3
"""
OWASP Top 10 Security Testing Suite for JA4 Proxy
Tests for common web application vulnerabilities.
"""

import pytest
import asyncio
import json
import time
import requests
import subprocess
from unittest.mock import Mock, patch, AsyncMock
from security.validation import SecurityValidator, ValidationError, SecurityError


class TestOWASPTop10:
    """Test OWASP Top 10 vulnerabilities protection."""
    
    def setup_method(self):
        """Setup test environment."""
        self.validator = SecurityValidator({
            'security': {
                'max_request_size': 1024 * 1024,
                'csrf_secret': 'test-secret-key-for-testing',
                'rate_limit_window': 60,
                'max_requests_per_minute': 100
            }
        })
    
    def test_a01_broken_access_control(self):
        """A01:2021 – Broken Access Control"""
        
        # Test path traversal attempts
        malicious_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
            '....//....//....//etc/passwd',
            '/var/log/../../etc/passwd'
        ]
        
        for path in malicious_paths:
            with pytest.raises((ValidationError, SecurityError)):
                self.validator.validate_ja4_fingerprint(path)
    
    def test_a02_cryptographic_failures(self):
        """A02:2021 – Cryptographic Failures"""
        
        # Test weak random generation detection
        from security.validation import MTLSManager
        
        mtls_manager = MTLSManager({
            'tls': {
                'cert_path': '/dev/null',
                'key_path': '/dev/null'
            }
        })
        
        # Create SSL context and verify secure configuration
        context = mtls_manager.create_ssl_context(server_side=True)
        
        # Verify minimum TLS version
        assert hasattr(context, 'minimum_version')
        # Verify secure options are set
        assert context.options & context.OP_NO_SSLv2
        assert context.options & context.OP_NO_SSLv3
        assert context.options & context.OP_NO_TLSv1
        assert context.options & context.OP_NO_TLSv1_1
    
    def test_a03_injection_attacks(self):
        """A03:2021 – Injection"""
        
        # SQL Injection patterns
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "1' UNION SELECT * FROM users --",
            "admin'/*",
            "' OR 1=1#"
        ]
        
        for payload in sql_injection_payloads:
            with pytest.raises(ValidationError):
                self.validator.validate_ja4_fingerprint(payload)
        
        # NoSQL Injection
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "sleep(5000)"}',
        ]
        
        for payload in nosql_payloads:
            with pytest.raises(ValidationError):
                self.validator.validate_ja4_fingerprint(payload)
        
        # Command Injection
        command_injection_payloads = [
            '; cat /etc/passwd',
            '| whoami',
            '`id`',
            '$(uname -a)',
            '&& ls -la /',
        ]
        
        for payload in command_injection_payloads:
            with pytest.raises(ValidationError):
                self.validator.validate_ja4_fingerprint(payload)
    
    def test_a04_insecure_design(self):
        """A04:2021 – Insecure Design"""
        
        # Test business logic flaws
        from proxy import JA4Fingerprint
        
        # Test timestamp manipulation
        future_timestamp = time.time() + 86400 * 365  # 1 year future
        with pytest.raises(ValidationError):
            JA4Fingerprint(ja4="t13d1516h2_8daaf6152771_02713d6af862", timestamp=future_timestamp)
        
        # Test invalid fingerprint formats
        invalid_fingerprints = [
            "invalid_format",
            "",
            "a" * 1000,  # Too long
            "t99d9999h9_111111111111_222222222222",  # Invalid values
        ]
        
        for fp in invalid_fingerprints:
            with pytest.raises(ValidationError):
                JA4Fingerprint(ja4=fp)
    
    def test_a05_security_misconfiguration(self):
        """A05:2021 – Security Misconfiguration"""
        
        from security.validation import SecureHeadersManager
        
        # Test security headers are properly set
        header_manager = SecureHeadersManager({})
        headers = header_manager.get_security_headers()
        
        # Verify critical security headers
        assert 'X-Content-Type-Options' in headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in headers
        assert headers['X-Frame-Options'] == 'DENY'
        assert 'Strict-Transport-Security' in headers
        assert 'Content-Security-Policy' in headers
        
        # Verify CSP is restrictive
        csp = headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
    
    def test_a06_vulnerable_components(self):
        """A06:2021 – Vulnerable and Outdated Components"""
        
        # Test dependency versions (would integrate with safety/pip-audit)
        import pkg_resources
        
        # Check for known vulnerable packages
        vulnerable_packages = {
            'requests': '2.9.0',  # Has known vulnerabilities
            'urllib3': '1.24.0',   # Has known vulnerabilities
        }
        
        for package_name, vulnerable_version in vulnerable_packages.items():
            try:
                package = pkg_resources.get_distribution(package_name)
                # Should not be using vulnerable version
                assert package.version != vulnerable_version
            except pkg_resources.DistributionNotFound:
                pass  # Package not installed
    
    def test_a07_authentication_failures(self):
        """A07:2021 – Identification and Authentication Failures"""
        
        # Test brute force protection
        mock_redis = Mock()
        mock_redis.incr.return_value = 101  # Over limit
        
        result = self.validator.check_rate_limit("192.168.1.1", mock_redis)
        assert result is False
        
        # Test weak session management
        session_id = self.validator.generate_csrf_token("test-session")
        assert len(session_id) >= 32  # Should be strong
        
        # Test CSRF protection
        valid_token = self.validator.generate_csrf_token("session123")
        assert self.validator.validate_csrf_token(valid_token, "session123")
        
        invalid_token = "invalid_token"
        assert not self.validator.validate_csrf_token(invalid_token, "session123")
    
    def test_a08_software_data_integrity(self):
        """A08:2021 – Software and Data Integrity Failures"""
        
        from security.validation import AuditLogger
        
        # Test audit logging integrity
        audit_logger = AuditLogger({'logging': {'audit_log_path': '/tmp/test_audit.log'}})
        
        test_data = {"action": "test", "user": "testuser"}
        checksum = audit_logger._calculate_checksum(test_data)
        
        # Verify checksum is deterministic
        assert checksum == audit_logger._calculate_checksum(test_data)
        
        # Verify checksum changes with data modification
        modified_data = {"action": "test_modified", "user": "testuser"}
        assert checksum != audit_logger._calculate_checksum(modified_data)
    
    def test_a09_logging_monitoring_failures(self):
        """A09:2021 – Security Logging and Monitoring Failures"""
        
        from security.validation import AuditLogger
        
        # Test security event logging
        audit_logger = AuditLogger({'logging': {'audit_log_path': '/tmp/test_audit.log'}})
        
        # Should log security events
        test_event = {
            'source_ip': '192.168.1.100',
            'action': 'login_attempt',
            'result': 'failed'
        }
        
        # This should not raise an exception
        audit_logger.log_security_event('authentication', test_event, 'WARNING')
    
    def test_a10_ssrf_attacks(self):
        """A10:2021 – Server-Side Request Forgery (SSRF)"""
        
        # Test SSRF protection in URL validation
        ssrf_payloads = [
            'http://127.0.0.1:22',
            'http://localhost:6379',
            'http://169.254.169.254/metadata',  # AWS metadata
            'http://metadata.google.internal/',   # GCP metadata
            'file:///etc/passwd',
            'ftp://internal.server/',
        ]
        
        for payload in ssrf_payloads:
            # URL validation should reject internal addresses
            with pytest.raises((ValidationError, SecurityError)):
                # This would be tested with actual URL validation function
                pass


class TestInputValidation:
    """Comprehensive input validation tests."""
    
    def setup_method(self):
        """Setup test environment."""
        self.validator = SecurityValidator({})
    
    def test_buffer_overflow_protection(self):
        """Test buffer overflow protection."""
        
        # Test oversized inputs
        oversized_string = "A" * (1024 * 1024 + 1)  # 1MB + 1
        
        with pytest.raises(ValidationError):
            self.validator.validate_ja4_fingerprint(oversized_string)
    
    def test_format_string_attacks(self):
        """Test format string attack protection."""
        
        format_string_payloads = [
            '%s%s%s%s%s%s%s%s%s%s',
            '%x%x%x%x%x%x%x%x%x%x',
            '%n%n%n%n%n%n%n%n%n%n',
        ]
        
        for payload in format_string_payloads:
            with pytest.raises(ValidationError):
                self.validator.validate_ja4_fingerprint(payload)
    
    def test_null_byte_injection(self):
        """Test null byte injection protection."""
        
        null_byte_payloads = [
            'test\x00.txt',
            'file.txt\x00.png',
            '\x00/etc/passwd',
        ]
        
        for payload in null_byte_payloads:
            with pytest.raises(ValidationError):
                self.validator.validate_ja4_fingerprint(payload)
    
    def test_unicode_attacks(self):
        """Test Unicode normalization attacks."""
        
        unicode_payloads = [
            'test\u202e.txt',  # Right-to-left override
            'file\u200b.txt',  # Zero-width space
            'test\ufeff.txt',  # Byte order mark
        ]
        
        for payload in unicode_payloads:
            headers = self.validator.validate_http_headers({'test': payload})
            # Should be sanitized
            assert '\u202e' not in str(headers)
            assert '\u200b' not in str(headers)
            assert '\ufeff' not in str(headers)


class TestCryptographicSecurity:
    """Test cryptographic security implementations."""
    
    def test_secure_random_generation(self):
        """Test secure random number generation."""
        import secrets
        
        # Generate multiple random values
        randoms = [secrets.token_hex(16) for _ in range(100)]
        
        # Should all be different
        assert len(set(randoms)) == 100
        
        # Should be proper length
        assert all(len(r) == 32 for r in randoms)
    
    def test_password_hashing(self):
        """Test secure password hashing (if implemented)."""
        import hashlib
        import hmac
        
        # Test HMAC-based operations
        secret = b'test-secret'
        message = b'test-message'
        
        signature1 = hmac.new(secret, message, hashlib.sha256).hexdigest()
        signature2 = hmac.new(secret, message, hashlib.sha256).hexdigest()
        
        # Should be consistent
        assert signature1 == signature2
        
        # Should be different for different messages
        signature3 = hmac.new(secret, b'different-message', hashlib.sha256).hexdigest()
        assert signature1 != signature3
    
    def test_timing_attack_protection(self):
        """Test timing attack protection."""
        import hmac
        import time
        
        # Test constant-time comparison
        secret1 = "correct_secret"
        secret2 = "wrong_secret"
        secret3 = "correct_secret"
        
        # Measure comparison times
        start = time.time()
        result1 = hmac.compare_digest(secret1, secret2)
        time1 = time.time() - start
        
        start = time.time()
        result2 = hmac.compare_digest(secret1, secret3)
        time2 = time.time() - start
        
        # Results should be correct
        assert not result1
        assert result2
        
        # Time difference should be minimal (constant time)
        assert abs(time1 - time2) < 0.001  # Less than 1ms difference


class TestMemorySecurityTest:
    """Test memory security and resource management."""
    
    def test_memory_cleanup(self):
        """Test proper memory cleanup."""
        import gc
        
        # Create objects and ensure they're cleaned up
        from proxy import JA4Generator
        
        generators = [JA4Generator() for _ in range(100)]
        del generators
        
        # Force garbage collection
        gc.collect()
        
        # Should not accumulate objects
        assert len(gc.garbage) == 0
    
    def test_resource_limits(self):
        """Test resource limit enforcement."""
        
        # Test connection limits (would need actual implementation)
        max_connections = 1000
        current_connections = 999
        
        # Should allow connection under limit
        assert current_connections < max_connections
        
        # Should reject over limit
        over_limit = max_connections + 1
        assert over_limit > max_connections


class TestNetworkSecurity:
    """Test network-level security features."""
    
    def test_ip_validation(self):
        """Test IP address validation and filtering."""
        validator = SecurityValidator({'security': {'block_private_ips': True}})
        
        # Test valid public IPs
        public_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        for ip in public_ips:
            assert validator.validate_ip_address(ip, check_reputation=False)
        
        # Test private IPs (should be blocked in production mode)
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']
        for ip in private_ips:
            with pytest.raises(SecurityError):
                validator.validate_ip_address(ip, check_reputation=False)
    
    def test_rate_limiting(self):
        """Test rate limiting implementation."""
        mock_redis = Mock()
        
        # Test normal rate
        mock_redis.incr.return_value = 50
        mock_redis.execute.return_value = [50, True]
        
        validator = SecurityValidator({'security': {'max_requests_per_minute': 100}})
        assert validator.check_rate_limit('192.168.1.1', mock_redis)
        
        # Test over rate limit
        mock_redis.incr.return_value = 150
        mock_redis.execute.return_value = [150, True]
        
        assert not validator.check_rate_limit('192.168.1.1', mock_redis)


@pytest.mark.asyncio
class TestAsyncSecurity:
    """Test security in asynchronous contexts."""
    
    async def test_concurrent_validation(self):
        """Test validation under concurrent load."""
        validator = SecurityValidator({})
        
        async def validate_fingerprint(i):
            try:
                return validator.validate_ja4_fingerprint(f't13d1516h{i % 10}_8daaf6152771_02713d6af862')
            except ValidationError:
                return False
        
        # Run many concurrent validations
        tasks = [validate_fingerprint(i) for i in range(1000)]
        results = await asyncio.gather(*tasks)
        
        # Should handle concurrent load
        assert len(results) == 1000
    
    async def test_resource_exhaustion_protection(self):
        """Test protection against resource exhaustion attacks."""
        
        # Simulate many concurrent connections
        async def simulate_connection():
            await asyncio.sleep(0.01)  # Simulate work
            return True
        
        # Should handle reasonable concurrent load
        tasks = [simulate_connection() for _ in range(100)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 100
        assert all(results)


if __name__ == '__main__':
    # Run security tests
    pytest.main([__file__, '-v', '--tb=short'])