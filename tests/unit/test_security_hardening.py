# Security Hardening Tests
# Phase 12d: Security Hardening

import json
import time
from unittest.mock import AsyncMock

import pytest

from src.analytics.security_hardening import (
    AuthenticationError,
    RateLimitExceededError,
    SecurityError,
    SecurityEvent,
    SecurityHardening,
)


@pytest.mark.asyncio
class TestSecurityHardening:
    """Test security hardening functionality."""
    
    async def test_rate_limiting(self):
        """Test rate limiting functionality."""
        mock_redis = AsyncMock()
        
        # Mock Redis pipeline
        mock_pipeline = AsyncMock()
        mock_pipeline.__aenter__.return_value = mock_pipeline
        mock_pipeline.__aexit__.return_value = None
        
        mock_redis.pipeline.return_value = mock_pipeline
        
        # Mock zcard responses
        def mock_zcard(key):
            if 'api_requests' in key:
                return 50  # Within limit
            elif 'auth_attempts' in key:
                return 10  # Exceeds limit
            return 0
        
        mock_redis.zcard.side_effect = mock_zcard
        
        config = {
            'security': {
                'rate_limiting': {
                    'api_requests': {'window': 60, 'limit': 100},
                    'auth_attempts': {'window': 300, 'limit': 5}
                }
            }
        }
        
        security = SecurityHardening(mock_redis, config)
        
        # Test API requests (should pass)
        result = await security.check_rate_limit('api_requests', 'test_ip')
        assert result == True
        
        # Test auth attempts (should fail)
        result = await security.check_rate_limit('auth_attempts', 'test_ip')
        assert result == False
    
    async def test_api_key_authentication(self):
        """Test API key authentication."""
        mock_redis = AsyncMock()
        
        config = {
            'security': {
                'authentication': {
                    'api_keys': {
                        'test-key-123': {
                            'user_id': 'test_user',
                            'role': 'analyst',
                            'last_ip': '192.168.1.1'
                        }
                    }
                }
            }
        }
        
        security = SecurityHardening(mock_redis, config)
        
        # Test valid API key
        result = await security.authenticate_api_key('test-key-123')
        assert result is not None
        assert result['user_id'] == 'test_user'
        assert result['role'] == 'analyst'
        
        # Test invalid API key
        result = await security.authenticate_api_key('invalid-key')
        assert result is None
    
    async def test_jwt_validation(self):
        """Test JWT token validation."""
        mock_redis = AsyncMock()
        
        config = {
            'security': {
                'authentication': {
                    'jwt_secret': 'test-secret-key'
                }
            }
        }
        
        security = SecurityHardening(mock_redis, config)
        
        # Create a valid JWT token (simplified format)
        import base64
        import json
        
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test_user", "exp": int(time.time()) + 3600}).encode()).decode().rstrip('=')
        data = f"{header}.{payload}"
        signature = security._generate_hmac_signature(data)
        
        valid_token = f"{data}.{signature}"
        
        # Test valid token
        result = await security.validate_jwt_token(valid_token)
        assert result is not None
        assert result['sub'] == 'test_user'
        
        # Test invalid token (wrong signature)
        invalid_token = f"{data}.wrong_signature"
        result = await security.validate_jwt_token(invalid_token)
        assert result is None
        
        # Test expired token
        expired_payload = base64.urlsafe_b64encode(json.dumps({"sub": "test_user", "exp": int(time.time()) - 3600}).encode()).decode().rstrip('=')
        expired_data = f"{header}.{expired_payload}"
        expired_signature = security._generate_hmac_signature(expired_data)
        expired_token = f"{expired_data}.{expired_signature}"
        
        result = await security.validate_jwt_token(expired_token)
        assert result is None
    
    async def test_input_validation(self):
        """Test input safety validation."""
        mock_redis = AsyncMock()
        
        config = {
            'security': {
                'max_input_size': 1000
            }
        }
        
        security = SecurityHardening(mock_redis, config)
        
        # Test valid input
        valid_data = {'name': 'test', 'value': 'hello world'}
        result = await security.validate_input_safety(valid_data)
        assert result == True
        
        # Test oversized input
        large_data = {'name': 'test', 'value': 'x' * 2000}
        result = await security.validate_input_safety(large_data)
        assert result == False
        
        # Test suspicious characters
        suspicious_data = {'name': 'test; rm -rf /', 'value': 'hello'}
        result = await security.validate_input_safety(suspicious_data)
        assert result == False
    
    async def test_suspicious_activity_detection(self):
        """Test suspicious activity detection."""
        mock_redis = AsyncMock()
        
        config = {}
        security = SecurityHardening(mock_redis, config)
        
        # Test normal request
        normal_request = {'action': 'get_status', 'source_ip': '192.168.1.1'}
        result = await security.check_suspicious_activity(normal_request)
        assert result == False
        
        # Test SQL injection attempt
        sql_injection = {'query': "SELECT * FROM users WHERE 1=1 --", 'source_ip': '192.168.1.1'}
        result = await security.check_suspicious_activity(sql_injection)
        assert result == True
        
        # Test XSS attempt
        xss_attempt = {'input': '<script>alert("XSS")</script>', 'source_ip': '192.168.1.1'}
        result = await security.check_suspicious_activity(xss_attempt)
        assert result == True
    
    async def test_security_audit_logging(self):
        """Test security event logging."""
        mock_redis = AsyncMock()
        
        config = {}
        security = SecurityHardening(mock_redis, config)
        
        # Create a test event
        test_event = SecurityEvent(
            event_type="authentication_success",
            severity="info",
            timestamp=time.time(),
            details={"user_id": "test_user"},
            source_ip="192.168.1.1"
        )
        
        # Log the event
        await security.log_security_event(test_event)
        
        # Verify Redis was called
        assert mock_redis.xadd.called
        assert mock_redis.zadd.called
    
    async def test_security_metrics(self):
        """Test security metrics retrieval."""
        mock_redis = AsyncMock()
        
        config = {}
        security = SecurityHardening(mock_redis, config)
        
        # Get security metrics
        metrics = await security.get_security_metrics()
        
        # Verify structure
        assert 'metrics' in metrics
        assert 'timestamp' in metrics
        assert 'status' in metrics
        assert metrics['status'] == 'active'
    
    async def test_security_event_dataclass(self):
        """Test SecurityEvent dataclass."""
        event = SecurityEvent(
            event_type="test_event",
            severity="high",
            timestamp=time.time(),
            details={"test": "data"},
            source_ip="192.168.1.1",
            user_agent="Test Agent"
        )
        
        assert event.event_type == "test_event"
        assert event.severity == "high"
        assert event.details == {"test": "data"}
        assert event.source_ip == "192.168.1.1"
        assert event.user_agent == "Test Agent"


@pytest.mark.asyncio
class TestSecurityIntegration:
    """Test security integration with monitoring system."""
    
    async def test_monitoring_system_security_integration(self):
        """Test security hardening integration with monitoring system."""
        from src.analytics.monitoring import MonitoringSystem
        
        mock_redis = AsyncMock()
        
        config = {
            'security': {
                'authentication': {
                    'api_keys': {
                        'test-api-key': {'user_id': 'test_user', 'role': 'admin'}
                    }
                },
                'rate_limiting': {
                    'api_requests': {'window': 60, 'limit': 100}
                }
            }
        }
        
        monitoring = MonitoringSystem(mock_redis, config)
        
        # Test API authentication
        result = await monitoring.check_api_authentication('test-api-key')
        assert result == True
        
        result = await monitoring.check_api_authentication('invalid-key')
        assert result == False
        
        # Test rate limiting
        result = await monitoring.check_rate_limit('api_requests', 'test_ip')
        assert result == True
        
        # Test input validation
        valid_data = {'name': 'test', 'value': 'hello'}
        result = await monitoring.validate_input_safety(valid_data)
        assert result == True
        
        # Test suspicious activity detection
        normal_request = {'action': 'get_status'}
        result = await monitoring.check_suspicious_activity(normal_request)
        assert result == False
        
        # Test security audit logs
        logs = await monitoring.get_security_audit_logs(10)
        assert isinstance(logs, list)
        
        # Test security metrics
        metrics = await monitoring.get_security_metrics()
        assert 'metrics' in metrics
        assert metrics['status'] == 'active'


@pytest.mark.asyncio
class TestSecurityErrorHandling:
    """Test security error handling."""
    
    async def test_security_error(self):
        """Test SecurityError exception."""
        with pytest.raises(SecurityError):
            raise SecurityError("Test security error")
    
    async def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError exception."""
        with pytest.raises(RateLimitExceededError):
            raise RateLimitExceededError("Rate limit exceeded")
    
    async def test_authentication_error(self):
        """Test AuthenticationError exception."""
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Authentication failed")


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestSecurityHardeningCoverageGaps:
    """Cover lines 73, 145, 169-174, 206-207, 300-302, 323-325.

    So what: these exception and early-return paths are the fail-open guarantees
    for the analytics security layer — if they are broken, a Redis outage or
    malformed JWT causes unhandled exceptions in the authentication middleware,
    potentially taking down the analytics node.
    """

    async def test_check_rate_limit_unknown_type_returns_true(self):
        """Unknown limit_type returns True (line 73 — no limit defined).
        So what: if this returns False, any API endpoint not in rate_limits config
        would be blocked immediately, breaking all unanticipated API paths."""
        security = SecurityHardening(AsyncMock(), {})
        result = await security.check_rate_limit("nonexistent_limit_type", "1.2.3.4")
        assert result is True

    async def test_validate_jwt_token_wrong_part_count_returns_none(self):
        """Token with != 3 dot-separated parts returns None (line 145).
        So what: if this check is missing, tuple unpacking below raises ValueError,
        crashing the authentication middleware and denying all API access."""
        security = SecurityHardening(AsyncMock(), {})
        result = await security.validate_jwt_token("only.two.dots.here.extra")
        # 5 parts — returns None without crashing
        assert result is None
        result2 = await security.validate_jwt_token("no-dots-at-all")
        assert result2 is None

    async def test_validate_jwt_token_invalid_payload_unicode_error(self):
        """Non-UTF-8 payload bytes trigger inner UnicodeDecodeError → None (lines 169-170).
        So what: a crafted JWT with a valid HMAC but undecodable payload must be
        rejected cleanly, not crash with an unhandled UnicodeDecodeError."""
        import base64 as _b64

        security = SecurityHardening(
            AsyncMock(), {"security": {"authentication": {"jwt_secret": "s3cr3t"}}}
        )
        header = "header"
        # base64 of raw \xff\xfe — valid base64, but not valid UTF-8 on decode
        invalid_bytes_payload = _b64.urlsafe_b64encode(b"\xff\xfe\xfd").decode().rstrip("=")
        data = f"{header}.{invalid_bytes_payload}"
        signature = security._generate_hmac_signature(data)
        result = await security.validate_jwt_token(f"{data}.{signature}")
        assert result is None

    async def test_validate_jwt_token_outer_exception_returns_none(self):
        """binascii.Error (ValueError subclass) from b64decode hits outer except (lines 172-174).
        So what: if the outer except is unreachable, a crafted token with valid HMAC
        but malformed base64 raises an unhandled ValueError and crashes the auth middleware."""
        import base64 as _base64
        import binascii
        from unittest.mock import patch

        security = SecurityHardening(
            AsyncMock(), {"security": {"authentication": {"jwt_secret": "s3cr3t"}}}
        )
        # Build a properly-HMAC'd token so the signature check passes
        header = "header"
        payload = _base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        data = f"{header}.{payload}"
        signature = security._generate_hmac_signature(data)

        # Patch urlsafe_b64decode to raise binascii.Error (ValueError subclass).
        # binascii.Error is NOT caught by the inner except (json.JSONDecodeError,
        # UnicodeDecodeError), so it propagates to the outer except (ValueError, ...).
        # By that point import json at line 156 has already executed, so json is bound.
        with patch("base64.urlsafe_b64decode", side_effect=binascii.Error("bad input")):
            result = await security.validate_jwt_token(f"{data}.{signature}")
        assert result is None

    async def test_log_security_event_redis_error_swallowed(self):
        """RedisError in log_security_event is swallowed (lines 206-207).
        So what: a Redis write failure during audit logging must not propagate to
        the caller — authentication and rate-limiting must still function."""
        import redis.asyncio as _redis

        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(side_effect=_redis.RedisError("write failed"))
        security = SecurityHardening(mock_redis, {})
        event = SecurityEvent(
            event_type="test", severity="info", timestamp=time.time(), details={}
        )
        await security.log_security_event(event)  # must not raise

    async def test_get_security_audit_logs_redis_error_returns_empty(self):
        """RedisError in get_security_audit_logs returns [] (lines 300-302).
        So what: a Redis read failure during audit log retrieval must return an
        empty list, not crash the management API endpoint."""
        import redis.asyncio as _redis

        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(side_effect=_redis.RedisError("read failed"))
        security = SecurityHardening(mock_redis, {})
        result = await security.get_security_audit_logs()
        assert result == []

    async def test_get_security_metrics_redis_error_returns_error_dict(self):
        """RedisError in get_security_metrics returns error dict (lines 323-325).
        So what: if this except is unreachable, any Redis error inside the metrics
        method crashes the monitoring endpoint, suppressing all alerting dashboards."""
        import time as _time_mod
        import redis.asyncio as _redis
        from unittest.mock import patch

        mock_redis = AsyncMock()
        security = SecurityHardening(mock_redis, {})

        # Use a counter-based mock so only the FIRST time.time() call (inside the
        # try block of get_security_metrics) raises RedisError.  Subsequent calls
        # from the logging framework use the real time.time() so that logger.error()
        # itself doesn't also crash.
        call_count = [0]
        _orig = _time_mod.time

        def _patched_time():
            call_count[0] += 1
            if call_count[0] == 1:
                raise _redis.RedisError("simulated")
            return _orig()

        with patch("time.time", _patched_time):
            result = await security.get_security_metrics()
        assert result["status"] == "error"