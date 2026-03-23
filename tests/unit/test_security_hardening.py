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