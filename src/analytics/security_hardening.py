# Security Hardening Module
# Phase 12d: Security Hardening

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import redis.asyncio as redis


@dataclass
class SecurityEvent:
    """Security event for audit logging."""
    event_type: str
    severity: str
    timestamp: float
    details: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


class SecurityHardening:
    """Comprehensive security hardening for analytics node."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Security configuration
        self.security_config = config.get('security', {})
        self.rate_limit_config = self.security_config.get('rate_limiting', {})
        self.auth_config = self.security_config.get('authentication', {})

        # Initialize security components
        self._init_rate_limiting()
        self._init_authentication()
        self._init_audit_logging()

    def _init_rate_limiting(self):
        """Initialize rate limiting configuration."""
        self.rate_limits = {
            'api_requests': self.rate_limit_config.get('api_requests', {'window': 60, 'limit': 100}),
            'auth_attempts': self.rate_limit_config.get('auth_attempts', {'window': 300, 'limit': 5}),
            'monitoring_access': self.rate_limit_config.get('monitoring_access', {'window': 60, 'limit': 60})
        }

    def _init_authentication(self):
        """Initialize authentication configuration."""
        self.api_keys = self.auth_config.get('api_keys', {})
        self.jwt_secret = self.auth_config.get('jwt_secret', 'default-secret-change-me')
        self.jwt_expiration = self.auth_config.get('jwt_expiration', 3600)  # 1 hour

    def _init_audit_logging(self):
        """Initialize audit logging."""
        self.audit_log_key = "analytics:security:audit"
        self.security_events_key = "analytics:security:events"

    async def check_rate_limit(self, limit_type: str, identifier: str) -> bool:
        """Check if request should be rate limited."""
        if limit_type not in self.rate_limits:
            return True  # No limit for this type

        config = self.rate_limits[limit_type]
        window = config['window']
        limit = config['limit']

        # Use Redis to track request counts
        key = f"analytics:ratelimit:{limit_type}:{identifier}"
        current_time = time.time()

        # Simple implementation for Phase 12d
        # In production, this would use a more sophisticated approach
        try:
            # Get current count
            request_count = await self.redis.zcard(key)

            # If limit exceeded, return False
            if request_count >= limit:
                return False

            # Add current request
            await self.redis.zadd(key, {str(current_time): current_time})
            await self.redis.expire(key, window)

            return True

        except (redis.RedisError, TypeError, ValueError) as e:
            self.logger.error("Rate limiting error: %s", e)
            return True  # Fail open for safety

    async def authenticate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Authenticate using API key."""
        if api_key in self.api_keys:
            user_data = self.api_keys[api_key]

            # Log successful authentication
            await self.log_security_event(
                SecurityEvent(
                    event_type="authentication_success",
                    severity="info",
                    timestamp=time.time(),
                    details={"auth_method": "api_key", "user_id": user_data.get("user_id")},
                    source_ip=user_data.get("last_ip")
                )
            )

            return user_data

        # Log failed authentication
        await self.log_security_event(
            SecurityEvent(
                event_type="authentication_failure",
                severity="warning",
                timestamp=time.time(),
                details={"auth_method": "api_key"}
            )
        )

        return None

    async def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token."""
        try:
            # In a real implementation, this would use proper JWT validation
            # For Phase 12d, we'll implement a simplified version

            # Check token format
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Verify signature (simplified)
            header, payload, signature = parts
            expected_signature = self._generate_hmac_signature(f"{header}.{payload}")

            if not hmac.compare_digest(signature, expected_signature):
                return None

            # Decode payload (simplified)
            import base64
            import json
            try:
                decoded_payload = json.loads(base64.urlsafe_b64decode(payload + '==').decode())

                # Check expiration
                if decoded_payload.get('exp', 0) < time.time():
                    return None

                return decoded_payload

            except (json.JSONDecodeError, UnicodeDecodeError):
                return None

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
            self.logger.error("JWT validation error: %s", e)
            return None

    def _generate_hmac_signature(self, data: str) -> str:
        """Generate HMAC signature for JWT."""
        import hmac
        signature = hmac.new(
            self.jwt_secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    async def log_security_event(self, event: SecurityEvent):
        """Log security event for audit trail."""
        try:
            # Store in Redis stream for real-time monitoring
            event_data: Dict[str, Any] = {
                'type': event.event_type,
                'severity': event.severity,
                'timestamp': str(event.timestamp),
                'details': json.dumps(event.details),
                'source_ip': event.source_ip or '',
                'user_agent': event.user_agent or ''
            }

            await self.redis.xadd(self.audit_log_key, event_data, maxlen=10000)

            # Also store in time-series for analytics
            await self.redis.zadd(
                self.security_events_key,
                {json.dumps(event_data): event.timestamp}
            )
            await self.redis.expire(self.security_events_key, 86400 * 30)  # 30 days

        except redis.RedisError as e:
            self.logger.error("Failed to log security event: %s", e)

    async def check_suspicious_activity(self, request_data: Dict[str, Any]) -> bool:
        """Check for suspicious activity patterns."""
        # Check for common attack patterns
        suspicious_patterns = [
            r'\b(union|select|insert|update|delete|drop)\b.*--',  # SQL injection
            r'<script.*>',  # XSS
            r'\b(eval|exec|system|passthru)\b',  # Code execution
            r'\.\./\.\./',  # Path traversal
        ]

        import re
        for pattern in suspicious_patterns:
            for key, value in request_data.items():
                if isinstance(value, str) and re.search(pattern, value, re.IGNORECASE):
                    # Log suspicious activity
                    await self.log_security_event(
                        SecurityEvent(
                            event_type="suspicious_activity_detected",
                            severity="high",
                            timestamp=time.time(),
                            details={
                                'pattern': pattern,
                                'field': key,
                                'value': value[:50] + '...' if len(value) > 50 else value
                            },
                            source_ip=request_data.get('source_ip')
                        )
                    )
                    return True

        return False

    async def validate_input_safety(self, data: Dict[str, Any]) -> bool:
        """Validate input for common security issues."""
        # Check for oversized inputs
        max_size = self.security_config.get('max_input_size', 1024 * 1024)  # 1MB

        for key, value in data.items():
            if isinstance(value, str) and len(value) > max_size:
                await self.log_security_event(
                    SecurityEvent(
                        event_type="input_size_violation",
                        severity="medium",
                        timestamp=time.time(),
                        details={'field': key, 'size': len(value), 'max_allowed': max_size}
                    )
                )
                return False

        # Check for suspicious characters
        suspicious_chars = [';', '|', '&', '$', '`', '\x00']

        for key, value in data.items():
            if isinstance(value, str):
                for char in suspicious_chars:
                    if char in value:
                        await self.log_security_event(
                            SecurityEvent(
                                event_type="suspicious_character_detected",
                                severity="medium",
                                timestamp=time.time(),
                                details={'field': key, 'character': char}
                            )
                        )
                        return False

        return True

    async def get_security_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security audit logs."""
        try:
            # Get logs from Redis stream
            logs = await self.redis.xrevrange(self.audit_log_key, '+', '-', count=limit)

            return [
                {
                    'id': log[0],
                    'data': {k: v.decode() if isinstance(v, bytes) else v for k, v in log[1].items()}
                }
                for log in logs
            ]
        except redis.RedisError as e:
            self.logger.error("Failed to get audit logs: %s", e)
            return []

    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics for monitoring."""
        try:
            # Get recent security events
            current_time = time.time()

            metrics = {
                'authentication_success': 0,
                'authentication_failure': 0,
                'suspicious_activity': 0,
                'input_violations': 0,
                'rate_limit_violations': 0
            }

            # This would be implemented with proper Redis queries
            # For Phase 12d, we'll return a basic structure

            return {
                'metrics': metrics,
                'timestamp': current_time,
                'status': 'active'
            }

        except redis.RedisError as e:
            self.logger.error("Failed to get security metrics: %s", e)
            return {'status': 'error', 'error': str(e)}


class SecurityError(Exception):
    """Security-related exception."""
    pass


class RateLimitExceededError(SecurityError):
    """Rate limit exceeded."""
    pass


class AuthenticationError(SecurityError):
    """Authentication failed."""
    pass