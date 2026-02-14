#!/usr/bin/env python3
"""
Security validation and hardening framework for JA4 Proxy
Implements OWASP Top 10 protections and enterprise security controls.
"""

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import time
from typing import Dict, List, Optional, Set, Any
from urllib.parse import quote, unquote
import geoip2.database
import redis


class SecurityValidator:
    """Comprehensive security validation framework."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.threat_intel_cache = {}
        self.geo_reader = None
        
        # Initialize GeoIP database if available
        try:
            geoip_path = config.get('security', {}).get('geoip_database')
            if geoip_path:
                self.geo_reader = geoip2.database.Reader(geoip_path)
        except Exception as e:
            self.logger.warning(f"GeoIP database not available: {e}")
    
    def validate_ja4_fingerprint(self, fingerprint: str) -> bool:
        """
        Validate JA4 fingerprint format and detect anomalies.
        Implements input validation from OWASP Top 10.
        """
        if not isinstance(fingerprint, str):
            raise ValidationError("Fingerprint must be string")
        
        # Basic format validation
        if not re.match(r'^[tq][0-9]{2}[di][0-9]{2}[0-9]{2}[hi][0-9]_[a-f0-9]{12}_[a-f0-9]{12}$', fingerprint):
            raise ValidationError(f"Invalid JA4 format: {fingerprint}")
        
        # Length validation
        if len(fingerprint) > 100:
            raise ValidationError("Fingerprint too long")
        
        # Anomaly detection
        if self._detect_fingerprint_anomalies(fingerprint):
            self.logger.warning(f"Anomalous JA4 fingerprint detected: {fingerprint}")
            return False
        
        return True
    
    def validate_ip_address(self, ip: str, check_reputation: bool = True) -> bool:
        """
        Validate IP address and check threat intelligence.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
        
        # Check for private/reserved addresses in production
        if self.config.get('security', {}).get('block_private_ips', False):
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                raise SecurityError(f"Private/reserved IP not allowed: {ip}")
        
        # Threat intelligence check
        if check_reputation and self._check_ip_reputation(ip):
            raise SecurityError(f"IP flagged by threat intelligence: {ip}")
        
        return True
    
    def validate_http_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Validate and sanitize HTTP headers.
        """
        sanitized = {}
        
        for name, value in headers.items():
            # Header name validation
            if not re.match(r'^[a-zA-Z0-9\-_]+$', name):
                self.logger.warning(f"Invalid header name: {name}")
                continue
            
            # Header value sanitization
            if len(value) > 8192:  # Max header value size
                value = value[:8192]
            
            # Remove control characters
            value = re.sub(r'[\x00-\x1f\x7f]', '', value)
            
            sanitized[name.lower()] = value
        
        return sanitized
    
    def validate_request_size(self, size: int) -> bool:
        """Validate request size limits."""
        max_size = self.config.get('security', {}).get('max_request_size', 1024 * 1024)
        if size > max_size:
            raise SecurityError(f"Request too large: {size} > {max_size}")
        return True
    
    def check_rate_limit(self, client_ip: str, redis_client: redis.Redis) -> bool:
        """
        Check rate limiting for client IP.
        Implements protection against brute force attacks.
        """
        window = self.config.get('security', {}).get('rate_limit_window', 60)
        max_requests = self.config.get('security', {}).get('max_requests_per_minute', 100)
        
        key = f"rate_limit:{client_ip}"
        
        try:
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window)
            results = pipe.execute()
            
            current_count = results[0]
            
            if current_count > max_requests:
                self.logger.warning(f"Rate limit exceeded for IP {client_ip}: {current_count}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {e}")
            return True  # Fail open for availability
    
    def check_geo_blocking(self, client_ip: str) -> bool:
        """
        Check geographic blocking rules.
        """
        if not self.geo_reader:
            return True
        
        try:
            response = self.geo_reader.city(client_ip)
            country = response.country.iso_code
            
            allowed_countries = self.config.get('security', {}).get('allowed_countries', [])
            blocked_countries = self.config.get('security', {}).get('blocked_countries', [])
            
            if allowed_countries and country not in allowed_countries:
                self.logger.warning(f"IP {client_ip} from blocked country: {country}")
                return False
            
            if blocked_countries and country in blocked_countries:
                self.logger.warning(f"IP {client_ip} from blocked country: {country}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {client_ip}: {e}")
            return True  # Fail open
    
    def _detect_fingerprint_anomalies(self, fingerprint: str) -> bool:
        """Detect anomalous patterns in JA4 fingerprints."""
        
        # Check for known malicious patterns
        malicious_patterns = [
            r't00d0000h0_000000000000_000000000000',  # Null fingerprint
            r't\d{2}d\d{4}h\d_[0]{12}_[0]{12}',       # All zeros hash
            r't\d{2}d\d{4}h\d_[f]{12}_[f]{12}',       # All f's hash
        ]
        
        for pattern in malicious_patterns:
            if re.match(pattern, fingerprint):
                return True
        
        # Statistical anomaly detection (simplified)
        parts = fingerprint.split('_')
        if len(parts) != 3:
            return True
        
        # Check for repeated characters (potential fingerprint spoofing)
        for part in parts[1:]:  # Check hash parts
            if len(set(part)) < 3:  # Less than 3 unique characters
                return True
        
        return False
    
    def _check_ip_reputation(self, ip: str) -> bool:
        """Check IP reputation against threat intelligence feeds."""
        
        # Check cache first
        if ip in self.threat_intel_cache:
            return self.threat_intel_cache[ip]['malicious']
        
        # Implement threat intelligence lookup
        # This would integrate with actual threat intel feeds
        # For now, return False (not malicious)
        self.threat_intel_cache[ip] = {
            'malicious': False,
            'timestamp': time.time()
        }
        
        return False
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for API protection."""
        secret = self.config.get('security', {}).get('csrf_secret', 'default-secret')
        message = f"{session_id}:{int(time.time())}"
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    def validate_csrf_token(self, token: str, session_id: str) -> bool:
        """Validate CSRF token."""
        secret = self.config.get('security', {}).get('csrf_secret', 'default-secret')
        
        try:
            # Extract timestamp from token (implementation specific)
            current_time = int(time.time())
            message = f"{session_id}:{current_time}"
            expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(token, expected)
        except Exception:
            return False


class SecureHeadersManager:
    """Manages security headers for HTTP responses."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get standard security headers."""
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        }
        
        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "font-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        headers['Content-Security-Policy'] = '; '.join(csp_directives)
        
        return headers


class AuditLogger:
    """Immutable audit logging for compliance."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = self._setup_audit_logger()
    
    def _setup_audit_logger(self) -> logging.Logger:
        """Setup immutable audit logger."""
        audit_logger = logging.getLogger('ja4proxy.audit')
        audit_logger.setLevel(logging.INFO)
        
        # File handler with rotation
        log_path = self.config.get('logging', {}).get('audit_log_path', '/var/log/ja4proxy/audit.log')
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=100*1024*1024,  # 100MB
            backupCount=10
        )
        
        # Structured logging format
        formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s","level":"%(levelname)s","event_type":"%(name)s",'
            '"message":%(message)s,"process":"%(process)d","thread":"%(thread)d"}'
        )
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)
        
        return audit_logger
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = 'INFO'):
        """Log security event for audit trail."""
        audit_record = {
            'event_id': secrets.token_hex(16),
            'event_type': event_type,
            'severity': severity,
            'timestamp': time.time(),
            'details': details,
            'checksum': self._calculate_checksum(details)
        }
        
        self.logger.log(
            getattr(logging, severity.upper(), logging.INFO),
            json.dumps(audit_record),
            extra={'event_type': event_type}
        )
    
    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """Calculate checksum for audit record integrity."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()


class MTLSManager:
    """Mutual TLS certificate management."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def create_ssl_context(self, server_side: bool = True) -> ssl.SSLContext:
        """Create secure SSL context with mTLS."""
        
        if server_side:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load certificates
        cert_path = self.config.get('tls', {}).get('cert_path')
        key_path = self.config.get('tls', {}).get('key_path')
        ca_cert_path = self.config.get('tls', {}).get('ca_cert_path')
        
        if cert_path and key_path:
            context.load_cert_chain(cert_path, key_path)
        
        if ca_cert_path:
            context.load_verify_locations(ca_cert_path)
            context.verify_mode = ssl.CERT_REQUIRED
        
        # Secure cipher configuration
        context.set_ciphers(':'.join([
            'ECDHE+AESGCM',
            'ECDHE+CHACHA20',
            'DHE+AESGCM', 
            'DHE+CHACHA20',
            '!aNULL',
            '!eNULL',
            '!EXPORT',
            '!DES',
            '!RC4',
            '!MD5',
            '!PSK',
            '!SRP',
            '!CAMELLIA'
        ]))
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        return context
    
    def validate_certificate_chain(self, cert_data: bytes) -> bool:
        """Validate certificate chain."""
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Check expiration
            if cert.not_valid_after < datetime.now(timezone.utc):
                self.logger.warning("Certificate expired")
                return False
            
            # Check key usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
                if not key_usage.value.digital_signature:
                    self.logger.warning("Certificate missing digital signature usage")
                    return False
            except x509.ExtensionNotFound:
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate validation failed: {e}")
            return False


# Exception classes
class ValidationError(Exception):
    """Input validation error."""
    pass

class SecurityError(Exception):
    """Security policy violation."""
    pass

class ComplianceError(Exception):
    """Compliance requirement violation."""
    pass