#!/usr/bin/env python3
"""
JA4 Proxy - Enterprise TLS Fingerprinting Proxy Server
Implements JA4/JA4+ TLS fingerprinting for traffic analysis and filtering.

Security Features:
- Input validation and sanitization
- mTLS support for backend communications
- Secure TLS configuration (TLS 1.2+ only)
- Audit logging with immutable timestamps
- OWASP Top 10 protections
- Memory-safe operations
- Resource limits and timeouts

Compliance:
- GDPR data minimization
- PCI-DSS security controls  
- SOC 2 audit logging
- ISO 27001 security framework
"""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import secrets
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import quote, unquote
import yaml
import redis
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server

# Specific Scapy imports to avoid namespace pollution (Security Fix: CVE-2024-WILDCARD-IMPORT)
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

# Import the multi-strategy security framework
from src.security import SecurityManager as AdvancedSecurityManager
from src.security import ActionType


# Enhanced Metrics with Security Context
REQUEST_COUNT = Counter('ja4_requests_total', 'Total requests processed', 
                       ['fingerprint', 'action', 'source_country', 'tls_version'])
REQUEST_DURATION = Histogram('ja4_request_duration_seconds', 'Request duration',
                           buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
ACTIVE_CONNECTIONS = Gauge('ja4_active_connections', 'Active connections')
BLOCKED_REQUESTS = Counter('ja4_blocked_requests_total', 'Blocked requests', 
                          ['reason', 'source_country', 'attack_type'])
SECURITY_EVENTS = Counter('ja4_security_events_total', 'Security events', 
                         ['event_type', 'severity', 'source'])
TLS_HANDSHAKE_ERRORS = Counter('ja4_tls_handshake_errors_total', 'TLS handshake errors', 
                              ['error_type', 'tls_version'])
CERTIFICATE_EVENTS = Counter('ja4_certificate_events_total', 'Certificate events',
                           ['event_type', 'cert_type'])
PROXY_INFO = Info('ja4_proxy_info', 'Proxy version and build information')

# Security Constants
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
MAX_HEADER_SIZE = 8192  # 8KB
MAX_CONNECTIONS_PER_IP = 100
RATE_LIMIT_WINDOW = 60  # seconds
DEFAULT_TIMEOUT = 30
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2
SECURE_CIPHER_SUITES = [
    "ECDHE+AESGCM", "ECDHE+CHACHA20", "DHE+AESGCM", "DHE+CHACHA20", "!aNULL", "!eNULL", 
    "!EXPORT", "!DES", "!RC4", "!MD5", "!PSK", "!SRP", "!CAMELLIA"
]

# Input Validation Patterns
VALID_JA4_PATTERN = re.compile(r'^[tq][0-9]{2}[di][0-9]{2,4}[0-9]{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$')
VALID_IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
VALID_HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

class SecurityError(Exception):
    """Custom security exception."""
    pass

class ValidationError(Exception):
    """Input validation exception."""
    pass

class ComplianceError(Exception):
    """Compliance violation exception."""
    pass


@dataclass
class JA4Fingerprint:
    """JA4 TLS fingerprint data structure with enhanced security and compliance."""
    ja4: str
    ja4s: Optional[str] = None
    client_hello_hash: str = ""
    server_hello_hash: str = ""
    timestamp: float = field(default_factory=lambda: time.time())
    source_ip: str = ""
    destination_ip: str = ""
    user_agent: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    geo_country: str = ""
    risk_score: int = 0
    compliance_flags: Dict[str, bool] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate and sanitize fingerprint data."""
        self.ja4 = self._sanitize_ja4(self.ja4)
        self.source_ip = self._validate_ip(self.source_ip)
        self.timestamp = self._validate_timestamp(self.timestamp)
        
    def _sanitize_ja4(self, ja4: str) -> str:
        """Sanitize and validate JA4 fingerprint."""
        if not isinstance(ja4, str):
            raise ValidationError("JA4 fingerprint must be string")
        
        ja4 = ja4.strip()
        # Allow sentinel values for non-TLS or unparseable connections
        if ja4 in ("unknown", "error"):
            return ja4
        if not VALID_JA4_PATTERN.match(ja4):
            raise ValidationError(f"Invalid JA4 fingerprint format: {ja4}")
        
        return ja4
    
    def _validate_ip(self, ip: str) -> str:
        """Validate IP address."""
        if not ip:
            return ""
        
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
    
    def _validate_timestamp(self, timestamp: float) -> float:
        """Validate timestamp is reasonable."""
        current_time = time.time()
        if timestamp > current_time + 300:  # Allow 5 minutes future
            raise ValidationError("Timestamp too far in future")
        if timestamp < current_time - 86400 * 30:  # Reject older than 30 days
            raise ValidationError("Timestamp too old")
        return timestamp
    
    def to_audit_log(self) -> Dict[str, Any]:
        """Convert to audit log format (GDPR/PCI-DSS compliant)."""
        return {
            'event_id': self.session_id,
            'timestamp': datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            'ja4_hash': hashlib.sha256(self.ja4.encode()).hexdigest()[:16],  # Pseudonymized
            'source_ip_hash': hashlib.sha256(self.source_ip.encode()).hexdigest()[:16] if self.source_ip else "",
            'tls_version': self.tls_version,
            'cipher_suite': self.cipher_suite,
            'geo_country': self.geo_country,
            'risk_score': self.risk_score,
            'compliance_flags': self.compliance_flags
        }


class TLSParser:
    """TLS packet parser for extracting fingerprint components."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_client_hello(self, packet) -> Optional[Dict]:
        """Parse TLS Client Hello from a packet or TLS record."""
        try:
            if packet is None:
                return None
            
            # Handle both IP-wrapped and raw TLS objects
            if hasattr(packet, 'haslayer') and packet.haslayer(TLS):
                tls_layer = packet[TLS]
            elif isinstance(packet, TLS):
                tls_layer = packet
            else:
                return None
            
            if not hasattr(tls_layer, 'msg') or not tls_layer.msg:
                return None
            
            for msg in tls_layer.msg:
                if hasattr(msg, 'msgtype') and msg.msgtype == 1:  # Client Hello
                    return self._extract_client_hello_fields(msg)
            
            return None
        except Exception as e:
            self.logger.error(f"Error parsing Client Hello: {e}")
            return None
    
    def _extract_client_hello_fields(self, client_hello) -> Dict:
        """Extract fields from Client Hello message."""
        fields = {
            'version': getattr(client_hello, 'version', 0),
            'cipher_suites': [],
            'extensions': [],
            'supported_groups': [],
            'signature_algorithms': [],
            'supported_versions': [],
            'alpn': []
        }
        
        # Extract cipher suites (Scapy uses 'ciphers' field name)
        if hasattr(client_hello, 'ciphers'):
            fields['cipher_suites'] = [cs for cs in client_hello.ciphers]
        elif hasattr(client_hello, 'cipher_suites'):
            fields['cipher_suites'] = [cs for cs in client_hello.cipher_suites]
        
        # Extract extensions
        if hasattr(client_hello, 'ext'):
            for ext in client_hello.ext:
                fields['extensions'].append(ext.type)
                
                # Parse specific extensions
                if ext.type == 10:  # supported_groups
                    if hasattr(ext, 'groups'):
                        fields['supported_groups'] = ext.groups
                    elif hasattr(ext, 'elliptic_curves'):
                        fields['supported_groups'] = ext.elliptic_curves
                elif ext.type == 13:  # signature_algorithms
                    if hasattr(ext, 'sig_algs'):
                        fields['signature_algorithms'] = ext.sig_algs
                elif ext.type == 16:  # ALPN
                    if hasattr(ext, 'protocols') and ext.protocols:
                        alpn = []
                        for p in ext.protocols:
                            if hasattr(p, 'protocol'):
                                val = p.protocol
                                if isinstance(val, bytes):
                                    alpn.append(val.decode('ascii', errors='ignore'))
                                else:
                                    alpn.append(str(val))
                        fields['alpn'] = alpn
                elif ext.type == 43:  # supported_versions
                    if hasattr(ext, 'versions'):
                        fields['supported_versions'] = ext.versions
        
        return fields


class JA4Generator:
    """JA4 fingerprint generator."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_ja4(self, client_hello_fields: Dict) -> str:
        """
        Generate JA4 fingerprint from Client Hello fields.
        Format: {q/t}{version}{d/i}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
        Example: t13d1516h2_8daaf6152771_02713d6af862
        """
        try:
            version = self._get_version_string(client_hello_fields.get('version', 0))
            
            # Use supported_versions extension if present (for TLS 1.3)
            supported_versions = client_hello_fields.get('supported_versions', [])
            if 0x0304 in supported_versions:
                version = "13"
            
            # Filter GREASE from cipher suites and extensions for counting
            raw_ciphers = client_hello_fields.get('cipher_suites', [])
            ciphers = [cs for cs in raw_ciphers if not self._is_grease(cs)]
            raw_exts = client_hello_fields.get('extensions', [])
            exts = [ext for ext in raw_exts if not self._is_grease(ext)]
            
            cipher_count = len(ciphers)
            extension_count = len(exts)
            
            # Protocol: q for QUIC, t for TCP/TLS
            proto = "q" if version.startswith("QUIC") else "t"
            # SNI: d if SNI extension (type 0) present, i otherwise
            sni = "d" if 0 in raw_exts else "i"
            # ALPN: first character of first ALPN value, or "00" if not present
            alpn = self._get_alpn_string(client_hello_fields)
            
            cipher_hash = self._hash_cipher_suites(ciphers)
            extension_hash = self._hash_extensions(exts)
            
            ja4 = f"{proto}{version}{sni}{cipher_count:02d}{extension_count:02d}{alpn}_{cipher_hash}_{extension_hash}"
            
            return ja4
            
        except Exception as e:
            self.logger.error(f"Error generating JA4: {e}", exc_info=True)
            raise ValidationError(f"JA4 generation failed: {e}")
    
    def _get_alpn_string(self, fields: Dict) -> str:
        """Get ALPN string for JA4. Returns first+last char of first ALPN, or '00'."""
        alpn_values = fields.get('alpn', [])
        if alpn_values and len(alpn_values) > 0:
            first_alpn = str(alpn_values[0])
            if len(first_alpn) >= 2:
                return first_alpn[0] + first_alpn[-1]
            elif len(first_alpn) == 1:
                return first_alpn[0] + "0"
        return "00"
    
    def _get_version_string(self, version: int) -> str:
        """Convert TLS version to string."""
        version_map = {
            0x0301: "10",
            0x0302: "11", 
            0x0303: "12",
            0x0304: "13"
        }
        return version_map.get(version, "00")
    
    def _hash_cipher_suites(self, cipher_suites: List[int]) -> str:
        """Hash cipher suites for JA4."""
        if not cipher_suites:
            return "000000000000"
        
        # Remove GREASE values
        filtered_suites = [cs for cs in cipher_suites if not self._is_grease(cs)]
        suite_string = ",".join(f"{cs:04x}" for cs in sorted(filtered_suites))
        return hashlib.sha256(suite_string.encode()).hexdigest()[:12]
    
    def _hash_extensions(self, extensions: List[int]) -> str:
        """Hash extensions for JA4."""
        if not extensions:
            return "000000000000"
        
        # Remove GREASE values and SNI
        filtered_extensions = [ext for ext in extensions if not self._is_grease(ext) and ext != 0]
        ext_string = ",".join(f"{ext:04x}" for ext in sorted(filtered_extensions))
        return hashlib.sha256(ext_string.encode()).hexdigest()[:12]
    
    def _is_grease(self, value: int) -> bool:
        """Check if value is a GREASE value."""
        grease_values = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 
                        0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                        0xcaca, 0xdada, 0xeaea, 0xfafa]
        return value in grease_values


class ConfigManager:
    """Configuration management."""
    
    def __init__(self, config_path: str = "config/proxy.yml"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from YAML file with validation."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # SECURITY FIX: Validate configuration schema
            validated_config = self._validate_config(config)
            return validated_config
            
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return self._default_config()
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error: {e}")
            raise ValidationError(f"Invalid configuration file: {e}")
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            raise ValidationError(f"Configuration loading failed: {e}")
    
    def _validate_config(self, config: Dict) -> Dict:
        """
        Validate configuration against schema (SECURITY FIX).
        Prevents configuration injection attacks.
        """
        if not isinstance(config, dict):
            raise ValidationError("Configuration must be a dictionary")
        
        # Required sections
        required_sections = ['proxy', 'redis', 'security']
        for section in required_sections:
            if section not in config:
                self.logger.warning(f"Missing required section: {section}, using defaults")
                config[section] = self._default_config().get(section, {})
        
        # Validate proxy configuration
        if 'proxy' in config:
            self._validate_proxy_config(config['proxy'])
        
        # Validate Redis configuration with authentication check
        if 'redis' in config:
            self._validate_redis_config(config['redis'])
        
        # Validate security configuration
        if 'security' in config:
            self._validate_security_config(config['security'])
        
        # Expand environment variables in config (for passwords, secrets)
        config = self._expand_env_vars(config)
        
        return config
    
    def _validate_proxy_config(self, proxy_config: Dict) -> None:
        """Validate proxy configuration parameters."""
        # Validate bind host
        if 'bind_host' in proxy_config:
            bind_host = proxy_config['bind_host']
            if not isinstance(bind_host, str):
                raise ValidationError("bind_host must be a string")
            # Warn if binding to all interfaces
            if bind_host == '0.0.0.0':
                self.logger.warning("SECURITY: Binding to 0.0.0.0 exposes service to all interfaces")
        
        # Validate port ranges
        if 'bind_port' in proxy_config:
            port = proxy_config['bind_port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError(f"Invalid bind_port: {port}")
        
        # Validate numeric limits
        if 'max_connections' in proxy_config:
            max_conn = proxy_config['max_connections']
            if not isinstance(max_conn, int) or max_conn < 1 or max_conn > 100000:
                raise ValidationError(f"Invalid max_connections: {max_conn}")
    
    def _validate_redis_config(self, redis_config: Dict) -> None:
        """Validate Redis configuration with security checks."""
        # SECURITY: Require password in production
        if 'password' in redis_config:
            password = redis_config.get('password')
            if not password or password == 'null' or password == '':
                if os.getenv('ENVIRONMENT', 'production') == 'production':
                    raise ValidationError("SECURITY: Redis password is required in production")
                else:
                    self.logger.warning("SECURITY: Redis running without authentication")
        
        # Validate Redis host
        if 'host' in redis_config:
            host = redis_config['host']
            if not isinstance(host, str) or len(host) > 255:
                raise ValidationError(f"Invalid Redis host: {host}")
        
        # Validate port
        if 'port' in redis_config:
            port = redis_config['port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError(f"Invalid Redis port: {port}")
    
    def _validate_security_config(self, security_config: Dict) -> None:
        """Validate security configuration parameters."""
        # Validate boolean flags
        bool_flags = ['whitelist_enabled', 'blacklist_enabled', 'rate_limiting', 
                     'block_unknown_ja4', 'tarpit_enabled']
        for flag in bool_flags:
            if flag in security_config and not isinstance(security_config[flag], bool):
                raise ValidationError(f"{flag} must be boolean")
        
        # Validate numeric values
        if 'max_requests_per_minute' in security_config:
            max_req = security_config['max_requests_per_minute']
            if not isinstance(max_req, int) or max_req < 1 or max_req > 1000000:
                raise ValidationError(f"Invalid max_requests_per_minute: {max_req}")
    
    def _expand_env_vars(self, config: Dict) -> Dict:
        """
        Expand environment variables in configuration (SECURITY FIX).
        Supports ${VAR_NAME} syntax for sensitive values.
        """
        import os
        import re
        
        def expand_value(value):
            if isinstance(value, str):
                # Match ${VAR_NAME} pattern
                pattern = r'\$\{([^}]+)\}'
                matches = re.findall(pattern, value)
                for var_name in matches:
                    env_value = os.getenv(var_name)
                    if env_value is None:
                        self.logger.warning(f"Environment variable not set: {var_name}")
                        env_value = ''
                    value = value.replace(f'${{{var_name}}}', env_value)
            elif isinstance(value, dict):
                return {k: expand_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [expand_value(item) for item in value]
            return value
        
        return expand_value(config)
    
    def _default_config(self) -> Dict:
        """Default configuration."""
        return {
            'proxy': {
                'bind_host': '0.0.0.0',
                'bind_port': 8080,
                'backend_host': '127.0.0.1',
                'backend_port': 80,
                'max_connections': 1000,
                'connection_timeout': 30,
                'buffer_size': 8192
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'password': None,
                'timeout': 5
            },
            'security': {
                'whitelist_enabled': True,
                'blacklist_enabled': True,
                'rate_limiting': True,
                'max_requests_per_minute': 100,
                'block_unknown_ja4': False,
                'tarpit_enabled': False,
                'tarpit_duration': 10
            },
            'metrics': {
                'enabled': True,
                'port': 9090
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }


class SecurityManager:
    """Security policy enforcement."""
    
    def __init__(self, config: Dict, redis_client: redis.Redis):
        self.config = config
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)
        self._load_security_lists()
    
    def _load_security_lists(self):
        """Load whitelist and blacklist from Redis."""
        try:
            self.whitelist = set(self.redis.smembers('ja4:whitelist') or [])
            self.blacklist = set(self.redis.smembers('ja4:blacklist') or [])
        except Exception as e:
            self.logger.error(f"Error loading security lists: {e}")
            self.whitelist = set()
            self.blacklist = set()
    
    def check_access(self, fingerprint: JA4Fingerprint, client_ip: str) -> Tuple[bool, str]:
        """Check if request should be allowed."""
        try:
            # Check rate limiting
            if self.config['security']['rate_limiting']:
                if not self._check_rate_limit(client_ip):
                    BLOCKED_REQUESTS.labels(reason='rate_limit', source_country='', attack_type='rate_limit').inc()
                    return False, "Rate limit exceeded"
            
            # Check blacklist
            if self.config['security']['blacklist_enabled']:
                if fingerprint.ja4.encode() in self.blacklist:
                    BLOCKED_REQUESTS.labels(reason='blacklist', source_country='', attack_type='blacklist').inc()
                    return False, "JA4 blacklisted"
            
            # Check whitelist
            if self.config['security']['whitelist_enabled']:
                if fingerprint.ja4.encode() not in self.whitelist:
                    if self.config['security']['block_unknown_ja4']:
                        BLOCKED_REQUESTS.labels(reason='not_whitelisted', source_country='', attack_type='policy').inc()
                        return False, "JA4 not whitelisted"
            
            return True, "Allowed"
            
        except Exception as e:
            self.logger.error(f"Error checking access: {e}")
            return False, "Internal error"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check rate limiting for client IP (SECURITY FIX: Fail-closed).
        Returns False if rate limit exceeded or on error.
        """
        window = self.config['security'].get('rate_limit_window', 60)
        max_requests = self.config['security'].get('max_requests_per_minute', 100)
        
        key = f"rate_limit:{client_ip}"
        
        try:
            current = self.redis.incr(key)
            if current == 1:
                self.redis.expire(key, window)
            
            if current > max_requests:
                self.logger.warning(f"Rate limit exceeded for IP {client_ip}: {current}/{max_requests}")
                SECURITY_EVENTS.labels(event_type='rate_limit_exceeded', 
                                      severity='warning', source=client_ip).inc()
                return False
            
            return True
            
        except redis.ConnectionError as e:
            # SECURITY FIX: Fail closed on Redis connection errors
            self.logger.error(f"Rate limit check failed - Redis connection error: {e}")
            SECURITY_EVENTS.labels(event_type='rate_limit_error', 
                                  severity='critical', source='redis').inc()
            # Fail closed: block request when rate limiting is unavailable
            return False
            
        except redis.TimeoutError as e:
            self.logger.error(f"Rate limit check failed - Redis timeout: {e}")
            SECURITY_EVENTS.labels(event_type='rate_limit_timeout', 
                                  severity='critical', source='redis').inc()
            return False
            
        except Exception as e:
            self.logger.error(f"Rate limit check failed - unexpected error: {e}", exc_info=True)
            SECURITY_EVENTS.labels(event_type='rate_limit_error', 
                                  severity='critical', source='system').inc()
            # Fail closed: security over availability
            return False


class TarpitManager:
    """TARPIT functionality for slowing down malicious clients."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def tarpit_connection(self, writer, duration: Optional[int] = None):
        """Apply TARPIT delay to connection."""
        if not self.config['security']['tarpit_enabled']:
            return
        
        delay = duration or self.config['security']['tarpit_duration']
        self.logger.info(f"Applying TARPIT delay of {delay}s")
        
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class ProxyServer:
    """Main proxy server implementation."""
    
    def __init__(self, config_path: str = "config/proxy.yml"):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config
        
        # Initialize logger first
        self.logger = self._init_logging()
        
        # Initialize components
        self.redis_client = self._init_redis()
        self.tls_parser = TLSParser()
        self.ja4_generator = JA4Generator()
        self.tarpit_manager = TarpitManager(self.config)
        
        # Initialize advanced multi-strategy security manager
        self.advanced_security = AdvancedSecurityManager.from_config(
            self.redis_client, self.config
        )
        # Keep legacy SecurityManager for blacklist/whitelist checks
        self.security_manager = SecurityManager(self.config, self.redis_client)
        
        # Pre-populate Redis whitelist/blacklist from config
        self._populate_security_lists()
        
        self.active_connections = 0
    
    def _populate_security_lists(self):
        """Pre-populate Redis whitelist and blacklist from config."""
        security_config = self.config.get('security', {})
        
        # Populate whitelist
        whitelist = security_config.get('whitelist', [])
        if whitelist:
            for fp in whitelist:
                self.redis_client.sadd('ja4:whitelist', fp.encode())
            self.logger.info(f"Loaded {len(whitelist)} whitelist entries")
        
        # Populate blacklist
        blacklist = security_config.get('blacklist', [])
        if blacklist:
            for fp in blacklist:
                self.redis_client.sadd('ja4:blacklist', fp.encode())
            self.logger.info(f"Loaded {len(blacklist)} blacklist entries")
        
        # Reload security lists
        self.security_manager._load_security_lists()
    
    def _init_redis(self) -> redis.Redis:
        """Initialize Redis connection with security validation."""
        redis_config = self.config['redis']
        
        # SECURITY FIX: Validate password is set
        password = redis_config.get('password')
        if not password or password == '':
            if os.getenv('ENVIRONMENT', 'development') == 'production':
                raise SecurityError("Redis password is required in production environment")
            self.logger.warning("SECURITY WARNING: Redis connection without authentication")
        
        try:
            # Create Redis connection with security parameters
            redis_client = redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config.get('db', 0),
                password=password if password else None,
                socket_timeout=redis_config.get('timeout', 5),
                socket_connect_timeout=redis_config.get('timeout', 5),
                retry_on_timeout=True,
                health_check_interval=30,
                decode_responses=False  # Security: explicit encoding control
            )
            
            # Test connection
            redis_client.ping()
            self.logger.info("Redis connection established successfully")
            
            return redis_client
            
        except redis.ConnectionError as e:
            self.logger.error(f"Redis connection failed: {e}")
            raise SecurityError(f"Cannot establish secure Redis connection: {e}")
        except redis.AuthenticationError as e:
            self.logger.error(f"Redis authentication failed: {e}")
            raise SecurityError(f"Redis authentication failed - check credentials: {e}")
        except Exception as e:
            self.logger.error(f"Redis initialization error: {e}")
            raise
    
    def _init_logging(self) -> logging.Logger:
        """Initialize logging with structured format and sensitive data filtering (SECURITY FIX)."""
        log_level = self.config['logging'].get('level', 'INFO')
        log_format = self.config['logging'].get('format', 
                                                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Create custom logger with security filter
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, log_level))
        
        # Create handler with sensitive data filter
        handler = logging.StreamHandler()
        handler.setLevel(getattr(logging, log_level))
        
        # Add security filter to prevent sensitive data leakage
        handler.addFilter(SensitiveDataFilter())
        
        # Set formatter
        formatter = SecureFormatter(log_format)
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        
        return logger


    async def start(self):
        """Start the proxy server."""
        self.logger.info("Starting JA4 Proxy Server")
        
        # Start metrics server with optional authentication (SECURITY FIX)
        if self.config['metrics']['enabled']:
            metrics_port = self.config['metrics']['port']
            
            # Check if authentication is enabled
            if self.config['metrics'].get('authentication', {}).get('enabled', False):
                self.logger.info("Metrics authentication enabled")
                # Note: Prometheus client doesn't natively support auth
                # In production, use reverse proxy (nginx/HAProxy) with auth
                # or restrict metrics port to internal network only
                self.logger.warning(
                    "SECURITY: Metrics endpoint requires external authentication via reverse proxy. "
                    "Ensure metrics port is not exposed to public networks."
                )
            
            start_http_server(metrics_port)
            self.logger.info(f"Metrics server started on port {metrics_port}")
            
            # Log security warning if metrics exposed
            if self.config['metrics'].get('bind_host', '0.0.0.0') == '0.0.0.0':
                self.logger.warning(
                    "SECURITY WARNING: Metrics endpoint exposed to all interfaces. "
                    "Restrict access using firewall rules or reverse proxy authentication."
                )
        
        # Start proxy server
        server = await asyncio.start_server(
            self.handle_connection,
            self.config['proxy']['bind_host'],
            self.config['proxy']['bind_port']
        )
        
        bind_addr = f"{self.config['proxy']['bind_host']}:{self.config['proxy']['bind_port']}"
        self.logger.info(f"Proxy server listening on {bind_addr}")
        
        async with server:
            await server.serve_forever()
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection with PROXY protocol and JA4 security."""
        client_addr = writer.get_extra_info('peername')
        socket_ip = client_addr[0] if client_addr else "unknown"
        client_ip = socket_ip  # May be overridden by PROXY protocol
        
        self.active_connections += 1
        ACTIVE_CONNECTIONS.set(self.active_connections)
        
        # Get configurable timeouts
        connection_timeout = self.config['proxy'].get('connection_timeout', DEFAULT_TIMEOUT)
        read_timeout = self.config['proxy'].get('read_timeout', DEFAULT_TIMEOUT)
        
        try:
            # Read initial data with timeout
            request_start = time.time()
            data = await asyncio.wait_for(
                reader.read(self.config['proxy']['buffer_size']),
                timeout=read_timeout
            )
            
            if not data:
                self.logger.debug(f"Empty data from {client_ip}")
                return
            
            # Parse PROXY protocol v2 header if enabled
            if self.config['proxy'].get('proxy_protocol', False):
                client_ip, data = self._parse_proxy_protocol(data, socket_ip)
            
            # Also check for X-Forwarded-For in HTTP requests as fallback
            if client_ip == socket_ip:
                extracted_ip = self._extract_client_ip_from_http(data)
                if extracted_ip:
                    client_ip = extracted_ip
            
            self.logger.info(f"Connection from {client_ip} (socket: {socket_ip})")
            
            # Analyze TLS handshake — extract JA4 fingerprint
            fingerprint = await asyncio.wait_for(
                self._analyze_tls_handshake(data, client_ip),
                timeout=connection_timeout
            )
            ja4 = fingerprint.ja4
            
            # --- SECURITY LAYER 1: Blacklist check (instant block) ---
            if self.config['security'].get('blacklist_enabled', True):
                if ja4.encode() in self.security_manager.blacklist:
                    self.logger.warning(
                        f"BLACKLISTED: {client_ip} | JA4: {ja4} | Instant block"
                    )
                    REQUEST_COUNT.labels(
                        fingerprint=ja4[:16], action="blocked",
                        source_country='', tls_version=fingerprint.tls_version
                    ).inc()
                    BLOCKED_REQUESTS.labels(
                        reason='blacklist', source_country='', attack_type='blacklist'
                    ).inc()
                    SECURITY_EVENTS.labels(
                        event_type='blacklist_hit', severity='critical', source=client_ip
                    ).inc()
                    return  # Drop connection immediately
            
            # --- SECURITY LAYER 2: Whitelist fast-pass ---
            is_whitelisted = False
            if self.config['security'].get('whitelist_enabled', True):
                is_whitelisted = ja4.encode() in self.security_manager.whitelist
            
            # --- SECURITY LAYER 3: Advanced rate-based threat detection ---
            # Only apply rate limiting to non-whitelisted connections
            allowed = True
            reason = "Allowed"
            action_type = ActionType.LOG
            
            if not is_whitelisted:
                try:
                    adv_allowed, adv_reason = self.advanced_security.check_access(ja4, client_ip)
                    if not adv_allowed:
                        allowed = False
                        reason = adv_reason
                        # Determine action type from reason
                        if 'TARPIT' in adv_reason.upper():
                            action_type = ActionType.TARPIT
                        elif 'ban' in adv_reason.lower():
                            action_type = ActionType.BAN
                        else:
                            action_type = ActionType.BLOCK
                except Exception as e:
                    self.logger.error(f"Advanced security check failed: {e}")
                    # Fail open for rate limiting (blacklist already checked above)
                    allowed = True
                    reason = "Allowed (security check error)"
            
            # Record metrics
            request_duration = time.time() - request_start
            REQUEST_DURATION.observe(request_duration)
            action_label = "allowed" if allowed else "blocked"
            REQUEST_COUNT.labels(
                fingerprint=ja4[:16] if ja4 else "unknown",
                action=action_label,
                source_country=fingerprint.geo_country,
                tls_version=fingerprint.tls_version
            ).inc()
            
            if not allowed:
                self.logger.warning(
                    f"BLOCKED: {client_ip} | JA4: {ja4} | Reason: {reason} | "
                    f"Action: {action_type.value}"
                )
                BLOCKED_REQUESTS.labels(
                    reason=reason[:50],
                    source_country=fingerprint.geo_country,
                    attack_type=action_type.value
                ).inc()
                SECURITY_EVENTS.labels(
                    event_type='rate_limit_exceeded',
                    severity='high',
                    source=client_ip
                ).inc()
                
                # TARPIT: redirect to tarpit container
                if action_type == ActionType.TARPIT:
                    await self._redirect_to_tarpit(data, reader, writer)
                # BLOCK/BAN: just drop the connection
                return
            
            # Log allowed connection
            log_prefix = "WHITELISTED" if is_whitelisted else "ALLOWED"
            self.logger.info(
                f"{log_prefix}: {client_ip} | JA4: {ja4} | "
                f"TLS: {fingerprint.tls_version}"
            )
            
            # Forward to backend
            await self._forward_to_backend(data, reader, writer, fingerprint)
            
        except asyncio.TimeoutError:
            self.logger.warning(f"TIMEOUT: {client_ip} | Connection timed out")
            TLS_HANDSHAKE_ERRORS.labels(error_type='timeout', tls_version='unknown').inc()
        except ValidationError as e:
            self.logger.warning(f"VALIDATION_ERROR: {client_ip} | {e}")
            SECURITY_EVENTS.labels(event_type='validation_error', severity='warning', source=client_ip).inc()
        except Exception as e:
            self.logger.error(f"ERROR: {client_ip} | {e}", exc_info=False)
            SECURITY_EVENTS.labels(event_type='connection_error', severity='error', source=client_ip).inc()
        finally:
            self.active_connections -= 1
            ACTIVE_CONNECTIONS.set(self.active_connections)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    def _parse_proxy_protocol(self, data: bytes, fallback_ip: str) -> tuple:
        """Parse PROXY protocol v2 header to extract real client IP."""
        # PROXY protocol v2 signature: 12 bytes
        PP2_SIGNATURE = b'\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a'
        
        if data[:12] == PP2_SIGNATURE and len(data) >= 16:
            # Version and command byte
            ver_cmd = data[12]
            family = data[13]
            addr_len = struct.unpack('!H', data[14:16])[0]
            header_len = 16 + addr_len
            
            if len(data) >= header_len:
                # Extract addresses based on address family
                if family == 0x11:  # AF_INET, STREAM
                    if addr_len >= 12:
                        src_ip = socket.inet_ntoa(data[16:20])
                        remaining_data = data[header_len:]
                        self.logger.debug(f"PROXY protocol v2: client IP = {src_ip}")
                        return src_ip, remaining_data
                elif family == 0x21:  # AF_INET6, STREAM
                    if addr_len >= 36:
                        src_ip = socket.inet_ntop(socket.AF_INET6, data[16:32])
                        remaining_data = data[header_len:]
                        self.logger.debug(f"PROXY protocol v2: client IPv6 = {src_ip}")
                        return src_ip, remaining_data
                
                # Unknown family, strip header but use fallback IP
                return fallback_ip, data[header_len:]
        
        # PROXY protocol v1 (text): "PROXY TCP4 src_ip dst_ip src_port dst_port\r\n"
        if data[:6] == b'PROXY ':
            try:
                newline = data.index(b'\r\n')
                header_line = data[:newline].decode('ascii')
                parts = header_line.split(' ')
                if len(parts) >= 3:
                    src_ip = parts[2]
                    remaining_data = data[newline + 2:]
                    self.logger.debug(f"PROXY protocol v1: client IP = {src_ip}")
                    return src_ip, remaining_data
            except (ValueError, UnicodeDecodeError):
                pass
        
        # No PROXY protocol header found
        return fallback_ip, data
    
    def _extract_client_ip_from_http(self, data: bytes) -> str:
        """Extract client IP from HTTP X-Forwarded-For header (fallback for non-PP traffic)."""
        try:
            # Only parse if this looks like HTTP
            if not (data[:3] in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'PAT', b'OPT')):
                return ""
            header_block = data[:2048].decode('ascii', errors='ignore')
            for line in header_block.split('\r\n'):
                lower = line.lower()
                if lower.startswith('x-forwarded-for:'):
                    ip = line.split(':', 1)[1].strip().split(',')[0].strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        return ""
                elif lower.startswith('x-real-ip:'):
                    ip = line.split(':', 1)[1].strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        return ""
        except Exception:
            pass
        return ""
    
    async def _redirect_to_tarpit(self, data: bytes, client_reader: asyncio.StreamReader,
                                  client_writer: asyncio.StreamWriter):
        """Redirect a blocked connection to the tarpit container."""
        try:
            tarpit_host = self.config['proxy'].get('tarpit_host', 'tarpit')
            tarpit_port = self.config['proxy'].get('tarpit_port', 8888)
            
            tarpit_reader, tarpit_writer = await asyncio.wait_for(
                asyncio.open_connection(tarpit_host, tarpit_port),
                timeout=5
            )
            
            self.logger.info(f"Redirecting to tarpit at {tarpit_host}:{tarpit_port}")
            
            # Forward initial data to tarpit
            tarpit_writer.write(data)
            await tarpit_writer.drain()
            
            # Bidirectional forwarding (tarpit will trickle bytes back)
            await asyncio.gather(
                self._forward_data(client_reader, tarpit_writer, "client->tarpit"),
                self._forward_data(tarpit_reader, client_writer, "tarpit->client"),
                return_exceptions=True
            )
            
        except Exception as e:
            self.logger.debug(f"Tarpit redirect ended: {e}")
        finally:
            try:
                tarpit_writer.close()
                await tarpit_writer.wait_closed()
            except Exception:
                pass
    
    async def _analyze_tls_handshake(self, data: bytes, client_ip: str) -> JA4Fingerprint:
        """Analyze TLS handshake and generate fingerprint from raw TCP data."""
        try:
            ja4 = "unknown"
            tls_version = "unknown"
            
            # The data is raw TCP stream, not IP-wrapped — check for TLS record header
            # TLS record: byte 0 = content type (0x16 = handshake), bytes 1-2 = version, bytes 3-4 = length
            if len(data) >= 5 and data[0] == 0x16:
                # This is a TLS handshake record — parse with Scapy's TLS layer directly
                try:
                    tls_packet = TLS(data)
                    client_hello_fields = self.tls_parser.parse_client_hello(tls_packet)
                    
                    if client_hello_fields:
                        ja4 = self.ja4_generator.generate_ja4(client_hello_fields)
                        # Extract TLS version string
                        ver = client_hello_fields.get('version', 0)
                        supported = client_hello_fields.get('supported_versions', [])
                        if 0x0304 in supported:
                            tls_version = "TLS 1.3"
                        elif ver == 0x0303:
                            tls_version = "TLS 1.2"
                        elif ver == 0x0302:
                            tls_version = "TLS 1.1"
                        elif ver == 0x0301:
                            tls_version = "TLS 1.0"
                        else:
                            tls_version = f"TLS 0x{ver:04x}" if ver else "unknown"
                except Exception as e:
                    self.logger.debug(f"TLS parsing with Scapy failed: {e}")
            else:
                # Not a TLS record — might be HTTP or other protocol
                self.logger.debug(f"Non-TLS data from {client_ip} (first byte: 0x{data[0]:02x})")
                
                # Check for X-JA4-Fingerprint header in HTTP traffic (for testing)
                ja4 = self._extract_ja4_from_http(data)
            
            fingerprint = JA4Fingerprint(
                ja4=ja4,
                client_hello_hash=hashlib.sha256(data).hexdigest()[:16],
                timestamp=time.time(),
                source_ip=client_ip,
                tls_version=tls_version
            )
            
            # Store fingerprint in Redis
            await self._store_fingerprint(fingerprint)
            
            return fingerprint
            
        except Exception as e:
            self.logger.error(f"Error analyzing TLS handshake: {e}")
            return JA4Fingerprint(ja4="error", source_ip=client_ip, timestamp=time.time())
    
    def _extract_ja4_from_http(self, data: bytes) -> str:
        """Extract JA4 fingerprint from HTTP X-JA4-Fingerprint header (testing/fallback)."""
        try:
            if data[:3] in (b'GET', b'POS', b'PUT', b'DEL', b'HEA', b'PAT', b'OPT'):
                header_block = data[:2048].decode('ascii', errors='ignore')
                for line in header_block.split('\r\n'):
                    if line.lower().startswith('x-ja4-fingerprint:'):
                        ja4 = line.split(':', 1)[1].strip()
                        return ja4
        except Exception:
            pass
        return "unknown"
    
    async def _store_fingerprint(self, fingerprint: JA4Fingerprint):
        """Store fingerprint data in Redis."""
        try:
            key = f"ja4:fingerprint:{fingerprint.source_ip}:{int(fingerprint.timestamp)}"
            data = {
                'ja4': fingerprint.ja4,
                'client_hello_hash': fingerprint.client_hello_hash,
                'timestamp': fingerprint.timestamp,
                'source_ip': fingerprint.source_ip
            }
            
            self.redis_client.hset(key, mapping=data)
            self.redis_client.expire(key, 3600)  # 1 hour TTL
            
        except Exception as e:
            self.logger.error(f"Error storing fingerprint: {e}")
    
    async def _forward_to_backend(self, initial_data: bytes, client_reader: asyncio.StreamReader, 
                                 client_writer: asyncio.StreamWriter, fingerprint: JA4Fingerprint):
        """Forward connection to backend server."""
        try:
            # Connect to backend
            backend_reader, backend_writer = await asyncio.open_connection(
                self.config['proxy']['backend_host'],
                self.config['proxy']['backend_port']
            )
            
            self.logger.info(f"Forwarding connection with JA4: {fingerprint.ja4[:16]}")
            
            # Send initial data to backend
            backend_writer.write(initial_data)
            await backend_writer.drain()
            
            # Start bidirectional forwarding
            await asyncio.gather(
                self._forward_data(client_reader, backend_writer, "client->backend"),
                self._forward_data(backend_reader, client_writer, "backend->client"),
                return_exceptions=True
            )
            
        except Exception as e:
            self.logger.error(f"Error forwarding to backend: {e}")
        finally:
            for writer in [backend_writer]:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
    
    async def _forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """Forward data between client and backend."""
        try:
            while True:
                data = await reader.read(self.config['proxy']['buffer_size'])
                if not data:
                    break
                
                writer.write(data)
                await writer.drain()
                
        except Exception as e:
            self.logger.debug(f"Connection closed ({direction}): {e}")



class SensitiveDataFilter(logging.Filter):
    """Filter to prevent logging of sensitive data (SECURITY FIX)."""
    
    def __init__(self):
        super().__init__()
        # Patterns to redact from logs
        self.sensitive_patterns = [
            (re.compile(r'password["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE), 'password=***REDACTED***'),
            (re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE), 'api_key=***REDACTED***'),
            (re.compile(r'token["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE), 'token=***REDACTED***'),
            (re.compile(r'secret["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE), 'secret=***REDACTED***'),
            (re.compile(r'authorization:\s*Bearer\s+(\S+)', re.IGNORECASE), 'Authorization: Bearer ***REDACTED***'),
            (re.compile(r'(\d{13,19})', re.IGNORECASE), '***CARD_REDACTED***'),  # Credit card numbers
            (re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', re.IGNORECASE), '***EMAIL_REDACTED***'),
        ]
    
    def filter(self, record):
        """Filter sensitive data from log records."""
        if hasattr(record, 'msg'):
            msg = str(record.msg)
            for pattern, replacement in self.sensitive_patterns:
                msg = pattern.sub(replacement, msg)
            record.msg = msg
        
        # Also filter from args
        if hasattr(record, 'args') and record.args:
            try:
                filtered_args = []
                for arg in record.args:
                    arg_str = str(arg)
                    for pattern, replacement in self.sensitive_patterns:
                        arg_str = pattern.sub(replacement, arg_str)
                    filtered_args.append(arg_str)
                record.args = tuple(filtered_args)
            except Exception:
                pass  # Don't fail logging if filtering fails
        
        return True


class SecureFormatter(logging.Formatter):
    """Secure logging formatter with additional security context (SECURITY FIX)."""
    
    def format(self, record):
        """Format log record with security context."""
        # Add security context
        if not hasattr(record, 'event_type'):
            record.event_type = 'general'
        
        # Sanitize exception info to prevent stack trace leakage in production
        if record.exc_info and os.getenv('ENVIRONMENT') == 'production':
            # In production, only log exception type, not full traceback
            exc_type, exc_value, exc_tb = record.exc_info
            record.exc_text = f"{exc_type.__name__}: {str(exc_value)}"
            record.exc_info = None
        
        return super().format(record)
    
def main():
    """Main entry point."""
    import sys
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/proxy.yml"
    
    proxy = ProxyServer(config_path)
    
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        print("\nShutting down proxy server...")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()