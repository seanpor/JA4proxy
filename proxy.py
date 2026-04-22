#!/usr/bin/env python3
"""
JA4 Proxy — EXPERIMENTAL Python prototype (NOT the production proxy).

===============================================================================
⚠  EXPERIMENTAL — DO NOT DEPLOY THIS FILE IN PRODUCTION  ⚠
===============================================================================

The **Go** implementation under ``cmd/proxy/`` and ``internal/`` is the
production JA4proxy.  It was promoted to production in Phase 15 and is what
ships in release artefacts, Docker images, Helm charts, and enterprise
documentation.

This Python file (``proxy.py``) is kept as a **prototyping surface** for
new signal modules and one-off experiments.  Prototype in Python, prove the
idea, then port to Go before it goes anywhere near real traffic.  Python
code under ``src/security/`` follows the same rule — it is a research
playground, not a supported runtime.

Use the Python proxy only for:
  * iterating quickly on a new signal before porting it to Go
  * running FP-corpus experiments that need the scipy/pandas ecosystem
  * local repro of bugs found by the Go proxy in a more interactive env

For production, use the Go proxy binary: ``bin/proxy`` (built via ``make``).

===============================================================================

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
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import signal
import socket
import ssl
import struct
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import redis
import yaml
from prometheus_client import Counter, Gauge, Histogram, Info, start_http_server

# GeoIP country lookup
try:
    import IP2Location

    GEOIP_AVAILABLE = True
except (
    ImportError
):  # pragma: no cover — only reachable when IP2Location is not installed
    GEOIP_AVAILABLE = False

# Specific Scapy imports for TLS fingerprinting
from scapy.layers.tls.record import TLS

from src.backup.scheduler import BackupScheduler
from src.backup.worker import BackupWorker
from src.cache.local_cache import LocalCache

# Phase 0+: Local cache and pipeline infrastructure
from src.config.loader import ConfigLoader
from src.pubsub import PubSubHandler
from src.security.action_decider import ActionDecider, DialManager
from src.security.feed_health import FeedHealthMonitor
from src.security.health import HealthMonitor, HealthServer
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer
from src.tap.tap_sensor import TapSensor

# Enhanced Metrics with Security Context
REQUEST_COUNT = Counter(
    "ja4_requests_total",
    "Total requests processed",
    ["fingerprint_name", "action", "source_country", "tls_version"],
)
REQUEST_DURATION = Histogram(
    "ja4_request_duration_seconds",
    "Request duration",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)
ACTIVE_CONNECTIONS = Gauge("ja4proxy_active_connections", "Active connections")
BLOCKED_REQUESTS = Counter(
    "ja4_blocked_requests_total",
    "Blocked requests",
    ["reason", "source_country", "attack_type"],
)
SECURITY_EVENTS = Counter(
    "ja4_security_events_total", "Security events", ["event_type", "severity", "source"]
)
TLS_HANDSHAKE_ERRORS = Counter(
    "ja4_tls_handshake_errors_total",
    "TLS handshake errors",
    ["error_type", "tls_version"],
)
CERTIFICATE_EVENTS = Counter(
    "ja4_certificate_events_total", "Certificate events", ["event_type", "cert_type"]
)
PROXY_INFO = Info("ja4_proxy_info", "Proxy version and build information")

# Phase 14c: Tarpit self-protection metrics
_TARPIT_CONCURRENT = Gauge(
    "ja4proxy_tarpit_concurrent",
    "Current concurrent tarpitted connections",
)
_TARPIT_OVERFLOW = Counter(
    "ja4proxy_tarpit_overflow_total",
    "Connections that hit the tarpit cap and were given the overflow action",
    ["action"],
)

# Security Constants
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
MAX_HEADER_SIZE = 8192  # 8KB
MAX_CONNECTIONS_PER_IP = 100
RATE_LIMIT_WINDOW = 60  # seconds
DEFAULT_TIMEOUT = 30
SERVER_BACKLOG = 4096  # TCP accept queue depth — high value to survive traffic bursts
MAX_CONCURRENT_CONNECTIONS = 2000  # asyncio semaphore limit
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2
SECURE_CIPHER_SUITES = [
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "DHE+AESGCM",
    "DHE+CHACHA20",
    "!aNULL",
    "!eNULL",
    "!EXPORT",
    "!DES",
    "!RC4",
    "!MD5",
    "!PSK",
    "!SRP",
    "!CAMELLIA",
]

# Input Validation Patterns
VALID_JA4_PATTERN = re.compile(
    r"^[tq][0-9]{2}[di][0-9]{2,4}[0-9]{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$"
)
VALID_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
VALID_HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)

# Phase 28a: Parser Isolation & Depth Limits
MAX_TLS_PARSER_DEPTH = 10

# JA4PROXY-2026-0033 — hard upper bound on bytes passed to the Scapy
# fallback parser. Upstream read size is already bounded by proxy.buffer_size
# (default 8192) but we enforce an independent defence-in-depth cap so a
# future refactor of the read path cannot silently uncork pathological
# inputs into Scapy. A valid TLS ClientHello is never even close to this.
MAX_TLS_PARSER_INPUT_BYTES = 65536

# JA4PROXY-2026-0033 — wall-clock budget for a single Scapy fallback parse
# attempt. If Scapy does not return within this window, abandon the attempt,
# log a counter, and fall through to ja4="unknown" rather than letting a
# crafted packet monopolise a worker thread indefinitely. ThreadPool
# execution cannot be forcibly cancelled, so this upper-bounds only how
# long the hot path waits — the thread itself will finish whenever Scapy
# decides to, which is exactly why the input size cap above matters.
TLS_PARSER_TIMEOUT_SECONDS = 2.0

# JA4PROXY-2026-0038 — atomic rate-limit INCR+EXPIRE. Redis runs Lua
# scripts under its single-threaded model, so the INCR and the
# conditional EXPIRE both execute without interleaving from other
# clients and without the previous "crash between INCR and EXPIRE
# strands the key without TTL" race. ARGV[1] is the window seconds.
# Returns the post-INCR count so the caller can apply its threshold
# identically to the previous implementation.
RATE_LIMIT_INCR_LUA = """\
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


def _parse_tls_task(data: bytes) -> Optional[Dict]:
    """
    Worker function for TLS parsing in the fallback thread pool.

    Phase 69 replaced the original ProcessPoolExecutor with a
    ThreadPoolExecutor for latency reasons. That change removed the process
    memory isolation the original resource.setrlimit(RLIMIT_AS, ...) relied
    on — RLIMIT_AS applies to the whole process, so calling it from a
    worker thread would cap the main proxy process too. We now rely on two
    other guards, enforced in _analyze_tls_handshake before dispatch:
      * MAX_TLS_PARSER_INPUT_BYTES — a hard input-size cap, so Scapy is
        never asked to parse an unbounded buffer.
      * TLS_PARSER_TIMEOUT_SECONDS — an asyncio-level timeout around
        run_in_executor, so a pathological parse cannot stall the hot path.
    JA4PROXY-2026-0033.
    """
    try:
        # Local import to avoid Scapy overhead in the main process
        from scapy.layers.tls.record import TLS

        tls_packet = TLS(data)
        parser = TLSParser()
        return parser.parse_client_hello(tls_packet)
    except Exception:
        return None


class SecurityError(Exception):
    """Custom security exception."""

    pass


class ValidationError(Exception):
    """Input validation exception."""

    pass


class ComplianceError(Exception):
    """Compliance violation exception."""

    pass


def classify_ja4(ja4: str, config: dict = None) -> str:
    """Decode a JA4 fingerprint into a human-readable classification.

    JA4 format: {q/t}{version}{d/i}{cipher_count}{ext_count}{alpn}_{hash}_{hash}
    Checks config fingerprint_labels first, then decodes the JA4 structure.
    """
    if config and "fingerprint_labels" in config.get("security", {}):
        labels = config["security"]["fingerprint_labels"]
        if ja4 in labels:
            return labels[ja4]
        for key, name in labels.items():
            if ja4.startswith(key) or key.startswith(ja4[:16]):
                return name

    if not ja4 or len(ja4) < 10 or ja4 in ("unknown", "error"):
        return "Unknown"

    proto = "QUIC" if ja4[0] == "q" else "TLS"
    ver_map = {"13": "1.3", "12": "1.2", "11": "1.1", "10": "1.0"}
    tls_ver = ver_map.get(ja4[1:3], ja4[1:3])
    prefix = ja4.split("_")[0]
    alpn_field = prefix[-2:] if len(prefix) >= 2 else "00"
    if alpn_field == "h2":
        return f"Browser ({proto} {tls_ver})"
    elif alpn_field == "00":
        return f"Tool/Bot ({proto} {tls_ver})"
    return f"Client ({proto} {tls_ver})"


class GeoIPLookup:
    """IP-to-country lookup using IP2Location LITE database."""

    # Common GeoIP database paths
    DB_PATHS = [
        "/app/geoip/IP2LOCATION-LITE-DB1.BIN",  # Docker container
        "data/geoip/IP2LOCATION-LITE-DB1.BIN",  # Local dev
    ]

    def __init__(self, db_path: str = None):
        self.db = None
        self.current_path = None
        self.logger = logging.getLogger(__name__)
        if not GEOIP_AVAILABLE:
            self.logger.warning("IP2Location not installed - country lookup disabled")
            return
        self.reload(db_path)

    def reload(self, db_path: str = None) -> bool:
        """Atomic hot-reload of the GeoIP database file.
        
        Args:
            db_path: Path to the new database file. If None, uses DB_PATHS.
            
        Returns:
            True if reload was successful, False otherwise.
        """
        paths = [db_path] if db_path else self.DB_PATHS
        for p in paths:
            if p and os.path.exists(p):
                try:
                    # Phase 42b: Validation before swapping
                    # We load it into a temporary object first
                    new_db = IP2Location.IP2Location(p)
                    # Simple test lookup to ensure it works
                    new_db.get_country_short("8.8.8.8")
                    
                    # Atomic swap
                    self.db = new_db
                    self.current_path = p
                    
                    # Explicitly close old DB if supported/needed
                    # IP2Location-Python doesn't have an explicit close() but we 
                    # let the old object be garbage collected.
                    
                    self.logger.info(f"GeoIP database hot-reloaded: {p}")
                    return True
                except Exception as e:
                    self.logger.error(f"Failed to hot-reload GeoIP database {p}: {e}")
        
        if not self.db:
            self.logger.warning("No GeoIP database found - country lookup disabled")
        return False

    def lookup(self, ip: str) -> str:
        """Return ISO 3166-1 alpha-2 country code for an IP, or '' if unknown."""
        if not self.db:
            return ""
        try:
            # Skip private/reserved IPs
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return ""
            rec = self.db.get_all(ip)
            code = rec.country_short
            return code if code and code != "-" else ""
        except Exception:
            return ""


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
    tls_version_int: int = 0  # Phase 3: raw integer version
    raw_cipher_suites: list = field(
        default_factory=list
    )  # Phase 3: ClientHello ciphers
    raw_sni: str = ""  # Phase 4: SNI hostname (empty = absent)
    alpn_code: str = ""  # Phase 4: JA4-style 2-char ALPN code
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
            "event_id": self.session_id,
            "timestamp": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "ja4_hash": hashlib.sha256(self.ja4.encode()).hexdigest()[
                :16
            ],  # Pseudonymized
            "source_ip_hash": (
                hashlib.sha256(self.source_ip.encode()).hexdigest()[:16]
                if self.source_ip
                else ""
            ),
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "geo_country": self.geo_country,
            "risk_score": self.risk_score,
            "compliance_flags": self.compliance_flags,
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
            if hasattr(packet, "haslayer") and packet.haslayer(TLS):
                tls_layer = packet[TLS]
            elif isinstance(packet, TLS):
                tls_layer = packet
            else:
                return None

            if not hasattr(tls_layer, "msg") or not tls_layer.msg:
                return None

            for msg in tls_layer.msg:
                if hasattr(msg, "msgtype") and msg.msgtype == 1:  # Client Hello
                    return self._extract_client_hello_fields(msg, depth=0)

            return None
        except Exception as e:
            self.logger.error(f"Error parsing Client Hello: {e}")
            return None

    def _extract_client_hello_fields(self, client_hello, depth: int = 0) -> Dict:
        """Extract fields from Client Hello message."""
        if depth > MAX_TLS_PARSER_DEPTH:
            self.logger.warning(f"Max TLS parsing depth exceeded: {depth}")
            return {}

        fields = {
            "version": getattr(client_hello, "version", 0),
            "cipher_suites": [],
            "extensions": [],
            "supported_groups": [],
            "signature_algorithms": [],
            "supported_versions": [],
            "alpn": [],
            "sni": None,  # Phase 4: SNI hostname string or None
        }

        # Extract cipher suites (Scapy uses 'ciphers' field name)
        if hasattr(client_hello, "ciphers"):
            fields["cipher_suites"] = [cs for cs in client_hello.ciphers]
        elif hasattr(client_hello, "cipher_suites"):
            fields["cipher_suites"] = [cs for cs in client_hello.cipher_suites]

        # Extract extensions
        if hasattr(client_hello, "ext"):
            for ext in client_hello.ext:
                fields["extensions"].append(ext.type)

                # Parse specific extensions
                if ext.type == 10:  # supported_groups
                    if hasattr(ext, "groups"):
                        fields["supported_groups"] = ext.groups
                    elif hasattr(ext, "elliptic_curves"):
                        fields["supported_groups"] = ext.elliptic_curves
                elif ext.type == 13:  # signature_algorithms
                    if hasattr(ext, "sig_algs"):
                        fields["signature_algorithms"] = ext.sig_algs
                elif ext.type == 16:  # ALPN
                    if hasattr(ext, "protocols") and ext.protocols:
                        alpn = []
                        for p in ext.protocols:
                            if hasattr(p, "protocol"):
                                val = p.protocol
                                if isinstance(val, bytes):
                                    alpn.append(val.decode("ascii", errors="ignore"))
                                else:
                                    alpn.append(str(val))
                        fields["alpn"] = alpn
                elif ext.type == 43:  # supported_versions
                    if hasattr(ext, "versions"):
                        fields["supported_versions"] = ext.versions
                elif ext.type == 0:  # SNI (server_name)  — Phase 4
                    # Scapy represents SNI as TLSExtServerName with servernames list
                    if hasattr(ext, "servernames") and ext.servernames:
                        sn = ext.servernames[0]
                        val = getattr(sn, "servername", None)
                        if val:
                            fields["sni"] = (
                                val.decode("ascii", errors="ignore")
                                if isinstance(val, bytes)
                                else str(val)
                            )
                    elif hasattr(ext, "server_name"):
                        val = ext.server_name
                        if val:
                            fields["sni"] = (
                                val.decode("ascii", errors="ignore")
                                if isinstance(val, bytes)
                                else str(val)
                            )

        return fields


# Phase 65: Optimized GREASE values set for O(1) lookup
_GREASE_VALUES: frozenset[int] = frozenset({
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
})


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
            version = self._get_version_string(client_hello_fields.get("version", 0))

            # Use supported_versions extension if present (for TLS 1.3)
            supported_versions = client_hello_fields.get("supported_versions", [])
            if 0x0304 in supported_versions:
                version = "13"

            # Filter GREASE from cipher suites and extensions for counting and hashing
            # Optimization: filter once here and pass pre-filtered lists to hash functions.
            # Phase 68b: bind module-level frozenset to local name to avoid repeated
            # global lookup inside list comprehensions (JIT-friendlier monomorphic callsite).
            _grease = _GREASE_VALUES
            raw_ciphers = client_hello_fields.get("cipher_suites", [])
            ciphers = [cs for cs in raw_ciphers if cs not in _grease]

            raw_exts = client_hello_fields.get("extensions", [])
            # Filter GREASE from extensions for counting
            exts_for_count = [ext for ext in raw_exts if ext not in _grease]
            # Filter GREASE and SNI (type 0) from extensions for the hash part
            exts_for_hash = [ext for ext in exts_for_count if ext != 0]

            cipher_count = len(ciphers)
            extension_count = len(exts_for_count)

            # Protocol: q for QUIC, t for TCP/TLS
            proto = "q" if version.startswith("QUIC") else "t"
            # SNI: d if SNI extension (type 0) present, i otherwise
            sni = "d" if 0 in raw_exts else "i"
            # ALPN: first character of first ALPN value, or "00" if not present
            alpn = self._get_alpn_string(client_hello_fields)

            cipher_hash = self._hash_cipher_suites(ciphers)
            extension_hash = self._hash_extensions(exts_for_hash)

            ja4 = f"{proto}{version}{sni}{cipher_count:02d}{extension_count:02d}{alpn}_{cipher_hash}_{extension_hash}"

            return ja4

        except Exception as e:
            self.logger.error(f"Error generating JA4: {e}", exc_info=True)
            raise ValidationError(f"JA4 generation failed: {e}")

    def generate_ja4x(self, issuer: str, subject: str, san: str) -> str:
        """
        Generate JA4X extended fingerprint from certificate fields.
        Format: {issuer_hash}_{subject_hash}_{san_hash}
        Each hash is SHA-256 truncated to 12 hex chars.
        """
        try:
            import hashlib

            def _truncate_hash(data: str) -> str:
                """Generate SHA-256 hash and truncate to 12 hex chars."""
                if not data:
                    return "000000000000"
                return hashlib.sha256(
                    data.encode("utf-8", errors="replace")
                ).hexdigest()[:12]

            issuer_hash = _truncate_hash(issuer)
            subject_hash = _truncate_hash(subject)
            san_hash = _truncate_hash(san)

            ja4x = f"{issuer_hash}_{subject_hash}_{san_hash}"
            return ja4x

        except Exception as e:
            self.logger.error(f"Error generating JA4X: {e}", exc_info=True)
            # Return sentinel value for missing/invalid certificates
            return "000000000000_000000000000_000000000000"

    def _get_alpn_string(self, fields: Dict) -> str:
        """Get ALPN string for JA4. Returns first+last char of first ALPN, or '00'."""
        alpn_values = fields.get("alpn", [])
        if alpn_values and len(alpn_values) > 0:
            first_alpn = str(alpn_values[0])
            if len(first_alpn) >= 2:
                return first_alpn[0] + first_alpn[-1]
            elif len(first_alpn) == 1:
                return first_alpn[0] + "0"
        return "00"

    def _get_version_string(self, version: int) -> str:
        """Convert TLS version to string."""
        version_map = {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}
        return version_map.get(version, "00")

    def _hash_cipher_suites(self, cipher_suites: List[int]) -> str:
        """Hash cipher suites for JA4. Expects pre-filtered list (no GREASE)."""
        if not cipher_suites:
            return "000000000000"

        suite_string = ",".join(f"{cs:04x}" for cs in sorted(cipher_suites))
        return hashlib.sha256(suite_string.encode()).hexdigest()[:12]

    def _hash_extensions(self, extensions: List[int]) -> str:
        """Hash extensions for JA4. Expects pre-filtered list (no GREASE, no SNI)."""
        if not extensions:
            return "000000000000"

        ext_string = ",".join(f"{ext:04x}" for ext in sorted(extensions))
        return hashlib.sha256(ext_string.encode()).hexdigest()[:12]

    def _is_grease(self, value: int) -> bool:
        """Check if value is a GREASE value. (Deprecated in Phase 65)"""
        return value in _GREASE_VALUES


class ConfigManager:
    """Configuration management."""

    def __init__(self, config_path: str = "config/proxy.yml"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.config = self.load_config()

    def load_config(self) -> Dict:
        """Load configuration from YAML file with validation."""
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            # SECURITY FIX: Validate configuration schema
            validated_config = self._validate_config(config)
            return validated_config

        except FileNotFoundError:
            self.logger.warning(
                f"Config file not found: {self.config_path}, using defaults"
            )
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

        # Expand environment variables before validation so ${VAR:-default}
        # placeholders are resolved to real values (int strings, host names, etc.)
        config = self._expand_env_vars(config)

        # Required sections
        required_sections = ["proxy", "redis", "security"]
        for section in required_sections:
            if section not in config:
                self.logger.warning(
                    f"Missing required section: {section}, using defaults"
                )
                config[section] = self._default_config().get(section, {})

        # Validate proxy configuration
        if "proxy" in config:
            self._validate_proxy_config(config["proxy"])

        # Validate Redis configuration with authentication check
        if "redis" in config:
            self._validate_redis_config(config["redis"])

        # Validate security configuration
        if "security" in config:
            self._validate_security_config(config["security"])

        # Validate metrics configuration
        if "metrics" in config:
            metrics_config = config["metrics"]
            if "port" in metrics_config:
                port = metrics_config["port"]
                if isinstance(port, str):
                    try:
                        metrics_config["port"] = int(port)
                    except ValueError:
                        raise ValidationError(f"Invalid metrics port: {port}")

        return config

    def _validate_proxy_config(self, proxy_config: Dict) -> None:
        """Validate proxy configuration parameters."""
        # Validate bind host
        if "bind_host" in proxy_config:
            bind_host = proxy_config["bind_host"]
            if not isinstance(bind_host, str):
                raise ValidationError("bind_host must be a string")
            # Warn if binding to all interfaces
            if bind_host == "0.0.0.0":  # nosec B104
                self.logger.warning(
                    "SECURITY: Binding to 0.0.0.0 exposes service to all interfaces"
                )

        # Validate port ranges
        if "bind_port" in proxy_config:
            port = proxy_config["bind_port"]
            # Accept string integers (result of env var expansion)
            if isinstance(port, str):
                try:
                    port = int(port)
                    proxy_config["bind_port"] = port
                except ValueError:
                    raise ValidationError(f"Invalid bind_port: {port}")
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError(f"Invalid bind_port: {port}")

        # Validate numeric limits
        if "max_connections" in proxy_config:
            max_conn = proxy_config["max_connections"]
            if not isinstance(max_conn, int) or max_conn < 1 or max_conn > 100000:
                raise ValidationError(f"Invalid max_connections: {max_conn}")

        # JA4PROXY-2026-0022 — validate upstream_trust.trusted_cidrs.
        # A trusted CIDR is the strongest authority in the system: it grants the
        # bearer the right to rewrite client IPs via the PROXY protocol. A
        # misconfiguration that leaves /0 in the list gives every attacker on the
        # Internet that authority, so trust-model bypass is complete. Validate
        # aggressively at load time rather than hoping ops catch it.
        if "upstream_trust" in proxy_config:
            self._validate_upstream_trust(proxy_config["upstream_trust"])

    def _validate_upstream_trust(self, trust_cfg: Dict) -> None:
        """Reject dangerously-broad trusted CIDRs. Phase 118h — JA4PROXY-2026-0022.

        - /0, /1, /2 on IPv4 (and /0–/7 on IPv6) are outright refused.
        - Any range covering /16 or broader (IPv4) or /32 or broader (IPv6) is
          logged at CRITICAL — it may be legitimate for a large enterprise but
          it is never routine.
        - RFC1918 and loopback ranges are warned (local testing is common).
        """
        if not isinstance(trust_cfg, dict):
            raise ValidationError("proxy.upstream_trust must be a mapping")
        cidrs = trust_cfg.get("trusted_cidrs", [])
        if cidrs is None:
            return
        if not isinstance(cidrs, list):
            raise ValidationError("proxy.upstream_trust.trusted_cidrs must be a list")
        for raw in cidrs:
            if not isinstance(raw, str):
                raise ValidationError(
                    f"trusted_cidrs entry must be a string CIDR, got {type(raw).__name__}"
                )
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except (ValueError, TypeError) as exc:
                raise ValidationError(f"Invalid trusted CIDR {raw!r}: {exc}") from exc
            if net.version == 4 and net.prefixlen <= 2:
                raise ValidationError(
                    f"trusted CIDR {raw!r} is dangerously broad "
                    "(IPv4 /0-/2 would trust the whole Internet)"
                )
            if net.version == 6 and net.prefixlen <= 7:
                raise ValidationError(
                    f"trusted CIDR {raw!r} is dangerously broad "
                    "(IPv6 /0-/7 would trust the whole Internet)"
                )
            if (net.version == 4 and net.prefixlen < 16) or (
                net.version == 6 and net.prefixlen < 32
            ):
                self.logger.critical(
                    "SECURITY: trusted upstream CIDR %s covers >= /16 v4 "
                    "(or /32 v6) — blast radius is very large",
                    raw,
                )
            if net.is_loopback or net.is_private:
                self.logger.warning(
                    "trusted upstream CIDR %s is loopback/private — "
                    "intended only for local testing, never production",
                    raw,
                )

    def _validate_redis_config(self, redis_config: Dict) -> None:
        """Validate Redis configuration with security checks."""
        # SECURITY: Require password in production (config validation pass)
        if "password" in redis_config:
            password = redis_config.get("password")
            if not password or password == "null" or password == "":
                if os.getenv("ENVIRONMENT", "development") == "production":
                    raise ValidationError(
                        "SECURITY: Redis password is required in production"
                    )
                else:
                    self.logger.warning(
                        "SECURITY: Redis running without authentication"
                    )

        # Validate Redis host
        if "host" in redis_config:
            host = redis_config["host"]
            if not isinstance(host, str) or len(host) > 255:
                raise ValidationError(f"Invalid Redis host: {host}")

        # Validate port
        if "port" in redis_config:
            port = redis_config["port"]
            # Accept string integers (result of env var expansion)
            if isinstance(port, str):
                try:
                    port = int(port)
                    redis_config["port"] = port
                except ValueError:
                    raise ValidationError(f"Invalid Redis port: {port}")
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError(f"Invalid Redis port: {port}")

    def _validate_security_config(self, security_config: Dict) -> None:
        """Validate security configuration parameters."""
        # Validate boolean flags
        bool_flags = [
            "whitelist_enabled",
            "blacklist_enabled",
            "rate_limiting",
            "block_unknown_ja4",
            "tarpit_enabled",
        ]
        for flag in bool_flags:
            if flag in security_config and not isinstance(security_config[flag], bool):
                raise ValidationError(f"{flag} must be boolean")

        # Validate numeric values
        if "max_requests_per_minute" in security_config:
            max_req = security_config["max_requests_per_minute"]
            if not isinstance(max_req, int) or max_req < 1 or max_req > 1000000:
                raise ValidationError(f"Invalid max_requests_per_minute: {max_req}")

    def _expand_env_vars(self, config: Dict) -> Dict:
        """
        Expand environment variables in configuration.
        Supports ${VAR_NAME} and ${VAR_NAME:-default_value} syntax.
        """
        import os
        import re

        # Matches ${VAR} and ${VAR:-default}
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")

        def expand_value(value):
            if isinstance(value, str):

                def replace_match(m):
                    var_name, default = m.group(1), m.group(2)
                    env_value = os.getenv(var_name)
                    if env_value is not None:
                        return env_value
                    if default is not None:
                        return default
                    self.logger.warning(
                        f"Environment variable not set and no default: {var_name}"
                    )
                    return ""

                return pattern.sub(replace_match, value)
            elif isinstance(value, dict):
                return {k: expand_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [expand_value(item) for item in value]
            return value

        return expand_value(config)

    def _default_config(self) -> Dict:
        """Default configuration."""
        return {
            "proxy": {
                "bind_host": "0.0.0.0",  # nosec B104
                "bind_port": 8080,
                "backend_host": "127.0.0.1",
                "backend_port": 80,
                "max_connections": 1000,
                "connection_timeout": 30,
                "buffer_size": 8192,
            },
            "redis": {
                "host": "localhost",
                "port": 6379,
                "db": 0,
                "password": None,
                "timeout": 5,
            },
            "security": {
                "whitelist_enabled": True,
                "blacklist_enabled": True,
                "rate_limiting": True,
                "max_requests_per_minute": 100,
                "block_unknown_ja4": False,
                "tarpit_enabled": False,
                "tarpit_duration": 10,
            },
            "metrics": {"enabled": True, "port": 9090},
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
        }


class SecurityManager:
    """Security policy enforcement."""

    def __init__(self, config: Dict, redis_client: redis.asyncio.Redis):
        self.config = config
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)
        self.whitelist = set()
        self.blacklist = set()

    def _verify_signature(self, data: bytes, expected_signature: str) -> bool:
        """
        Verify the cryptographic signature of a security list (Phase 28b).
        Prevents lateral movement from compromising security lists in Redis.
        """
        if not expected_signature:
            return False

        secret = self.config.get("redis", {}).get("signing_key")
        # For POC/development, if no key is configured, warn but allow
        if not secret:
            if os.getenv("ENVIRONMENT") == "production":
                self.logger.error(
                    "SECURITY: No Redis signing key configured in production! "
                    "Rejecting all Redis security lists."
                )
                return False
            return True

        import hashlib
        import hmac

        h = hmac.new(secret.encode(), data, hashlib.sha256)
        return hmac.compare_digest(h.hexdigest(), expected_signature)

    async def _load_security_lists(self):
        """Load whitelist and blacklist from Redis with signature verification."""
        try:
            # Load and verify blacklist
            bl_raw = await self.redis.smembers("ja4:blacklist")
            bl_list = sorted(
                [m.decode() if isinstance(m, bytes) else m for m in bl_raw]
            )
            bl_data = "".join(bl_list).encode()

            bl_sig_raw = await self.redis.get("ja4:blacklist:sig")
            bl_sig = (
                bl_sig_raw.decode() if isinstance(bl_sig_raw, bytes) else bl_sig_raw
            )

            if self._verify_signature(bl_data, bl_sig):
                self.blacklist = set(bl_list)
            else:
                self.logger.error(
                    "SECURITY: ja4:blacklist signature verification failed! "
                    "Rejecting update to preserve existing state."
                )

            # Load and verify whitelist
            wl_raw = await self.redis.smembers("ja4:whitelist")
            wl_list = sorted(
                [m.decode() if isinstance(m, bytes) else m for m in wl_raw]
            )
            wl_data = "".join(wl_list).encode()

            wl_sig_raw = await self.redis.get("ja4:whitelist:sig")
            wl_sig = (
                wl_sig_raw.decode() if isinstance(wl_sig_raw, bytes) else wl_sig_raw
            )

            if self._verify_signature(wl_data, wl_sig):
                self.whitelist = set(wl_list)
            else:
                self.logger.error(
                    "SECURITY: ja4:whitelist signature verification failed! "
                    "Rejecting update."
                )

        except Exception as e:
            self.logger.error(f"Error loading security lists: {e}")
            # Do NOT clear existing lists on error — preserve last known good state

    async def check_access(
        self, fingerprint: JA4Fingerprint, client_ip: str, alpn: str = None
    ) -> Tuple[bool, str]:
        """Check if request should be allowed."""
        try:
            # Get current dial - at dial 0 (monitor mode), never block anything
            dial = 0
            try:
                dial_val = await self.redis.get("dial")
                if dial_val:
                    dial = int(dial_val)
            except Exception:
                pass  # Use default dial=0 on error

            # At dial=0 (monitor mode), NEVER block - just log what would happen
            if dial == 0:
                self.logger.debug("Monitor mode (dial=0) - allowing all traffic")
                return True, "Monitor mode"

            # Check ALPN bypass - browser traffic doesn't get rate limited
            alpn_bypass = self.config.get("security_policy", {}).get(
                "alpn_browser_bypass", {}
            )
            if alpn_bypass.get("enabled", True) and alpn in ("h2", "http/1.1", "h1"):
                self.logger.debug(f"ALPN bypass: {alpn} - skipping rate limit")
                # Still check blacklist/whitelist but skip rate limiting
                return self._check_list_based_access(fingerprint)

            # Check rate limiting (only when dial > 0)
            if self.config["security"]["rate_limiting"]:
                if not await self._check_rate_limit(client_ip):
                    BLOCKED_REQUESTS.labels(
                        reason="rate_limit", source_country="", attack_type="rate_limit"
                    ).inc()
                    return False, "Rate limit exceeded"

            return self._check_list_based_access(fingerprint)

        except Exception as e:
            self.logger.error(f"Error checking access: {e}")
            return False, "Internal error"

    def _check_list_based_access(self, fingerprint: JA4Fingerprint) -> Tuple[bool, str]:
        """Check blacklist and whitelist (called after rate limit check)."""
        # Check blacklist
        if self.config["security"]["blacklist_enabled"]:
            if fingerprint.ja4.encode() in self.blacklist:
                BLOCKED_REQUESTS.labels(
                    reason="blacklist", source_country="", attack_type="blacklist"
                ).inc()
                return False, "JA4 blacklisted"

        # Check whitelist
        if self.config["security"]["whitelist_enabled"]:
            if fingerprint.ja4.encode() not in self.whitelist:
                if self.config["security"]["block_unknown_ja4"]:
                    BLOCKED_REQUESTS.labels(
                        reason="not_whitelisted",
                        source_country="",
                        attack_type="policy",
                    ).inc()
                    return False, "JA4 not whitelisted"

        return True, "Allowed"

    async def _get_adaptive_rate_threshold(self, client_ip: str) -> int:
        """
        Get adaptive rate threshold from Redis (Phase 16).
        Falls back to static config if adaptive data not available.
        """
        # Extract /24 subnet for adaptive rate limiting
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(client_ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # For IPv4, get the /24 network
                subnet = str(
                    ipaddress.IPv4Network(f"{ip_obj}/24", strict=False).network_address
                )
            else:  # IPv6
                # For IPv6, get the /64 network
                subnet = str(
                    ipaddress.IPv6Network(f"{ip_obj}/64", strict=False).network_address
                )
        except Exception:
            subnet = "unknown"

        # Read adaptive threshold from Redis
        adaptive_key = f"rate:adaptive:{subnet}"
        try:
            adaptive_data = await self.redis.hgetall(adaptive_key)
            if adaptive_data and b"confidence" in adaptive_data:
                confidence = float(adaptive_data[b"confidence"])
                if confidence >= 0.7:  # Minimum confidence threshold
                    threshold = int(adaptive_data[b"threshold_rps"])
                    min_threshold = (
                        self.config.get("rate_limiter", {})
                        .get("adaptive", {})
                        .get("min_threshold_rps", 5)
                    )
                    max_threshold = (
                        self.config.get("rate_limiter", {})
                        .get("adaptive", {})
                        .get("max_threshold_rps", 1000)
                    )
                    # Clamp to configured bounds
                    return max(min_threshold, min(threshold, max_threshold))
        except Exception as e:
            self.logger.debug(f"Adaptive rate data read failed: {e}")

        # Fallback to static configuration
        return self.config["security"].get("max_requests_per_minute", 100)

    async def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check rate limiting for client IP (SECURITY FIX: Fail-closed).
        Returns False if rate limit exceeded or on error.
        """
        window = self.config["security"].get("rate_limit_window", 60)

        # Get adaptive threshold if enabled (Phase 16)
        adaptive_enabled = (
            self.config.get("rate_limiter", {})
            .get("adaptive", {})
            .get("enabled", False)
        )
        if adaptive_enabled:
            max_requests = await self._get_adaptive_rate_threshold(client_ip)
        else:
            max_requests = self.config["security"].get("max_requests_per_minute", 100)

        key = f"rate_limit:{client_ip}"

        try:
            # JA4PROXY-2026-0038: atomic INCR + conditional EXPIRE.
            # The previous form was two round-trips (INCR then, when
            # current==1, EXPIRE) — a crash between them left the key
            # with no TTL, permanently rate-limiting that IP. The Lua
            # below runs atomically under Redis' single-threaded model.
            current = await self.redis.eval(
                RATE_LIMIT_INCR_LUA,
                1,
                key,
                window,
            )

            if current > max_requests:
                self.logger.warning(
                    f"Rate limit exceeded for IP {client_ip}: {current}/{max_requests}"
                )
                SECURITY_EVENTS.labels(
                    event_type="rate_limit_exceeded",
                    severity="warning",
                    source=client_ip,
                ).inc()
                return False

            return True

        except redis.ConnectionError as e:
            # SECURITY FIX: Fail closed on Redis connection errors
            self.logger.error(f"Rate limit check failed - Redis connection error: {e}")
            SECURITY_EVENTS.labels(
                event_type="rate_limit_error", severity="critical", source="redis"
            ).inc()
            # Fail closed: block request when rate limiting is unavailable
            return False

        except redis.TimeoutError as e:
            self.logger.error(f"Rate limit check failed - Redis timeout: {e}")
            SECURITY_EVENTS.labels(
                event_type="rate_limit_timeout", severity="critical", source="redis"
            ).inc()
            return False

        except Exception as e:
            self.logger.error(
                f"Rate limit check failed - unexpected error: {e}", exc_info=True
            )
            SECURITY_EVENTS.labels(
                event_type="rate_limit_error", severity="critical", source="system"
            ).inc()
            # Fail closed: security over availability
            return False


class TarpitManager:
    """TARPIT functionality for slowing down malicious clients."""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def tarpit_connection(self, writer, duration: Optional[int] = None):
        """Apply TARPIT delay to connection."""
        if not self.config["security"]["tarpit_enabled"]:
            return

        delay = duration or self.config["security"]["tarpit_duration"]
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

    def __init__(self, config_path: str = None):
        self.config_loader = None
        self.config = None
        self.logger = None
        self.redis_client = None
        self.tls_parser = None
        self.ja4_generator = None
        self.tarpit_manager = None
        self.security_manager = None
        self._conn_semaphore = None
        self.geoip = None
        self.country_whitelist = set()
        self.country_blacklist = set()
        self.country_whitelist_enabled = False
        self.country_blacklist_enabled = False
        self._cidr_blocks = []
        self._cidr_blocks_loaded_at = 0.0
        self._cidr_cache_ttl = 30
        self._local_cache = None
        self.pipeline = None
        self._dial_manager = None
        self._abuseipdb_checker = None
        self.greynoise_provider = None
        self.alienvault_provider = None
        self.misp_provider = None
        self.threatfox_provider = None
        self.virustotal_provider = None
        self.confidence_manager = None
        self._aiohttp_session = None
        self._rdap_enricher = None
        self.active_connections = 0
        # Phase 14c: tarpit self-protection counters
        self._tarpit_concurrent: int = 0
        self._tarpit_per_ip: dict = {}
        self._tarpit_lock: asyncio.Lock = asyncio.Lock()
        # Phase 20 G0-A: backup scheduler
        self._backup_scheduler: Optional[BackupScheduler] = None
        # Phase 28b: pub/sub handler for state updates
        self._pubsub_task: Optional[asyncio.Task] = None
        # Phase 35: integrity monitor task
        self._integrity_monitor_task: Optional[asyncio.Task] = None  # phase-35
        self._integrity_monitor = None  # phase-35

        if config_path:
            self.config_path = config_path
            # Use the new ConfigLoader (Phase 20)
            self.config_loader = ConfigLoader(config_path)
            # Sync load for __init__ compatibility (tests)
            import yaml

            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
            self._init_from_config()

    def _init_from_config(self):
        """Initialize from config (sync part). For testing compatibility."""
        self.logger = self._init_logging()

        geo_config = self.config.get("geoip", {})
        self.country_whitelist = set(
            c.upper() for c in geo_config.get("country_whitelist", [])
        )
        self.country_blacklist = set(
            c.upper() for c in geo_config.get("country_blacklist", [])
        )
        self.country_whitelist_enabled = geo_config.get(
            "country_whitelist_enabled", False
        )
        self.country_blacklist_enabled = geo_config.get(
            "country_blacklist_enabled", False
        )
        if self.country_whitelist_enabled:
            self.logger.info(
                f"Country whitelist enabled: {sorted(self.country_whitelist)}"
            )
        if self.country_blacklist_enabled:
            self.logger.info(
                f"Country blacklist enabled: {sorted(self.country_blacklist)}"
            )

    @classmethod
    async def create(cls, config_path: str = "config/proxy.yml"):
        self = cls()
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.config

        # Initialize logger first
        self.logger = self._init_logging()

        # Initialize components
        self.redis_client = await self._init_redis()

        # Core state components (needed by TI providers and pipeline)
        from src.security.adaptive_cache import AdaptiveCacheManager
        from src.security.confidence_manager import ConfidenceManager

        self._local_cache = LocalCache(self.config)
        self.confidence_manager = ConfidenceManager(self.redis_client)
        self.adaptive_cache = AdaptiveCacheManager(self.redis_client)
        try:
            import aiohttp
            self._aiohttp_session = aiohttp.ClientSession()
        except (ImportError, Exception):
            self.logger.warning("aiohttp not installed or failed to init - TI providers using network will be disabled")
            self._aiohttp_session = None

        self.tls_parser = TLSParser()
        self.ja4_generator = JA4Generator()
        self.tarpit_manager = TarpitManager(self.config)

        # Phase 69: ThreadPoolExecutor for TLS parsing fallback (Scapy).
        # Replaced ProcessPoolExecutor (Phase 28a) — zero-IPC overhead, safe for free-threaded Python.
        # Thread count bounded to CPU count; named for observability.
        self.executor = ThreadPoolExecutor(
            max_workers=min(4, os.cpu_count() or 1),
            thread_name_prefix="tls-parser",
        )

        # Keep legacy SecurityManager for _populate_security_lists (seeds Redis sets)
        self.security_manager = SecurityManager(self.config, self.redis_client)

        # Connection concurrency semaphore — prevents TCP exhaustion under DDoS
        self._conn_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)

        # Phase 41: Health Monitoring
        self.health_monitor = HealthMonitor(
            redis_client=self.redis_client,
            config=self.config,
            geoip_path=self.config.get("geoip", {}).get("database_path")
        )
        self.health_server = HealthServer(
            monitor=self.health_monitor,
            host=self.config["metrics"].get("bind_host", "0.0.0.0"),
            port=int(self.config["metrics"].get("port", 9090))
        )
        self._health_task = None

        # Phase 23: Advanced TI Providers
        from src.security.alienvault import AlienVaultOTXProvider, OTXConfig
        from src.security.greynoise import GreyNoiseConfig, GreyNoiseProvider
        from src.security.misp import MISPConfig, MISPProvider
        from src.security.threatfox import ThreatFoxConfig, ThreatFoxProvider
        from src.security.virustotal import VirusTotalConfig, VirusTotalProvider

        # Phase 59: Single shared FeedHealthMonitor for all TI providers
        self._feed_health_monitor = FeedHealthMonitor()

        self.greynoise_provider = GreyNoiseProvider(
            config=GreyNoiseConfig.from_config(self.config),
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            session=self._aiohttp_session,
            health_monitor=self._feed_health_monitor,
        )
        self.alienvault_provider = AlienVaultOTXProvider(
            config=OTXConfig.from_config(self.config),
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            session=self._aiohttp_session,
            health_monitor=self._feed_health_monitor,
        )
        # Phase 46: MISP Threat Intelligence Provider
        self.misp_provider = MISPProvider(
            config=MISPConfig.from_config(self.config),
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            session=self._aiohttp_session,
            adaptive_cache=self.adaptive_cache,
            health_monitor=self._feed_health_monitor,
        )
        # Phase 46: ThreatFox Threat Intelligence Provider
        self.threatfox_provider = ThreatFoxProvider(
            config=ThreatFoxConfig.from_config(self.config),
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            session=self._aiohttp_session,
            adaptive_cache=self.adaptive_cache,
            health_monitor=self._feed_health_monitor,
        )
        # Phase 46: VirusTotal Threat Intelligence Provider
        self.virustotal_provider = VirusTotalProvider(
            config=VirusTotalConfig.from_config(self.config),
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            session=self._aiohttp_session,
            adaptive_cache=self.adaptive_cache,
            health_monitor=self._feed_health_monitor,
        )

        # Initialize GeoIP lookup
        geoip_path = self.config.get("geoip", {}).get("database_path")
        self.geoip = GeoIPLookup(geoip_path)

        # Load country whitelist/blacklist from config
        geo_config = self.config.get("geoip", {})
        self.country_whitelist = set(
            c.upper() for c in geo_config.get("country_whitelist", [])
        )
        self.country_blacklist = set(
            c.upper() for c in geo_config.get("country_blacklist", [])
        )
        self.country_whitelist_enabled = geo_config.get(
            "country_whitelist_enabled", False
        )
        self.country_blacklist_enabled = geo_config.get(
            "country_blacklist_enabled", False
        )
        # Dynamic country/CIDR blocking — Redis-backed, no restart needed.
        # geoip:dynamic_blacklist  — SET of country codes (auto-blocked or admin-added)
        # geoip:safe_countries     — SET of country codes never auto-blocked
        # geoip:blocked_cidrs      — SET of CIDR strings (e.g. "203.0.113.0/24")
        self._cidr_blocks: List[ipaddress.IPv4Network] = []
        self._cidr_blocks_loaded_at: float = 0.0
        self._cidr_cache_ttl: int = 30  # seconds between Redis reloads
        if self.country_whitelist_enabled:
            self.logger.info(
                f"Country whitelist enabled: {sorted(self.country_whitelist)}"
            )
        if self.country_blacklist_enabled:
            self.logger.info(
                f"Country blacklist enabled: {sorted(self.country_blacklist)}"
            )

        # Pre-populate Redis whitelist/blacklist from config
        await self._populate_security_lists()

        # Phase 1+: Pipeline replaces legacy security layers
        _scorer = RiskScorer.from_config(self.config)
        _decider = ActionDecider.from_config(self.config)
        self.pipeline = Pipeline(self.config, self._local_cache, self.redis_client)
        self.pipeline.update_scorer(_scorer, _decider)

        # Load JA4 whitelist/blacklist into pipeline's in-process sets
        wl_raw = await self.redis_client.smembers("ja4:whitelist")
        bl_raw = await self.redis_client.smembers("ja4:blacklist")
        self.pipeline.update_sets(
            whitelist={k.decode("utf-8", errors="ignore") for k in wl_raw},
            blacklist={k.decode("utf-8", errors="ignore") for k in bl_raw},
        )

        # Phase 26e: Start WriteBuffer for deferred batching
        await self.pipeline.start()

        # Phase 2: Dial manager (safety: reset to 0 + hourly rate-limit)
        self._dial_manager = DialManager(self.config)

        # Phase 10: AbuseIPDB checker — shared aiohttp session, background workers
        try:
            if self._aiohttp_session is None:
                raise Exception("aiohttp session not available")

            from src.security.abuseipdb import AbuseIPDBChecker, AbuseIPDBConfig

            _abuseipdb_cfg = AbuseIPDBConfig.from_config(self.config)
            self._abuseipdb_checker = AbuseIPDBChecker(
                _abuseipdb_cfg,
                self.redis_client,
                self._local_cache,
                self._aiohttp_session,
            )
            await self._abuseipdb_checker.start()
            self.pipeline.set_abuseipdb_checker(self._abuseipdb_checker)
        except Exception as exc:
            self.logger.warning(
                f"abuseipdb | event=init_failed | error={exc} — AbuseIPDB disabled"
            )
            self._abuseipdb_checker = None

        # Phase 11: RDAP enricher — reuses shared aiohttp session; background workers
        try:
            if self._aiohttp_session is None:
                raise Exception("aiohttp session not available")

            from src.security.rdap_enrichment import RDAPConfig, RDAPEnricher

            _rdap_cfg = RDAPConfig.from_config(self.config)
            self._rdap_enricher = RDAPEnricher(
                _rdap_cfg,
                self.redis_client,
                self._local_cache,
                self._aiohttp_session,
                blocklist_manager=self.pipeline._blocklist_manager,
                instance_id=str(id(self)),
            )
            await self._rdap_enricher.start()
            self.pipeline.set_rdap_enricher(self._rdap_enricher)
        except Exception as exc:
            self.logger.warning(
                f"rdap | event=init_failed | error={exc} — RDAP enrichment disabled"
            )
            self._rdap_enricher = None

        self.active_connections = 0
        self._tarpit_concurrent = 0
        self._tarpit_per_ip = {}
        self._tarpit_lock = asyncio.Lock()

        # Phase 42: Register hot-reload callback
        if self.config_loader:
            self.config_loader.on_reload(self._on_config_reload)

        # Phase 35: Integrity monitor — verify config signature on startup
        try:
            from src.security.integrity_monitor import IntegrityMonitor  # phase-35
            self._integrity_monitor = IntegrityMonitor(self.config)  # phase-35
            integrity_cfg = self.config.get("integrity", {})  # phase-35
            if integrity_cfg.get("verify_on_startup", False):  # phase-35
                pubkey_path = integrity_cfg.get(  # phase-35
                    "pubkey_path", "config/keys/integrity.pub"  # phase-35
                )  # phase-35
                config_path_for_verify = getattr(self, "config_path", "config/proxy.yml")  # phase-35
                if not self._integrity_monitor.verify_config_signature(  # phase-35
                    config_path_for_verify, pubkey_path  # phase-35
                ):  # phase-35
                    self.logger.critical(  # phase-35
                        "integrity | event=startup_verify_failed | "  # phase-35
                        "path=%s | effect=exiting",  # phase-35
                        config_path_for_verify,  # phase-35
                    )  # phase-35
                    import sys  # phase-35
                    sys.exit(1)  # phase-35
        except SystemExit:  # phase-35
            raise  # phase-35
        except Exception as exc:  # phase-35
            self.logger.error(  # phase-35
                "integrity | event=init_error | error=%s | effect=continuing", exc  # phase-35
            )  # phase-35

        return self

    async def _on_config_reload(self, new_config: dict) -> None:
        """Callback for hot-reloading components when config changes."""
        self.logger.info("proxy | event=hot_reload_triggered")
        self.config = new_config
        
        # 1. Update GeoIP if path changed
        new_geoip_path = new_config.get("geoip", {}).get("database_path")
        if new_geoip_path != self.geoip.current_path:
            self.geoip.reload(new_geoip_path)
            
        # 2. Update Pipeline (RiskScorer, ActionDecider)
        from src.security.action_decider import ActionDecider
        from src.security.risk_scorer import RiskScorer
        
        new_scorer = RiskScorer.from_config(new_config)
        new_decider = ActionDecider.from_config(new_config)
        self.pipeline.update_scorer(new_scorer, new_decider)
        
        # 3. Update TI Providers
        if hasattr(self, "greynoise_provider") and self.greynoise_provider:
            self.greynoise_provider.on_config_reload(new_config)
        if hasattr(self, "alienvault_provider") and self.alienvault_provider:
            self.alienvault_provider.on_config_reload(new_config)
        if hasattr(self, "_abuseipdb_checker") and self._abuseipdb_checker:
            from src.security.abuseipdb import AbuseIPDBConfig
            self._abuseipdb_checker.on_config_reload(AbuseIPDBConfig.from_config(new_config))
        if hasattr(self, "_rdap_enricher") and self._rdap_enricher:
            from src.security.rdap_enrichment import RDAPConfig
            self._rdap_enricher.on_config_reload(new_config)
            
        # 4. Update Health Monitor
        self.health_monitor.config = new_config
        self.health_monitor.geoip_path = new_geoip_path
        
        self.logger.info("proxy | event=hot_reload_complete")

    async def _populate_security_lists(self):
        """Pre-populate Redis whitelist and blacklist from config."""
        security_config = self.config.get("security", {})

        # Populate whitelist
        whitelist = security_config.get("whitelist", [])
        if whitelist:
            for fp in whitelist:
                await self.redis_client.sadd("ja4:whitelist", fp.encode())
            self.logger.info(f"Loaded {len(whitelist)} whitelist entries")

        # Populate blacklist
        blacklist = security_config.get("blacklist", [])
        if blacklist:
            for fp in blacklist:
                await self.redis_client.sadd("ja4:blacklist", fp.encode())
            self.logger.info(f"Loaded {len(blacklist)} blacklist entries")

        # Reload security lists
        await self.security_manager._load_security_lists()

        # Populate geoip:safe_countries from config (never auto-blocked by geoip-monitor)
        safe_countries = self.config.get("geoip", {}).get("safe_countries", [])
        if safe_countries:
            for cc in safe_countries:
                await self.redis_client.sadd("geoip:safe_countries", cc.upper())
            self.logger.info(f"Loaded {len(safe_countries)} safe countries")

    async def _refresh_cidr_blocks(self) -> None:
        """Reload CIDR block list from Redis if cache is stale (every 30s)."""
        if time.monotonic() - self._cidr_blocks_loaded_at < self._cidr_cache_ttl:
            return
        try:
            raw = await self.redis_client.smembers("geoip:blocked_cidrs")
            nets = []
            for m in raw:
                cidr = m.decode() if isinstance(m, bytes) else m
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    self.logger.warning(
                        f"Invalid CIDR in geoip:blocked_cidrs: {cidr!r}"
                    )
            self._cidr_blocks = nets
            self._cidr_blocks_loaded_at = time.monotonic()
        except Exception as e:
            self.logger.debug(f"CIDR block refresh skipped: {e}")

    def _is_cidr_blocked(self, ip: str) -> Optional[str]:
        """Return the matching CIDR string if this IP is blocked, else None."""
        if not self._cidr_blocks:
            return None
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._cidr_blocks:
                if addr in net:
                    return str(net)
        except ValueError:
            pass
        return None

    async def _init_redis(self) -> redis.asyncio.Redis:
        """Initialize Redis connection with security validation."""
        redis_config = self.config["redis"]

        # SECURITY: Validate password is set.
        # Missing password in production is a startup FATAL — fail before accepting
        # any connections so the operator is forced to fix the configuration.
        password = redis_config.get("password")
        if not password or password == "":
            if os.getenv("ENVIRONMENT", "development") == "production":
                self.logger.critical(
                    '{"type":"system","level":"FATAL","subsystem":"proxy",'
                    '"event":"startup_failed",'
                    '"reason":"Redis password is required in production — '
                    'set REDIS_PASSWORD environment variable"}'
                )
                import sys

                sys.exit(1)
            self.logger.warning(
                "SECURITY WARNING: Redis connection without authentication"
            )

        try:
            # Create Redis connection with security parameters
            timeout = redis_config.get("timeout", 5)
            if isinstance(timeout, str):
                try:
                    timeout = int(timeout)
                except ValueError:
                    timeout = 5

            db = redis_config.get("db", 0)
            if isinstance(db, str):
                try:
                    db = int(db)
                except ValueError:
                    db = 0

            # Phase 28b: Secure Redis connection (SSL/TLS)
            ssl_enabled = redis_config.get("ssl", False)
            ssl_ca_certs = redis_config.get("ssl_ca_certs")

            # In production, SSL is mandatory if configured
            if (
                os.getenv("ENVIRONMENT") == "production"
                and not ssl_enabled
                and not redis_config.get("unix_socket_path")
            ):
                self.logger.warning(
                    "SECURITY: Redis SSL is disabled in production. "
                    "Enable 'ssl: true' in config for transport security."
                )

            # Check for Unix domain socket configuration
            unix_socket_path = redis_config.get("unix_socket_path")
            if unix_socket_path:
                # Use Unix domain socket
                self.logger.info(f"Using Redis Unix domain socket: {unix_socket_path}")
                redis_client = redis.asyncio.Redis(
                    unix_socket_path=unix_socket_path,
                    db=db,
                    username=redis_config.get("username"),
                    password=password if password else None,
                    socket_timeout=timeout,
                    socket_connect_timeout=timeout,
                    health_check_interval=30,
                    decode_responses=False,  # Security: explicit encoding control
                )
            else:
                # Use TCP connection (default)
                redis_client = redis.asyncio.Redis(
                    host=redis_config["host"],
                    port=redis_config["port"],
                    db=db,
                    username=redis_config.get("username"),
                    password=password if password else None,
                    socket_timeout=timeout,
                    socket_connect_timeout=timeout,
                    health_check_interval=30,
                    decode_responses=False,  # Security: explicit encoding control
                    # Phase 28b security parameters
                    ssl=ssl_enabled,
                    ssl_cert_reqs=redis_config.get("ssl_cert_reqs", "required"),
                    ssl_ca_certs=ssl_ca_certs,
                )

            # Test connection
            await redis_client.ping()
            self.logger.info("Redis connection established successfully")

            return redis_client

        except redis.AuthenticationError as e:
            # Must precede ConnectionError: AuthenticationError is a subclass of it.
            self.logger.error(f"Redis authentication failed: {e}")
            raise SecurityError(f"Redis authentication failed - check credentials: {e}")
        except redis.ConnectionError as e:
            self.logger.error(f"Redis connection failed: {e}")
            raise SecurityError(f"Cannot establish secure Redis connection: {e}")
        except Exception as e:
            self.logger.error(f"Redis initialization error: {e}")
            raise

    def _init_logging(self) -> logging.Logger:
        """Initialize logging with structured format and sensitive data filtering.

        JSON mode is enabled when ``logging.json_enabled: true`` in config OR
        when the ``ENVIRONMENT`` environment variable is set to ``production``.
        In JSON mode every log line is a valid JSON object suitable for SIEM ingest.
        The SensitiveDataFilter runs before the formatter so passwords and tokens
        are stripped from all output regardless of format.
        """
        log_cfg = self.config.get("logging", {})
        log_level = log_cfg.get("level", "INFO")
        # `logging.format` in proxy.yml accepts preset names ("legacy", "ecs")
        # *or* a Python logging format string.  Presets indicate JSON schema
        # style and are consumed by JSONFormatter; for plain (non-JSON) output
        # fall back to the default printf format.
        _raw_format = log_cfg.get(
            "format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        if "%" in _raw_format:
            log_format = _raw_format
        else:
            log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        # JSON logging: explicit config flag OR auto-detected production environment
        json_enabled = log_cfg.get("json_enabled", False) or (
            os.getenv("ENVIRONMENT", "development") == "production"
        )

        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, log_level))

        # Replace existing handlers added by this method (e.g. on hot-reload)
        # without affecting handlers from other sources.  We identify ours by
        # class: only remove StreamHandlers — not FileHandlers, NullHandlers, etc.
        logger.handlers = [
            h for h in logger.handlers if not isinstance(h, logging.StreamHandler)
        ]

        handler = logging.StreamHandler()
        handler.setLevel(getattr(logging, log_level))

        # Sensitive data filter runs first — modifies LogRecord before formatting
        handler.addFilter(SensitiveDataFilter())

        if json_enabled:
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(SecureFormatter(log_format))

        logger.addHandler(handler)

        return logger

    async def start(self, shutdown_event: Optional[asyncio.Event] = None):
        """Start the proxy server.

        Args:
            shutdown_event: When set, the server stops accepting new connections
                and drains in-flight connections up to ``drain_timeout_seconds``
                before returning.  Used by the SIGTERM handler in ``main()``.
                If ``None`` the server runs until cancelled.
        """
        self.logger.info("Starting JA4 Proxy Server")

        # Phase 41: Robust Health API & Anti-Flap Logic
        if self.config["metrics"]["enabled"]:
            # Start Health/Metrics server (replaces simple prometheus_client server)
            await self.health_server.start()

            # Start background health check task (checks every 2s)
            async def _health_checker_loop():
                while True:
                    try:
                        await self.health_monitor.check()
                    except Exception as e:
                        self.logger.error(f"Error in health check loop: {e}")
                    await asyncio.sleep(2)

            self._health_task = asyncio.create_task(_health_checker_loop())

            # Log security warning if metrics exposed
            if (
                self.config["metrics"].get("bind_host", "0.0.0.0") == "0.0.0.0"
            ):  # nosec B104
                self.logger.warning(
                    "SECURITY WARNING: Health/Metrics endpoint exposed to all interfaces. "
                    "Restrict access using firewall rules or reverse proxy authentication."
                )

        # Phase 2: Initialize dial from Redis; reset to 0 if blocking_acknowledged=false
        initial_dial = await self._dial_manager.initialize(self.redis_client)
        self._local_cache.dial = initial_dial
        self.logger.info(
            '{"type":"system","level":"INFO","subsystem":"dial",'
            '"event":"dial_initialized","value":%s}',
            int(initial_dial),
        )
        
        # Phase 47: Initialize confidence manager
        _cm = getattr(self, "confidence_manager", None)
        if _cm:
            await _cm.initialize()
        # Phase 47: Initialize adaptive cache manager
        _ac = getattr(self, "adaptive_cache", None)
        if _ac:
            await _ac.initialize()

        # Phase 28b: Secure pub/sub for state updates (signed blacklist/dial/config)
        pubsub_handler = PubSubHandler(
            redis_client=self.redis_client,
            local_cache=self._local_cache,
            config_loader=self.config_loader,
            blacklist_set=self.pipeline._blacklist,
            whitelist_set=self.pipeline._whitelist,
            blocklist_manager=self.pipeline._blocklist_manager,
            signing_key=self.config.get("redis", {}).get("signing_key"),
        )
        self._pubsub_task = asyncio.create_task(pubsub_handler.run())

        # Phase 35: Start background integrity monitor
        _im = getattr(self, "_integrity_monitor", None)  # phase-35
        if _im is not None:  # phase-35
            _integrity_cfg = self.config.get("integrity", {})  # phase-35
            _monitor_paths = _integrity_cfg.get(  # phase-35
                "monitor_paths", ["proxy.py", "src/"]  # phase-35
            )  # phase-35
            _monitor_interval = _integrity_cfg.get("monitor_interval_s", 60)  # phase-35
            self._integrity_monitor_task = asyncio.create_task(  # phase-35
                _im.start_background_monitor(_monitor_paths, _monitor_interval)  # phase-35
            )  # phase-35
            self.logger.info(  # phase-35
                "integrity | event=monitor_started | paths=%s | interval=%d",  # phase-35
                _monitor_paths, _monitor_interval,  # phase-35
            )  # phase-35

        # Phase 56b: Dead-Man's Switch — self-terminates if integrity monitor goes silent
        from src.security.dead_man_switch import DeadManSwitch  # phase-56
        _dms_cfg = self.config.get("deception", {}).get("dead_man_switch", {})  # phase-56
        if _dms_cfg.get("enabled", False) and _im is not None:  # phase-56
            _dms = DeadManSwitch(  # phase-56
                integrity_monitor=_im,  # phase-56
                timeout_seconds=_dms_cfg.get("timeout_seconds", 300),  # phase-56
                grace_period_seconds=_dms_cfg.get("grace_period_seconds", 30),  # phase-56
            )  # phase-56
            self._dead_man_task = asyncio.create_task(_dms.run())  # phase-56
            self.logger.info(  # phase-56
                "integrity | event=dead_man_switch_armed | timeout=%d",  # phase-56
                _dms_cfg.get("timeout_seconds", 300),  # phase-56
            )  # phase-56

        # Phase 23: Start and wire TI providers
        ti_tasks = []
        _gn = getattr(self, "greynoise_provider", None)
        if _gn:
            ti_tasks.append(_gn.start())
        _av = getattr(self, "alienvault_provider", None)
        if _av:
            ti_tasks.append(_av.start())
        _misp = getattr(self, "misp_provider", None)
        if _misp:
            ti_tasks.append(_misp.start())
        _tf = getattr(self, "threatfox_provider", None)
        if _tf:
            ti_tasks.append(_tf.start())
        _vt = getattr(self, "virustotal_provider", None)
        if _vt:
            ti_tasks.append(_vt.start())
            
        if ti_tasks:
            await asyncio.gather(*ti_tasks)

        # Phase 59: Register per-feed health probes and start background probing
        _ti_cfg = self.config.get("threat_intelligence", {})
        _cb_fail = _ti_cfg.get("circuit_breaker_failure_threshold", 5)
        _cb_recovery = _ti_cfg.get("circuit_breaker_recovery_probe_interval", 60.0)
        _probe_interval = _ti_cfg.get("health_probe_interval_seconds", 30.0)
        _probe_session = self._aiohttp_session

        async def _http_probe(url: str, feed: str) -> float:
            import time as _t

            import aiohttp as _aiohttp
            t0 = _t.monotonic()
            async with _probe_session.head(url, timeout=_aiohttp.ClientTimeout(total=5)) as r:  # pylint: disable=not-async-context-manager
                if r.status >= 500:
                    raise RuntimeError(f"{feed} probe returned HTTP {r.status}")
            return _t.monotonic() - t0

        if getattr(self, "greynoise_provider", None) and self.greynoise_provider._config.enabled:
            self._feed_health_monitor.get_circuit_breaker("greynoise", _cb_fail, _cb_recovery)
            self._feed_health_monitor.register_probe(
                "greynoise",
                lambda: _http_probe("https://api.greynoise.io/ping", "greynoise"),
                _probe_interval,
            )
        if getattr(self, "alienvault_provider", None) and self.alienvault_provider._config.enabled:
            self._feed_health_monitor.get_circuit_breaker("alienvault_otx", _cb_fail, _cb_recovery)
            self._feed_health_monitor.register_probe(
                "alienvault_otx",
                lambda: _http_probe("https://otx.alienvault.com/api/v1/user/me", "alienvault_otx"),
                _probe_interval,
            )
        if getattr(self, "misp_provider", None) and self.misp_provider._config.enabled:
            _misp_base = self.misp_provider._config.base_url.rstrip("/")
            self._feed_health_monitor.get_circuit_breaker("misp", _cb_fail, _cb_recovery)
            self._feed_health_monitor.register_probe(
                "misp",
                lambda: _http_probe(f"{_misp_base}/users/login.json", "misp"),
                _probe_interval,
            )
        if getattr(self, "threatfox_provider", None) and self.threatfox_provider._config.enabled:
            self._feed_health_monitor.get_circuit_breaker("threatfox", _cb_fail, _cb_recovery)
            self._feed_health_monitor.register_probe(
                "threatfox",
                lambda: _http_probe("https://threatfox-api.abuse.ch/api/v1/", "threatfox"),
                _probe_interval,
            )
        # VirusTotal: no probe (quota-sensitive; no free health endpoint)
        if getattr(self, "virustotal_provider", None) and self.virustotal_provider._config.enabled:
            self._feed_health_monitor.get_circuit_breaker("virustotal", _cb_fail, _cb_recovery)

        await self._feed_health_monitor.start_probing()

        self.pipeline.set_ti_providers(
            greynoise=getattr(self, "greynoise_provider", None),
            alienvault=getattr(self, "alienvault_provider", None),
            misp=getattr(self, "misp_provider", None),
            threatfox=getattr(self, "threatfox_provider", None),
            virustotal=getattr(self, "virustotal_provider", None),
        )
        # Wire confidence manager into pipeline
        self.pipeline.set_confidence_manager(self.confidence_manager)

        # Start proxy server
        server = await asyncio.start_server(
            self.handle_connection,
            self.config["proxy"]["bind_host"],
            self.config["proxy"]["bind_port"],
            backlog=SERVER_BACKLOG,
        )

        bind_addr = (
            f"{self.config['proxy']['bind_host']}:{self.config['proxy']['bind_port']}"
        )
        self.logger.info(f"Proxy server listening on {bind_addr}")

        # Phase 56b: Apply runtime seccomp profile — narrower than startup profile.
        # Startup (Docker seccomp JSON) allows file loading and module imports;
        # runtime profile removes execve/fork/vfork once socket is bound and listening.
        # Fails open: if python-libseccomp is absent or the profile is malformed,
        # the proxy continues on the Docker-applied startup profile.
        try:  # phase-56
            from src.security.seccomp_transition import apply_runtime_seccomp, is_supported  # phase-56
            _sc_cfg = self.config.get("deception", {}).get("seccomp_transition", {})  # phase-56
            if _sc_cfg.get("enabled", True) and is_supported():  # phase-56
                _sc_profile = _sc_cfg.get(  # phase-56
                    "runtime_profile", "config/seccomp/proxy_runtime.json"  # phase-56
                )  # phase-56
                _sc_ok = apply_runtime_seccomp(_sc_profile)  # phase-56
                self.logger.info(  # phase-56
                    "seccomp | event=runtime_transition | applied=%s | profile=%s",  # phase-56
                    _sc_ok, _sc_profile,  # phase-56
                )  # phase-56
        except Exception as _sc_exc:  # phase-56
            self.logger.warning(  # phase-56
                "seccomp | event=transition_error | error=%s | effect=continuing",  # phase-56
                _sc_exc,  # phase-56
            )  # phase-56

        # Phase 14b: Shutdown watcher — stops the server when shutdown_event fires.
        # Runs concurrently with serve_forever(); cancels itself if serve_forever()
        # exits first (e.g. via CancelledError from a test).
        async def _shutdown_watcher() -> None:
            if shutdown_event is None:
                return
            await shutdown_event.wait()
            server.close()

        watcher_task: asyncio.Task = asyncio.create_task(_shutdown_watcher())

        # Phase 20 G0-A: start backup scheduler if configured
        backup_cfg = self.config.get("backup", {})
        if backup_cfg.get("enabled", False) and backup_cfg.get("schedule"):
            backup_worker = BackupWorker(
                redis_host=self.config["redis"]["host"],
                redis_port=self.config["redis"]["port"],
                redis_db=self.config["redis"].get("db", 0),
                max_keys_per_run=backup_cfg.get("max_keys_per_run", 1000),
            )
            self._backup_scheduler = BackupScheduler(backup_worker, backup_cfg)
            await self._backup_scheduler.start()

        try:
            async with server:
                await server.serve_forever()
        finally:
            watcher_task.cancel()
            if self._pubsub_task:
                self._pubsub_task.cancel()

            try:
                if self._pubsub_task:
                    await self._pubsub_task
                await watcher_task
            except asyncio.CancelledError:
                pass

            # Phase 35: Stop integrity monitor
            _imt = getattr(self, "_integrity_monitor_task", None)  # phase-35
            if _imt:  # phase-35
                _imt.cancel()  # phase-35
                try:  # phase-35
                    await _imt  # phase-35
                except asyncio.CancelledError:  # phase-35
                    pass  # phase-35

            # Phase 56b: Stop dead-man's switch watchdog
            _dmt = getattr(self, "_dead_man_task", None)  # phase-56
            if _dmt:  # phase-56
                _dmt.cancel()  # phase-56
                try:  # phase-56
                    await _dmt  # phase-56
                except asyncio.CancelledError:  # phase-56
                    pass  # phase-56

            # Phase 20 G0-A: stop backup scheduler
            if self._backup_scheduler is not None:
                await self._backup_scheduler.stop()

            # Phase 41: Stop health monitor and server
            if self._health_task:
                self._health_task.cancel()
            await self.health_server.stop()

            # Phase 59: Stop feed health probing before providers shut down
            await self._feed_health_monitor.stop_probing()

            # Phase 23: Stop TI providers
            stop_tasks = []
            _gn = getattr(self, "greynoise_provider", None)
            if _gn:
                stop_tasks.append(_gn.stop())
            _av = getattr(self, "alienvault_provider", None)
            if _av:
                stop_tasks.append(_av.stop())
            _misp = getattr(self, "misp_provider", None)
            if _misp:
                stop_tasks.append(_misp.stop())
            _tf = getattr(self, "threatfox_provider", None)
            if _tf:
                stop_tasks.append(_tf.stop())
            _vt = getattr(self, "virustotal_provider", None)
            if _vt:
                stop_tasks.append(_vt.stop())
                
            if stop_tasks:
                # Filter out None tasks if any stop() returned None
                stop_tasks = [t for t in stop_tasks if t is not None]
                if stop_tasks:
                    await asyncio.gather(*stop_tasks, return_exceptions=True)

            # Phase 47: Save confidence manager state
            _cm = getattr(self, "confidence_manager", None)
            if _cm:
                await _cm.save_state()

            # Phase 26e: Stop WriteBuffer and flush remaining writes
            await self.pipeline.stop()

            # Drain in-flight connections when a graceful shutdown was requested.
            if shutdown_event is not None and shutdown_event.is_set():
                drain_timeout = self.config.get("proxy", {}).get(
                    "drain_timeout_seconds", 30
                )
                initial_count = self.active_connections
                self.logger.info(
                    "proxy | event=shutdown_initiated | active_connections=%d",
                    initial_count,
                )
                deadline = time.monotonic() + drain_timeout
                while self.active_connections > 0 and time.monotonic() < deadline:
                    await asyncio.sleep(0.1)
                forced = self.active_connections
                self.logger.info(
                    "proxy | event=shutdown_complete | drained=%d | forced_close=%d",
                    initial_count - forced,
                    forced,
                )

            # Phase 10: Graceful shutdown of AbuseIPDB workers and aiohttp session
            if getattr(self, "_abuseipdb_checker", None) is not None:
                try:
                    await self._abuseipdb_checker.stop()
                except Exception as exc:
                    self.logger.warning(f"abuseipdb | event=stop_error | error={exc}")
            # Phase 11: Graceful shutdown of RDAP enricher workers
            if getattr(self, "_rdap_enricher", None) is not None:
                try:
                    await self._rdap_enricher.stop()
                except Exception as exc:
                    self.logger.warning(f"rdap | event=stop_error | error={exc}")
            if getattr(self, "_aiohttp_session", None) is not None:
                try:
                    await self._aiohttp_session.close()
                except Exception as exc:
                    self.logger.warning(f"aiohttp | event=close_error | error={exc}")

            # Phase 28a: Shutdown isolated TLS parsing executor
            if getattr(self, "executor", None) is not None:
                try:
                    self.executor.shutdown(wait=True)
                except Exception as exc:
                    self.logger.warning(
                        f"executor | event=shutdown_error | error={exc}"
                    )

    def _is_trusted_proxy_source(self, ip: str) -> bool:
        """Return True if the peer IP is allowed to provide PROXY/XFF headers.

        Controlled by proxy.upstream_trust:
            enabled: bool        — must be true to trust any header
            trusted_cidrs: list  — list of CIDR strings allowed to provide headers
        """
        trust_cfg = self.config.get("proxy", {}).get("upstream_trust", {})
        if not trust_cfg.get("enabled", False):
            return False

        trusted_cidrs = trust_cfg.get("trusted_cidrs", [])
        if not trusted_cidrs:
            return False

        try:
            addr = ipaddress.ip_address(ip)
            for cidr in trusted_cidrs:
                if addr in ipaddress.ip_network(cidr):
                    return True
        except (ValueError, TypeError):
            pass

        return False

    def _sanitize_log(self, text: Any) -> str:
        """Sanitize text for logging — strip every byte that could corrupt a log line.

        JA4PROXY-2026-0029 — the earlier implementation only escaped ``\\r``
        and ``\\n``. That left the door open for:

        * **NUL bytes** — truncate log lines in downstream syslog/journald
          pipelines, hiding later content on the same line.
        * **ANSI escape sequences** (``\\x1b[…]``) — hide, colour, or rewrite
          log entries in a terminal viewer, letting an attacker disguise a
          malicious SNI/IP as a harmless one.
        * **C0 / C1 controls** — form feed, vertical tab, DEL, etc. corrupt
          log-viewer state and can split a single entry across two records in
          line-oriented log pipelines.

        We replace every byte whose codepoint is below ``0x20`` (except
        ``\\t``) and the DEL byte (``0x7f``) with an escaped ``\\xHH`` form,
        and drop every C1 control (``0x80``–``0x9f``). Tabs pass through
        because they're part of legitimate structured-log formats.
        """
        if text is None:
            return ""
        s = str(text)
        out = []
        for ch in s:
            code = ord(ch)
            if ch == "\t":
                out.append(ch)
            elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
                out.append(f"\\x{code:02x}")
            else:
                out.append(ch)
        return "".join(out)

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle incoming client connection with PROXY protocol and JA4 security."""
        client_addr = writer.get_extra_info("peername")
        socket_ip = self._sanitize_log(client_addr[0]) if client_addr else "unknown"
        client_ip = socket_ip  # May be overridden by PROXY protocol

        self.active_connections += 1
        ACTIVE_CONNECTIONS.set(self.active_connections)

        # Get configurable timeouts
        connection_timeout = self.config["proxy"].get(
            "connection_timeout", DEFAULT_TIMEOUT
        )
        read_timeout = self.config["proxy"].get("read_timeout", DEFAULT_TIMEOUT)

        # Semaphore: cap concurrent handlers to prevent resource exhaustion
        async with self._conn_semaphore:
            try:
                # Read initial data with timeout
                request_start = time.time()
                data = await asyncio.wait_for(
                    reader.read(self.config["proxy"]["buffer_size"]),
                    timeout=read_timeout,
                )

                if not data:
                    self.logger.debug("Empty data from %s", socket_ip)
                    return

                # Phase 1: IP Spoofing Prevention
                # Parse PROXY protocol v2 header ONLY if source is trusted
                proxy_info: Dict[str, Any] = {}
                if self.config["proxy"].get(
                    "proxy_protocol", False
                ) and self._is_trusted_proxy_source(socket_ip):
                    proxy_info, data = self._parse_proxy_protocol(data, socket_ip)
                    client_ip = self._sanitize_log(
                        proxy_info.get("client_ip", socket_ip)
                    )

                # Fallback to X-Forwarded-For ONLY if source is trusted
                if client_ip == socket_ip and self._is_trusted_proxy_source(socket_ip):
                    extracted_ip = self._extract_client_ip_from_http(data)
                    if extracted_ip:
                        client_ip = self._sanitize_log(extracted_ip)

                self.logger.info(
                    "Connection from %s (socket: %s)", client_ip, socket_ip
                )

                # Analyze TLS handshake — extract JA4 fingerprint
                fingerprint = await asyncio.wait_for(
                    self._analyze_tls_handshake(data, client_ip),
                    timeout=connection_timeout,
                )
                ja4 = fingerprint.ja4

                # --- GeoIP lookup ---
                country = self.geoip.lookup(client_ip)
                fingerprint.geo_country = country

                # --- Dynamic country blacklist (Redis) — Phase 6 TODO: move into Pipeline ---
                # Added by ja4-admin block-country or auto-blocked by geoip-monitor.
                # Respects geoip:safe_countries — those can never enter the dynamic list.
                if country:
                    try:
                        if await self.redis_client.sismember(
                            "geoip:dynamic_blacklist", country
                        ):
                            self.logger.warning(
                                f"COUNTRY_DYNAMIC_BLOCKED: {client_ip} | Country: {country} | "
                                f"JA4: {ja4} | Name: {classify_ja4(ja4, self.config)}"
                            )
                            REQUEST_COUNT.labels(
                                fingerprint_name=classify_ja4(ja4, self.config),
                                action="blocked",
                                source_country=country,
                                tls_version=fingerprint.tls_version,
                            ).inc()
                            BLOCKED_REQUESTS.labels(
                                reason="country_dynamic_block",
                                source_country=country,
                                attack_type="geo_block",
                            ).inc()
                            return
                    except Exception:
                        pass  # fail open on Redis error

                # --- CIDR block check (Redis-backed, 30s cache) — Phase 6 TODO: move into Pipeline ---
                await self._refresh_cidr_blocks()
                matched_cidr = self._is_cidr_blocked(client_ip)
                if matched_cidr:
                    self.logger.warning(
                        f"CIDR_BLOCKED: {client_ip} | CIDR: {matched_cidr} | "
                        f"Country: {country or 'N/A'} | JA4: {ja4} | "
                        f"Name: {classify_ja4(ja4, self.config)}"
                    )
                    REQUEST_COUNT.labels(
                        fingerprint_name=classify_ja4(ja4, self.config),
                        action="blocked",
                        source_country=country or "",
                        tls_version=fingerprint.tls_version,
                    ).inc()
                    BLOCKED_REQUESTS.labels(
                        reason="cidr_block",
                        source_country=country or "",
                        attack_type="geo_block",
                    ).inc()
                    return

                # --- FAIL OPEN for unparseable TLS ---
                # If we couldn't extract a JA4 fingerprint (Scapy parse failure, non-TLS
                # protocol, or unusual TLS extension), pipeline scoring on "unknown"/"error"
                # adds no value. Forward and let the backend decide.
                if ja4 in ("unknown", "error"):
                    self.logger.info(
                        f"UNKNOWN_JA4: {client_ip} | Country: {country or 'N/A'} | "
                        f"Forwarding (TLS parse failed — fail open)"
                    )
                    REQUEST_COUNT.labels(
                        fingerprint_name="Unknown",
                        action="allowed",
                        source_country=country,
                        tls_version=fingerprint.tls_version,
                    ).inc()
                    await self._forward_to_backend(data, reader, writer, fingerprint)
                    return

                # --- Pipeline: bypass checks + signal collection + scoring + action ---
                # Generate JA4X if certificate info is available (Phase 16)
                ja4x = None
                # TODO: Extract certificate info from TLS session and generate JA4X
                # if certificate_info:
                #     ja4x = self.ja4_generator.generate_ja4x(
                #         certificate_info.get("issuer", ""),
                #         certificate_info.get("subject", ""),
                #         certificate_info.get("san", "")
                #     )

                ctx = ConnectionContext(
                    client_ip=client_ip,
                    ja4=ja4,
                    ja4x=ja4x,  # JA4X extended fingerprint (Phase 16)
                    country=country or None,
                    tls_version=fingerprint.tls_version_int or None,
                    cipher_list=fingerprint.raw_cipher_suites,
                    alpn=fingerprint.alpn_code or None,
                    sni=fingerprint.raw_sni or None,
                    tcp_ja4t=proxy_info.get("ja4t", ""),
                    tcp_window_size=proxy_info.get("window_size", 0),
                    tcp_ttl=proxy_info.get("ttl", 0),
                    tcp_options=proxy_info.get("tcp_options", ""),
                )
                result = await self.pipeline.process(ctx)

                # Phase 41: Record pipeline latency in health monitor
                request_duration = time.time() - request_start
                self.health_monitor.record_pipeline_latency(request_duration * 1000)

                # Record metrics
                REQUEST_DURATION.observe(request_duration)
                action_label = (
                    "allowed"
                    if result.action in ("allow", "flag", "rate_limit")
                    else "blocked"
                )
                REQUEST_COUNT.labels(
                    fingerprint_name=classify_ja4(ja4, self.config),
                    action=action_label,
                    source_country=fingerprint.geo_country,
                    tls_version=fingerprint.tls_version,
                ).inc()

                if result.action in ("allow", "flag", "rate_limit"):
                    await self._forward_to_backend(data, reader, writer, fingerprint)
                elif result.action == "tarpit":
                    BLOCKED_REQUESTS.labels(
                        reason="tarpit",
                        source_country=fingerprint.geo_country,
                        attack_type="tarpit",
                    ).inc()
                    await self._redirect_to_tarpit(data, reader, writer, client_ip)
                else:
                    # block | ban — drop connection
                    BLOCKED_REQUESTS.labels(
                        reason=result.action,
                        source_country=fingerprint.geo_country,
                        attack_type=result.action,
                    ).inc()
                    return

            except asyncio.TimeoutError:
                self.logger.warning(f"TIMEOUT: {client_ip} | Connection timed out")
                TLS_HANDSHAKE_ERRORS.labels(
                    error_type="timeout", tls_version="unknown"
                ).inc()
            except ValidationError as e:
                self.logger.warning(f"VALIDATION_ERROR: {client_ip} | {e}")
                SECURITY_EVENTS.labels(
                    event_type="validation_error", severity="warning", source=client_ip
                ).inc()
            except ssl.SSLError as e:
                error_msg = str(e)
                self.logger.warning(f"TLS_ERROR: {client_ip} | {error_msg}")
                error_type = "generic_ssl_error"
                if "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_msg:
                    error_type = "handshake_failure"
                elif "CERTIFICATE_VERIFY_FAILED" in error_msg:
                    error_type = "certificate_error"
                elif "WRONG_VERSION_NUMBER" in error_msg:
                    error_type = "protocol_version_error"
                TLS_HANDSHAKE_ERRORS.labels(
                    error_type=error_type, tls_version="unknown"
                ).inc()
                SECURITY_EVENTS.labels(
                    event_type="tls_handshake_error",
                    severity="warning",
                    source=client_ip,
                ).inc()
            except Exception as e:
                self.logger.error(f"ERROR: {client_ip} | {e}", exc_info=False)
                SECURITY_EVENTS.labels(
                    event_type="connection_error", severity="error", source=client_ip
                ).inc()
            finally:
                self.active_connections -= 1
                ACTIVE_CONNECTIONS.set(self.active_connections)
                if "client_ip" in locals():
                    await self.pipeline._tcp_analyzer.decrement_concurrent_connections(
                        client_ip
                    )
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    def _parse_proxy_protocol(
        self, data: bytes, fallback_ip: str
    ) -> tuple[dict, bytes]:
        """Parse PROXY protocol header to extract real client IP and TCP info."""
        # PROXY protocol v2 signature: 12 bytes
        PP2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

        info = {"client_ip": fallback_ip}

        if data[:12] == PP2_SIGNATURE and len(data) >= 16:
            # Version and command byte (data[12]) parsed but only family byte used
            family = data[13]
            addr_len = struct.unpack("!H", data[14:16])[0]
            header_len = 16 + addr_len

            if len(data) >= header_len:
                # Extract addresses based on address family
                if family == 0x11:  # AF_INET, STREAM
                    if addr_len >= 12:
                        info["client_ip"] = socket.inet_ntoa(data[16:20])
                elif family == 0x21:  # AF_INET6, STREAM
                    if addr_len >= 36:
                        info["client_ip"] = socket.inet_ntop(
                            socket.AF_INET6, data[16:32]
                        )

                remaining_data = data[header_len:]

                # Parse TLV fields for JA4T data.
                # TLVs live between end of fixed address block and header_len.
                # Fixed address block sizes: AF_INET=12 bytes, AF_INET6=36 bytes.
                _addr_block_len = (
                    12 if family == 0x11 else (36 if family == 0x21 else addr_len)
                )
                tlv_data = data[16 + _addr_block_len : header_len]
                idx = 0
                while idx < len(tlv_data):
                    tlv_type = tlv_data[idx]
                    idx += 1
                    if idx + 2 > len(tlv_data):
                        break
                    tlv_len = struct.unpack("!H", tlv_data[idx : idx + 2])[0]
                    idx += 2
                    if idx + tlv_len > len(tlv_data):
                        break

                    # For now, we only care about a few types for JA4T
                    if tlv_type == 0x04:  # PP2_TYPE_TCP_INFO
                        # This is a custom type we can use for JA4T components
                        # In a real scenario, you'd coordinate with your LB config
                        try:
                            # Example: pack ttl, window_size, and options
                            info["ttl"], info["window_size"] = struct.unpack(
                                "!BH", tlv_data[idx : idx + 3]
                            )
                            info["tcp_options"] = tlv_data[
                                idx + 3 : idx + tlv_len
                            ].hex()
                        except struct.error:
                            pass  # Ignore malformed TLV

                    idx += tlv_len

                return info, remaining_data

        # PROXY protocol v1 (text): "PROXY TCP4 src_ip dst_ip src_port dst_port\r\n"
        if data[:6] == b"PROXY ":
            try:
                newline = data.index(b"\r\n")
                header_line = data[:newline].decode("ascii")
                parts = header_line.split(" ")
                if len(parts) >= 3:
                    info["client_ip"] = parts[2]
                    remaining_data = data[newline + 2 :]
                    return info, remaining_data
            except (ValueError, UnicodeDecodeError):
                pass

        # No PROXY protocol header found
        return info, data

    def _extract_client_ip_from_http(self, data: bytes) -> str:
        """Extract client IP from HTTP X-Forwarded-For header (fallback for non-PP traffic)."""
        try:
            # Only parse if this looks like HTTP
            if data[:3] not in (b"GET", b"POS", b"PUT", b"DEL", b"HEA", b"PAT", b"OPT"):
                return ""
            header_block = data[:2048].decode("ascii", errors="ignore")
            for line in header_block.split("\r\n"):
                lower = line.lower()
                if lower.startswith("x-forwarded-for:"):
                    # JA4PROXY-2026-0006: take the RIGHTMOST XFF entry, not
                    # the leftmost. Each reverse proxy in the chain appends
                    # the IP it actually saw; the last entry is the one
                    # appended by our trusted upstream HAProxy and is the
                    # only value we can attribute to it. Taking [0] lets
                    # any client forge an arbitrary source IP.
                    ip = line.split(":", 1)[1].strip().split(",")[-1].strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        return ""
                elif lower.startswith("x-real-ip:"):
                    ip = line.split(":", 1)[1].strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        return ""
        except Exception:
            pass
        return ""

    async def _redirect_to_tarpit(
        self,
        data: bytes,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str = "unknown",
    ):
        """Redirect a blocked connection to the tarpit container.

        Phase 14c: Enforces a global concurrent cap and a per-IP cap so that a
        flood of tarpit-worthy connections cannot exhaust the tarpit container or
        consume unbounded memory.  When either cap is reached the configured
        overflow_action is taken (block | rst | allow).
        """
        # --- Phase 14c: cap enforcement -----------------------------------------
        cfg = self.config.get("tarpit", {})
        max_concurrent = cfg.get("max_concurrent_connections", 500)
        max_per_ip = cfg.get("max_per_ip", 3)
        overflow_action = cfg.get("overflow_action", "block")

        acquired = False
        async with self._tarpit_lock:
            over_global = self._tarpit_concurrent >= max_concurrent
            over_per_ip = self._tarpit_per_ip.get(client_ip, 0) >= max_per_ip
            if not over_global and not over_per_ip:
                self._tarpit_concurrent += 1
                self._tarpit_per_ip[client_ip] = (
                    self._tarpit_per_ip.get(client_ip, 0) + 1
                )
                _TARPIT_CONCURRENT.set(self._tarpit_concurrent)
                acquired = True

        if not acquired:
            _TARPIT_OVERFLOW.labels(action=overflow_action).inc()
            self.logger.info(
                "tarpit | event=overflow | ip=%s | action=%s",
                client_ip,
                overflow_action,
            )
            if overflow_action == "allow":
                await self._forward_to_backend(
                    data, client_reader, client_writer,
                    JA4Fingerprint(ja4="unknown", source_ip=client_ip),
                )
            else:
                # "block" or "rst": drop the connection
                try:
                    client_writer.close()
                except Exception:
                    pass
            return
        # -------------------------------------------------------------------------

        tarpit_writer = None
        try:
            tarpit_host = self.config["proxy"].get("tarpit_host", "tarpit")
            tarpit_port = self.config["proxy"].get("tarpit_port", 8888)

            tarpit_reader, tarpit_writer = await asyncio.wait_for(
                asyncio.open_connection(tarpit_host, tarpit_port), timeout=5
            )

            self.logger.info(f"Redirecting to tarpit at {tarpit_host}:{tarpit_port}")

            # Forward initial data to tarpit
            tarpit_writer.write(data)
            await tarpit_writer.drain()

            # Bidirectional forwarding (tarpit will trickle bytes back)
            await asyncio.gather(
                self._forward_data(client_reader, tarpit_writer, "client->tarpit"),
                self._forward_data(tarpit_reader, client_writer, "tarpit->client"),
                return_exceptions=True,
            )

        except Exception as e:
            self.logger.debug(f"Tarpit redirect ended: {e}")
        finally:
            if tarpit_writer is not None:
                try:
                    tarpit_writer.close()
                    await tarpit_writer.wait_closed()
                except Exception:
                    pass
            # Phase 14c: always decrement counters, even on abrupt disconnect
            async with self._tarpit_lock:
                self._tarpit_concurrent = max(0, self._tarpit_concurrent - 1)
                ip_count = self._tarpit_per_ip.get(client_ip, 0)
                if ip_count <= 1:
                    self._tarpit_per_ip.pop(client_ip, None)
                else:
                    self._tarpit_per_ip[client_ip] = ip_count - 1
                _TARPIT_CONCURRENT.set(self._tarpit_concurrent)

    async def _analyze_tls_handshake(
        self, data: bytes, client_ip: str
    ) -> JA4Fingerprint:
        """Analyze TLS handshake and generate fingerprint from raw TCP data."""
        try:
            ja4 = "unknown"
            tls_version = "unknown"
            tls_version_int = 0  # Phase 3: integer version for TLSEnforcer
            raw_cipher_suites: list = []  # Phase 3: raw cipher list for TLSEnforcer

            # The data is raw TCP stream, not IP-wrapped — check for TLS record header
            # TLS record: byte 0 = content type (0x16 = handshake), bytes 1-2 = version, bytes 3-4 = length
            if len(data) >= 5 and data[0] == 0x16:
                # Phase 65: Use pure-Python parser first (fast, direct call)
                from src.tls.parser import parse_client_hello
                client_hello_fields = parse_client_hello(data)

                # Fallback to Scapy in subprocess if pure-Python parser fails
                if client_hello_fields is None:
                    # JA4PROXY-2026-0033 — ThreadPoolExecutor provides no
                    # memory isolation (Phase 69 traded it for latency).
                    # Bound the input size and wall-clock time spent in the
                    # fallback parser so a crafted TLS record cannot
                    # monopolise a worker thread or run Scapy against a
                    # buffer that somehow grew past the read cap.
                    if len(data) > MAX_TLS_PARSER_INPUT_BYTES:
                        self.logger.debug(
                            "TLS parsing fallback skipped: input too large "
                            f"({len(data)} > {MAX_TLS_PARSER_INPUT_BYTES})"
                        )
                    else:
                        try:
                            loop = asyncio.get_running_loop()
                            client_hello_fields = await asyncio.wait_for(
                                loop.run_in_executor(
                                    self.executor, _parse_tls_task, data
                                ),
                                timeout=TLS_PARSER_TIMEOUT_SECONDS,
                            )
                        except asyncio.TimeoutError:
                            self.logger.debug(
                                "TLS parsing fallback timed out after "
                                f"{TLS_PARSER_TIMEOUT_SECONDS}s"
                            )
                        except Exception as e:
                            self.logger.debug(
                                f"TLS parsing fallback with Scapy failed: {e}"
                            )

                if client_hello_fields:
                    ja4 = self.ja4_generator.generate_ja4(client_hello_fields)
                    # Extract TLS version string
                    ver = client_hello_fields.get("version", 0)
                    supported = client_hello_fields.get("supported_versions", [])
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
                    # Phase 3: raw integer version and cipher list for TLSEnforcer
                    tls_version_int = 0x0304 if 0x0304 in supported else ver
                    raw_cipher_suites = client_hello_fields.get("cipher_suites", [])
            else:
                # Not a TLS record — might be HTTP or other protocol.
                # JA4PROXY-2026-0005: previously we called
                # _extract_ja4_from_http() here and used whatever the client
                # put in an X-JA4-Fingerprint HTTP header as the connection's
                # JA4. An attacker could then send a whitelisted JA4 value in
                # plain HTTP and bypass every JA4-based control. The header
                # is now ignored; JA4 stays "unknown" on non-TLS traffic.
                self.logger.debug(
                    f"Non-TLS data from {client_ip} (first byte: 0x{data[0]:02x})"
                )

            fingerprint = JA4Fingerprint(
                ja4=ja4,
                # Phase 65: Only hash the first 64 bytes for the log field (5x faster)
                client_hello_hash=hashlib.sha256(data[:64]).hexdigest()[:16],
                timestamp=time.time(),
                source_ip=client_ip,
                tls_version=tls_version,
                tls_version_int=tls_version_int,
                raw_cipher_suites=raw_cipher_suites,
            )

            # Store fingerprint in Redis
            await self._store_fingerprint(fingerprint)

            return fingerprint

        except Exception as e:
            self.logger.error(f"Error analyzing TLS handshake: {e}")
            return JA4Fingerprint(
                ja4="error", source_ip=client_ip, timestamp=time.time()
            )

    def _extract_ja4_from_http(self, data: bytes) -> str:
        """Deprecated. Always returns "unknown".

        JA4PROXY-2026-0005: this function used to read an
        ``X-JA4-Fingerprint`` HTTP header and return it as the connection's
        JA4 fingerprint. Because the header is attacker-controlled, any
        client could assert a whitelisted JA4 in plain HTTP and bypass
        every JA4-based control. The lookup has been removed; the function
        is kept only so callers in tests keep a stable API. It now always
        returns "unknown".
        """
        return "unknown"

    async def _store_fingerprint(self, fingerprint: JA4Fingerprint):
        """Store fingerprint data in Redis."""
        try:
            key = (
                f"ja4:fingerprint:{fingerprint.source_ip}:{int(fingerprint.timestamp)}"
            )
            data = {
                "ja4": fingerprint.ja4,
                "client_hello_hash": fingerprint.client_hello_hash,
                "timestamp": fingerprint.timestamp,
                "source_ip": fingerprint.source_ip,
            }

            await self.redis_client.hset(key, mapping=data)
            await self.redis_client.expire(key, 3600)  # 1 hour TTL

        except Exception as e:
            self.logger.error(f"Error storing fingerprint: {e}")

    async def _forward_to_backend(
        self,
        initial_data: bytes,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        fingerprint: JA4Fingerprint,
    ):
        """Forward connection to backend server."""
        backend_writer = None
        try:
            # JA4PROXY-2026-0028 — bound the backend TCP connect so a slow or
            # unresponsive backend can't tie up handler coroutines for the
            # default OS TCP timeout (~2 minutes). Without this, a backend
            # under separate load would let any attacker exhaust the event
            # loop simply by opening connections. Matches the tarpit redirect
            # bound (5s) by default; operators can tune via
            # proxy.backend_connect_timeout_seconds.
            connect_timeout = float(
                self.config["proxy"].get("backend_connect_timeout_seconds", 5)
            )
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config["proxy"]["backend_host"],
                    int(self.config["proxy"]["backend_port"]),
                ),
                timeout=connect_timeout,
            )

            self.logger.info(f"Forwarding connection with JA4: {fingerprint.ja4}")

            # Send initial data to backend
            backend_writer.write(initial_data)
            await backend_writer.drain()

            # Start bidirectional forwarding
            await asyncio.gather(
                self._forward_data(client_reader, backend_writer, "client->backend"),
                self._forward_data(backend_reader, client_writer, "backend->client"),
                return_exceptions=True,
            )

        except asyncio.TimeoutError:
            # JA4PROXY-2026-0028 — log distinctly so operators can page on
            # sustained backend-connect timeouts (separate from arbitrary
            # forward errors).
            self.logger.warning(
                "backend connect timed out after %ss (host=%s port=%s)",
                connect_timeout,
                self.config["proxy"]["backend_host"],
                self.config["proxy"]["backend_port"],
            )
        except Exception as e:
            self.logger.error(f"Error forwarding to backend: {e}")
        finally:
            if backend_writer is not None:
                try:
                    backend_writer.close()
                    await backend_writer.wait_closed()
                except Exception:
                    pass

    async def _forward_data(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str
    ):
        """Forward data between client and backend."""
        try:
            while True:
                data = await reader.read(self.config["proxy"]["buffer_size"])
                if not data:
                    break

                writer.write(data)
                await writer.drain()

        except Exception as e:
            self.logger.debug(f"Connection closed ({direction}): {e}")


def _luhn_check(digits: str) -> bool:
    """Return True iff ``digits`` (pure-digit string) passes the Luhn mod-10
    checksum used by real credit card numbers.

    JA4PROXY-2026-0039: a bare ``\\d{13,19}`` pattern matches Unix
    timestamps in milliseconds (13 digits), large counters, Redis keys,
    and many JA4 fingerprints — corrupting operational logs with
    ``***CARD_REDACTED***`` placeholders. Real PANs always satisfy
    Luhn, so gating the redaction on Luhn success drops the false-
    positive rate to ~1-in-10 for random digit runs while still
    catching real card numbers.
    """
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        value = ord(ch) - 48  # '0' == 48
        if idx % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_card_if_luhn(match: "re.Match[str]") -> str:
    """Re.sub callback: redact only when the captured run passes Luhn.

    JA4PROXY-2026-0039: keeps timestamps and other long-digit-runs
    intact in logs so operators can debug without secondary corruption.
    """
    digits = match.group(1)
    return "***CARD_REDACTED***" if _luhn_check(digits) else digits


class SensitiveDataFilter(logging.Filter):
    """Filter to prevent logging of sensitive data (SECURITY FIX)."""

    def __init__(self):
        super().__init__()
        # Patterns to redact from logs. Each entry is (compiled-regex,
        # replacement) where replacement is either a string (plain
        # substitution) or a callable taking an ``re.Match`` — re.sub
        # accepts both natively.
        self.sensitive_patterns = [
            (
                re.compile(
                    r'password["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE
                ),
                "password=***REDACTED***",
            ),
            (
                re.compile(
                    r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE
                ),
                "api_key=***REDACTED***",
            ),
            (
                re.compile(r'token["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE),
                "token=***REDACTED***",
            ),
            (
                re.compile(r'secret["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)', re.IGNORECASE),
                "secret=***REDACTED***",
            ),
            (
                re.compile(r"authorization:\s*Bearer\s+(\S+)", re.IGNORECASE),
                "Authorization: Bearer ***REDACTED***",
            ),
            (
                # JA4PROXY-2026-0039: word-boundary + Luhn gate so the
                # filter only redacts strings that are plausibly real
                # card numbers, not random 13-19 digit runs.
                re.compile(r"\b(\d{13,19})\b"),
                _redact_card_if_luhn,
            ),
            (
                re.compile(
                    r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE
                ),
                "***EMAIL_REDACTED***",
            ),
        ]

    def filter(self, record):
        """Filter sensitive data from log records."""
        if hasattr(record, "msg"):
            msg = str(record.msg)
            for pattern, replacement in self.sensitive_patterns:
                msg = pattern.sub(replacement, msg)
            record.msg = msg

        # Also filter from args
        if hasattr(record, "args") and record.args:
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
        if not hasattr(record, "event_type"):
            record.event_type = "general"

        # Sanitize exception info to prevent stack trace leakage in production
        if record.exc_info and os.getenv("ENVIRONMENT") == "production":
            # In production, only log exception type, not full traceback
            exc_type, exc_value, exc_tb = record.exc_info
            record.exc_text = f"{exc_type.__name__}: {str(exc_value)}"
            record.exc_info = None

        return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON log formatter for SIEM integration (Phase 14a).

    Emits one JSON object per log line. SensitiveDataFilter must run before
    this formatter — it operates on the LogRecord fields so that getMessage()
    already returns a filtered string.

    Output shape::

        {"timestamp":"2026-03-15T14:30:01.234Z","level":"INFO",
         "subsystem":"proxy","message":"connection allowed | ip=1.2.3.4"}
    """

    def format(self, record: logging.LogRecord) -> str:
        # In production: replace full traceback with type:message only
        if record.exc_info and os.getenv("ENVIRONMENT") == "production":
            exc_type, exc_value, _ = record.exc_info
            record.exc_text = f"{exc_type.__name__}: {str(exc_value)}"
            record.exc_info = None
        elif record.exc_info and not record.exc_text:
            # In development: format full traceback into exc_text
            record.exc_text = self.formatException(record.exc_info)

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
        # ISO-8601 millisecond precision with Z suffix
        timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

        entry: dict = {
            "timestamp": timestamp,
            "level": record.levelname,
            "subsystem": record.name,
            "message": record.getMessage(),
        }
        if record.exc_text:
            entry["exception"] = record.exc_text

        return json.dumps(entry, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Phase 68c: Event loop policy selection
# ---------------------------------------------------------------------------


def _install_event_loop() -> None:
    """Install uvloop event loop policy if available (Linux + Python >= 3.14).

    Falls back gracefully to the default asyncio event loop policy when
    uvloop is not installed or import fails. Controlled by
    ``runtime.event_loop`` in config/proxy.yml (informational only — the
    actual switch is purely availability-based here).

    Must be called before the event loop is started (i.e. before asyncio.run()).
    Calling inside an already-running coroutine has no effect on the current
    loop but will apply to any subsequent asyncio.run() calls in the same process.
    """
    _logger = logging.getLogger(__name__)
    try:
        import uvloop  # type: ignore[import-untyped]

        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        _logger.info("proxy | event=event_loop_policy | loop=uvloop")
    except ImportError:
        _logger.info("proxy | event=event_loop_policy | loop=asyncio_default")


async def main():
    """Main entry point.

    Reads ``proxy.mode`` from the config file to dispatch between
    passthrough proxy mode (default) and TAP/SPAN passive capture mode.
    Registers SIGTERM and SIGINT handlers for graceful shutdown.
    """
    import sys

    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/proxy.yml"

    # Early config read — used only for mode dispatch.
    # ProxyServer.create() does its own full config load below.
    try:
        with open(config_path, "r") as _f:
            _raw_cfg = yaml.safe_load(_f) or {}
    except (OSError, yaml.YAMLError):
        _raw_cfg = {}

    mode = (_raw_cfg.get("proxy") or {}).get("mode", "passthrough")

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_shutdown() -> (
        None
    ):  # pragma: no cover — signal path not exercised in unit tests
        if not shutdown_event.is_set():
            shutdown_event.set()

    try:
        loop.add_signal_handler(signal.SIGTERM, _handle_shutdown)
        loop.add_signal_handler(signal.SIGINT, _handle_shutdown)
    except (NotImplementedError, ValueError):  # pragma: no cover — Windows
        pass

    match mode:
        case "passthrough":
            proxy = await ProxyServer.create(config_path)
            try:
                await proxy.start(shutdown_event=shutdown_event)
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass  # Clean shutdown already handled via shutdown_event drain path
            except Exception as e:
                logging.error(f"Fatal error: {e}")
                sys.exit(1)
        case "tap":
            sensor = TapSensor(_raw_cfg, None)
            try:
                await sensor.run()
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
        case _:
            logging.critical("startup | event=invalid_mode | mode=%r -- exiting", mode)
            sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    # Emit a loud startup banner so operators cannot accidentally deploy
    # the Python prototype thinking it is the production Go proxy.
    # Suppress with JA4PROXY_PYTHON_EXPERIMENTAL_ACK=1 for intentional runs.
    if os.environ.get("JA4PROXY_PYTHON_EXPERIMENTAL_ACK") != "1":
        import sys as _sys
        _banner = (
            "\n"
            "================================================================\n"
            "  JA4proxy Python proxy — EXPERIMENTAL PROTOTYPE\n"
            "================================================================\n"
            "  The production proxy is the Go binary (bin/proxy, Phase 15+).\n"
            "  This Python implementation is retained for experimentation\n"
            "  and signal-module prototyping only.  DO NOT DEPLOY THIS FILE\n"
            "  IN PRODUCTION.\n"
            "\n"
            "  To acknowledge and run anyway, set:\n"
            "      JA4PROXY_PYTHON_EXPERIMENTAL_ACK=1\n"
            "================================================================\n"
        )
        print(_banner, file=_sys.stderr, flush=True)
    _install_event_loop()  # Must be before asyncio.run() to take effect
    asyncio.run(main())
