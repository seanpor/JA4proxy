# JA4proxy Security Fix Plan
## Phased Approach to Security Remediation

**Date:** 2026-02-14  
**Status:** READY FOR IMPLEMENTATION  
**Total Issues:** 32 vulnerabilities across 4 severity levels

---

## Overview

This document outlines the phased approach to fixing all identified security vulnerabilities in JA4proxy. Each phase is designed to be completed independently with full testing before moving to the next phase.

---

## Phase 1: Critical Infrastructure Security (Week 1)

**Goal:** Fix vulnerabilities that could lead to immediate system compromise

### Fix 1.1: Secure Password Management
**Vulnerability:** CRIT-1 - Hardcoded default Redis password

**Files to modify:**
- `docker-compose.poc.yml`
- `docker-compose.prod.yml`
- `quick-start.sh`
- `config/proxy.yml`

**Changes:**
1. Remove all default password fallbacks:
```yaml
# BEFORE
environment:
  - REDIS_PASSWORD=${REDIS_PASSWORD:-changeme}

# AFTER  
environment:
  - REDIS_PASSWORD=${REDIS_PASSWORD}
```

2. Add startup validation in `quick-start.sh`:
```bash
# Generate strong password (32+ chars, alphanumeric + symbols)
export REDIS_PASSWORD=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-32)

# Validate password strength
if [ ${#REDIS_PASSWORD} -lt 32 ]; then
    echo "ERROR: Redis password must be at least 32 characters"
    exit 1
fi
```

3. Add validation in `proxy.py`:
```python
def _validate_redis_password(self, password: str) -> None:
    """Validate Redis password meets security requirements."""
    if not password or len(password) < 32:
        raise SecurityError("Redis password must be at least 32 characters")
    
    # Check complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        raise SecurityError("Redis password must contain uppercase, lowercase, digits, and special characters")
```

**Testing:**
- Unit test: Password validation function
- Integration test: Redis connection with strong password
- Negative test: Reject weak passwords
- Regression test: Ensure startup fails without password

---

### Fix 1.2: Docker Secrets Migration
**Vulnerability:** CRIT-2 - Environment variable secret exposure

**Files to modify:**
- `docker-compose.poc.yml`
- `docker-compose.prod.yml`
- `proxy.py` (ConfigManager class)
- New file: `secrets/redis_password.txt.example`

**Changes:**
1. Create secrets in docker-compose:
```yaml
services:
  proxy:
    secrets:
      - redis_password
      - metrics_password
    environment:
      # Remove all password env vars
      - ENVIRONMENT=production

secrets:
  redis_password:
    file: ./secrets/redis_password.txt
  metrics_password:
    file: ./secrets/metrics_password.txt
```

2. Update `proxy.py` to read secrets from files:
```python
def _load_secret(self, secret_name: str) -> str:
    """Load secret from Docker secrets or file."""
    # Try Docker secrets first
    secret_path = Path(f"/run/secrets/{secret_name}")
    if secret_path.exists():
        return secret_path.read_text().strip()
    
    # Fall back to secrets directory (development)
    dev_secret_path = Path(f"secrets/{secret_name}.txt")
    if dev_secret_path.exists():
        return dev_secret_path.read_text().strip()
    
    raise SecurityError(f"Secret not found: {secret_name}")

def _init_redis(self) -> redis.Redis:
    redis_config = self.config['redis']
    
    # Load password from secret file
    password = self._load_secret('redis_password')
    
    # Validate password
    self._validate_redis_password(password)
    
    # Create connection with secret
    redis_client = redis.Redis(
        host=redis_config['host'],
        port=redis_config['port'],
        password=password,
        ...
    )
```

3. Create secret generation script `scripts/generate-secrets.sh`:
```bash
#!/bin/bash
set -e

SECRETS_DIR="./secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Generate Redis password
openssl rand -base64 48 | tr -d "=+/" | cut -c1-32 > "$SECRETS_DIR/redis_password.txt"
chmod 600 "$SECRETS_DIR/redis_password.txt"

# Generate metrics password
openssl rand -base64 48 | tr -d "=+/" | cut -c1-32 > "$SECRETS_DIR/metrics_password.txt"
chmod 600 "$SECRETS_DIR/metrics_password.txt"

echo "✅ Secrets generated successfully in $SECRETS_DIR"
echo "⚠️  IMPORTANT: Add secrets/ to .gitignore"
echo "⚠️  IMPORTANT: Set proper file permissions (600)"
```

**Testing:**
- Unit test: Secret loading from files
- Integration test: Docker secrets mounting
- Security test: Verify secrets not in environment
- Negative test: Fail if secrets missing

---

### Fix 1.3: Backend TLS Validation
**Vulnerability:** CRIT-3 - Missing TLS certificate validation

**Files to modify:**
- `proxy.py` (_forward_to_backend method)
- `config/proxy.yml`

**Changes:**
1. Add TLS configuration options:
```yaml
# config/proxy.yml
proxy:
  backend_host: "127.0.0.1"
  backend_port: 443
  backend_tls:
    enabled: true
    verify: true
    ca_bundle: "/etc/ssl/certs/ca-certificates.crt"
    client_cert: null  # Optional mTLS
    client_key: null
    hostname_check: true
    min_tls_version: "TLSv1.2"
```

2. Implement secure backend connection:
```python
async def _forward_to_backend(self, initial_data: bytes, client_reader, 
                              client_writer, fingerprint):
    """Forward connection to backend with TLS validation."""
    backend_config = self.config['proxy'].get('backend_tls', {})
    
    if backend_config.get('enabled', False):
        # Create SSL context
        ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=backend_config.get('ca_bundle')
        )
        
        # Set minimum TLS version
        min_version = backend_config.get('min_tls_version', 'TLSv1.2')
        ssl_context.minimum_version = getattr(ssl.TLSVersion, min_version.upper())
        
        # Configure verification
        if backend_config.get('verify', True):
            ssl_context.check_hostname = backend_config.get('hostname_check', True)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            self.logger.warning("SECURITY: Backend TLS verification disabled!")
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Load client certificate for mTLS
        if backend_config.get('client_cert') and backend_config.get('client_key'):
            ssl_context.load_cert_chain(
                certfile=backend_config['client_cert'],
                keyfile=backend_config['client_key']
            )
        
        # Connect with TLS
        try:
            backend_reader, backend_writer = await asyncio.open_connection(
                self.config['proxy']['backend_host'],
                self.config['proxy']['backend_port'],
                ssl=ssl_context,
                server_hostname=self.config['proxy']['backend_host']
            )
        except ssl.SSLError as e:
            self.logger.error(f"Backend TLS validation failed: {e}")
            TLS_HANDSHAKE_ERRORS.labels(
                error_type='backend_tls_error',
                tls_version='unknown'
            ).inc()
            raise SecurityError(f"Backend TLS validation failed: {e}")
    else:
        # Plaintext connection (only for development)
        if os.getenv('ENVIRONMENT') == 'production':
            raise SecurityError("Backend TLS required in production")
        
        self.logger.warning("SECURITY: Backend connection without TLS!")
        backend_reader, backend_writer = await asyncio.open_connection(
            self.config['proxy']['backend_host'],
            self.config['proxy']['backend_port']
        )
    
    # Rest of forwarding logic...
```

**Testing:**
- Unit test: SSL context creation
- Integration test: TLS connection to test backend
- Security test: Reject invalid certificates
- Negative test: Fail on certificate mismatch
- mTLS test: Client certificate authentication

---

### Fix 1.4: Request Size Limits
**Vulnerability:** CRIT-4 - Missing input size limits

**Files to modify:**
- `proxy.py` (handle_connection method)

**Changes:**
1. Implement connection-level size tracking:
```python
class ConnectionTracker:
    """Track connection resource usage."""
    
    def __init__(self, max_size: int, max_duration: int):
        self.max_size = max_size
        self.max_duration = max_duration
        self.bytes_read = 0
        self.start_time = time.time()
    
    def track_read(self, data_size: int) -> None:
        """Track bytes read and enforce limits."""
        self.bytes_read += data_size
        
        if self.bytes_read > self.max_size:
            raise SecurityError(f"Request size limit exceeded: {self.bytes_read}/{self.max_size}")
        
        elapsed = time.time() - self.start_time
        if elapsed > self.max_duration:
            raise SecurityError(f"Connection duration limit exceeded: {elapsed}/{self.max_duration}")

async def handle_connection(self, reader, writer):
    """Handle connection with size limits."""
    client_addr = writer.get_extra_info('peername')
    client_ip = client_addr[0] if client_addr else "unknown"
    
    # Create tracker
    tracker = ConnectionTracker(
        max_size=MAX_REQUEST_SIZE,  # 1MB
        max_duration=self.config['proxy'].get('max_connection_duration', 300)  # 5 min
    )
    
    self.active_connections += 1
    ACTIVE_CONNECTIONS.set(self.active_connections)
    
    try:
        buffer_size = self.config['proxy']['buffer_size']
        all_data = bytearray()
        
        # Read with cumulative size tracking
        while True:
            chunk = await asyncio.wait_for(
                reader.read(buffer_size),
                timeout=self.config['proxy']['read_timeout']
            )
            
            if not chunk:
                break
            
            # Track size before processing
            tracker.track_read(len(chunk))
            all_data.extend(chunk)
            
            # Check if we have complete TLS handshake
            if len(all_data) >= 5:  # Minimum TLS record size
                # Try to parse
                try:
                    fingerprint = await self._analyze_tls_handshake(bytes(all_data), client_ip)
                    break  # Got complete handshake
                except Exception:
                    # Need more data
                    continue
        
        if not all_data:
            self.logger.debug(f"No data from {client_ip}")
            return
        
        # Continue with security checks...
```

**Testing:**
- Unit test: ConnectionTracker limits
- Integration test: Large request rejection
- Performance test: No impact on normal requests
- DoS test: Multiple large requests

---

### Fix 1.5: Atomic Rate Limiting
**Vulnerability:** CRIT-5 - Race condition in rate limiting

**Files to modify:**
- `proxy.py` (SecurityManager._check_rate_limit)

**Changes:**
1. Implement Lua-based atomic rate limiting:
```python
class SecurityManager:
    """Security policy enforcement with atomic operations."""
    
    def __init__(self, config: Dict, redis_client: redis.Redis):
        self.config = config
        self.redis = redis_client
        self.logger = logging.getLogger(__name__)
        
        # Register Lua script for atomic rate limiting
        self.rate_limit_script = self.redis.register_script("""
            local key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local current_time = tonumber(ARGV[3])
            
            -- Use sorted set for sliding window
            local window_start = current_time - window
            
            -- Remove old entries
            redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
            
            -- Count current entries
            local current = redis.call('ZCARD', key)
            
            if current < limit then
                -- Add new entry
                redis.call('ZADD', key, current_time, current_time)
                redis.call('EXPIRE', key, window)
                return 1  -- Allowed
            else
                return 0  -- Rate limit exceeded
            end
        """)
        
        self._load_security_lists()
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check rate limiting using atomic Lua script."""
        window = self.config['security'].get('rate_limit_window', 60)
        max_requests = self.config['security'].get('max_requests_per_minute', 100)
        
        key = f"rate_limit:{client_ip}"
        current_time = time.time()
        
        try:
            # Execute atomic rate limit check
            result = self.rate_limit_script(
                keys=[key],
                args=[max_requests, window, current_time]
            )
            
            if result == 0:
                self.logger.warning(f"Rate limit exceeded for IP {client_ip}")
                SECURITY_EVENTS.labels(
                    event_type='rate_limit_exceeded',
                    severity='warning',
                    source=client_ip
                ).inc()
                return False
            
            return True
            
        except redis.ConnectionError as e:
            # Fail closed on Redis errors
            self.logger.error(f"Rate limit check failed - Redis error: {e}")
            SECURITY_EVENTS.labels(
                event_type='rate_limit_error',
                severity='critical',
                source='redis'
            ).inc()
            return False
        
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {e}", exc_info=True)
            return False  # Fail closed
```

**Testing:**
- Unit test: Lua script logic
- Integration test: Rate limit enforcement
- Concurrency test: Parallel requests don't bypass limit
- Redis test: Atomic operations verified
- Failover test: Fail closed on Redis errors

---

## Phase 1 Testing & Validation

After completing all Phase 1 fixes:

1. **Run full test suite:**
```bash
pytest tests/ -v --cov=proxy --cov-report=html
```

2. **Security validation:**
```bash
# Check for hardcoded secrets
bandit -r proxy.py -ll

# Verify no passwords in environment
docker inspect ja4proxy | grep -i password
# Should return nothing

# Test rate limiting
./tests/security/test_rate_limit_race.py

# Test TLS validation
./tests/security/test_backend_tls.py
```

3. **Integration tests:**
```bash
./quick-start.sh --test
```

4. **Documentation update:**
- Update README.md with security fixes
- Update CHANGELOG.md
- Add SECURITY.md with disclosure policy

---

## Phase 2: High Severity Fixes (Week 2)

### Fix 2.1: Secure Metrics Endpoint
**Vulnerability:** HIGH-1

**Changes:**
1. Add nginx reverse proxy configuration
2. Implement basic auth for metrics
3. Bind metrics to 127.0.0.1 by default
4. Add mTLS support for metrics scraping

**Files:**
- New: `monitoring/nginx-metrics-proxy.conf`
- Modify: `config/proxy.yml`
- Modify: `docker-compose.prod.yml`

---

### Fix 2.2: Enhanced Logging Security
**Vulnerability:** HIGH-2

**Changes:**
1. Add comprehensive sensitive data patterns
2. Implement structured logging
3. Add GDPR-compliant log sanitization
4. Implement log rotation and retention

**Files:**
- Modify: `proxy.py` (SensitiveDataFilter class)
- New: `logging_config.yml`

---

### Fix 2.3: Docker Hardening
**Vulnerability:** HIGH-3

**Changes:**
1. Enable read-only root filesystem
2. Drop unnecessary capabilities
3. Add custom seccomp profile
4. Implement AppArmor profile

**Files:**
- Modify: `Dockerfile`
- New: `security/seccomp-profile.json`
- New: `security/apparmor-profile`

---

### Fix 2.4: Isolate Packet Processing
**Vulnerability:** HIGH-4

**Changes:**
1. Move Scapy to separate container
2. Add input validation before parsing
3. Implement parsing timeouts
4. Add sandboxing for packet analysis

**Files:**
- New: `packet-parser/Dockerfile`
- New: `packet-parser/parser-service.py`
- Modify: `docker-compose.prod.yml`

---

### Fix 2.5: Comprehensive Timeout Management
**Vulnerability:** HIGH-5

**Changes:**
1. Add request-level timeout wrapper
2. Implement connection idle tracking
3. Add max connection duration
4. Implement graceful connection cleanup

**Files:**
- Modify: `proxy.py` (ProxyServer class)

---

### Fix 2.6: Redis Connection Pooling
**Vulnerability:** HIGH-6

**Changes:**
1. Configure connection pool with limits
2. Add keepalive settings
3. Implement connection monitoring
4. Add pool metrics

**Files:**
- Modify: `proxy.py` (_init_redis method)

---

## Phase 3: Medium Severity (Week 3-4)

All MED-1 through MED-11 issues will be addressed:
- JA4 validation improvements
- Configuration security
- YAML bomb protection
- Timestamp validation
- IP validation enhancements
- Secure random validation
- Redis operation atomicity
- Audit log integrity
- Metrics cardinality
- Process hardening
- Configuration schema

---

## Phase 4: Low Severity & Infrastructure (Week 5)

All LOW-1 through LOW-7 issues:
- Dependency management
- Supply chain security
- Security documentation
- Rate limit headers
- Certificate monitoring
- Security automation

---

## Phase 5: Testing & Validation (Week 6)

1. Comprehensive security testing
2. Penetration testing
3. Performance regression testing
4. Documentation review
5. Compliance validation
6. Final security audit

---

## Success Criteria

Each phase must meet these criteria before moving to next phase:

1. ✅ All fixes implemented with code review
2. ✅ Unit tests passing (>90% coverage)
3. ✅ Integration tests passing
4. ✅ Security tests passing
5. ✅ No new vulnerabilities introduced
6. ✅ Performance benchmarks met
7. ✅ Documentation updated
8. ✅ CHANGELOG updated

---

## Risk Mitigation

**Rollback Plan:** Each phase will be in a separate branch with full rollback capability

**Testing Strategy:** Progressive testing with increasing security rigor

**Deployment Strategy:** Phased rollout with monitoring

---

**Do you want me to proceed with implementing Phase 1 fixes?**
