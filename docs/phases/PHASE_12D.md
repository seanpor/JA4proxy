# Phase 12d — Security Hardening

## Goal
Comprehensive security hardening of the analytics node to prevent poisoning, ensure data integrity, and protect against various attack vectors.

## Threat Model

### 12d.1 Attack Vectors

**1. Event Poisoning:**
- Malicious proxy instance sends fake events
- Compromised proxy sends manipulated data
- Replay attacks with old events

**2. Data Tampering:**
- Man-in-the-middle attacks on Redis communication
- Unauthorized access to Redis data
- Event stream manipulation

**3. Denial of Service:**
- Flooding analytics node with events
- Resource exhaustion attacks
- Algorithm complexity attacks

**4. Privilege Escalation:**
- Analytics node compromise → Redis access
- Redis access → proxy configuration manipulation
- Data exfiltration through analytics

## Security Architecture

### 12d.2 Defense in Depth

```
[Proxy] → [Event Validation] → [Authentication] → [Rate Limiting] → [Analytics]
                     ↓
               [Audit Logging] → [SIEM]
                     ↓
               [Alerting] → [SOC]
```

## Event Validation & Sanitization

### 12d.3 Schema Enforcement

**Strict Validation:**
```python
EVENT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Analytics Event",
    "description": "Validated event from proxy instance",
    "type": "object",
    "required": ["timestamp", "src_ip", "ja4", "action", "score", "proxy_id", "hmac"],
    "properties": {
        "timestamp": {
            "type": "number",
            "minimum": 0,
            "maximum": 9999999999
        },
        "src_ip": {
            "type": "string",
            "pattern": "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",
            "maxLength": 45
        },
        "ja4": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_\-]{1,64}$",
            "maxLength": 64
        },
        "action": {
            "type": "string",
            "enum": ["allow", "block", "monitor", "tarpit"]
        },
        "score": {
            "type": "number",
            "minimum": 0,
            "maximum": 100
        },
        "proxy_id": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9\-]{1,32}$"
        },
        "hmac": {
            "type": "string",
            "pattern": "^[a-fA-F0-9]{64}$"
        }
    },
    "additionalProperties": False
}
```

**Validation Pipeline:**
```python
def validate_event(event):
    # 1. Schema validation
    try:
        validate(instance=event, schema=EVENT_SCHEMA)
    except ValidationError as e:
        raise InvalidEventError(f"Schema validation failed: {e}")
    
    # 2. Temporal validation
    if abs(time.time() - event["timestamp"]) > 300:  # 5 minute window
        raise InvalidEventError("Timestamp too old or in future")
    
    # 3. IP validation
    if not is_valid_ip(event["src_ip"]):
        raise InvalidEventError("Invalid source IP")
    
    # 4. HMAC verification
    if not verify_hmac(event):
        raise InvalidEventError("HMAC verification failed")
    
    # 5. Proxy registration check
    if not is_registered_proxy(event["proxy_id"]):
        raise InvalidEventError("Unregistered proxy")
    
    return True
```

### 12d.4 HMAC Authentication

**Event Signing:**
```python
def sign_event(event_data, secret):
    # Create HMAC signature
    message = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    hmac_signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac_signature

# Proxy side
event_data["hmac"] = sign_event(event_data, shared_secret)
```

**Verification:**
```python
def verify_hmac(event):
    # Reconstruct message (without HMAC)
    event_copy = event.copy()
    del event_copy["hmac"]
    message = json.dumps(event_copy, sort_keys=True, separators=(",", ":"))
    
    # Verify signature
    expected_hmac = hmac.new(
        shared_secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_hmac, event["hmac"])
```

## Rate Limiting & DoS Protection

### 12d.5 Event Rate Limiting

**Token Bucket Algorithm:**
```python
class ProxyRateLimiter:
    def __init__(self, capacity, fill_rate):
        self.capacity = capacity  # Max tokens
        self.fill_rate = fill_rate  # Tokens per second
        self.tokens = capacity
        self.last_check = time.time()
        self.lock = asyncio.Lock()
    
    async def allow_event(self, proxy_id):
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_check
            
            # Add new tokens
            new_tokens = time_passed * self.fill_rate
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_check = now
            
            # Check if token available
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
```

**Configuration:**
```yaml
analytics_node:
  security:
    rate_limiting:
      enabled: true
      default_limit: 10000  # events per second per proxy
      burst_capacity: 15000
      fill_rate: 10000
      
      proxy_specific:
        proxy-1: 5000
        proxy-2: 8000
        
      global_limit: 100000  # total events per second
```

### 12d.6 Algorithm Complexity Protection

**Resource Limits:**
```python
# Decorator for resource-limited functions
@resource_limit(memory_mb=100, timeout_seconds=5)
def process_event_batch(batch):
    # Process batch with resource constraints
    try:
        return complex_analysis(batch)
    except MemoryError:
        log.warning("Memory limit exceeded in batch processing")
        return partial_result
    except TimeoutError:
        log.warning("Timeout in batch processing")
        return partial_result
```

**Circuit Breakers:**
```python
class CircuitBreaker:
    def __init__(self, max_failures, reset_timeout):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.state = "closed"
        self.last_failure = 0
    
    def call(self, func, *args, **kwargs):
        if self.state == "open":
            if time.time() - self.last_failure > self.reset_timeout:
                self.state = "half-open"
            else:
                raise CircuitBreakerOpenError()
        
        try:
            result = func(*args, **kwargs)
            self.failures = 0
            self.state = "closed"
            return result
        except Exception as e:
            self.failures += 1
            self.last_failure = time.time()
            
            if self.failures >= self.max_failures:
                self.state = "open"
            
            raise e
```

## Secure Communication

### 12d.7 Redis Security

**TLS Encryption:**
```yaml
# Redis configuration
redis:
  host: redis-analytics
  port: 6379
  ssl: true
  ssl_ca_certs: "/etc/ssl/certs/ca-certificates.crt"
  ssl_certfile: "/etc/ssl/certs/analytics.crt"
  ssl_keyfile: "/etc/ssl/private/analytics.key"
  ssl_cert_reqs: "required"
```

**Authentication:**
```yaml
redis:
  password: "${REDIS_PASSWORD}"
  username: "analytics_user"
  
  # Separate users for different operations
  users:
    read_only:
      password: "${REDIS_READONLY_PASSWORD}"
      permissions: ["+read", "-write"]
    write_only:
      password: "${REDIS_WRITEONLY_PASSWORD}"
      permissions: ["-read", "+write"]
```

### 12d.8 Network Security

**Container Networking:**
```yaml
# Docker compose networking
services:
  analytics:
    networks:
      - analytics_net
    
  proxy:
    networks:
      - proxy_net
      - analytics_net  # Only for event publishing
    
  redis:
    networks:
      - analytics_net
    
networks:
  analytics_net:
    internal: true
    driver: bridge
    
  proxy_net:
    internal: true
    driver: bridge
```

**Firewall Rules:**
```bash
# Analytics container firewall
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/24 -j ACCEPT  # Monitoring
iptables -A INPUT -p tcp --dport 6379 -s 10.0.1.0/24 -j ACCEPT  # Redis from proxy
iptables -A INPUT -j DROP  # Default deny
```

## Audit & Forensics

### 12d.9 Comprehensive Logging

**Audit Trail:**
```json
{
  "type": "audit",
  "level": "INFO",
  "subsystem": "analytics",
  "event": "event_processed",
  "proxy_id": "proxy-1",
  "event_id": "1678901234567-0",
  "src_ip": "192.168.1.100",
  "action": "block",
  "score": 85,
  "processing_duration_ms": 42,
  "timestamp": "2024-03-15T14:30:45.123Z",
  "user_agent": "Mozilla/5.0",
  "ja4": "t13d1520h3_abc123..."
}
```

**Security Events:**
```json
{
  "type": "security",
  "level": "WARN",
  "subsystem": "analytics",
  "event": "invalid_event_rejected",
  "reason": "hmac_verification_failed",
  "proxy_id": "proxy-3",
  "event_id": "1678901234567-1",
  "src_ip": "192.168.2.50",
  "timestamp": "2024-03-15T14:31:12.456Z"
}

{
  "type": "security",
  "level": "ERROR",
  "subsystem": "analytics",
  "event": "rate_limit_exceeded",
  "proxy_id": "proxy-5",
  "limit": 10000,
  "attempted": 12500,
  "timestamp": "2024-03-15T14:32:00.000Z"
}
```

### 12d.10 Forensic Data Retention

**Redis Forensics:**
```yaml
analytics_node:
  forensics:
    enabled: true
    
    # Retain raw events for investigation
    raw_event_retention:
      enabled: true
      ttl_seconds: 86400  # 24 hours
      max_events: 1000000
      
    # Suspicious event flagging
    suspicious_patterns:
      - "score > 90 and action = 'allow'"  # False negatives
      - "score < 10 and action = 'block'"  # False positives
      - "rate > 1000 events/second from single IP"
      
    # Forensic logging
    forensic_log:
      enabled: true
      retention_days: 30
      compression: "gzip"
```

## Security Testing

### 12d.11 Penetration Testing

**Test Cases:**
- [ ] Event schema validation bypass
- [ ] HMAC spoofing attempts
- [ ] Replay attack detection
- [ ] Rate limit bypass
- [ ] Memory exhaustion attack
- [ ] Algorithm complexity attack
- [ ] Redis injection attempts
- [ ] Privilege escalation paths

### 12d.12 Fuzzing

**Event Fuzzing:**
```python
# Fuzz testing for event validation
def fuzz_event_validation():
    fuzzer = Fuzzer()
    
    for i in range(10000):
        # Generate mutated event
        fuzzed_event = fuzzer.mutate(valid_event)
        
        try:
            validate_event(fuzzed_event)
            log.warning(f"Fuzz test {i}: Validation passed unexpectedly")
        except InvalidEventError:
            # Expected
            pass
        except Exception as e:
            log.error(f"Fuzz test {i}: Unexpected error: {e}")
```

## Incident Response

### 12d.13 Security Incident Procedures

**Detection → Containment → Eradication → Recovery → Lessons Learned**

**Automated Response:**
```yaml
incident_response:
  automated_actions:
    - action: "quarantine_proxy"
      trigger: "rate_limit_exceeded > 5 times in 1 hour"
      
    - action: "alert_soc"
      trigger: "invalid_event_rejected > 100 in 5 minutes"
      
    - action: "disable_analytics_module"
      trigger: "memory_exhaustion_detected"
      
    - action: "snapshot_forensics"
      trigger: "security_event_severity = 'high'"
```

## Configuration

```yaml
analytics_node:
  security:
    enabled: true
    
    # Event validation
    validation:
      strict_schema: true
      temporal_window_seconds: 300
      ip_validation: true
      hmac_required: true
      proxy_registration_required: true
      
    # Rate limiting
    rate_limiting:
      enabled: true
      default_limit: 10000
      burst_capacity: 15000
      global_limit: 100000
      
    # Authentication
    authentication:
      hmac_secret: "${HMAC_SECRET}"
      secret_rotation_interval: "30d"
      
    # Redis security
    redis:
      tls_enabled: true
      password_required: true
      separate_users: true
      
    # Network security
    network:
      internal_network_only: true
      firewall_enabled: true
      
    # Audit logging
    auditing:
      enabled: true
      retention_days: 90
      compression: "gzip"
      
    # Forensics
    forensics:
      enabled: true
      raw_event_retention: true
      suspicious_pattern_monitoring: true
      
    # Incident response
    incident_response:
      automated_quarantine: true
      soc_alerting: true
      forensic_snapshots: true
```

## Acceptance Criteria

### Security Functional
- [ ] Event schema validation with JSON Schema
- [ ] HMAC authentication for all events
- [ ] Proxy registration whitelist
- [ ] Rate limiting per proxy and global
- [ ] Algorithm resource limits
- [ ] Circuit breakers implemented
- [ ] TLS for Redis communication
- [ ] Redis authentication and RBAC
- [ ] Network isolation and firewall rules
- [ ] Comprehensive audit logging
- [ ] Forensic data retention

### Security Testing
- [ ] Penetration testing completed
- [ ] Fuzz testing for event validation
- [ ] Rate limit bypass testing
- [ ] Memory exhaustion testing
- [ ] Replay attack testing
- [ ] Privilege escalation testing

### Observability & Incident Response
- [ ] Security events logged
- [ ] Audit trail complete
- [ ] Forensic data retained
- [ ] Incident response procedures documented
- [ ] Automated quarantine working
- [ ] SOC alerting integrated

### Documentation
- [ ] Security architecture documented
- [ ] Threat model updated
- [ ] Incident response plan
- [ ] Security testing report
- [ ] Hardening checklist

## Performance Impact

**Security Overhead:**
- Validation: < 1ms per event
- HMAC verification: < 0.5ms per event
- Rate limiting: < 0.1ms per event
- Total security overhead: < 2ms per event

**Resource Usage:**
- Memory: +50MB for security context
- CPU: +5% for validation and encryption
- Storage: +100MB/day for audit logs

## Compliance

**Standards:**
- NIST SP 800-53
- CIS Benchmarks
- OWASP Top 10
- PCI DSS (where applicable)

## Next Steps
- Phase 13: Deployment and scaling
- Phase 14: Production monitoring
- Regular security audits