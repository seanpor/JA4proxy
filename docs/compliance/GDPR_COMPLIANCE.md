# GDPR Compliance Documentation

**Last Updated:** 2026-02-15  
**System:** JA4 Proxy Fail2Ban  
**Version:** 2.1.0

---

## Executive Summary

The JA4 Proxy fail2ban system is designed with **GDPR compliance by default**. All personal data (IP addresses, connection metadata) is stored temporarily with automatic expiration, implementing the principle of **data minimization**.

This document outlines the GDPR compliance measures, data retention policies, and verification procedures implemented in the system.

---

## GDPR Principles Applied

### 1. Data Minimization (Article 5(1)(c))

**Implementation:**
- Only essential data is stored (IP addresses, JA4 fingerprints, timestamps)
- No personally identifiable information beyond IP addresses
- JA4 fingerprints are not PII (they identify TLS client implementations, not individuals)
- Connection metadata limited to what's necessary for security

**Evidence:**
```python
# Only minimal data stored
entity_id = f"{ip}|{ja4}"  # Minimal identifier
timestamp = time.time()    # Only current timestamp
rate = connections_per_second  # Aggregate metric, not individual
```

### 2. Storage Limitation (Article 5(1)(e))

**Implementation:**
- All data has automatic expiration (TTL-based)
- Retention periods based on necessity and proportionality
- No permanent storage by default
- Regular compliance verification

**Retention Periods:**
| Data Category | Default TTL | Maximum TTL | Justification |
|---------------|-------------|-------------|---------------|
| Rate Tracking | 60 seconds | 5 minutes | Immediate rate calculation only |
| Fingerprints | 1 hour | 24 hours | Short-term analysis and debugging |
| Suspicious Activity | 30 minutes | 1 hour | Investigation window |
| Temporary Blocks | 1 hour | 2 hours | Match enforcement duration |
| Bans | 7 days | 30 days | Serious threats with justification |
| Audit Logs | 30 days | 90 days | Legal compliance requirement |

### 3. Accuracy (Article 5(1)(d))

**Implementation:**
- Sliding window rate calculations ensure current data
- Automatic expiration prevents stale data
- Real-time threat evaluation
- Manual unban for false positives

### 4. Integrity and Confidentiality (Article 5(1)(f))

**Implementation:**
- Redis authentication required
- TLS encryption for Redis connections (recommended)
- Input validation prevents injection
- Fail-secure design on errors
- Audit logging for compliance verification

### 5. Accountability (Article 5(2))

**Implementation:**
- Comprehensive audit logging
- Compliance verification tools
- Retention reports
- Configuration validation
- Documentation of all processing activities

---

## Data Processing Activities

### Data Collected

**Type 1: IP Addresses**
- **Category:** Personal Data (GDPR Article 4(1))
- **Purpose:** Security monitoring, rate limiting, attack detection
- **Legal Basis:** Legitimate Interest (Article 6(1)(f))
  - Interest: Protecting system from attacks
  - Necessity: IP addresses essential for network-level blocking
  - Balance: Minimal retention, automatic expiry
- **Retention:** Maximum 30 days (for bans), typically 1 hour or less
- **Recipients:** System logs only (not shared)

**Type 2: JA4 Fingerprints**
- **Category:** Non-Personal Data (identifies software, not individuals)
- **Purpose:** TLS client identification, botnet detection
- **Legal Basis:** Not required (not personal data)
- **Retention:** Maximum 24 hours, typically 1 hour
- **Recipients:** System logs only

**Type 3: Connection Metadata**
- **Category:** Technical Data
- **Purpose:** Rate calculation, threat evaluation
- **Legal Basis:** Legitimate Interest
- **Retention:** 60 seconds (rate tracking only)
- **Recipients:** Not stored permanently

### Data Not Collected

- Names, email addresses, or other direct identifiers
- Browsing history or content
- Geolocation beyond IP-based
- Device identifiers beyond TLS fingerprint
- Any data beyond what's technically necessary

---

## Technical Implementation

### Automatic Expiration

All data stored in Redis has TTLs enforced:

```python
# Example: Rate tracking
self.redis.zadd(key, {timestamp: timestamp})
self.redis.expire(key, 60)  # Auto-expire after 60 seconds

# Example: Temporary block
self.redis.setex(block_key, 3600, "1")  # Auto-expire after 1 hour

# Example: Ban
self.redis.setex(ban_key, 604800, "1")  # Auto-expire after 7 days
```

### GDPR Storage Module

The `GDPRStorage` class enforces compliance:

```python
from src.security import GDPRStorage, DataCategory

storage = GDPRStorage(redis_client, config)

# Store with automatic TTL enforcement
storage.store(
    key="fingerprint:12345",
    value=fingerprint_data,
    category=DataCategory.FINGERPRINTS,  # Auto-applies 1 hour TTL
)

# Verify compliance
compliance = storage.verify_compliance()
# Returns: {'compliant_keys': 1000, 'non_compliant_keys': 0, ...}
```

### Configuration

```yaml
security:
  gdpr:
    enabled: true
    audit_logging: true
    
    # Configurable retention periods (within GDPR limits)
    retention_periods:
      rate_tracking: 60      # 1 minute (max: 5 minutes)
      fingerprints: 3600     # 1 hour (max: 24 hours)
      suspicious: 1800       # 30 minutes (max: 1 hour)
      temp_blocks: 3600      # 1 hour (max: 2 hours)
      bans: 604800          # 7 days (max: 30 days)
      audit_logs: 2592000   # 30 days (max: 90 days)
```

---

## Compliance Verification

### Automatic Verification

```bash
# Check GDPR compliance
python3 -m pytest tests/compliance/test_gdpr_retention.py -v

# Expected output:
# test_all_keys_have_ttl ... PASSED
# test_retention_within_limits ... PASSED
# test_no_permanent_storage ... PASSED
```

### Manual Verification

```python
from src.security import GDPRStorage

storage = GDPRStorage.from_config(redis_client, config)

# Get compliance report
compliance = storage.verify_compliance()
print(f"Compliance rate: {compliance['compliance_rate'] * 100}%")
print(f"Non-compliant keys: {compliance['non_compliant_keys']}")

# Get retention report
report = storage.get_retention_report()
for category, info in report['retention_periods'].items():
    print(f"{category}: {info['configured_ttl']}s (compliant: {info['compliant']})")
```

### Audit Logs

```python
# Retrieve audit logs for review
audit_logs = storage.get_audit_logs(limit=100)

for log in audit_logs:
    print(f"{log['timestamp']}: {log['action']} - {log['category']} (TTL: {log['ttl']}s)")
```

---

## Data Subject Rights

### Right to Erasure (Article 17)

**Manual Unban:** System administrators can manually remove data:

```python
from src.security import ActionEnforcer

enforcer = ActionEnforcer.from_config(redis_client, config)

# Unban removes all blocks/bans for an entity
was_unbanned = enforcer.unban(
    ja4="t13d1516h2_abc_def",
    ip="192.168.1.100",
)
```

**Automatic Erasure:** All data auto-expires per retention periods.

### Right to Access (Article 15)

**Current Status Check:**

```python
# Check if entity is currently blocked
is_blocked, reason = enforcer.is_blocked(ja4, ip)
if is_blocked:
    print(f"Currently blocked: {reason}")
else:
    print("Not blocked")
```

**Historical Data:** Limited to audit logs (30 days max).

### Right to Rectification (Article 16)

**False Positive Correction:** Manual unban addresses incorrect blocking.

**Accuracy:** Sliding window rate calculations ensure current, accurate data.

---

## Legitimate Interest Assessment

### Interest

Protecting the system and legitimate users from:
- Distributed Denial of Service (DDoS) attacks
- Botnet-driven attacks
- Credential stuffing attempts
- Automated scanning and exploitation

### Necessity

IP addresses are **technically necessary** for:
- Network-level blocking at firewall/proxy
- Rate limiting enforcement
- Attack source identification

Alternative approaches considered:
- ❌ Cookie-based blocking: Bypassable, not effective for DDoS
- ❌ CAPTCHA only: Impacts legitimate users, ineffective for automated attacks
- ✅ IP + TLS fingerprint: Most effective with minimal data

### Balance of Interests

**System Interests:**
- Availability for legitimate users
- Protection from financial/reputational damage
- Prevention of resource exhaustion

**Data Subject Interests:**
- Privacy of IP address (limited)
- Minimal data retention ✅
- No tracking or profiling ✅
- Automatic expiration ✅

**Conclusion:** Legitimate interest justified with appropriate safeguards.

---

## Data Protection Impact Assessment (DPIA)

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Unauthorized access to IP data | Low | Medium | Redis authentication, TLS encryption |
| Data retention too long | Low | Low | Automatic expiration, GDPR limits enforced |
| False positive blocking | Medium | Low | Manual unban, conservative thresholds |
| Data breach | Low | Medium | Redis security, no permanent storage |

### Conclusion

Processing necessary and proportionate. Risks adequately mitigated through:
- Minimal data collection
- Automatic expiration
- Security measures
- Manual override capability

---

## Compliance Checklist

### Implementation

- ✅ Data minimization implemented
- ✅ Automatic expiration for all data
- ✅ Retention periods documented and enforced
- ✅ GDPR limits validated in code
- ✅ Audit logging enabled
- ✅ Compliance verification tools provided
- ✅ Manual unban functionality
- ✅ Configuration validation
- ✅ No permanent storage by default

### Documentation

- ✅ Data processing activities documented
- ✅ Legal basis identified (legitimate interest)
- ✅ Retention periods justified
- ✅ Data subject rights addressed
- ✅ Technical measures described
- ✅ Compliance procedures defined

### Testing

- ✅ Unit tests for retention enforcement
- ✅ Compliance verification tests
- ✅ No permanent storage tests
- ✅ TTL validation tests
- ✅ Audit log tests

---

## Recommended Practices

### For System Administrators

1. **Regular Compliance Checks**
   ```bash
   # Weekly compliance verification
   python3 -c "from src.security import GDPRStorage; \
               s = GDPRStorage.from_config(redis, config); \
               print(s.verify_compliance())"
   ```

2. **Monitor Retention Periods**
   ```bash
   # Monthly retention report
   python3 -c "from src.security import GDPRStorage; \
               s = GDPRStorage.from_config(redis, config); \
               print(s.get_retention_report())"
   ```

3. **Review Audit Logs**
   ```bash
   # Review recent activity
   python3 -c "from src.security import GDPRStorage; \
               s = GDPRStorage.from_config(redis, config); \
               print(s.get_audit_logs(100))"
   ```

4. **Handle Data Subject Requests**
   - Access requests: Check current block status
   - Erasure requests: Use manual unban
   - Document all requests and responses

### For Developers

1. **Always Use GDPRStorage**
   ```python
   # Good: Uses GDPR-compliant storage
   storage.store(key, value, DataCategory.FINGERPRINTS)
   
   # Bad: Direct Redis storage without TTL
   redis.set(key, value)  # NO TTL! GDPR violation!
   ```

2. **Never Disable Automatic Expiration**
   ```python
   # Good: TTL enforced
   redis.setex(key, ttl, value)
   
   # Bad: Permanent storage
   redis.set(key, value)  # Avoid!
   ```

3. **Validate Retention Periods**
   ```python
   # Always check against GDPR limits
   max_ttl = DataCategory.FINGERPRINTS.get_max_ttl()
   if custom_ttl > max_ttl:
       ttl = max_ttl  # Enforce limit
   ```

---

## Contact Information

**Data Protection Officer (DPO):** [To be assigned]  
**System Administrator:** [To be assigned]  
**Compliance Questions:** [To be assigned]

---

## Updates and Changes

### Version History

- **2.1.0 (2026-02-15):** Phase 4 implementation - GDPR compliance module
- **2.0.0 (2026-02-14):** Initial GDPR-by-design implementation

### Review Schedule

- **Technical Review:** Quarterly
- **Legal Review:** Annually
- **DPIA Update:** When processing changes significantly

---

## References

- **GDPR:** Regulation (EU) 2016/679
- **Article 6(1)(f):** Legitimate Interest
- **Article 5:** Principles of Data Processing
- **Recital 47:** Legitimate Interest Balancing Test

---

**Last Reviewed:** 2026-02-15  
**Next Review Due:** 2026-05-15  
**Document Owner:** System Architecture Team
