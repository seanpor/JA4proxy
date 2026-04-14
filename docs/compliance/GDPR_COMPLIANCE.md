<!--
title: Gdpr_Compliance
audience: Compliance Officers, Auditors
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — GDPR Compliance

> **Audience:** Compliance officers, Data Protection Officers, security auditors
> **Purpose:** Comprehensive GDPR compliance documentation for JA4proxy deployment
> **Last Reviewed:** 2026-03-27
> **Status:** Enterprise standard documentation

---

## §1. Executive Summary

JA4proxy is designed with **GDPR compliance by default** and **privacy by design** principles. This document provides a comprehensive analysis of how JA4proxy handles personal data in accordance with EU General Data Protection Regulation (GDPR) requirements.

**Key Compliance Features:**
- ✅ **Data Minimisation:** Only essential data collected (IP addresses, TLS fingerprints)
- ✅ **Purpose Limitation:** Data used solely for security monitoring and threat detection
- ✅ **Storage Limitation:** Automatic expiration with configurable TTLs
- ✅ **Security by Design:** Encryption in transit, access controls, audit logging
- ✅ **Data Subject Rights:** Procedures for access, rectification, erasure
- ✅ **Breach Notification:** Documented incident response procedures

---

## §2. Data Inventory

This section provides a comprehensive inventory of all personal data processed by JA4proxy.

### 2.1. Personal Data Elements

| Data Element | Category | GDPR Article 4(1) Classification | Legal Basis | Retention Period |
|--------------|----------|-----------------------------------|--------------|------------------|
| **IP Address** (Source) | Identifier | ✅ Personal Data | Legitimate interest (Art. 6(1)(f)) | Configurable (default: 24h) |
| **IP Address** (Destination) | Identifier | ✅ Personal Data | Legitimate interest (Art. 6(1)(f)) | Configurable (default: 24h) |
| **JA4 Fingerprint** | Derived data | ❌ Not personal data | N/A | Configurable (default: 30d) |
| **JA4T Fingerprint** | Derived data | ❌ Not personal data | N/A | Configurable (default: 30d) |
| **ASN** | Derived data | ❌ Not personal data | N/A | Configurable (default: 30d) |
| **Country Code** | Derived data | ❌ Not personal data | N/A | Configurable (default: 30d) |
| **User Agent** | Technical data | ❌ Not personal data | N/A | Not stored |
| **TLS Version** | Technical data | ❌ Not personal data | N/A | Not stored |
| **Cipher Suite** | Technical data | ❌ Not personal data | N/A | Not stored |
| **SNI** | Technical data | ❌ Not personal data | N/A | Not stored |
| **Timestamp** | Metadata | ❌ Not personal data | N/A | Configurable |

### 2.2. Data Flow Diagram

```mermaid
graph TD
    A[Client] -->|TLS Connection| B[JA4proxy]
    B -->|Extract: IP, JA4, JA4T| C[Signal Processing]
    C -->|Store: IP→Redis| D[Redis Database]
    C -->|Store: JA4→Redis| D
    C -->|Log: Access Log| E[Structured JSON Logs]
    D -->|Expire: TTL| F[Automatic Deletion]
    E -->|Rotate: 30d| G[Log Rotation]
```

### 2.3. Data Storage Locations

| Storage Location | Data Types | Retention Mechanism | Encryption |
|------------------|------------|---------------------|------------|
| **Redis keys** (`ban:{ip}`) | IP addresses | TTL (configurable) | ✅ TLS to Redis |
| **Redis keys** (`visitor:{ip}`) | IP addresses, JA4 | TTL (configurable) | ✅ TLS to Redis |
| **Redis streams** (`analytics:events`) | IP addresses, JA4, timestamps | Stream trimming (7d) | ✅ TLS to Redis |
| **Access logs** | IP addresses, JA4, timestamps | Log rotation (30d) | ✅ File system |
| **Prometheus metrics** | Aggregated counts (no IPs) | Volatile (no retention) | ✅ HTTPS |

---

## §3. Legal Basis for Processing

### 3.1. Primary Legal Basis: Legitimate Interest (Article 6(1)(f))

JA4proxy processes personal data (IP addresses) based on **legitimate interest** for:

- **Network security:** Protecting systems from unauthorized access and attacks
- **Fraud prevention:** Detecting and blocking malicious bot traffic
- **Service availability:** Maintaining uptime by mitigating DDoS attacks

**Balancing Test (Article 6(1)(f)):**

| Factor | Analysis |
|--------|----------|
| **Purpose** | Critical security function that benefits both controller and data subjects |
| **Necessity** | No less intrusive method provides equivalent protection |
| **Impact on individuals** | Minimal — temporary storage, no profiling, no sharing |
| **Safeguards** | Strong — encryption, access controls, short retention, audit logging |
| **Conclusion** | Legitimate interest outweighs individual impact |

### 3.2. Alternative Legal Bases Considered

| Legal Basis | Applicability | Reason for Non-Use |
|-------------|--------------|-------------------|
| **Consent (Art. 6(1)(a))** | Not applicable | Cannot obtain consent from attack sources |
| **Contract (Art. 6(1)(b))** | Not applicable | No contractual relationship with attackers |
| **Legal obligation (Art. 6(1)(c))** | Limited | No EU-wide obligation to implement this specific security measure |
| **Vital interest (Art. 6(1)(d))** | Not applicable | Not life-critical systems |
| **Public task (Art. 6(1)(e))** | Limited | Only applies to public authorities |

### 3.3. Special Category Data

**JA4proxy does not process any special category data** as defined in GDPR Article 9:

- ❌ No racial or ethnic origin data
- ❌ No political opinions
- ❌ No religious or philosophical beliefs
- ❌ No trade union membership
- ❌ No genetic data
- ❌ No biometric data for identification
- ❌ No health data
- ❌ No sex life or sexual orientation data

---

## §4. Data Minimisation Principles

### 4.1. What We Do NOT Collect

**Explicitly excluded from collection:**

- ❌ **No HTTP headers** (Cookies, Authorization, etc.)
- ❌ **No HTTP body content**
- ❌ **No form data or user input**
- ❌ **No session identifiers**
- ❌ **No user accounts or credentials**
- ❌ **No personally identifiable information (PII)**
- ❌ **No decrypted TLS traffic**

**Technical enforcement:**
- TLS termination happens after JA4 fingerprinting
- Proxy operates at Layer 4 (TCP) and Layer 5 (TLS handshake)
- No access to Layer 7 (HTTP) content

### 4.2. What We DO Collect (Minimal Set)

| Data | Purpose | Retention |
|------|---------|-----------|
| **Source IP** | Identify connection origin for security analysis | 24h default |
| **Destination IP** | Identify target service | 24h default |
| **JA4 fingerprint** | Identify TLS client software | 30d default |
| **JA4T fingerprint** | Identify TLS transport characteristics | 30d default |
| **Timestamp** | Temporal analysis and correlation | 30d default |
| **ASN** | Geographical and organizational context | 30d default |

### 4.3. Derived vs. Raw Data

**Strategy:** Store derived data (JA4 fingerprints) rather than raw data where possible

- ✅ **JA4 fingerprint** (derived from TLS ClientHello) → Not personal data
- ✅ **ASN** (derived from IP) → Not personal data  
- ✅ **Country code** (derived from IP) → Not personal data
- ❌ **Raw IP address** → Personal data (but minimized retention)

---

## §5. Storage Limitation & Retention Periods

### 5.1. Retention Periods by Data Type

| Redis Key Pattern | Data Stored | Default TTL | Config Key | Rationale |
|-------------------|-------------|-------------|------------|-----------|
| `ban:{ip}` | Blocked IP addresses | 24 hours | `redis.ban_ttl_seconds` | Short-term enforcement; revisit on next connection |
| `visitor:{ip}` | Return visitor classification | 30 days | `redis.visitor_ttl_seconds` | Return visitor detection window |
| `rate_limit:{ip}` | Rate limit counters | 60 seconds | `rate_limit.window_seconds` | Sliding window duration |
| `beaconing:{ip}` | Beaconing timestamps | 24 hours | `beaconing.long_window_hours` | Detection window |
| `abuseipdb:{ip}` | AbuseIPDB cache | 24 hours | `abuseipdb.cache_ttl_seconds` | API quota preservation |
| `analytics:events` | Connection events | 7 days | `redis.stream_max_age_seconds` | Replay and analysis window |
| `analytics:report:*` | Aggregated reports | 30 days | `analytics.report_ttl_seconds` | Trend analysis window |

### 5.2. Automatic Expiration Mechanisms

**Redis TTL:** All keys have explicit TTL (Time-To-Live) set on creation

```python
# Example: Setting TTL for ban key
redis.set(f"ban:{ip}", "1", ex=config.redis.ban_ttl_seconds)
```

**Stream Trimming:** Analytics streams automatically trimmed based on age and size

```bash
# Redis configuration for stream trimming
127.0.0.1:6379> XTRIM analytics:events MAXLEN ~ 100000 MINID ~ 604800000
```

**Log Rotation:** Access logs rotated and deleted after 30 days

```yaml
# config/logging.yml
access_log:
  rotation: daily
  retention: 30  # days
  compress: true
```

### 5.3. Data Subject Erasure Procedures

**Manual Erasure Command:**
```bash
# Erase all data for a specific IP address
redis-cli DEL ban:{ip} visitor:{ip} rate_limit:{ip} beaconing:{ip} abuseipdb:{ip}

# Verify erasure
redis-cli KEYS "*{ip}*" | wc -l  # Should return 0
```

**Automated Erasure Script:**
```bash
# docs/compliance/gdpr_erasure.sh
#!/bin/bash
IP=$1
if [ -z "$IP" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

# Delete all keys containing the IP
echo "Deleting Redis keys for $IP..."
redis-cli DEL ban:$IP visitor:$IP rate_limit:$IP beaconing:$IP abuseipdb:$IP

# Delete from analytics streams (requires Lua script)
echo "Purging from analytics streams..."
redis-cli --eval purge_from_stream.lua analytics:events , $IP

echo "Erasure complete for $IP"
```

---

## §6. Data Subject Rights

### 6.1. Right of Access (Article 15)

**Procedure:** Data subjects can request access to their personal data stored in JA4proxy.

**Implementation:**
```bash
# Check if IP is currently blocked
redis-cli GET ban:{ip}

# Check visitor history
redis-cli HGETALL visitor:{ip}

# Search analytics stream for IP (last 7 days)
redis-cli XRANGE analytics:events - + COUNT 10000 | grep "\"ip\":\"{ip}\""
```

**Response Format:**
```json
{
  "ip_address": "1.2.3.4",
  "currently_blocked": true,
  "block_reason": "high_risk_score",
  "block_expiry": "2026-03-28T14:30:00Z",
  "visitor_history": {
    "first_seen": "2026-03-27T10:15:23Z",
    "last_seen": "2026-03-27T14:25:47Z",
    "connection_count": 42,
    "average_score": 78.5
  },
  "data_sources": ["Redis ban keys", "Redis visitor keys", "Analytics stream"]
}
```

### 6.2. Right to Rectification (Article 16)

**Applicability:** Limited for JA4proxy since:
- IP addresses are factual (cannot be "corrected")
- Derived data (JA4 fingerprints) is computed from technical characteristics
- No profile or personal information stored

**Procedure for disputed blocks:**
```bash
# Manually whitelist an IP (removes from all block lists)
redis-cli SADD whitelist:ips {ip}

# Clear any existing ban
redis-cli DEL ban:{ip}
```

### 6.3. Right to Erasure (Article 17)

**Procedure:** See §5.3 for complete erasure procedures.

**Verification:**
```bash
# Verify no keys remain for the IP
redis-cli KEYS "*{ip}*" | wc -l  # Should return 0

# Check access logs (if within retention period)
grep "\"ip\": \"{ip}\"" /var/log/ja4proxy/access*.log
```

### 6.4. Right to Restrict Processing (Article 18)

**Implementation:** Temporary whitelisting

```bash
# Add to temporary whitelist (expires in 24h)
redis-cli SETEX temp_whitelist:{ip} 86400 1
```

### 6.5. Right to Data Portability (Article 20)

**Applicability:** Not applicable — no personal data stored in structured, commonly used, machine-readable format beyond what's necessary for security operations.

### 6.6. Right to Object (Article 21)

**Procedure:**
1. Data subject objects to processing
2. Controller evaluates objection
3. If objection upheld: add IP to permanent whitelist
4. Document decision in audit log

```yaml
# config/audit.yml
audit:
  dsar_actions:
    - type: whitelist_add
      ip: "1.2.3.4"
      reason: "data_subject_objected"
      timestamp: "2026-03-27T14:30:00Z"
      approved_by: "dpo@example.com"
```

### 6.7. Rights Related to Automated Decision-Making (Article 22)

**Automated decisions made by JA4proxy:**
- Block/allow decisions based on risk scoring
- Rate limiting decisions
- IP reputation decisions

**Safeguards implemented:**
- ✅ Human review possible (whitelist mechanism)
- ✅ Right to contest decisions (incident response procedure)
- ✅ Regular algorithm auditing (Phase 12 analytics)
- ✅ Bias testing (false positive corpus)

---

## §7. Data Transfers & International Considerations

### 7.1. Data Transfers to Third Countries

| Third Party | Data Transferred | Transfer Mechanism | Safeguards |
|-------------|------------------|--------------------|------------|
| **AbuseIPDB** (US) | IP addresses | Standard Contractual Clauses | Data minimization, pseudonymization |
| **MaxMind GeoIP** | IP addresses | Local database download | No real-time transfer |
| **Spamhaus** (UK/CH) | IP addresses | Adequacy decision (UK) | Pre-loaded feed data |
| **RDAP Registries** | IP ranges | Public data (no transfer) | No personal data |

### 7.2. AbuseIPDB Transfer Details

**Data transferred:** Individual IP addresses for reputation lookup

**Mechanism:**
- ✅ Standard Contractual Clauses (SCC) in place
- ✅ Data Processing Addendum signed
- ✅ Subprocessor agreement reviewed annually

**Minimization:**
- Cache results locally (24h TTL)
- Rate limit queries (respect API quota)
- Only query for IPs that exceed score threshold

### 7.3. MaxMind GeoIP (No Transfer)

**Approach:** Download database locally, no real-time IP transfer

```python
# No IP addresses sent to MaxMind
country = geoip_lookup.local_database_lookup(ip)  # Local file only
```

---

## §8. Security of Processing (GDPR Article 32)

### 8.1. Technical Measures

| Requirement | Implementation | Verification |
|-------------|----------------|--------------|
| **Encryption in transit** | TLS 1.2+ for all connections | `openssl s_client -connect redis:6379` |
| **Encryption at rest** | Redis `requirepass`, file system encryption | `redis-cli PING` (auth required) |
| **Access control** | Redis ACLs, firewall rules | `redis-cli ACL LIST` |
| **Audit logging** | Structured JSON logs with access tracking | `grep "access" /var/log/ja4proxy/*.log` |
| **Pseudonymization** | JA4 fingerprints instead of raw IPs where possible | Code review |
| **Regular testing** | Penetration testing (Phase 14) | [Security Audit](../security/COMPREHENSIVE_SECURITY_AUDIT.md) |

### 8.2. Organizational Measures

| Measure | Implementation |
|---------|----------------|
| **Data Protection Officer** | Assigned DPO for deployment organization |
| **Staff training** | Annual GDPR training for operators |
| **Incident response** | [Documented procedure](../INCIDENT_RESPONSE.md) |
| **Policy review** | Quarterly compliance review |
| **Data mapping** | This document (updated annually) |

### 8.3. Data Protection by Design (Article 25)

**Implemented principles:**

1. **Minimisation by default:** Only essential data collected
2. **Purpose limitation:** Data used solely for declared security purposes
3. **Storage limitation:** Automatic expiration with short TTLs
4. **Security by default:** Encryption and access controls enabled by default
5. **Transparency:** Clear documentation of all processing activities
6. **Data subject rights:** Procedures documented and testable

---

## §9. Data Breach Notification (Articles 33-34)

### 9.1. Breach Detection

**Monitoring for breaches:**
- Redis unauthorized access attempts (`failed_auth` metric)
- Unusual data export patterns (`keyspace_hits` anomalies)
- Access log anomalies (unexpected client IPs)

```yaml
# deploy/monitoring/alertmanager/rules/security.rules.yml
- alert: SuspiciousRedisAccess
  expr: rate(redis_failed_auth_total[5m]) > 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Redis unauthorized access attempt detected"
    description: "Failed authentication attempts: {{ $value }}"
```

### 9.2. Breach Response Procedure

**Immediate actions (within 1 hour):**
1. ✅ Isolate affected Redis instance
2. ✅ Rotate Redis password
3. ✅ Rotate AbuseIPDB API key
4. ✅ Preserve logs for forensic analysis
5. ✅ Notify DPO and security team

**Investigation (within 24 hours):**
1. Determine scope (IPs exposed, time window)
2. Assess risk to data subjects
3. Document timeline and evidence
4. Implement remediation measures

**Notification (within 72 hours if required):**
1. Notify supervisory authority if high risk to individuals
2. Notify affected data subjects if high risk
3. Provide breach details and mitigation steps

### 9.3. Notification Template

**To Supervisory Authority:**
```
[Your Organization Letterhead]

Date: [DD/MM/YYYY]
Ref: GDPR Breach Notification - JA4proxy Incident

To: [Supervisory Authority]

1. Nature of breach:
   - Unauthorized access to JA4proxy Redis database
   - Potential exposure of IP addresses and block lists

2. Categories and approximate number of data subjects: [X] IP addresses

3. Categories and approximate number of personal data records: [Y] Redis keys

4. Name and contact details of DPO: [Name], [Email], [Phone]

5. Likely consequences: Potential insight into security operations, but no sensitive personal data exposed

6. Measures taken to address breach:
   - Redis instance isolated and password rotated
   - API keys rotated
   - Access logs preserved for investigation
   - Additional monitoring implemented

7. Measures to mitigate possible adverse effects:
   - Enhanced authentication requirements
   - Network segmentation review
   - Incident response plan updated

[Signature]
[Organization]
```

---

## §10. Data Protection Impact Assessment (DPIA)

### 10.1. DPIA Summary

| Aspect | Assessment |
|--------|------------|
| **Nature of processing** | Security monitoring of network connections |
| **Scope of processing** | All inbound TLS connections to protected services |
| **Context of processing** | Cybersecurity operations for fraud prevention |
| **Risks to data subjects** | Low — temporary IP storage, no profiling |
| **Safeguards implemented** | Encryption, access control, short retention, audit logging |
| **DPIA conclusion** | Processing is necessary and proportionate; risks are acceptable with implemented safeguards |

### 10.2. Risk Assessment Matrix

| Risk | Likelihood | Impact | Mitigation | Residual Risk |
|------|-----------|--------|------------|---------------|
| Unauthorized Redis access | Low | Medium | Strong passwords, ACLs, network isolation | Low |
| Data retention violation | Low | Medium | Automatic TTL, monitoring | Low |
| Inappropriate data access | Low | Medium | Access logging, audit trail | Low |
| Data subject rights violation | Low | Medium | Documented procedures, training | Low |
| International transfer issue | Low | Low | SCCs in place, data minimization | Very Low |

### 10.3. Consultation with Supervisory Authority

**Not required** based on:
- ✅ Processing is necessary for legitimate security purposes
- ✅ Risks to data subjects are low with implemented safeguards
- ✅ No large-scale processing of special category data
- ✅ No systematic monitoring of publicly accessible areas
- ✅ No processing that may result in legal effects or similar significant effects

---

## §11. Compliance Verification & Auditing

### 11.1. Compliance Checklist

| Requirement | Implementation | Verification Method |
|-------------|----------------|---------------------|
| **Article 5(1)(a) - Lawfulness** | Legitimate interest balancing test | Documentation review |
| **Article 5(1)(b) - Purpose limitation** | Data used only for security | Code audit |
| **Article 5(1)(c) - Data minimisation** | Only essential data collected | Configuration review |
| **Article 5(1)(d) - Accuracy** | Data derived from technical sources | N/A (not applicable) |
| **Article 5(1)(e) - Storage limitation** | Automatic TTL on all keys | Redis configuration review |
| **Article 5(1)(f) - Integrity & confidentiality** | Encryption, access control | Security audit |
| **Article 6 - Lawful basis** | Legitimate interest documented | Documentation review |
| **Article 15 - Right of access** | Procedures documented | Test access request |
| **Article 17 - Right to erasure** | Erasure script available | Test erasure procedure |
| **Article 25 - Data protection by design** | Principles implemented | Architecture review |
| **Article 32 - Security of processing** | Technical measures in place | Penetration test |
| **Article 33 - Breach notification** | Procedure documented | Incident simulation |

### 11.2. Audit Procedures

**Quarterly Audit:**
1. Review Redis key patterns and TTLs
2. Verify no unauthorized data collection
3. Test erasure procedures
4. Review access logs for anomalies
5. Update documentation

**Annual Audit:**
1. Full DPIA review
2. Legitimate interest balancing test reassessment
3. Third-party transfer mechanism review
4. Staff training verification
5. Incident response drill

### 11.3. Documentation Maintenance

**Update triggers:**
- New Redis key patterns added
- Changes to retention periods
- New third-party data transfers
- Significant incidents or breaches
- Regulatory guidance updates
- Annual review cycle

---

## §12. Frequently Asked Questions

### 12.1. Is JA4proxy GDPR compliant out-of-the-box?

**Yes, with proper configuration.** The default configuration implements GDPR principles, but operators must:
- Configure appropriate TTLs for their use case
- Implement proper access controls
- Document their legitimate interest balancing test
- Establish breach notification procedures

### 12.2. What personal data does JA4proxy store?

**Primarily IP addresses.** JA4proxy stores:
- ✅ IP addresses (personal data)
- ❌ No names, emails, or identifiers
- ❌ No HTTP content or headers
- ❌ No session data or credentials

### 12.3. How long is personal data retained?

**Configurable, with sensible defaults:**
- Block lists: 24 hours (default)
- Visitor history: 30 days (default)
- Analytics events: 7 days (default)
- Access logs: 30 days (default)

All retention periods are configurable in `config/proxy.yml`.

### 12.4. Can data subjects request erasure?

**Yes.** Operators can:
1. Use the erasure script: `docs/compliance/gdpr_erasure.sh {ip}`
2. Manually delete keys: `redis-cli DEL ban:{ip} visitor:{ip}`
3. Verify erasure: `redis-cli KEYS "*{ip}*"`

### 12.5. Does JA4proxy transfer data internationally?

**Limited transfers with safeguards:**
- AbuseIPDB (US): Standard Contractual Clauses in place
- MaxMind: Local database download (no transfer)
- Spamhaus: UK adequacy decision
- RDAP: Public data (no personal data transferred)

### 12.6. What should we document for our Records of Processing Activities (ROPA)?

**Minimum ROPA entry:**
```
Processing Activity: Network Security Monitoring (JA4proxy)
Purpose: Fraud prevention, DDoS mitigation, bot detection
Legal Basis: Legitimate interest (Article 6(1)(f))
Data Categories: IP addresses, connection timestamps
Data Subjects: Website visitors, API clients
Recipients: Internal security team only
Transfers: AbuseIPDB (US, SCCs), MaxMind (local)
Retention: 24h-30d depending on data type
Security Measures: Encryption, access control, audit logging
DPIA: Conducted 2026-03-27, low risk
```

---

## §13. Glossary

| Term | Definition |
|------|-----------|
| **Personal Data** | Any information relating to an identified or identifiable natural person (GDPR Art. 4(1)) |
| **Data Subject** | Identified or identifiable natural person whose data is processed |
| **Controller** | Organization that determines purposes and means of processing |
| **Processor** | Organization that processes data on behalf of controller |
| **Legitimate Interest** | Lawful basis where processing is necessary for purposes of legitimate interests (Art. 6(1)(f)) |
| **DPIA** | Data Protection Impact Assessment (GDPR Art. 35) |
| **ROPA** | Records of Processing Activities (GDPR Art. 30) |
| **TTL** | Time-To-Live — automatic expiration mechanism |
| **JA4 Fingerprint** | TLS client fingerprint (not personal data) |
| **SNI** | Server Name Indication — TLS extension |

---

## §14. References

### 14.1. GDPR Articles Cited

- **Article 4(1):** Definition of personal data
- **Article 5:** Principles relating to processing of personal data
- **Article 6(1)(f):** Legitimate interest as legal basis
- **Article 9:** Processing of special categories of data
- **Article 15:** Right of access by the data subject
- **Article 16:** Right to rectification
- **Article 17:** Right to erasure ('right to be forgotten')
- **Article 18:** Right to restriction of processing
- **Article 20:** Right to data portability
- **Article 21:** Right to object
- **Article 22:** Automated individual decision-making
- **Article 25:** Data protection by design and by default
- **Article 30:** Records of processing activities
- **Article 32:** Security of processing
- **Article 33:** Notification of a personal data breach to the supervisory authority
- **Article 34:** Communication of a personal data breach to the data subject
- **Article 35:** Data protection impact assessment

### 14.2. Related Documentation

- [Comprehensive Security Audit](../security/COMPREHENSIVE_SECURITY_AUDIT.md)
- [Security Checklist](../security/SECURITY_CHECKLIST.md)
- [Incident Response Runbook](../INCIDENT_RESPONSE.md)
- [Redis Security Review](../REDIS_SECURITY_REVIEW.md)
- [Security Controls Mapping](SECURITY_CONTROLS_MAPPING.md)

### 14.3. External Resources

- [GDPR Full Text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [EDPB Guidelines on Legitimate Interest](https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-220205-legitimate-interest_en)
- [ICO Guide to GDPR](https://ico.org.uk/for-organisations/guide-to-data-protection/)

---

**Document Status:** ✅ Enterprise Standard (2026-03-27)
**Word Count:** 4,287 words
**Next Review:** 2026-06-27 (Quarterly)