# JA4 Proxy Threat Model

> **Note:** This threat model covers the full target architecture including enterprise components (PostgreSQL, Elasticsearch, Kubernetes) not yet implemented in the POC. See [README](../../README.md) for current POC capabilities.

## Executive Summary

This document provides a comprehensive threat model for the JA4 Proxy system using the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). The analysis covers threat identification, risk assessment, and mitigation strategies to ensure robust security posture.

## System Overview

### Assets and Data Flows

```mermaid
graph TB
    subgraph "Trust Boundary: Internet"
        Client[Client Applications]
        Attacker[Malicious Actors]
    end
    
    subgraph "Trust Boundary: DMZ"
        WAF[Web Application Firewall]
        LB[Load Balancer]
    end
    
    subgraph "Trust Boundary: Application Layer"
        Proxy1[JA4 Proxy Instance 1]
        Proxy2[JA4 Proxy Instance 2]
        ProxyN[JA4 Proxy Instance N]
    end
    
    subgraph "Trust Boundary: Data Layer"
        Redis[Redis Cluster]
        ES[Elasticsearch]
        Postgres[PostgreSQL]
    end
    
    subgraph "Trust Boundary: Backend"
        Backend1[Backend Service 1]
        Backend2[Backend Service 2]
    end
    
    Client --> WAF
    Attacker --> WAF
    WAF --> LB
    LB --> Proxy1
    LB --> Proxy2
    LB --> ProxyN
    
    Proxy1 --> Redis
    Proxy1 --> ES
    Proxy1 --> Postgres
    Proxy1 --> Backend1
    
    Proxy2 --> Redis
    Proxy2 --> ES
    Proxy2 --> Postgres
    Proxy2 --> Backend2
```

### Critical Assets

1. **JA4 Fingerprint Database**
   - Contains TLS fingerprints and associated metadata
   - Risk: Privacy breach, competitive intelligence
   - Value: High (contains patterns used for security decisions)

2. **Security Policies and Rules**
   - Whitelist/blacklist configurations
   - Rate limiting and filtering rules
   - Risk: Security bypass, unauthorized access
   - Value: Critical (core security controls)

3. **TLS Traffic Metadata**
   - Connection patterns and analysis results
   - Risk: Privacy violation, traffic analysis
   - Value: Medium (contains behavioral patterns)

4. **Authentication Credentials**
   - API keys, certificates, tokens
   - Risk: Complete system compromise
   - Value: Critical (system access control)

5. **System Configuration**
   - Infrastructure and application settings
   - Risk: Service disruption, security bypass
   - Value: High (operational integrity)

## STRIDE Threat Analysis

### Spoofing (Identity)

#### Threat: Client Identity Spoofing
- **Description**: Attacker impersonates legitimate client using stolen credentials or certificates
- **Impact**: Unauthorized access, security bypass, data manipulation
- **Likelihood**: Medium
- **Attack Vectors**:
  - Certificate theft and replay
  - API key compromise
  - Session hijacking
  - IP address spoofing

**Mitigation Controls**:
```yaml
Authentication:
  - Multi-factor authentication (MFA)
  - Certificate-based authentication with CRL checking
  - Mutual TLS (mTLS) for service communication
  - Regular credential rotation

Network Security:
  - IP allowlist for administrative access
  - Network-level authentication
  - Anti-spoofing filters
  - Source address validation
```

#### Threat: Service Identity Spoofing
- **Description**: Malicious service impersonates legitimate backend services
- **Impact**: Data interception, service disruption, credential theft
- **Likelihood**: Low
- **Attack Vectors**:
  - DNS poisoning
  - Certificate authority compromise
  - Man-in-the-middle attacks

**Mitigation Controls**:
```yaml
Service Authentication:
  - Certificate pinning
  - Mutual TLS verification
  - Service mesh authentication
  - Regular certificate validation
```

### Tampering (Integrity)

#### Threat: Configuration Tampering
- **Description**: Unauthorized modification of security policies and system configuration
- **Impact**: Security bypass, service disruption, compliance violations
- **Likelihood**: Medium
- **Attack Vectors**:
  - Privileged account compromise
  - Configuration file modification
  - Database manipulation
  - Memory corruption attacks

**Mitigation Controls**:
```yaml
Configuration Protection:
  - Configuration signing and verification
  - Immutable infrastructure patterns
  - Version control for all configurations
  - Regular integrity checks
  - Role-based access control (RBAC)

Runtime Protection:
  - Memory protection mechanisms
  - Code signing verification
  - Runtime application self-protection (RASP)
  - Filesystem integrity monitoring
```

#### Threat: Data Tampering
- **Description**: Modification of JA4 fingerprints, security lists, or audit logs
- **Impact**: Security bypass, evidence destruction, compliance violations
- **Likelihood**: Low
- **Attack Vectors**:
  - Database compromise
  - Memory injection attacks
  - Log file modification
  - Cache poisoning

**Mitigation Controls**:
```yaml
Data Integrity:
  - Cryptographic checksums for all data
  - Blockchain-based audit trails
  - Write-once-read-many (WORM) storage
  - Database transaction logging
  - Regular data validation checks
```

### Repudiation (Non-repudiation)

#### Threat: Action Repudiation
- **Description**: Users or administrators deny performing security-relevant actions
- **Impact**: Compliance violations, forensic challenges, accountability gaps
- **Likelihood**: Medium
- **Attack Vectors**:
  - Shared account usage
  - Log tampering or deletion
  - Insufficient audit trails
  - Time synchronization attacks

**Mitigation Controls**:
```yaml
Audit and Logging:
  - Comprehensive audit logging for all actions
  - Immutable audit trails with cryptographic signing
  - Network Time Protocol (NTP) synchronization
  - Individual account requirements
  - Multi-party authorization for critical actions

Evidence Preservation:
  - Tamper-evident logging systems
  - Log correlation across multiple systems
  - Legal hold procedures
  - Chain of custody documentation
```

### Information Disclosure (Confidentiality)

#### Threat: Sensitive Data Exposure
- **Description**: Unauthorized access to TLS fingerprints, personal data, or system information
- **Impact**: Privacy violations, competitive disadvantage, regulatory penalties
- **Likelihood**: High
- **Attack Vectors**:
  - Database breach
  - Memory dumps
  - Log file exposure
  - Side-channel attacks
  - Insider threats

**Mitigation Controls**:
```yaml
Data Protection:
  - Encryption at rest (AES-256)
  - Encryption in transit (TLS 1.3)
  - Data pseudonymization and anonymization
  - Field-level encryption for sensitive data
  - Regular data classification reviews

Access Control:
  - Principle of least privilege
  - Need-to-know basis access
  - Regular access reviews
  - Data loss prevention (DLP) tools
  - Privileged access management (PAM)
```

#### Threat: System Information Disclosure
- **Description**: Exposure of system architecture, vulnerabilities, or operational details
- **Impact**: Targeted attacks, vulnerability exploitation, reconnaissance
- **Likelihood**: Medium
- **Attack Vectors**:
  - Error message leakage
  - Debug information exposure
  - Metadata extraction
  - Timing attacks
  - Network reconnaissance

**Mitigation Controls**:
```yaml
Information Security:
  - Generic error messages
  - Debug mode disabled in production
  - Metadata scrubbing
  - Network segmentation
  - Security headers implementation
```

### Denial of Service (Availability)

#### Threat: Resource Exhaustion Attacks
- **Description**: Overwhelming system resources to cause service degradation or outage
- **Impact**: Service unavailability, performance degradation, business disruption
- **Likelihood**: High
- **Attack Vectors**:
  - Volume-based DDoS attacks
  - Protocol-based attacks
  - Application-layer attacks
  - Resource consumption attacks
  - Amplification attacks

**Mitigation Controls**:
```yaml
DDoS Protection:
  - Rate limiting and throttling
  - Traffic shaping and prioritization
  - CDN and DDoS mitigation services
  - Auto-scaling capabilities
  - Circuit breaker patterns

Resource Management:
  - Connection limits and timeouts
  - Memory and CPU quotas
  - Database connection pooling
  - Graceful degradation mechanisms
  - Health checks and monitoring
```

#### Threat: Service Logic Attacks
- **Description**: Exploiting business logic flaws to cause service disruption
- **Impact**: Service malfunction, data corruption, business logic bypass
- **Likelihood**: Medium
- **Attack Vectors**:
  - Business logic manipulation
  - State confusion attacks
  - Race condition exploitation
  - Input validation bypass

**Mitigation Controls**:
```yaml
Logic Protection:
  - Comprehensive input validation
  - State machine validation
  - Race condition prevention
  - Business rule enforcement
  - Comprehensive testing including edge cases
```

### Elevation of Privilege (Authorization)

#### Threat: Privilege Escalation
- **Description**: Gaining higher privileges than authorized through system vulnerabilities
- **Impact**: Complete system compromise, data breach, service disruption
- **Likelihood**: Medium
- **Attack Vectors**:
  - Buffer overflow exploitation
  - SQL injection attacks
  - Container escape
  - Kernel vulnerabilities
  - Misconfigurations

**Mitigation Controls**:
```yaml
Privilege Management:
  - Principle of least privilege enforcement
  - Regular privilege reviews and attestation
  - Privileged access management (PAM) solutions
  - Just-in-time (JIT) access provisioning
  - Separation of duties implementation

System Hardening:
  - Container security best practices
  - Kernel hardening and patching
  - Security-Enhanced Linux (SELinux) or AppArmor
  - Address Space Layout Randomization (ASLR)
  - Data Execution Prevention (DEP)
```

## Risk Assessment Matrix

### Risk Calculation
Risk = Impact × Likelihood × Asset Value

| Threat Category | Impact | Likelihood | Asset Value | Risk Score | Priority |
|----------------|--------|------------|-------------|------------|----------|
| Client Spoofing | High | Medium | Critical | 9 | P1 |
| Configuration Tampering | High | Medium | Critical | 9 | P1 |
| Data Exposure | High | High | High | 12 | P0 |
| DDoS Attacks | Medium | High | High | 8 | P1 |
| Privilege Escalation | High | Medium | Critical | 9 | P1 |
| Log Tampering | Medium | Low | Medium | 3 | P3 |
| Service Spoofing | Medium | Low | High | 4 | P2 |
| Info Disclosure | Medium | Medium | Medium | 4 | P2 |

### Risk Prioritization

**P0 (Critical - Immediate Action Required)**
- Sensitive Data Exposure
- Authentication Bypass

**P1 (High - Address Within 30 Days)**
- Client Identity Spoofing
- Configuration Tampering
- DDoS Resource Exhaustion
- Privilege Escalation Attacks

**P2 (Medium - Address Within 90 Days)**
- System Information Disclosure
- Service Logic Attacks
- Business Logic Bypass

**P3 (Low - Monitor and Address as Resources Allow)**
- Log File Tampering
- Minor Information Leaks
- Non-critical Service Disruptions

## Attack Trees

### Attack Tree: Data Breach via Database Compromise

```
Goal: Steal JA4 Fingerprint Database
├── OR
    ├── Direct Database Access
    │   ├── AND
    │   │   ├── Credential Compromise
    │   │   │   ├── Password Brute Force
    │   │   │   ├── Credential Stuffing
    │   │   │   └── Social Engineering
    │   │   └── Network Access
    │   │       ├── VPN Compromise
    │   │       ├── Internal Network Access
    │   │       └── Database Port Exposure
    │   └── Database Vulnerability Exploitation
    │       ├── SQL Injection
    │       ├── Unpatched Database Software
    │       └── Weak Database Configuration
    ├── Application Layer Attack
    │   ├── AND
    │   │   ├── Application Vulnerability
    │   │   │   ├── Code Injection
    │   │   │   ├── Authentication Bypass
    │   │   │   └── Authorization Flaws
    │   │   └── Data Access
    │   │       ├── ORM Manipulation
    │   │   │       ├── Cache Poisoning
    │   │       └── Memory Extraction
    └── Infrastructure Compromise
        ├── AND
        │   ├── System Access
        │   │   ├── Container Escape
        │   │   ├── Privilege Escalation
        │   │   └── Host Compromise
        │   └── Data Extraction
        │       ├── Memory Dumps
        │       ├── File System Access
        │       └── Network Sniffing
```

### Attack Tree: Service Disruption via DDoS

```
Goal: Disrupt JA4 Proxy Service
├── OR
    ├── Network Layer DDoS
    │   ├── Volumetric Attacks
    │   │   ├── UDP Flood
    │   │   ├── ICMP Flood
    │   │   └── Spoofed Packet Flood
    │   └── Protocol Attacks
    │       ├── SYN Flood
    │       ├── TCP Reset Attack
    │       └── Fragmentation Attack
    ├── Application Layer DDoS
    │   ├── HTTP Flood
    │   ├── Slowloris Attack
    │   ├── Slow POST Attack
    │   └── Resource Exhaustion
    │       ├── Memory Exhaustion
    │       ├── CPU Exhaustion
    │       └── Connection Exhaustion
    └── Logic Layer Attacks
        ├── Business Logic Abuse
        ├── API Rate Limit Bypass
        ├── Cache Exhaustion
        └── Database Connection Pool Exhaustion
```

## Security Controls Mapping

### NIST Cybersecurity Framework Mapping

| Function | Category | Controls | Implementation |
|----------|----------|----------|----------------|
| Identify | Asset Management | Asset inventory, data classification | CMDB, data flow diagrams |
| Identify | Risk Assessment | Threat modeling, vulnerability assessment | This document, regular scans |
| Protect | Access Control | Authentication, authorization | MFA, RBAC, PAM |
| Protect | Data Security | Encryption, data protection | AES-256, TLS 1.3, DLP |
| Detect | Anomaly Detection | Behavior analysis, monitoring | SIEM, ML-based detection |
| Detect | Security Monitoring | Logging, real-time monitoring | ELK stack, Prometheus |
| Respond | Incident Response | Response planning, communications | IRP, escalation procedures |
| Respond | Mitigation | Containment, eradication | Automated responses, isolation |
| Recover | Recovery Planning | Recovery procedures, improvements | DR plans, lessons learned |
| Recover | Communications | Recovery communications | Status pages, stakeholder updates |

### OWASP Top 10 Mapping

| OWASP Risk | Threat Scenario | Mitigation Controls |
|------------|-----------------|-------------------|
| A01: Broken Access Control | Privilege escalation, unauthorized access | RBAC, access reviews, principle of least privilege |
| A02: Cryptographic Failures | Data exposure, weak encryption | Strong encryption (AES-256), proper key management |
| A03: Injection | SQL injection, command injection | Input validation, parameterized queries, sandboxing |
| A04: Insecure Design | Business logic flaws, architectural issues | Threat modeling, secure design principles |
| A05: Security Misconfiguration | Default passwords, unnecessary services | Security baselines, configuration management |
| A06: Vulnerable Components | Known vulnerabilities in dependencies | Dependency scanning, patch management |
| A07: Authentication Failures | Weak passwords, session management | MFA, strong password policy, session security |
| A08: Software Integrity Failures | Supply chain attacks, unsigned code | Code signing, integrity verification, SCA |
| A09: Logging Failures | Insufficient logging, log tampering | Comprehensive logging, SIEM, log integrity |
| A10: Server-Side Request Forgery | Internal network access, data exfiltration | Input validation, network segmentation, allowlists |

## Recommendations

### Immediate Actions (0-30 days)

1. **Implement Comprehensive Logging**
   - Deploy SIEM solution with real-time monitoring
   - Ensure all security events are logged and correlated
   - Implement log integrity protection mechanisms

2. **Strengthen Authentication**
   - Mandate multi-factor authentication for all accounts
   - Implement certificate-based authentication for services
   - Deploy privileged access management (PAM) solution

3. **Enhance Network Security**
   - Deploy web application firewall (WAF)
   - Implement DDoS protection services
   - Configure network segmentation and micro-segmentation

### Medium-term Actions (30-90 days)

1. **Implement Advanced Threat Detection**
   - Deploy user and entity behavior analytics (UEBA)
   - Implement machine learning-based anomaly detection
   - Integrate threat intelligence feeds

2. **Strengthen Data Protection**
   - Implement field-level encryption for sensitive data
   - Deploy data loss prevention (DLP) solutions
   - Enhance backup and recovery procedures

3. **Improve Incident Response**
   - Develop automated incident response playbooks
   - Conduct regular incident response exercises
   - Implement security orchestration and automated response (SOAR)

### Long-term Actions (90+ days)

1. **Implement Zero Trust Architecture**
   - Deploy identity-based network access controls
   - Implement continuous authentication and authorization
   - Enhance endpoint detection and response (EDR)

2. **Advanced Security Testing**
   - Implement continuous security testing in CI/CD pipeline
   - Conduct regular red team exercises
   - Deploy application security testing tools (SAST/DAST/IAST)

3. **Compliance and Governance**
   - Achieve SOC 2 Type II certification
   - Implement privacy by design principles
   - Establish security governance framework

## Conclusion

This threat model provides a comprehensive analysis of security threats facing the JA4 Proxy system. The identified threats range from common web application vulnerabilities to sophisticated advanced persistent threats. The recommended security controls and mitigation strategies follow industry best practices and regulatory requirements.

Regular review and updates of this threat model are essential as the system evolves and new threats emerge. The threat model should be revisited quarterly or whenever significant changes are made to the system architecture or threat landscape.

---

## Phase 8-12 Threat Vectors

This section covers threat vectors introduced or relevant to Phases 8-12 of the JA4proxy
implementation. These are specific to the proxy's operational components, not the general
web application threats covered above.

### Phase 8: Spamhaus Blocklist CIDR Trie Poisoning

**Threat:** An attacker compromises the Spamhaus feed delivery path (DNS hijack, BGP
hijack, or CDN compromise) and injects a crafted DROP/EDROP feed containing fraudulent
CIDR entries. If accepted, the proxy would hard-block legitimate IPs.

**Attack vector:**
- Attacker serves a fake Spamhaus feed via DNS poisoning of the feed hostname.
- Feed contains a CIDR range belonging to a legitimate CDN or ISP.
- Proxy loads the poisoned feed and hard-blocks legitimate users.

**Mitigations:**
- ETag validation: the feed manager stores ETags. A changed feed triggers a new fetch,
  but the ETag mismatch alerts on unexpected content changes.
- HTTPS feed source: the official Spamhaus DROP feeds are served over HTTPS with a
  valid certificate. A DNS hijack alone is insufficient — the attacker would also need
  to present a valid TLS certificate for the Spamhaus domain.
- Feed size sanity check: a feed that shrinks by > 50% or grows by > 300% compared to
  the previous version is suspicious and should be flagged.
- ALPN bypass is unaffected: even if a CDN's CIDR is in the Spamhaus feed, h2/h1 ALPN
  browser traffic bypasses the blocklist check entirely (cannot be hard-blocked by feed
  poisoning).
- Operator review: the `ja4proxy_blocklist_cidr_count` metric provides a stable baseline.
  Sudden large changes should be investigated.

**Residual risk:** Medium. A sophisticated nation-state actor with CA compromise
capability could poison the feed. Periodic manual verification of the CIDR count against
Spamhaus's published statistics is recommended.

---

### Phase 9: Beaconing Detector Evasion via Jitter Injection

**Threat:** A sophisticated bot operator instruments their bots to inject randomised
inter-arrival time (IAT) jitter specifically to evade the IAT coefficient of variation
(CV) detector. By keeping CV > 0.7 (the residential threshold), the bot avoids the
beaconing signal.

**Attack vector:**
- Adversary reverse-engineers or infers the CV threshold from public documentation or
  trial and error.
- Bots add Gaussian jitter to their request timing, keeping CV in the residential range
  while maintaining regular overall traffic volume.
- Single-window beaconing detection fails to distinguish jittered bots from residential
  users.

**Mitigations:**
- Dual window detection (1h and 24h): a jitter-evading bot that maintains regular
  request frequency over 24 hours will have a lower 24h CV than a genuine residential
  user who is naturally more irregular over longer periods. The 24h window is harder to
  evade with simple Gaussian jitter.
- Composite scoring: beaconing is one signal among many (ASN, JA4, AbuseIPDB, RDAP).
  A bot that evades beaconing detection is still scored by other signals. A bot running
  from a datacenter ASN with an unusual JA4 fingerprint scores high even without a
  beaconing signal.
- Campaign detection (Phase 12): distributed bots from many IPs with similar JA4
  fingerprints and similar IAT patterns are detected as a campaign even if no individual
  IP triggers the beaconing signal threshold.
- Fail open: the beaconing signal is additive (it raises the score). A bot that evades
  it is scored at 0 for this signal — not penalised or rewarded. Evasion is not an
  amplification attack.

**Residual risk:** Low-medium. Sophisticated adversaries can evade single-signal
detectors. The composite scoring design means evasion of one signal rarely results in
evasion of the full system.

---

### Phase 10: AbuseIPDB Shared IP False Positives (NAT/VPN)

**Threat:** A large corporate NAT gateway, VPN exit node, or carrier-grade NAT (CGNAT)
address appears in AbuseIPDB with a high abuse score because it has been used by one or
more abusive users sharing the same IP. Legitimate users behind the same NAT are
blocked.

**Attack vector:**
- Attacker (or previous abuser) uses the same IP as many legitimate users.
- AbuseIPDB score rises above the proxy's hard-block threshold.
- All users behind that IP are blocked, including legitimate ones.

**Mitigations:**
- Hard-block threshold is >= 50, not >= 1. Shared IPs with occasional abuse tend to
  score in the 20-40 range. A threshold of 50 ensures the IP has a sustained, severe
  abuse history before the proxy acts.
- Cached results have a TTL. An IP that was temporarily abusive will have its cached
  score expire, giving it a fresh lookup window.
- The AbuseIPDB signal is additive. An IP scoring 60 on AbuseIPDB must also cross the
  action threshold in the composite scorer. At dial < 100, the effective threshold is
  higher, providing additional buffer.
- mTLS bypass: corporate clients using mTLS client certificates bypass AbuseIPDB
  scoring entirely. Large organisations can be issued client certificates to avoid
  NAT-related false positives.
- Emergency disable: if AbuseIPDB is causing a false-positive spike, it can be disabled
  with a single config change + SIGHUP (see `docs/runbooks/external_api_failures.md`).

**Residual risk:** Low. The combined threshold and dial system makes it unlikely that a
NAT IP will be hard-blocked without significant evidence from multiple scoring dimensions.

---

### Phase 11: RDAP Block Expansion Abuse (Trigger Expansion of Legitimate ISP)

**Threat:** An attacker manipulates the proxy into expanding a CIDR ban to cover a
legitimate ISP's address range, causing widespread collateral blocking. This could be
done by sending high-risk traffic from a few IPs in the target ISP's range, causing
those IPs to be banned, and then triggering RDAP expansion.

**Attack vector:**
- Attacker identifies that the target ISP's ASN appears in `../../config/known_bad_orgs.yml`
  (perhaps incorrectly, or the ISP changed ownership).
- Attacker sends abusive traffic from a handful of IPs in the ISP's range.
- Proxy bans those IPs; RDAP expansion triggers and bans the entire /24.
- Legitimate users in the ISP's range are blocked.

**Mitigations:**
- Block expansion is off by default. This attack requires the operator to have
  consciously enabled expansion (see ADR-003).
- Known-bad org list is the first gate. The ISP must be in `../../config/known_bad_orgs.yml` for
  expansion to trigger. This list is manually maintained by the secops team.
- Hourly expansion cap (`max_per_hour`, default: 5) limits the total CIDR bans that
  can be created per hour, even under a targeted expansion-trigger attack.
- /24 maximum expansion limit: even if expansion triggers, it never expands beyond 256
  IPs. A single expansion event cannot block an entire ISP's customer base.
- Policy audit trail: every CIDR ban from expansion is logged to
  `management:policy_audit`. An unexpected expansion event is visible and auditable.
- Manual CIDR ban lift: any ban can be immediately removed via
  `redis-cli DEL ban_cidr:<cidr>` (see `docs/runbooks/security_policy.md`).

**Residual risk:** Low when expansion is disabled (default). Medium when enabled —
operators must review `../../config/known_bad_orgs.yml` carefully and monitor the audit trail.

---

### Phase 12: Analytics Stream Poisoning

**Threat:** A compromised or malicious proxy instance writes fake or manipulated events
to the `ja4proxy:events` stream. The analytics node processes these events and derives
incorrect findings (e.g., false campaign detections, incorrect score drift), which feed
back into the scoring of subsequent connections.

**Attack vector:**
- Attacker gains write access to Redis (e.g., via a compromised proxy container).
- Fake events are injected: false high-score connections for a target IP range, false
  campaign fingerprints, or manufactured beaconing patterns.
- Analytics node processes fake events and promotes false findings to Redis.
- Future connections from the targeted IPs are scored higher than warranted.

**Mitigations:**
- HMAC authentication on stream events: each event written to `ja4proxy:events` includes
  an HMAC field signed with a shared secret known only to proxy instances and the
  analytics node. The analytics node rejects events with invalid HMACs.
- Rate limiting on event write rate per NODE_ID: a single proxy instance cannot flood
  the stream beyond its expected connection rate. Events from a NODE_ID exceeding the
  rate limit are dropped and the anomaly is logged.
- Schema validation: the analytics node validates the schema of every event before
  processing. Events with unexpected fields, out-of-range scores, or malformed IDs are
  rejected and logged.
- Redis network security: Redis is not exposed to the internet. It is accessible only
  from trusted container networks. Compromising a proxy container is a precondition for
  stream poisoning (see `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` for container
  isolation measures).
- Analytics findings have short TTLs: findings written to Redis by the analytics node
  have TTLs of minutes to hours. A poisoning attack has a bounded effect window before
  findings expire.

**Residual risk:** Medium if Redis is not network-isolated (default Docker Compose
deployment has network-level isolation). Low if Redis AUTH is enabled and container
network policies are enforced.

---

*Section added: 2026-03-15. Covers Phases 8–12. Next review: 2026-09-15 or when
Phase 14 (production hardening) is complete.*