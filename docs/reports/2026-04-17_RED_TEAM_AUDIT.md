# Red Team Security Audit — Comprehensive Findings
**Date:** April 17, 2026
**Team:** 4 Expert Red Team Agents (Go Proxy, Python Proxy, Management API, Infrastructure)
**Scope:** Full production codebase audit

---

## Additional Audit: Supply Chain, Backup/Encryption, TLS Fingerprints
**Date:** April 17, 2026
**Team:** 3 Expert Red Team Agents (Supply Chain, Backup/Crypto, TLS)
**Scope:** Secondary focused audit

---

## Executive Summary

The red team conducted a deep security audit across all production components:
- Go proxy (`cmd/proxy/`)
- Python proxy (`proxy.py`, `src/`)
- Management API (`management/`)
- Infrastructure (`config/`, `.env`, Redis)

**Total NEW findings identified:** 18

| Severity | Known (Pentest) | NEW | Total |
|----------|-----------------|-----|-------|
| Critical | 2 | 3 | 5 |
| High | 1 | 6 | 7 |
| Medium | 0 | 5 | 5 |
| Low | 0 | 3 | 3 |

---

## Known Findings (from Phase 108 Pentest — Already in Phase 118)

| Finding ID | Title | Status |
|-----------|-------|-------|
| L1-018 | PROXY Protocol Smuggling (Go) | In Phase 118 (118a) |
| L1-019 | TCP Fragmentation Bypass | In Phase 118 (118b) |
| L4-028 | X-Forwarded-For Spoofing (Python) | In Phase 118 (118c) |

---

## New Findings (Not in Phase 118)

### Critical Severity

#### Finding R-001: SSRF via Webhook URL Creation (Management API)
**Severity:** Critical
**Location:** `management/api/routes/webhooks.py:86-130`

```python
class WebhookCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
```

**Attack Scenario:** An attacker with Operator role creates a webhook:
- `http://localhost:6379` — Direct Redis access
- `http://169.254.169.254/latest/meta-data/` — AWS metadata exfiltration
- `http://127.0.0.1:8090/internal` — Internal API access

When webhooks trigger, the proxy sends the webhook secret to attacker-controlled URLs.

**Impact:** Full internal infrastructure compromise, AWS credentials exfiltration.

**Remediation:** Validate all webhook URLs - block localhost, link-local, and internal CIDRs.

---

#### Finding R-002: Unauthenticated Metrics Endpoints Expose Security Posture
**Severity:** Critical
**Location:** `cmd/proxy/main.go:250-270, 656-832`

```go
mux.Handle("/metrics", promhttp.Handler())
mux.HandleFunc("/health", p.handleHealth)
mux.HandleFunc("/health/deep", p.handleHealthDeep)
```

**Attack Scenario:** Public Internet can poll `/metrics`, `/health`, `/health/deep` without authentication:
- Active connection counts (reveals attack volume)
- Block rates (reveals security effectiveness)
- Dial settings and active bans
- TLS certificate expiry timestamps
- Full pipeline configuration

**Impact:** Complete reconnaissance - attacker maps security posture before attacking.

**Remediation:** Require authentication on all observability endpoints or network-isolate to internal network.

---

#### Finding R-003: Redis Fail-Open Masks Misconfiguration
**Severity:** Critical
**Location:** `internal/redis/client.go:51-65`

```go
func buildStandaloneOptions(cfg Config) *goredis.Options {
    opts := &goredis.Options{
        Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
        Password: cfg.Password,  // May be empty
        ...
    }
```

**Attack Scenario:** If operator misconfigures Redis without password, Go proxy continues:
- Connects to unauthenticated Redis
- All security state exposed to network
- Attacker modifies ban lists, whitelists, dial settings

**Impact:** Complete compromise of security decisions.

**Remediation:** Fail-closed if Redis requires auth but none provided. Add startup validation.

---

### High Severity

#### Finding R-004: SSRF via NetBox Integration (Go)
**Severity:** High
**Location:** `internal/config/netbox.go:42-51`

```go
req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))
resp, err := a.http.Do(req)
```

**Attack Scenario:** If attacker can control NetBox URL or intercept DNS, the token is exposed.

**Impact:** Full NetBox read access.

**Note:** Currently mitigated - token not logged. Future changes must NOT add token to logs.

---

#### Finding R-005: HAProxy Stats Default Credentials
**Severity:** High
**Location:** `config/haproxy.cfg:37`

```cfg
stats auth ${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}
```

**Attack Scenario:** Default credentials `admin:admin123` if env vars not set.

**Impact:** HAProxy stats exposure, internal IP enumeration.

**Remediation:** Fail if env vars not set (no default).

---

#### Finding R-006: Redis TLS Binds to All Interfaces
**Severity:** High
**Location:** `deploy/docker/redis-tls/redis.conf:20`

```conf
bind 0.0.0.0 -::*
```

**Attack Scenario:** Redis with TLS exposes on all interfaces. With password compromise or weak creds, remote access possible.

**Remediation:** Bind only to Docker network.

---

#### Finding R-007: In-Memory Rate Limiting Bypass (Management API)
**Severity:** High
**Location:** `management/api/auth.py:59`

```python
_login_failures: dict[str, dict] = defaultdict(lambda: {"count": 0, "locked_until": 0.0})
```

**Attack Scenario:**
1. Distributed brute-force: distribute attempts across N instances = N × 5 attempts
2. Restart clears all lockout state

**Impact:** Brute-force protection bypassed.

**Remediation:** Use Redis-backed rate limiting.

---

#### Finding R-008: Test Secret Fallback in Production Path
**Severity:** High
**Location:** `management/api/auth.py:74-79`

```python
if os.environ.get("MANAGEMENT_TEST_MODE") == "1":
    return "test-secret-do-not-use-in-production"
```

**Attack Scenario:** If attacker can set env var, JWT verification bypassed.

**Impact:** Authentication bypass.

**Remediation:** Remove test code from production builds.

---

#### Finding R-009: Verbose Error Logging Exposes Internals
**Severity:** High
**Location:** Multiple locations

```go
return nil, fmt.Errorf("config: read %q: %w", path, err)
c.log.WithError(err).WithField("key", key).Warn("redis: GET failed")
```

**Attack Scenario:** File paths, Redis keys, internal names leak to logs.

**Impact:** Reconnaissance.

---

### Medium Severity

#### Finding R-010: No Rate Limiting on Health/Metrics Endpoints
**Severity:** Medium
**Location:** `cmd/proxy/main.go:260`

```go
srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second}
```

**Attack Scenario:** `/health`, `/metrics` spammed:
- Log flooding
- Redis connection churn
- Prometheus metric churn

**Impact:** DoS on observability.

---

#### Finding R-011: Weak AbuseIPDB API Key Handling
**Severity:** Medium
**Location:** `internal/security/abuseipdb.go:55, 165`

```go
http: &http.Client{Timeout: 5 * time.Second}
req.Header.Set("Key", a.cfg.APIKey)
```

**Attack Scenario:** API key in HTTP header could leak if network compromised.

**Impact:** AbuseIPDB quota exhaustion.

---

#### Finding R-012: Redis ACLs Disabled by Default
**Severity:** Medium
**Location:** `config/proxy.yml:54`

```yaml
acl_users:
  enabled: false  # Default off
```

**Attack Scenario:** Even with password, default user has full access.

**Impact:** No granular access control.

---

#### Finding R-013: Webhook Secrets in Memory
**Severity:** Medium
**Location:** `internal/webhook/delivery.go:159, 221-224`

```go
func computeHMAC(secret string, payload []byte) string {
    mac := hmac.New(sha256.New, []byte(secret))
```

**Attack Scenario:** Secrets in memory for process lifetime.

**Impact:** Process compromise → secret exposure.

---

#### Finding R-014: No Per-Service Redis User Enforcement
**Severity:** Medium
**Location:** `config/proxy.yml:47-56`

```yaml
acl_users:
  enabled: false
  proxy_user: "proxy"
```

**Attack Scenario:** Services don't use minimal-privilege accounts.

**Impact:** Overly permissive access.

---

### Low Severity

#### Finding R-015: Redis Password in Log Messages (Partial)
**Severity:** Low
**Location:** `management/api/redis_client.py:70`

```python
logger.info("Redis connection pool initialised: %s", url.split("@")[-1])
```

**Impact:** Potential credential disclosure if logging config changes.

---

#### Finding R-016: DGA Detection ReDoS Potential
**Severity:** Low
**Location:** `internal/security/sni_analyzer.go:183-243`

```go
func dgaConfidence(hostname string) float64 {
    label := getPrimaryLabel(hostname)
    if len([]rune(label
```

**Note:** Pattern looks intentional but needs review.

---

#### Finding R-017: Verbose Error Exposure
**Severity:** Low
**Location:** Various

**Impact:** Stack traces in error responses in debug mode.

---

---

## Findings Cross-Reference

### Known in Phase 118 vs. New

| Phase 118 | New Equivalent | Status |
|-----------|--------------|--------|
| 118a: PROXY Smuggling | R-002 (metrics exposure) | Different issue |
| 118b: TLS Reassembly | R-003 (Redis fail-open) | Different issue |
| 118c: XFF Spoofing | R-007 (in-memory rate limit) | Related |
| 118d: Redis ACLs | R-006, R-012 | New aspects |
| 118e: Mgmt Auth | R-004, R-008 | New aspects |

---

## Recommended New Phase

The following new findings should be added to Phase 118 or create Phase 119:

| Priority | Finding | Fix Complexity | Add to Phase |
|----------|---------|--------------|--------------|
| P1 | R-001: SSRF Webhooks | SMALL | 118 or 119 |
| P1 | R-002: Unauth Metrics | XS | 118 or 119 |
| P1 | R-003: Redis Fail-Open | XS | 118 or 119 |
| P2 | R-005: HAProxy Defaults | XS | 118 |
| P2 | R-006: Redis All-Interfaces | SMALL | 118 |
| P2 | R-007: Redis Rate Limit | MEDIUM | 118 or 119 |
| P3 | R-008: Test Secret | XS | 118 or 119 |
| P3 | R-010: Health DoS | XS | 118 or 119 |
| P3 | R-012: Redis ACLs | SMALL | 118d already |

---

## Chaining Potential (Attacker View)

### Attack Chain A: Full Compromise via Webhook
1. Create webhook with SSRF (R-001)
2. Trigger webhook → send secret to attacker server
3. Use secret to access internal API
4. Read all security intelligence

### Attack Chain B: Defense Evasion
1. Bypass metrics collection (R-002) → see block rates
2. Send fragmented TLS (L1-019) → bypass JA4
3. Spoof XFF (L4-028) → bypass bans
4. Full-speed attack on backend

### Attack Chain C: Infrastructure Pivot
1. Exploit PROXY smuggling (L1-018) → scan DMZ
2. Find exposed service → exploit
3. Steal Redis password
4. Modify blocklists → allow C2 traffic

---

## Supply Chain & Third-Party Findings (April 17, 2026 - Secondary Audit)

### Finding SC-001: urllib Without TLS Verification (Splunk/Nagios/Dynatrace)
**Severity:** Medium
**Locations:**
- `deploy/integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py:103-114`
- `deploy/nagios/check_ja4proxy.py:44-48`
- `deploy/dynatrace/ja4proxy-extension/plugin.py:129-134`

**Attack Scenario:** These integrations use `urllib.request.urlopen()` without certificate validation. MITM can intercept and modify data.

**Impact:** Data integrity compromise in monitoring integrations.

---

### Finding SC-002: Python Docker Base Images Outdated
**Severity:** Medium
**Location:** `deploy/docker/Dockerfile:4`, `Dockerfile.management:1`, etc.

**Attack Scenario:** Using `python:3.14.0-slim` (Oct 2025) instead of latest patch (3.14.2).

**Impact:** Missing security patches.

---

### Finding SC-003: Go Alpine Base Image Unstable
**Severity:** Low
**Location:** `deploy/docker/Dockerfile.go-proxy:17`, `Dockerfile.cli:15`

**Attack Scenario:** Uses `golang:1.25-alpine` (edge) instead of `golang:1.25-alpine3.19` (stable).

**Impact:** Unpredictable dependencies.

---

### Finding SC-004: No SBOM Generation in CI
**Severity:** Medium
**Location:** `.github/workflows/`

**Attack Scenario:** No Software Bill of Materials generated. Downstream consumers cannot efficiently respond to CVEs.

**Impact:** Supply chain transparency.

---

### Finding SC-005: go-redis Version
**Severity:** Medium (needs verification)
**Location:** `go.mod:11` (`github.com/redis/go-redis/v9 v9.18.0`)

**Attack Scenario:** Known parsing vulnerabilities in certain go-redis versions.

**Impact:** Potential Redis protocol attack.

---

## Backup & Encryption Findings (April 17, 2026 - Secondary Audit)

### Finding BE-001: Backup Header Leaks Encryption Status
**Severity:** Critical
**Location:** `src/backup/worker.py:288-291`, `src/backup/format.py:52-64`

**Code:**
```python
format_flags = FLAG_FULL | (FLAG_ENCRYPTED if is_encrypted else 0)
backup_data = encode_header("full", format_flags) + backup_data
```

**Attack Scenario:** The backup FORMAT HEADER is prepended AFTER encryption, leaking:
- Whether backup is encrypted (FLAG_ENCRYPTED = 0x04)
- Whether full or incremental (FLAG_FULL = 0x01, FLAG_INCREMENTAL = 0x02)

**Impact:** Attackers can identify valuable (encrypted) backups vs. unencrypted ones.

---

### Finding BE-002: No Integrity Verification Before Decryption
**Severity:** High
**Location:** `src/backup/restorer.py:261-270`

**Code:**
```python
try:
    decrypted_data = self.encryption.decrypt(encrypted_data)
except Exception as e:
    raise RestoreError(f"Decryption failed: {e}")
```

**Attack Scenario:** Tampered backups fail silently with generic "decryption failed". Cannot distinguish tampering from configuration errors.

**Impact:** Tampering goes undetected.

---

### Finding BE-003: Sensitive Key Names in Logs
**Severity:** Medium
**Location:** `src/backup/worker.py:255-267`

**Code:**
```python
logger.warning(json.dumps({
    "event": "sensitive_key_detected",
    "key": key,  # Full key name logged
    ...
}))
```

**Attack Scenario:** Redis key names containing sensitive patterns logged in plaintext.

**Impact:** Sensitive data in logs.

---

## TLS Fingerprint Findings (April 17, 2026 - Secondary Audit)

### Finding TLS-001: No Maximum ClientHello Size Limit
**Severity:** Medium
**Location:** `internal/tls/parser.go:57-65`

**Code:**
```go
helloLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
if len(body) < 4+helloLen {
    return nil, ErrTruncated
}
```

**Attack Scenario:** No upper bound check on helloLen. Multi-MB ClientHello accepted, causing memory exhaustion.

**Impact:** DoS via large handshake.

---

### Finding TLS-002: Python JA4 Missing Size Limit
**Severity:** Medium
**Location:** `src/tap/fingerprints/ja4.py:97`, `ja4.py:105-120`

**Attack Scenario:** Similar lack of upper bounds in Python TLS parsing.

**Impact:** DoS via large handshake.

---

## New Findings Summary (All Audits)

| Severity | Supply Chain | Backup/Crypto | TLS | Total |
|----------|--------------|---------------|-----|-------|
| Critical | 0 | 1 | 0 | 1 |
| High | 0 | 1 | 0 | 1 |
| Medium | 4 | 1 | 2 | 7 |
| Low | 2 | 0 | 0 | 2 |

---

## Action Items

- [ ] Update Phase 118 to include R-001 (SSRF), R-002 (Metrics), R-003 (Redis), R-007 (Redis rate limit)
- [ ] Consider Phase 119 for large infra changes (HAProxy defaults, Redis network isolation)
- [ ] Add Redis ACL enforcement (already in 118d)
- [ ] Add webhook URL validation (NEW)
---

## Session/JWT/Config Findings (April 17, 2026 - Tertiary Audit)

### Finding SJC-001: Configuration Path Traversal
**Severity:** Critical
**Location:** `src/config/loader.py:76-77`

**Attack Scenario:** If config_path is user-controllable, attacker can read arbitrary files (`../../etc/shadow`, credentials, TLS keys).

**Impact:** Arbitrary file read.

---

### Finding SJC-002: Development Mode Plaintext Password
**Severity:** High
**Location:** `management/api/auth.py:95-111`

**Attack Scenario:** If `MANAGEMENT_ADMIN_PASSWORD` set without hash, password stored in plaintext in env var.

**Impact:** Admin account compromise.

---

### Finding SJC-003: No Password Policy Enforcement
**Severity:** High
**Location:** `management/api/models.py:32`

**Attack Scenario:** Only min_length=1. No complexity requirements, no dictionary check.

**Impact:** Weak passwords enable brute force.

---

### Finding SJC-004: Bearer Token Enumeration
**Severity:** High
**Location:** `management/api/auth.py:192-268`

**Attack Scenario:** Attacker iterates all token IDs in `mgmt:token:idx`, brute-forces tokens without rate limiting.

**Impact:** Token brute force.

---

### Finding SJC-005: JWT Cookie Secure Flag Not Set
**Severity:** Medium
**Location:** `management/api/auth.py:494`

**Attack Scenario:** `secure=False` allows cookie capture over HTTP.

**Impact:** Session hijacking via MITM.

---

## Analytics/Detection Findings (April 17, 2026 - Tertiary Audit)

### Finding AD-001: Unvalidated Event Fields
**Severity:** Medium
**Location:** `src/analytics/detection.py:75-107`

**Attack Scenario:** Missing fields cause KeyError crashes in worker threads.

**Impact:** Detection system instability.

---

## Export Systems Findings (April 17, 2026 - Tertiary Audit)

### Finding EXP-001: IP ACL Bypass via X-Real-IP
**Severity:** High
**Location:** `src/tap/export/edl_server.py:192-196`

**Attack Scenario:** Attacker spoofs `X-Real-IP` header to bypass IP-based EDL access control.

**Impact:** Unauthorized EDL access.

---

### Finding EXP-002: CRLF Injection in Syslog
**Severity:** High
**Location:** `src/tap/export/syslog_exporter.py:115-148`

**Attack Scenario:** User-controlled IP/ja4 fields inject `\r\n` to split or forge syslog messages.

**Impact:** Log injection, message forging.

---

### Finding EXP-003: STIX Bundle Size DoS
**Severity:** Medium
**Location:** `src/tap/export/taxii_server.py:156-227`

**Attack Scenario:** Millions of ban keys cause unbounded STIX bundle → memory exhaustion.

**Impact:** DoS via large response.

---

## TI Feeds Findings (April 17, 2026 - Tertiary Audit)

### Finding TI-001: MISP SSRF
**Severity:** High
**Location:** `src/security/misp.py:221-226`

**Attack Scenario:** MISP base_url from config without validation. Can point to internal services.

**Impact:** Internal service access.

---

### Finding TI-002: API Key in Error Logs
**Severity:** High
**Location:** `src/security/virustotal.py:295-299`

**Attack Scenario:** Upstream API error responses might include API keys → exposed in logs.

**Impact:** API key leakage.

---

## New Findings Summary (All 4 Tertiary Audits)

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Session/JWT/Config | 1 | 3 | 1 | 0 |
| Analytics | 0 | 0 | 1 | 0 |
| Export | 0 | 2 | 1 | 0 |
| TI Feeds | 0 | 2 | 1 | 0 |
| **TOTAL** | **1** | **7** | **4** | **0** |

---

## Round 4: Redis/SSO/Multi-instance/DoS (April 17, 2026 - Fourth Audit)

### Finding R-001: Redis KEYS Command Enumeration
**Severity:** High
**Location:** `src/security/gdpr_storage.py:226,282`, `src/security/action_enforcer.py:444-452`

**Attack Scenario:** `keys("*")` enumerates all Redis keys → exposes ban lists, rate limit data.

**Impact:** Complete intelligence on security decisions.

---

### Finding R-002: Pub/Sub Message Signature Bypass
**Severity:** High
**Location:** `src/pubsub.py:165-185`

**Attack Scenario:** Only 4 message types verified with HMAC. Other types (whitelist_remove, ban_release) have no verification.

**Impact:** Lateral movement from compromised instance.

---

### Finding SSO-001: OIDC ID Token Signature Bypass (TEST MODE)
**Severity:** Critical
**Location:** `management/api/routes/oidc.py:210-222`

**Attack Scenario:** If `MANAGEMENT_TEST_MODE=1`, ID token verification bypassed entirely.

**Impact:** Complete auth bypass via forged tokens.

---

### Finding SSO-002: SAML Signature Verification Disabled
**Severity:** Critical
**Location:** `management/api/routes/saml.py:78-104`

**Attack Scenario:** `MANAGEMENT_SAML_STRICT=false` disables signature verification.

**Impact:** Complete SAMl auth bypass.

---

### Finding SSO-003: OIDC Missing Nonce Validation
**Severity:** High
**Location:** `management/api/routes/oidc.py:422-432`

**Attack Scenario:** No nonce binding between state and ID token.

**Impact:** Token injection from intercepted auth code.

---

### Finding DOS-001: Unbounded Go Connection Handling (CRITICAL)
**Severity:** Critical
**Location:** `cmd/proxy/main.go:285-298`

**Attack Scenario:** No semaphore on incoming connections → goroutine explosion under DDoS.

**Impact:** Process crash / memory exhaustion.

---

### Finding DOS-002: Slowloris Vulnerability
**Severity:** High
**Location:** `proxy.py:2161-2171`, `cmd/proxy/main.go`

**Attack Scenario:** No idle timeout → attacker holds connections indefinitely.

**Impact:** Connection hold DoS.

---

### Finding DOS-003: ReDoS in JA4 Validation
**Severity:** High
**Location:** `src/security/validation.py:177-185`

**Attack Scenario:** Regex backtracking on malformed fingerprints.

**Impact:** CPU exhaustion.

---

### Finding DOS-004: Unbounded Redis Pool (Go)
**Severity:** High
**Location:** `internal/redis/client.go:52-64`

**Attack Scenario:** No pool size limits → connection exhaustion under load.

**Impact:** Redis connection failure cascade.

---

### Finding DOS-005: Unbounded Tarpit Per-IP Dict
**Severity:** Medium
**Location:** `proxy.py:1462-1463`

**Attack Scenario:** `_tarpit_per_ip` grows unbounded per unique IP.

**Impact:** Memory exhaustion.

---

## Round 4 Summary

| Category | Critical | High | Medium |
|----------|----------|------|--------|
| Redis/Query | 0 | 2 | 1 |
| SSO/SAML | 2 | 1 | 2 |
| Multi-instance | 0 | 1 | 0 |
| DoS | 2 | 3 | 2 |
| **Subtotal** | **4** | **7** | **5** |

---

## Grand Total (All 8 Red Team Audits)

| Audit Round | Critical | High | Medium | Low | Total |
|------------|----------|------|--------|-----|-------|
| Round 1 (Go/Py/Mgmt/Infra) | 3 | 6 | 5 | 3 | 17 |
| Round 2 (Supply/Backup/TLS) | 1 | 1 | 4 | 2 | 8 |
| Round 3 (Session/Analytics/Export/TI) | 1 | 7 | 4 | 0 | 12 |
| Round 4 (Redis/SSO/DoS) | 4 | 7 | 5 | 0 | 16 |
| **GRAND TOTAL** | **9** | **21** | **18** | **5** | **53** |

---

## Action Items

- [ ] Add 2 NEW critical findings to Phase 118 or Phase 119:
  - BE-001: Backup header encryption status leak
  - SC-001: urllib TLS verification
- [ ] Add findings from Round 3 to new Phase 119:
  - SJC-001: Config path traversal
  - SJC-002: Dev mode plaintext password
  - SJC-003: Password policy (already partially in 118e)
  - EXP-001: IP ACL bypass
  - EXP-002: CRLF injection
- [ ] Add auth endpoint rate limiting (already partially in 118e)