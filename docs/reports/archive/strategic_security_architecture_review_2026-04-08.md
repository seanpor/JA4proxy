> **Archived snapshot — Phase 105 (2026-04-25).** This report reflects the
> project state at the time of writing (2026-04-08, pre-Phase-200). Current
> canonical reference: [`../../PROJECT_STATUS.md`](../../reference/PROJECT_STATUS.md)
> and the [phase manifest](../../phases/manifest.yaml).
> Body untouched below.

# JA4proxy — Strategic Security Architecture Review

**Date:** 2026-04-08  
**Reviewer:** Senior Security Architect (AI)  
**Scope:** Full codebase review — architecture, security signals, cryptography, data integrity, network layer, observability, deployment, testing  
**Branch:** `review/strategic-security-architecture`

---

## Executive Summary

JA4proxy is a well-architected TLS-layer security proxy with a fundamentally sound design. The decision to operate at the TLS ClientHello level — without decrypting traffic — is strategically correct: it eliminates key management complexity, reduces compliance exposure, and enables truly transparent deployment.

> **Production context:** The Go proxy (`cmd/proxy/`, `internal/`) is the production runtime. The Python proxy (`proxy.py`, `src/security/`) is deprecated and retained only as an experimental prototyping surface. All findings in this review are scored through this lens: Go-only gaps are production gaps; Python-only issues are maintenance debt; shared infrastructure (deployment, CI, Helm, Redis config) applies equally.

**Overall assessment: Strong Go foundation, but production deployment has exploitable gaps.** The core pipeline architecture is sound and the fail-open policy is consistently implemented. However, several HIGH-severity findings exist in the production Go code path — most critically, the Go proxy trusts PROXY protocol headers from any source, and the production Docker compose file points to the deprecated Python Dockerfile.

### Key Metrics

Ratings reflect **Go production reality**. Python-only findings are downgraded to maintenance debt unless they represent design patterns that should be ported to Go.

| Area | Rating | Summary | Detail Report |
|------|--------|---------|--------------|
| Architecture & Pipeline | **B+** | Go pipeline sound; PROXY trust gap in Go is CRITICAL | Main report §1 |
| Security Signals | **C+** | Score drift in Go code, missing signals in Go, cipher coverage gap | [01_signal_implementation_review.md](01_signal_implementation_review.md) — 14 findings |
| Cryptography & TLS | **B−** | JA4 solid in Go; missing `ja4_tls_mismatch` and JA4T are production gaps | Main report §3 |
| Data Integrity & Caching | **B** | Well-designed; Go Redis client omits TLS, FLUSHDB risk | [02_redis_caching_data_integrity_review.md](02_redis_caching_data_integrity_review.md) — 25 findings |
| Network & Evasion | **C+** | Go trusts PROXY from any source (CRITICAL), no v2 support, JA4T stub | [03_network_evasion_review.md](03_network_evasion_review.md) — 12 findings |
| Observability | **C+** | Go health check superficial; f-strings in Python (deprecated); metrics unauthenticated | [04_observability_logging_alerting_review.md](04_observability_logging_alerting_review.md) — 21 findings |
| Deployment & Supply Chain | **C−** | Prod compose deploys Python not Go; default credentials; no SBOM | [05_deployment_supply_chain_review.md](05_deployment_supply_chain_review.md) — 30 findings |
| Management API | **B−** | Auth model incomplete; RBAC not yet implemented (Phase 79) | Main report §8 |
| Test Coverage | **B** | Large suite; adversarial tests target HTTP not TLS layer | Main report §9 |

### Critical Findings (Must Fix Before Production)

> Tags: **[Go-PROD]** = production code gap · **[Infra]** = deployment/config · **[Python-deprecated]** = maintenance only

1. **Prod compose deploys Python, not Go** — `docker-compose.prod.yml` points to `Dockerfile`, not `Dockerfile-go-proxy` (05) **[Go-PROD + Infra]**
2. **Go trusts PROXY protocol from any source** — trivial IP spoofing bypasses ALL geo/IP/rate/block controls in production (03) **[Go-PROD]**
3. **Go Redis client omits TLS despite config having SSL field** — production credentials on wire (02) **[Go-PROD]**
4. **Default credentials everywhere** — Grafana `admin`, Management `admin/admin`, HAProxy `admin/admin123` (05) **[Infra]**
5. **Signal score drift in Go** — 5 signals differ from `config/signal_scores.yml` registry (01) **[Go-PROD]**
6. **CI workflow actions not SHA-pinned** — supply chain risk (05) **[Infra]**

### High-Priority Findings (Should Fix Before Production)

7. **Go lacks PROXY protocol v2 support** — modern HAProxy/NLB send v2 by default, silently ignored (03) **[Go-PROD]**
8. **Go JA4T is a stub** — no TCP-level evasion detection in production (01) **[Go-PROD]**
9. **Go weak cipher coverage gap** — 13 suites vs 37+; NULL, EXPORT, DH_anon, ECDH_anon missed (01) **[Go-PROD]**
10. **Go `ja4_tls_mismatch` not implemented** — TLS version spoofing undetected in production (01) **[Go-PROD]**
11. **Backup `FLUSHDB` wipes entire Redis DB** — not just JA4proxy keys (02) **[Infra]**
12. **Go reads dial from Redis per-connection with no rate limiting** — latency tax at 15K+ conn/s; no safety gates (01) **[Go-PROD]**
13. **Helm chart has no NetworkPolicy** — any pod can reach proxy and Redis (05) **[Infra]**
14. **No SBOM generation or image signing** — supply chain gap (05) **[Infra]**
15. **Metrics endpoint unauthenticated, binds `0.0.0.0`** — information disclosure (04) **[Infra]**
16. **Hardcoded placeholder secrets in alertmanager.yml** — (04) **[Infra]**
17. **Alert references undefined metric** — `PipelineInternalError` fires on nothing (04) **[Infra]**
18. **Shadow scoring uses ALPN-only for "known-good"** — forgeable baseline breaks analytics calibration (04) **[Infra]**

---

## 1. Architecture & Pipeline

### 1.1 Pipeline Design — Sound with Minor Gaps

The pipeline follows the correct ordering: bypass checks → signal collection → scoring → decision → action. Both Python and Go implementations maintain this ordering.

**Strengths:**
- Fail-open is consistently applied across I/O-dependent modules
- The confidence-weighted scoring model is architecturally correct
- Local LRU cache with per-entry TTL provides good performance/isolation
- Pub/sub dial updates ensure cluster-wide consistency (Python)

**Finding A-1 (LOW — Python-deprecated): Pre-pipeline bypass drift in Python**

Python's `proxy.py` (lines 2193-2246) checks country dynamic blacklist and CIDR blocks **before** calling `pipeline.process()`. Go handles both inside the pipeline (`checkHardBlocks`) — correctly. Since Python is deprecated, this is maintenance debt, not a production gap.

**Recommendation:** Only fix if Python prototype is kept. Otherwise, safe to ignore.

**Finding A-2 (MEDIUM): Bypass check order differs — audit log inconsistency**

Python checks `static_ip_allowlist` first; Go checks it last (after ALPN, JA4 whitelist, mTLS). While the functional result is the same (connection is allowed), the `bypass_reason` label differs for audit/SIEM purposes. In Go production, this means the `bypass_reason` field will reflect whichever Go check matched first, not what the Python prototype would have reported.

**Finding A-3 (LOW — Python-deprecated): CIDR block check lacks explicit fail-open guard**

Python-only. Go handles CIDR blocks inside the pipeline with proper error handling. Since Python is deprecated, this is maintenance debt.

### 1.2 Dial Mechanism

**Finding A-4 (HIGH — Go-PROD): Go reads dial from Redis per-connection with no safety gates**

| Aspect | Python (deprecated) | Go (production) |
|--------|--------|-----|
| Source | In-memory cache (pub/sub) | Redis GET per connection |
| Rate limiting | `DialManager.validate_change()` (max 25/hr) | **None** |
| Safety gate | `blocking_acknowledged` check | **None** |

Go performs a Redis GET on every single connection. At 15,000+ conn/s, this adds a measurable latency tax. Worse, Go has no rate-limiting on dial changes and no `blocking_acknowledged` safety gate — any process that writes to `config:dial` in Redis immediately affects the proxy with no throttling.

### 1.3 Concurrency Model

Python uses asyncio with `asyncio.gather()` for parallel signal collection (15 I/O-bound collectors run concurrently). Go runs signals sequentially — expected to have higher per-connection latency when external lookups are enabled. This is a known trade-off: Go compensates with higher raw throughput.

The `_conn_semaphore` gates handlers but not connection acceptance — under SYN flood, OS-level buffering (`SERVER_BACKLOG = 4096`) is the only defense. This is a known limitation of application-layer semaphores.

---

## 2. Security Signal Implementations

**See companion report:** [`docs/reports/01_signal_implementation_review.md`](01_signal_implementation_review.md)

### 2.1 Critical Score Drift (Go-PROD)

`make check-scores` reports **4 signals** where Go diverges from `config/signal_scores.yml` — this is a **production issue**, not a parity problem:

| Signal | Go | Registry | Delta |
|--------|----|----------|-------|
| `tls_version` | 40 | 10 | +300% |
| `weak_cipher` | 20 | 35 | −43% |
| `high_concurrency` | 25 | 40 | −37% |
| `moderate_concurrency` | 10 | 25 | −60% |

These incorrect scores mean the Go production proxy is making wrong scoring decisions. A connection that should score 75 could score 55, causing different actions (block vs. tarpit). This is a close-out checklist requirement that is currently failing.

Note: `return_visitor` Python drift (−1 vs −20) is Python-deprecated and not a production concern.

### 2.2 Stub Code — Python-Deprecated

`tcp_analyzer.py` uses `__import__("random").random() < 0.9` for session resumption detection. Since Python is deprecated, this is maintenance debt, not a production issue.

**However:** If these signals are ported to Go in the future, they must be implemented properly — not with random values.

### 2.3 DGA Algorithm Mismatch

Python and Go DGA detectors use different entropy thresholds, vowel analysis, label length heuristics, and digit detection. Python strips common prefixes (`www`, `api`) before analysis; Go does not. An attacker could craft hostnames that pass the Go production proxy but would be flagged by the Python prototype.

**Impact:** The Go production proxy's SNI analysis is less effective than the Python prototype's.

### 2.4 Missing Signals in Go (Production Gaps)

| Signal | Python (prototype) | Go (production) | Impact |
|--------|--------|-----|--------|
| `ja4_tls_mismatch` | ✅ (score 35) | ❌ | TLS version spoofing undetected in production |
| JA4T | ✅ (actual fingerprint) | ❌ (stub, returns `""`) | TCP-level evasion possible in production |
| Deception checker | ✅ (honey-fingerprint/SNI) | ❌ | No active defense traps in production |

### 2.5 Cipher Suite Coverage (Production Gap)

Go's `weakCipherSet` has **13** suites; Python's `WEAK_CIPHERS` has **37+**. The Go production proxy misses: NULL ciphers, EXPORT suites, DH_anon, ECDH_anon, non-PFS RSA. An attacker offering a weak cipher that Go doesn't recognize would bypass this check entirely.

---

## 3. Cryptography & TLS Handling

### 3.1 JA4 Fingerprinting

The JA4 implementation is solid:
- SNI presence detection is consistent between Python and Go
- GREASE value filtering is correctly implemented
- The fingerprint format matches the FoxIO specification

### 3.2 TLS Enforcement

**Finding C-1 (HIGH — Go-PROD):** The `ja4_tls_mismatch` signal exists only in Python. An attacker could craft a ClientHello that claims TLS 1.3 in JA4 but uses TLS 1.2 on the wire — the Go production proxy would not detect this inconsistency.

**Finding C-2 (LOW — Python-deprecated):** Python's `tls_enforcer.py` uses hardcoded `score=35` for `ja4_tls_mismatch`. Not a production concern.

### 3.3 TLS Parsing

Python uses pure-Python TLS parsing with Scapy fallback via `ThreadPoolExecutor`. Go uses pure-Go parsing. Both approaches avoid the openssl dependency, which is correct — the proxy must not terminate TLS.

---

## 4. Data Integrity & Caching

### 4.1 Cache Architecture — Strong

| Component | Implementation | Assessment |
|-----------|---------------|------------|
| LRU cache (Python) | `OrderedDict` + TTL, lazy eviction | ✅ Correct |
| LRU cache (Go) | `container/list` + `sync.Mutex`, TTL | ✅ Correct |
| Bloom filter | RedisBloom with SET fallback | ✅ Graceful degradation |
| Cache coherence | Redis says block + local says allow → local wins | ✅ Fail-open aligned |

**Finding D-1 (LOW):** Python's `bloom.py` uses `except Exception` (broad catch) for Bloom filter initialization errors. This is acceptable given the fallback behavior, but should use specific exception types.

### 4.2 Backup System — Strong

The backup system (Phase 40) is well-designed:
- **AES-256-GCM** with PBKDF2 (100K iterations) — appropriate key derivation
- **Binary format** with header/magic bytes for integrity
- **Never-backup patterns** — passwords, auth tokens, API keys excluded
- **Pipeline batching** (1000 keys per batch) — efficient
- **Retention policy** — configurable, with cleanup

**Finding D-2 (LOW):** The `_KEY_PATTERNS_NEVER_BACKUP` list is maintained manually. If new sensitive key patterns are added to Redis without updating this list, they could leak into backups.

### 4.3 Redis Schema — Well Documented

The `docs/reference/REDIS_SCHEMA.md` is comprehensive and follows good conventions. All keys document pattern, type, TTL, writer, and notes.

**Finding D-3 (LOW):** Several keys have `none` TTL (no expiry): `config:dial`, `ja4:whitelist`, `ja4:blacklist`, `static:allowlist`, `behavioral:known_ja4`, `confidence:scores`. These persist indefinitely until explicitly deleted. If Redis is restored from a backup taken before a config change, stale values could be served. The pub/sub `config:reload` mechanism mitigates this, but only if the proxy is running when the restore happens.

---

## 5. Network Layer & Evasion Resistance

### 5.1 PROXY Protocol Handling — CRITICAL GAP IN GO

**Finding N-1 (CRITICAL — Go-PROD): Go trusts PROXY protocol from any source**

Python guards PROXY protocol parsing with `_is_trusted_proxy_source()` which validates the peer IP against a configurable `trusted_cidrs` list. **The Go production proxy has no equivalent trust check.** Any client that sends `PROXY TCP4 1.2.3.4 ...` as its first bytes will have its source IP set to `1.2.3.4`, bypassing:
- GeoIP country blocking
- CIDR block checks
- Rate limiting by IP
- ASN classification
- All IP-based security controls

**Attack scenario:** An attacker from a blocked country sends `PROXY TCP4 8.8.8.8 ...` — the Go proxy treats the connection as coming from 8.8.8.8 (US).

**Finding N-2 (HIGH — Go-PROD): Go lacks PROXY protocol v2 support**

Modern HAProxy and AWS NLB send PROXY protocol v2 by default. The Go proxy silently ignores v2 headers and uses the LB's IP as the client IP, breaking all per-IP controls.

**Finding N-3 (LOW):** Python PROXY v2 `addr_len` trusted without bounds check. Python-deprecated, not a production concern.

### 5.2 TLS Passthrough — Correct

The `_forward_to_backend()` method forwards the raw `data` (including the ClientHello) byte-for-byte to the backend, then pipes between client and backend sockets. The proxy never decrypts — correct.

### 5.3 Evasion Vectors

**Finding N-4 (HIGH — Go-PROD): JA4T stub removes TCP-level evasion detection**

Go's `ComputeJA4T()` always returns `""`. This removes TCP fingerprinting from the production proxy — an attacker can forge JA4 while having different TCP characteristics (TTL, window size, TCP options) that would normally flag them.

**Finding N-5 (MEDIUM):** JA4 fingerprint forging is theoretically possible. An attacker with a custom TLS stack could match a known-good JA4 + set ALPN to `h2` to bypass the entire pipeline. The JA4X (certificate) signal partially mitigates this, but JA4T is missing from Go.

**Finding N-6 (MEDIUM):** GeoIP blocking relies on Country DB only — no proxy/VPN/hosting detection. This is a known limitation of IP geolocation, not a bug.

**Finding N-7 (LOW):** Tarpit capacity is per-instance, not shared. Distributed attacks can exhaust tarpit across multiple instances independently.

---

## 6. Observability, Logging & Alerting

### 6.1 Metrics — Present but Could Be Richer

Prometheus metrics are defined across the codebase with consistent `ja4proxy_` prefix naming. Key metrics include:
- `ja4proxy_request_count_total` (by action, country, TLS version)
- `ja4proxy_blocked_requests_total` (by reason, attack type)
- `ja4proxy_security_events_total` (by type, severity)
- `ja4proxy_cache_operations_total` (by type, result)
- `ja4proxy_backup_*` (operations, duration, size)

**Finding O-1 (MEDIUM):** The Prometheus scrape config (`deploy/monitoring/prometheus.yml`) uses a 15s global interval with 5s for the proxy job. This is reasonable for monitoring but may miss short-lived spikes. For a proxy making 10K+ decisions/sec, a 5s scrape window means ~50K decisions per data point — sufficient for trends but not for real-time alerting.

**Finding O-2 (MEDIUM):** No alerting rules were found for critical security events:
- No alert on sudden block rate increase (could indicate misconfiguration)
- No alert on false positive reports from users
- No alert on signal collector failures
- No alert on backup failures

### 6.2 Logging — Standards Violations (Mostly Python-Deprecated)

**Finding O-3 (LOW — Python-deprecated):** Multiple Python files use f-string logging. Since Python is deprecated, these are maintenance debt. The 17 instances across 7 modules (`virustotal.py`, `behavioral.py`, `greynoise.py`, `alienvault.py`, `misp.py`, `threatfox.py`, `attribution.py`) should only be fixed if Python prototype is kept.

**Finding O-3a (MEDIUM — Go-PROD):** Go logging uses structured logrus correctly. However, the Go health check logs at INFO level for every check, which could produce noise at 15K+ conn/s. No rate-limiting on health check logs.

### 6.3 Grafana Dashboards

Grafana dashboards exist in `deploy/monitoring/grafana/` showing allowed vs blocked traffic, JA4 fingerprint names, action distribution, and logs. The dashboard design is appropriate for operational monitoring.

---

## 7. Deployment, Infrastructure & Supply Chain

### 7.1 CRITICAL: Production Compose Deploys Wrong Proxy

**Finding D-1 (CRITICAL — Go-PROD + Infra):** `docker-compose.prod.yml` line 53 points to `deploy/docker/Dockerfile` (the legacy Python proxy) instead of `deploy/docker/Dockerfile-go-proxy`. The POC compose correctly uses the Go Dockerfile. This means a production deployment runs the deprecated Python proxy.

### 7.2 CI/CD Pipeline

**Finding D-2 (HIGH): GitHub Actions not SHA-pinned**

`.github/workflows/ja4proxy-policy.yml` uses:
```yaml
uses: actions/checkout@v4
uses: actions/setup-python@v5
```

These are tag-pinned, not SHA-pinned. If the tag is moved to a compromised version, the workflow would execute malicious code. AGENTS.md and Phase 61 mandate SHA pinning.

**Recommendation:** Pin to commit SHA:
```yaml
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
uses: actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236  # v5.0.0
```

### 7.3 Docker Images

Dockerfiles use pinned base images (python:3.14-slim, etc.). The project runs `trivy` scans (`make scan-images`, `make scan-first-party`). This is good practice.

**Finding D-3 (MEDIUM):** No evidence of SBOM generation in the CI pipeline. Phase 61 mandates CycloneDX 1.4 SBOMs.

### 7.4 Helm Chart

The Helm chart at `deploy/helm/ja4proxy/` provides standard Kubernetes deployment with:
- Configurable replicas and HPA
- External Redis support
- Secret management via Helm values

**Finding D-4 (HIGH):** No network policies in the Helm chart. In a production Kubernetes deployment, network policies should restrict traffic to only necessary paths (proxy → backend, proxy → Redis, proxy → monitoring).

**Finding D-5 (LOW):** Resource limits should be explicitly set in the Helm chart's `values.yaml` to prevent noisy-neighbor issues in shared clusters.

### 7.5 Redis Security

Redis is configured with password authentication (`REDIS_PASSWORD` env var). The schema shows no evidence of Redis ACLs or TLS-to-Redis in the production configuration.

**Finding D-6 (HIGH — Go-PROD):** The Go Redis client omits TLS despite the config having an `ssl` field. Python applies `ssl=ssl_enabled` correctly; Go does not set `TLSConfig`. Production credentials are transmitted in plaintext when Redis TLS is enabled.

**Finding D-7 (MEDIUM):** Redis ACLs should be implemented for defense-in-depth. The Go client also lacks username support for ACL-based auth.

---

## 8. Management API & Access Control

### 8.1 Current State

The management API (FastAPI, Phase 13/51/52) provides:
- Real-time monitoring dashboard
- Configuration management
- Allowlist/ban management

**Finding M-1 (HIGH):** RBAC is not yet implemented — this is the scope of Phase 79. Without RBAC, all API users have equivalent permissions. This is acceptable for the current prototype but is a blocking gap for enterprise production deployment.

**Finding M-2 (MEDIUM):** The `management:audit_log` Redis key (LIST, last 1000 entries) has no TTL and grows unbounded beyond 1000 entries. The `maxlen=1000` is enforced at write time but there's no alerting if the list grows unexpectedly.

### 8.2 Session Management

Token-based authentication is used for the management API. The `*:auth_token` key pattern is excluded from backups (correct).

**Finding M-3 (LOW):** No evidence of token expiry or rotation policy. Management API tokens appear to be long-lived. In a regulated environment, tokens should have configurable TTL and automatic rotation.

---

## 9. Test Coverage & Adversarial Resilience

### 9.1 Test Suite Size

~2,948 tests across unit, integration, chaos, adversarial, and performance categories. The 1.3× test-to-code ratio is commendable.

**Finding T-1 (MEDIUM):** The adversarial test suite (`tests/adversarial/`) covers SQLi, XSS, and command injection patterns. However, these are HTTP-level attacks that the proxy (operating at TLS layer) would not inspect. The adversarial tests should focus on:
- JA4 fingerprint forgery (can an attacker match a known-good fingerprint?)
- PROXY protocol spoofing (beyond the trusted CIDR check)
- TTL manipulation (bypass JA4T OS detection)
- Signal score manipulation (can an attacker reduce their score by manipulating individual signals?)
- Dial manipulation (can an attacker change the dial via Redis if they compromise one instance?)

### 9.2 Chaos Testing

Chaos tests (`tests/chaos/`) cover Redis disconnection, external API failures, and configuration reload. This is good coverage of infrastructure failure modes.

**Finding T-2 (LOW):** No chaos tests for:
- GeoIP database corruption or stale data
- Bloom filter failure (RedisBloom module crash)
- Prometheus/monitoring stack failure (does the proxy continue working if metrics endpoint is unreachable?)

---

## 10. Compliance & Privacy

### 10.1 GDPR

The project has a `docs/compliance/GDPR_COMPLIANCE.md` document and a `gdpr_delete.py` script for DSAR handling. The `management:gdpr_erasure_log` tracks erasure requests.

**Finding CP-1 (MEDIUM):** The GDPR delete script operates on known key patterns. If new IP-personal-data patterns are added to Redis without updating the deletion script, data could be retained beyond the legal requirement.

### 10.2 Data Minimization

The proxy logs IP addresses, JA4 fingerprints, country codes, and scores. These are necessary for security operations but constitute personal data under GDPR.

**Finding CP-2 (LOW):** No evidence of log anonymization for non-security use cases. Analytics and monitoring dashboards show raw IP addresses. In regulated environments, IP masking for dashboard views (with unmasking available to authorized investigators) would reduce privacy exposure.

---

## 11. Strategic Recommendations

### Immediate (Blockers — Fix Before Any Production Deploy)

1. **[CRITICAL] Point `docker-compose.prod.yml` to `Dockerfile-go-proxy`** — currently deploys the deprecated Python proxy
2. **[CRITICAL] Add `_is_trusted_proxy_source()` to Go** — Go trusts PROXY protocol from any source; trivial IP spoofing bypass
3. **[CRITICAL] Add TLS to Go Redis client** — credentials on wire when Redis TLS is enabled
4. **[CRITICAL] Remove all default credential fallbacks** — Grafana `admin`, Management `admin/admin`, HAProxy `admin/admin123`
5. **[CRITICAL] Fix Go signal score drift** — `make check-scores` must exit 0; 4 signals wrong in production code
6. **[HIGH] SHA-pin GitHub Actions** — supply chain security

### Short-Term (Next 2-3 Phases)

7. **[HIGH] Add PROXY protocol v2 support to Go** — modern HAProxy/NLB send v2 by default
8. **[HIGH] Implement JA4T in Go** — currently a stub; no TCP-level evasion detection
9. **[HIGH] Expand Go weak cipher coverage** — 13 suites vs 37+; NULL, EXPORT, DH_anon, ECDH_anon missing
10. **[HIGH] Implement `ja4_tls_mismatch` in Go** — TLS version spoofing undetected
11. **[HIGH] Add NetworkPolicy to Helm chart** — any pod can reach proxy and Redis
12. **[MEDIUM] Add Redis username + TLS config to Go client** — ACL and TLS support
13. **[MEDIUM] Add backup maxlen to Redis stream** — unbounded growth
14. **[MEDIUM] Add dial rate-limiting and safety gates to Go** — no throttling on production dial changes
15. **[MEDIUM] Fix backup FLUSHDB** — wipes entire Redis DB, not just JA4proxy keys
16. **[MEDIUM] Align DGA algorithms** — Go SNI analysis less effective than Python prototype
17. **[MEDIUM] Fix Go health check depth** — only tests Redis, no GeoIP/connections/queue checks
18. **[LOW] Fix f-string logging in Python** — maintenance debt on deprecated surface

### Medium-Term (Before Enterprise Production)

19. Implement RBAC — Phase 79
20. Add SBOM generation to CI — supply chain compliance
21. Add image signing (cosign) — supply chain integrity
22. Add Redis ACLs — defense-in-depth
23. Expand adversarial tests — TLS-layer attacks, not HTTP
24. Add SLO/SLI definitions — error budget management
25. Fix metric naming — 15+ Python metrics lack `ja4proxy_` prefix (maintenance debt)

### Long-Term (Strategic)

16. **Evaluate sequential signal collection in Go** — consider `asyncio.gather` equivalent for I/O-bound signals.
17. **Implement log anonymization** — configurable for regulated environments.
18. **Add alerting for security event anomalies** — sudden block rate changes, signal failures, backup failures.
19. **Implement automated GeoIP database update verification** — detect stale or corrupted databases.
20. **Develop a formal threat model update** — the existing threat model should be revisited after the enterprise phases (79-86) are complete.

---

## Appendix A: Finding Severity Distribution (Recalibrated for Go Production)

Severity counts after recalibration. **[Go-PROD]** = production gap · **[Infra]** = deployment/config · **[Python-deprecated]** = maintenance debt only.

| Severity | Main Report | 01 Signals | 02 Redis | 03 Network | 04 Observability | 05 Deployment | **Total** |
|----------|------------|-----------|----------|------------|-----------------|--------------|----------|
| CRITICAL | 3 | 0 | 1 | 1 | 0 | 4 | **9** |
| HIGH | 5 | 4 | 2 | 4 | 4 | 9 | **28** |
| MEDIUM | 6 | 3 | 6 | 3 | 6 | 10 | **34** |
| LOW | 5 | 2 | 7 | 3 | 4 | 5 | **26** |
| INFO | 0 | 0 | 3 | 0 | 0 | 1 | **4** |
| Python-deprecated | 4 | 3 | 2 | 1 | 5 | 1 | **16** |
| **Total** | **23** | **12** | **21** | **14** | **19** | **30** | **119** |

Changes from original review:
- Python-only findings downgraded from HIGH/MEDIUM → Python-deprecated (16 total)
- Go-only gaps elevated where they were previously scored lower
- Prod compose wrong-image finding elevated to CRITICAL
- Go PROXY protocol trust elevated to CRITICAL
- Go Redis TLS omission elevated to CRITICAL
- Python `random()` stubs downgraded from CRITICAL → Python-deprecated
- Net reduction: 135 → 119 unique production-relevant findings

## Appendix B: Detailed Review Reports

This strategic review is supported by 5 detailed deep-dive reports:

| Report | File | Findings | Scope |
|--------|------|----------|-------|
| Main | `strategic_security_architecture_review.md` | 33 | Executive summary, all areas |
| 01 | `01_signal_implementation_review.md` | 14 | Signal modules Python + Go, score registry |
| 02 | `02_redis_caching_data_integrity_review.md` | 25 | Redis clients, caching, backup, Lua scripts, pub/sub |
| 03 | `03_network_evasion_review.md` | 12 | PROXY protocol, TLS passthrough, tarpit, eBPF |
| 04 | `04_observability_logging_alerting_review.md` | 21 | Prometheus, Alertmanager, Grafana, analytics, health checks |
| 05 | `05_deployment_supply_chain_review.md` | 30 | Dockerfiles, compose, Helm, CI/CD, secrets |

## Appendix C: Files Reviewed (Main Report)

| Area | Key Files |
|------|-----------|
| Architecture | `proxy.py`, `cmd/proxy/main.go`, `src/security/pipeline.py`, `internal/security/pipeline.go` |
| Signals | All `src/security/*.py`, all `internal/security/*.go`, `config/signal_scores.yml` |
| Caching | `src/cache/local_cache.py`, `src/cache/bloom.py`, `internal/cache/local.go` |
| Backup | `src/backup/worker.py`, `src/backup/encryption.py`, `src/backup/format.py` |
| Network | `proxy.py` (handle_connection, _parse_proxy_protocol, _forward_to_backend) |
| Observability | `deploy/monitoring/`, Prometheus metrics across codebase |
| Deployment | `.github/workflows/`, `deploy/helm/`, `Dockerfile*`, `deploy/docker/` |
| Schema | `docs/reference/REDIS_SCHEMA.md`, `config/proxy.yml` |

## Appendix D: Comparison with Existing Reports

This review complements the existing documentation:
- [`COMPREHENSIVE_SECURITY_AUDIT.md`](../security/COMPREHENSIVE_SECURITY_AUDIT.md) — focused on vulnerability assessment; this review adds architectural depth
- [`DMZ_DEPLOYMENT_READINESS.md`](../DMZ_DEPLOYMENT_READINESS.md) — focused on deployment gaps; this review adds implementation-level findings
- Phase close-out checklists — this review identifies gaps that passed through close-out (e.g., signal score drift)
