# JA4proxy — Strategic Security Architecture Review

**Date:** 2026-04-08  
**Reviewer:** Senior Security Architect (AI)  
**Scope:** Full codebase review — architecture, security signals, cryptography, data integrity, network layer, observability, deployment, testing  
**Branch:** `review/strategic-security-architecture`

---

## Executive Summary

JA4proxy is a well-architected TLS-layer security proxy with a fundamentally sound design. The decision to operate at the TLS ClientHello level — without decrypting traffic — is strategically correct: it eliminates key management complexity, reduces compliance exposure, and enables truly transparent deployment.

**Overall assessment: Strong foundation with actionable gaps.** The core pipeline architecture is sound, the fail-open policy is consistently applied, and the test coverage ratio (1.3× test-to-code) is commendable. However, several findings require attention before enterprise production deployment.

### Key Metrics

| Area | Rating | Summary | Detail Report |
|------|--------|---------|--------------|
| Architecture & Pipeline | **B+** | Sound design, pre-pipeline bypass drift needs fixing | Main report §1 |
| Security Signals | **B−** | Multiple score drifts, stub code in production, algorithm mismatches | [01_signal_implementation_review.md](01_signal_implementation_review.md) — 14 findings |
| Cryptography & TLS | **B** | Solid JA4 implementation; missing TLS-level signals in Go | Main report §3 |
| Data Integrity & Caching | **B+** | Well-designed LRU + Bloom + TTL; Go TLS gap, FLUSHDB risk | [02_redis_caching_data_integrity_review.md](02_redis_caching_data_integrity_review.md) — 25 findings |
| Network & Evasion | **B** | PROXY protocol gap in Go is HIGH; ALPN bypass forgeable | [03_network_evasion_review.md](03_network_evasion_review.md) — 12 findings |
| Observability | **C+** | Metrics present but naming broken; alerting thin; secrets in config | [04_observability_logging_alerting_review.md](04_observability_logging_alerting_review.md) — 21 findings |
| Deployment & Supply Chain | **C** | Prod compose points to wrong image; default credentials everywhere | [05_deployment_supply_chain_review.md](05_deployment_supply_chain_review.md) — 30 findings |
| Management API | **B−** | Auth model incomplete; RBAC not yet implemented (Phase 79) | Main report §8 |
| Test Coverage | **B+** | Large test suite, but adversarial coverage needs expansion | Main report §9 |

### Critical Findings (Must Fix Before Production)

1. **Prod compose uses legacy Python proxy, not Go** — `docker-compose.prod.yml` points to `Dockerfile`, not `Dockerfile-go-proxy` (05)
2. **Default credentials everywhere** — Grafana `admin`, Management `admin/admin`, HAProxy `admin/admin123` (05)
3. **Go proxy trusts PROXY protocol from any source** — no `_is_trusted_proxy_source()` equivalent (03)
4. **Go Redis client omits TLS despite config having SSL field** — credentials exposed on wire (02)
5. **Signal score drift between Python and Go** — 5+ signals produce different scores (01)
6. **Stub code in production** — `random()` used for session resumption and lifespan detection (01)
7. **DGA detection algorithm mismatch** — Python and Go use fundamentally different heuristics (01)
8. **CI workflow actions not SHA-pinned** — supply chain risk (05)

### High-Priority Findings (Should Fix Before Production)

9. **Broad `except Exception` + f-string logging** in 8+ signal modules (01, 04)
10. **Pre-pipeline bypass drift** — Python's proxy.py short-circuits bypass the pipeline (§1)
11. **Missing signals in Go** — `ja4_tls_mismatch`, JA4T (stub), deception checker not ported (01)
12. **Backup `FLUSHDB` wipes entire Redis DB** — not just JA4proxy keys (02)
13. **Go reads dial from Redis per-connection** — latency concern at scale; no rate limiting (§1)
14. **Weak cipher suite coverage gap in Go** — 13 suites vs Python's 37+ (01)
15. **Helm chart has no NetworkPolicy** — any pod can reach proxy and Redis (05)
16. **No SBOM generation or image signing** — supply chain gap (05)
17. **Return visitor score mismatch** — Python uses -1, Go uses -20, registry says -20 (01)
18. **Metrics endpoint unauthenticated, binds `0.0.0.0`** — information disclosure (04)
19. **Alert references undefined metric** — `PipelineInternalError` alert fires on nothing (04)
20. **Shadow scoring uses ALPN-only for "known-good"** — forgeable baseline (04)
21. **Hardcoded placeholder secrets in alertmanager.yml** — (04)

---

## 1. Architecture & Pipeline

### 1.1 Pipeline Design — Sound with Minor Gaps

The pipeline follows the correct ordering: bypass checks → signal collection → scoring → decision → action. Both Python and Go implementations maintain this ordering.

**Strengths:**
- Fail-open is consistently applied across I/O-dependent modules
- The confidence-weighted scoring model is architecturally correct
- Local LRU cache with per-entry TTL provides good performance/isolation
- Pub/sub dial updates ensure cluster-wide consistency (Python)

**Finding A-1 (HIGH): Pre-pipeline bypass drift in Python**

Python's `proxy.py` (lines 2193-2246) checks country dynamic blacklist and CIDR blocks **before** calling `pipeline.process()`. Go handles both inside the pipeline (`checkHardBlocks`). This means:
- Python's country/CIDR blocks bypass pipeline logging, counterfactual reporting, and stream event emission
- Inconsistent observability between implementations

**Recommendation:** Move country and CIDR checks into `Pipeline._check_block_bypasses()` for architectural consistency. TODO comments at lines 2193 and 2231 acknowledge this debt.

**Finding A-2 (HIGH): Bypass check order differs**

Python checks `static_ip_allowlist` first; Go checks it last (after ALPN, JA4 whitelist, mTLS). While the functional result is the same (connection is allowed), the `bypass_reason` label differs for audit/SIEM purposes.

**Finding A-3 (MEDIUM): CIDR block check lacks explicit fail-open guard**

Python's `_is_cidr_blocked()` has no try/except around the trie lookup. If `_blocked_cidrs` is corrupted, the error propagates to `handle_connection`'s outer handler, which is effectively fail-close.

### 1.2 Dial Mechanism

**Finding A-4 (HIGH): Dial mechanism divergence**

| Aspect | Python | Go |
|--------|--------|-----|
| Source | In-memory cache (pub/sub) | Redis GET per connection |
| Rate limiting | `DialManager.validate_change()` (max 25/hr) | None |
| Safety gate | `blocking_acknowledged` check | None |

Go's per-connection Redis read adds measurable latency at 10K+ conn/s. Python's in-memory approach is more efficient but has an eventual consistency window. Neither is wrong, but Go lacks the safety gates (rate limiting, acknowledgment check) that Python has.

### 1.3 Concurrency Model

Python uses asyncio with `asyncio.gather()` for parallel signal collection (15 I/O-bound collectors run concurrently). Go runs signals sequentially — expected to have higher per-connection latency when external lookups are enabled. This is a known trade-off: Go compensates with higher raw throughput.

The `_conn_semaphore` gates handlers but not connection acceptance — under SYN flood, OS-level buffering (`SERVER_BACKLOG = 4096`) is the only defense. This is a known limitation of application-layer semaphores.

---

## 2. Security Signal Implementations

**See companion report:** [`docs/reports/01_signal_implementation_review.md`](01_signal_implementation_review.md)

### 2.1 Critical Score Drift

`make check-scores` reports **5 signals** where Go diverges from `config/signal_scores.yml`:

| Signal | Go | Registry | Delta |
|--------|----|----------|-------|
| `tls_version` | 40 | 10 | +300% |
| `weak_cipher` | 20 | 35 | −43% |
| `high_concurrency` | 25 | 40 | −37% |
| `moderate_concurrency` | 10 | 25 | −60% |
| `return_visitor` (Python) | -1 | -20 | 1900% |

This is a **close-out checklist requirement** that is currently failing.

### 2.2 Stub Code in Production

`tcp_analyzer.py` uses `__import__("random").random() < 0.9` for session resumption detection and `random.randint(100, 2000)` for connection lifespan. These produce non-deterministic, meaningless signals.

### 2.3 DGA Algorithm Mismatch

Python and Go DGA detectors use different entropy thresholds, vowel analysis, label length heuristics, and digit detection. Python strips common prefixes (`www`, `api`) before analysis; Go does not. An attacker could craft hostnames that pass one proxy but fail the other.

### 2.4 Missing Signals in Go

| Signal | Python | Go | Impact |
|--------|--------|-----|--------|
| `ja4_tls_mismatch` | ✅ (score 35) | ❌ | TLS version spoofing undetected |
| JA4T | ✅ (actual fingerprint) | ❌ (stub, returns `""`) | TCP-level evasion possible |
| Deception checker | ✅ (honey-fingerprint/SNI) | ❌ | No active defense traps |

### 2.5 Cipher Suite Coverage

Go's `weakCipherSet` has **13** suites; Python's `WEAK_CIPHERS` has **37+**. Missing: NULL ciphers, EXPORT suites, DH_anon, ECDH_anon, non-PFS RSA.

---

## 3. Cryptography & TLS Handling

### 3.1 JA4 Fingerprinting

The JA4 implementation is solid:
- SNI presence detection is consistent between Python and Go
- GREASE value filtering is correctly implemented
- The fingerprint format matches the FoxIO specification

### 3.2 TLS Enforcement

**Finding C-1 (HIGH):** The `ja4_tls_mismatch` signal (detecting when JA4's declared TLS version differs from the actual connection) exists only in Python. An attacker could craft a ClientHello that claims TLS 1.3 in JA4 but uses TLS 1.2 on the wire — the Go proxy would not detect this inconsistency.

**Finding C-2 (MEDIUM):** Python's `tls_enforcer.py` uses `score=35` (hardcoded) for `ja4_tls_mismatch`. While this matches the registry's `score_cap: 35`, it is not enforced by the linter due to multi-line RiskSignal construction escaping the regex.

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

The `docs/REDIS_SCHEMA.md` is comprehensive and follows good conventions. All keys document pattern, type, TTL, writer, and notes.

**Finding D-3 (LOW):** Several keys have `none` TTL (no expiry): `config:dial`, `ja4:whitelist`, `ja4:blacklist`, `static:allowlist`, `behavioral:known_ja4`, `confidence:scores`. These persist indefinitely until explicitly deleted. If Redis is restored from a backup taken before a config change, stale values could be served. The pub/sub `config:reload` mechanism mitigates this, but only if the proxy is running when the restore happens.

---

## 5. Network Layer & Evasion Resistance

### 5.1 PROXY Protocol Handling — Strong

**Finding N-1 (MEDIUM):** PROXY protocol parsing is guarded by `_is_trusted_proxy_source()` which checks an upstream trust config (enabled flag + trusted CIDRs). This is the correct design — it prevents arbitrary clients from spoofing source IPs.

**Finding N-2 (LOW):** The PROXY protocol parser validates the signature bytes and length correctly. However, it only supports IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) for the STREAM variant. UNIX variant (`0x30`) and UNSPEC (`0x00`) are not handled. This is acceptable if HAProxy is always configured to use TCP STREAM.

### 5.2 TLS Passthrough — Correct

The `_forward_to_backend()` method forwards the raw `data` (including the ClientHello) byte-for-byte to the backend, then pipes between client and backend sockets. The proxy never decrypts — correct.

### 5.3 Evasion Vectors

**Finding N-3 (MEDIUM):** JA4 fingerprint forging is theoretically possible but difficult:
- An attacker could craft a ClientHello with specific cipher suites and extensions to match a known-good JA4 fingerprint
- However, the JA4X (certificate) and JA4T (TCP) fingerprints provide additional signals that are harder to forge
- **Gap:** Go's JA4T is a stub, removing one evasion-resistance layer

**Finding N-4 (MEDIUM):** The geoip blocking relies on IP2Location LITE database. An attacker using residential proxies, Tor, or cloud egress IPs could bypass country-based blocks. This is a known limitation of IP geolocation — the system correctly treats geoip as one signal among many, not a sole decision factor.

**Finding N-5 (LOW):** The tarpit server could be abused for resource exhaustion if an attacker deliberately triggers tarpit responses at scale. The tarpit has `max_concurrent` and `max_per_ip` caps, but these are in-memory counters (not shared across proxy instances). A distributed attack could tarpit connections on multiple instances independently.

---

## 6. Observability, Logging & Alerting

### 6.1 Metrics — Present but Could Be Richer

Prometheus metrics are defined across the codebase with consistent `ja4proxy_` prefix naming. Key metrics include:
- `ja4proxy_request_count_total` (by action, country, TLS version)
- `ja4proxy_blocked_requests_total` (by reason, attack type)
- `ja4proxy_security_events_total` (by type, severity)
- `ja4proxy_cache_operations_total` (by type, result)
- `ja4proxy_backup_*` (operations, duration, size)

**Finding O-1 (MEDIUM):** The Prometheus scrape config (`monitoring/prometheus.yml`) uses a 15s global interval with 5s for the proxy job. This is reasonable for monitoring but may miss short-lived spikes. For a proxy making 10K+ decisions/sec, a 5s scrape window means ~50K decisions per data point — sufficient for trends but not for real-time alerting.

**Finding O-2 (MEDIUM):** No alerting rules were found for critical security events:
- No alert on sudden block rate increase (could indicate misconfiguration)
- No alert on false positive reports from users
- No alert on signal collector failures
- No alert on backup failures

### 6.2 Logging — Standards Violations

**Finding O-3 (HIGH):** Multiple files use f-string logging, violating AGENTS.md standards:

| File | Count |
|------|-------|
| `proxy.py` (pre-pipeline) | Multiple |
| `src/security/attribution.py` | 1 |
| `src/security/behavioral.py` | 3 |
| `src/security/greynoise.py` | 2 |
| `src/security/virustotal.py` | 5 |
| `src/security/alienvault.py` | 2 |
| `src/security/misp.py` | 2 |
| `src/security/threatfox.py` | 2 |

F-strings force eager string interpolation even when the log level is below the emitted level — a performance waste and potential data exposure risk if the interpolated values contain sensitive data.

### 6.3 Grafana Dashboards

Grafana dashboards exist in `monitoring/grafana/` showing allowed vs blocked traffic, JA4 fingerprint names, action distribution, and logs. The dashboard design is appropriate for operational monitoring.

---

## 7. Deployment, Infrastructure & Supply Chain

### 7.1 CI/CD Pipeline

**Finding D-1 (HIGH): GitHub Actions not SHA-pinned**

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

### 7.2 Docker Images

Dockerfiles use pinned base images (python:3.14-slim, etc.). The project runs `trivy` scans (`make scan-images`, `make scan-first-party`). This is good practice.

**Finding D-2 (MEDIUM):** No evidence of SBOM generation in the CI pipeline. Phase 61 mandates CycloneDX 1.4 SBOMs. The `make scan-images` target runs Trivy for CVE scanning, but SBOM generation requires a separate step (`syft` or `trivy image --format cyclonedx`).

### 7.3 Helm Chart

The Helm chart at `deploy/helm/ja4proxy/` provides standard Kubernetes deployment with:
- Configurable replicas and HPA
- External Redis support
- Secret management via Helm values

**Finding D-3 (MEDIUM):** No network policies in the Helm chart. In a production Kubernetes deployment, network policies should restrict traffic to only necessary paths (proxy → backend, proxy → Redis, proxy → monitoring).

**Finding D-4 (LOW):** Resource limits should be explicitly set in the Helm chart's `values.yaml` to prevent noisy-neighbor issues in shared clusters.

### 7.4 Redis Security

Redis is configured with password authentication (`REDIS_PASSWORD` env var). The schema shows no evidence of Redis ACLs or TLS-to-Redis in the production configuration.

**Finding D-5 (MEDIUM):** Redis ACLs and TLS for Redis connections should be implemented for defense-in-depth. A compromised proxy instance should not be able to read/write all Redis keys — ACLs would restrict each instance to only the keys it needs.

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

### Immediate (Before Next Release)

1. **Fix signal score drift** — `make check-scores` must exit 0. Update Go scores to match registry.
2. **Remove random() stubs** from `tcp_analyzer.py` — disable or implement properly.
3. **SHA-pin GitHub Actions** — supply chain security.
4. **Run `make check-scores` in CI** — prevent future drift.

### Short-Term (Next 2-3 Phases)

5. **Align DGA algorithms** between Python and Go — port Python's algorithm exactly or document gap.
6. **Port missing signals to Go** — `ja4_tls_mismatch`, JA4T, deception checker.
7. **Move pre-pipeline bypasses into pipeline** — for consistent logging and observability.
8. **Expand adversarial tests** — focus on TLS-layer attacks, not HTTP-layer patterns.
9. **Fix f-string logging** — convert to lazy `%` formatting across all signal modules.

### Medium-Term (Before Enterprise Production)

10. **Implement RBAC** — Phase 79 is the critical path.
11. **Add Redis ACLs and TLS** — defense-in-depth.
12. **Implement network policies in Helm** — production Kubernetes readiness.
13. **Add SBOM generation to CI** — supply chain compliance.
14. **Implement dial rate limiting in Go** — parity with Python's safety gates.
15. **Expand weak cipher coverage in Go** — match Python's 37+ suites.

### Long-Term (Strategic)

16. **Evaluate sequential signal collection in Go** — consider `asyncio.gather` equivalent for I/O-bound signals.
17. **Implement log anonymization** — configurable for regulated environments.
18. **Add alerting for security event anomalies** — sudden block rate changes, signal failures, backup failures.
19. **Implement automated GeoIP database update verification** — detect stale or corrupted databases.
20. **Develop a formal threat model update** — the existing threat model should be revisited after the enterprise phases (79-86) are complete.

---

## Appendix A: Finding Severity Distribution

| Severity | Main Report | 01 Signals | 02 Redis | 03 Network | 04 Observability | 05 Deployment | **Total** |
|----------|------------|-----------|----------|------------|-----------------|--------------|----------|
| CRITICAL | 0 | 2 | 0 | 0 | 0 | 4 | **6** |
| HIGH | 10 | 4 | 2 | 1 | 5 | 10 | **32** |
| MEDIUM | 15 | 5 | 8 | 4 | 8 | 11 | **51** |
| LOW | 8 | 3 | 8 | 6 | 3 | 5 | **33** |
| INFO | 0 | 0 | 3 | 0 | 0 | 1 | **4** |
| **Total** | **33** | **14** | **25** | **12** | **21** | **30** | **135** |

Note: The main report counts overlap with the detailed reports where the same finding appears in both. The 135 total is the unique count across all 6 review documents.

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
| Observability | `monitoring/`, Prometheus metrics across codebase |
| Deployment | `.github/workflows/`, `deploy/helm/`, `Dockerfile*`, `docker/` |
| Schema | `docs/REDIS_SCHEMA.md`, `config/proxy.yml` |

## Appendix D: Comparison with Existing Reports

This review complements the existing documentation:
- [`COMPREHENSIVE_SECURITY_AUDIT.md`](../security/COMPREHENSIVE_SECURITY_AUDIT.md) — focused on vulnerability assessment; this review adds architectural depth
- [`DMZ_DEPLOYMENT_READINESS.md`](../DMZ_DEPLOYMENT_READINESS.md) — focused on deployment gaps; this review adds implementation-level findings
- Phase close-out checklists — this review identifies gaps that passed through close-out (e.g., signal score drift)
