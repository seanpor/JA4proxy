---
phase: 215
title: "White-Box Penetration Test — Go Production Proxy"
size: LARGE
created: 2026-06-03
audience: [security, developer]
---

# White-Box Penetration Test — Go Production Proxy

## Goal

Conduct a full white-box (source-code-aided) penetration test of the Go production proxy (`cmd/proxy/` + `internal/`), identifying security vulnerabilities in the connection-handling pipeline, TLS parsing, signal modules, Redis integration, webhook delivery, and the metrics/health server. The Python prototype proxy (`proxy.py`, `src/`) is explicitly **out of scope** — it is deprecated and slated for removal.

Every finding is assigned a severity (CRITICAL / HIGH / MEDIUM / LOW) per `docs/security/SEVERITY_RUBRIC.md`, recorded in `docs/security/findings.yaml`, and backed by a regression test. The output is a pentest report in `docs/security/pentest/report.md` and any new findings triaged into the remediation backlog.

## Scope

### In scope

| Layer | Component | Files |
|-------|-----------|-------|
| **L1 — TCP / Network** | Accept loop, connection admission, PROXY protocol parsing, TLS record reassembly, forwarding, tarpit | `cmd/proxy/main.go` (lines 353–929) |
| **L2 — TLS / Fingerprint** | ClientHello parsing, JA4/JA4X computation, TLS version enforcement, cipher enforcement | `internal/tls/` (parser, ja4, ja4x, hello_info) |
| **L3 — Signal Pipeline** | All 14+ signal modules: blocklists, RDAP, AbuseIPDB, DNS enrichment, SNI analyzer (DGA, literal, missing, unexpected, malicious), ASN classifier, TCP analyzer, beaconing detector, TLS enforcer, analytics signals, rate limiter | `internal/security/` (all `_test.go`-excluded files) |
| **L4 — Risk Scoring & Action** | RiskScorer scoring weights, ActionDecider threshold logic, dial setting propagation | `internal/security/risk_scorer.go`, `internal/security/action_decider.go` |
| **L5 — Redis Integration** | Client connection, pub/sub with HMAC, health checks, Lua scripts, sentinel | `internal/redis/` (client, pubsub, lua, sentinel) |
| **L6 — Webhook Delivery** | Dispatcher, retry/backoff, secret redaction, DLQ | `internal/webhook/` |
| **L7 — Metrics & Health** | Auth middleware, rate limiter, health/deep endpoint, Prometheus metrics exposure | `cmd/proxy/main.go` (lines 1004–1388), `internal/metrics/` |
| **L8 — Config & Crypto** | Config loader, Redis auth validation, metrics auth validation, TLS cert handling, GeoIP | `internal/config/`, `internal/cache/`, `internal/logging/` |
| **L9 — CLI** | ja4proxy-cli client commands, auth, dial simulation, fingerprint query, policy management | `internal/cli/` |

### Out of scope

- Python prototype proxy (`proxy.py`, `src/`) — deprecated
- Management API (`management/`) — separate service, covered by Phase 122
- Terraform provider / Kubernetes operator — separate repos
- Infrastructure-as-code (`deploy/`) — covered by Phase 125
- CI/CD pipeline security — covered by Phase 213
- Supply-chain security — covered by Phase 125
- Third-party services (AbuseIPDB API, Spamhaus, RDAP servers, GeoIP DB) — pentesting them is unlawful
- Documentation and compliance artefacts
- Any finding already fully remediated and closed in `docs/security/findings.yaml` (re-verification only)

## Methodology

Each layer is reviewed through these lenses:

1. **Source code audit** — manual review of every Go source file for common vulnerability classes (CWE Top 25, OWASP Top 10 for API, Go-specific pitfalls)
2. **Business logic flaws** — bypass opportunities in bypass-policy toggles, threshold manipulation, dial setting subversion, race conditions in `sync.RWMutex`-guarded state
3. **Cryptographic review** — TLS parsing correctness, constant-time comparisons, HMAC secret handling, certificate validation
4. **Authentication / authorization** — metrics endpoint auth, rate-limiter bypass, admin token handling, Redis ACL enforcement
5. **Error handling & fail-open safety** — signal-module errors must not silently degrade security posture
6. **Concurrency safety** — shared-mutable-state access patterns, goroutine leaks, channel capacity under load
7. **Dependency security** — govulncheck, semgrep findings review, known CVEs in Go proxy dependencies

## Implementation Plan

### A — Pre-engagement setup

1. Create `docs/security/pentest/` directory with:
   - `SCOPE.md` — this scope document
   - `REPORT.md` — findings report (populated during review)
2. Create `tests/pentest/go-proxy/` directory for regression tests
3. Review findings register to exclude already-closed findings from re-audit
4. Set up isolated test environment (standalone Go proxy + fakeredis)

### B — L1: TCP / Network layer review

1. **Accept loop** — verify `admitConn` semaphore correctly bounds goroutine growth; no race between `acceptSem` release and `activeConns` decrement
2. **PROXY protocol** — verify v1/v2 parsing bounds, smuggling detection logic, trusted-CIDR check correctness; confirm `# nosemgrep`-equivalent Go static analysis passes
3. **TLS record reassembly** (`reassembleClientHello`) — verify buffer bounds, hard cap logic, handshake fragmentation across records; test with crafted truncated and oversized inputs
4. **Forwarding** — verify bidirectional copy goroutine cleanup (`JA4PROXY-2026-0009`); confirm `SetLinger(0)` RST force for block/ban
5. **Tarpit** — verify concurrency limits, per-IP tracking, overflow action fallthrough, inactivity timeout, lifetime cap; test for slot-exhaustion DoS

### C — L2: TLS / Fingerprint layer review

1. **ClientHello parser** (`internal/tls/parser.go`) — review length checks, extension parsing, SNI extraction bounds; test with crafted malformed ClientHellos
2. **JA4 computation** — verify hash computation matches spec; confirm JA4X extension handling; test parity against golden corpus
3. **TLS enforcer** — verify TLS version blocking (1.0/1.1), weak cipher detection, logging accuracy
4. **Protocol lockdown** — verify `enforce_tls_record` bypass logic and logging

### D — L3: Signal pipeline review

1. **Bypass policy chain** — verify every bypass toggle route (ALPN browser bypass, JA4 whitelist/blacklist, mTLS, country blacklist, TLS version) correctly short-circuits scoring; test for bypass chaining
2. **Blocklist manager** — verify Redis-backed list loading, CIDR ranger usage, dynamic list refresh via pub/sub
3. **RDAP enrichment** — verify HTTP timeout, error handling (fail-open), caching behaviour
4. **AbuseIPDB** — verify API key handling (not logged), HTTP timeout, caching, fail-open on API error
5. **DNS enrichment** — verify resolver usage, caching, timeout
6. **SNI analyzer** — verify DGA detection, IP-literal detection, missing-SNI handling, unexpected-hostname matching, malicious-SNI regex; test for bypass with crafted SNI values
7. **ASN classifier** — verify GeoIP MaxMind DB reader usage, country-code extraction
8. **TCP analyzer** — verify window-size and TTL analysis
9. **Beaconing detector** — verify sliding-window state management
10. **Analytics signals** — verify anomaly detection thresholds

### E — L4: Risk scoring & action review

1. **RiskScorer** — verify signal-score weights against `config/signal_scores.yml`; check overflow safety in score aggregation; verify zero-score default when signal is missing
2. **ActionDecider** — verify threshold comparisons (flag → rate_limit → tarpit → block → ban); confirm dial setting propagation
3. **Fail-open integrity** — verify that a scoring panic or Redis error does not default to `allow`

### F — L5: Redis integration review

1. **Client** — verify auth (password + ACL username), TLS connection, sentinel failover, timeout handling
2. **Pub/Sub** — verify HMAC signature verification on critical channels, secret handling (not logged), channel subscription validation
3. **Lua scripts** — review for injection via key arguments; verify KEYS[1] usage
4. **Health check** — verify panic recovery, timeout, fail-threshold anti-flap
5. **Sync capture** — verify DC-ID stream key construction

### G — L6: Webhook delivery review

1. **Dispatcher** — verify retry/backoff bounds, DLQ overflow, endpoint secret handling (redacted in logs)
2. **Event serialization** — verify JSON marshalling of connection context, no sensitive field leakage
3. **Stream queue** — verify bounded channel capacity, non-blocking send, drop counting

### H — L7: Metrics & health review

1. **Auth middleware** — verify bearer token constant-time compare, loopback exemption, error responses
2. **Rate limiter** — verify per-IP bucket logic, eviction policy, no memory exhaustion from spoofed IPs
3. **Health endpoints** — verify information disclosure (active bans, dial setting, cert expiry, metrics summary); confirm sensitive fields are appropriate for authenticated access
4. **Prometheus registry access** — verify gatherer usage does not expose unexpected metrics

### I — L8: Config & crypto review

1. **Config loader** — verify YAML parsing safety, env-var interpolation, sensitive-field redaction in logs
2. **Redis auth validators** — verify startup gates (unauthenticated Redis, unauthenticated metrics, ACL consistency) cannot be bypassed
3. **Secrets handling** — verify Redis password, webhook secrets, metrics auth token are never logged or exposed in error messages
4. **TLS cert handling** — verify `updateTLSCertExpiryGauge`, PEM decoding path

### J — L9: CLI review

1. **Auth commands** — verify keychain storage, token handling
2. **Dial simulation** — verify policy evaluation correctness
3. **Fingerprint query** — verify Redis key construction, no injection

### K — Reporting & findings triage

1. Write `docs/security/pentest/REPORT.md` with all findings structured as:

```markdown
### F-{N}: {Title}

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **CVSS 3.1** | X.X |
| **Component** | Layer / File |
| **Line** | line number |
| **CWE** | CWE-NNN |
| **Status** | OPEN / DUPLICATE / NOT-APPLICABLE |

**Description:** ...
**Impact:** ...
**Recommendation:** ...
```

2. Add each new finding to `docs/security/findings.yaml` using the findings register CLI
3. Write regression tests for each confirmed finding in `tests/pentest/go-proxy/`
4. For DUPLICATE findings, reference the existing canonical ID

## Test Strategy

| Check | What to verify |
|-------|---------------|
| `GOROOT=/snap/go/current go vet ./...` | No static-analysis violations in Go proxy |
| `GOROOT=/snap/go/current govulncheck ./...` | Zero known CVEs in Go proxy dependencies |
| `make lint-phases` | Must exit 0 |
| `python3 scripts/sync-roadmap.py` | Must not fail |
| `make check-scores` | Signal scores match registry |
| `make parity-check` | Go/Python parity (if Python proxy still running) |
| New regression tests | Every OPEN finding has a corresponding Go test in `tests/pentest/go-proxy/` |
| `python3 scripts/findings_register.py validate` | Finding register is consistent |

## Acceptance Criteria

1. All Go proxy source files (`cmd/proxy/`, `internal/`) have been reviewed through all 9 methodology lenses
2. Every confirmed finding has a severity, CVSS vector, CWE, and recommendation written to `docs/security/pentest/REPORT.md`
3. Every new finding with status != DUPLICATE is entered into `docs/security/findings.yaml`
4. Every OPEN finding has a regression test in `tests/pentest/go-proxy/`
5. No false positives from known remediated findings (cross-check against `findings.yaml` CLOSED entries)
6. `make test` remains green (same pre-existing baseline, no new failures)

## Out of Scope

- Python prototype proxy (`proxy.py`, `src/`) — deprecated
- Management API / UI — separate service
- Terraform provider / Kubernetes operator — separate repos
- Infrastructure-as-code — covered by Phase 125
- CI/CD pipeline — covered by Phase 213
- Third-party APIs (pentesting them is unlawful)
- Supply-chain dependency audit — covered by Phase 125
- SAST/DAST tool integration — deferred (Phase 108m planned this)
- Fuzzing campaign — deferred (Phase 108j planned this)
- Any finding already CLOSED in findings register (re-verification only)
