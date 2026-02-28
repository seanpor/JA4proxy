# Phase 5 — TCP & Connection Behaviour + mTLS

## Goal

Phase 5 adds two complementary capabilities: TCP-level signals that are entirely independent of TLS content, and mTLS client certificate support as a cryptographic allowlist. Both operate at the handshake level, require no external services, and have zero dependency on the backend webserver.

## 5a. TCP & Connection Behaviour

### 5a. `src/security/tcp_analyzer.py`

**5a. JA4T — TCP Fingerprint (+30 on mismatch)**

JA4T encodes TCP SYN characteristics: window size, TTL, TCP options ordering.
This fingerprints the OS/stack independently of TLS. Key signal: mismatch between
JA4 (claims to be Chrome on Windows) and JA4T (looks like Linux container).

Accessed via PROXY protocol v2 header from HAProxy (already configured).
Document if any JA4T fields are unavailable via PROXY protocol and fall back gracefully.

**5b. Session Resumption Rate (+15)**

Track per IP+JA4: `resumed / total` connections. Legitimate browsers use session
tickets consistently. Most scanners never attempt resumption.

```
Redis key: session:ip:{ip}:ja4:{ja4} → Hash {total, resumed}  TTL: 3600s (1h)
```

Score +15 when resumption rate = 0.0 after ≥ 10 connections.

**5c. Connection Lifespan (+20)**

Very short connections (TLS handshake then immediate close) = scanner probes.

```
Redis key: lifespan:{ip} → Sorted Set of durations  TTL: 1800s (30m)
```

Score +20 when median lifespan < 500ms across ≥ 5 connections.

**5d. Concurrent Connections (graduated)**

```
Redis key: concurrent:{ip} → INCR on accept, DECR on close  TTL: 60s
```

| Concurrent | Score |
|-----------|-------|
| ≥ 100 | +40 |
| ≥ 50 | +25 |
| ≥ 20 | +10 |

**5e. Return Visitor Trust Modifier (score reduction)**

This is the only signal that **reduces** other scores. IPs seen for > 7 days with
> 90% allow rate get a 20% reduction on their composite score. Protects long-term
legitimate clients from marginal false positives.

```
Redis key: visitor:{ip} → Hash {first_seen, last_seen, total, allowed, blocked}  TTL: 604800
```

Trust reduction: `composite_score *= 0.80` (only applies when trust conditions met).
Score never goes below 0.

**5f. TLS Alert Message Patterns (+20)**

TLS alert messages are plaintext and visible. High rate of `handshake_failure` or
`certificate_unknown` alerts from one IP = automated probing.

## 5b. mTLS Client Certificate Whitelist

### 5b. `src/security/mtls.py`

Trusted API clients (internal services, monitoring) can present a client certificate
signed by a configured CA. Valid client cert = scorer bypass (always ALLOW) when
`security_policy.mtls_bypass.enabled: true` (default).

This is a **cryptographic whitelist** — stronger than any scored signal. A client
with a valid cert from your CA is allowed via bypass — unless `security_policy.mtls_bypass`
is disabled, in which case they go through the scorer like any other connection.

```yaml
mtls:
  enabled: false
  ca_cert_path: "config/trusted_cas.pem"   # CA(s) that sign trusted client certs
  require_client_cert: false               # If true, reject connections WITHOUT cert
                                           # If false, cert is optional (bypass if present)
  cert_cn_allowlist: []                    # If set, only these CNs are trusted
                                           # Empty = any cert from CA is trusted
```

The proxy must inspect the TLS ClientHello for the `client_certificate` extension.
If present and valid against the configured CA, add to hard-allow bypass list.

Note: without TLS termination, client cert validation requires reading the Certificate
handshake message. Verify this is feasible as a passthrough proxy with the existing
ClientHello parsing. If not, document the limitation and provide an alternative
(e.g., HAProxy can validate client certs and pass a header).

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s (1h) | Proxy | TLS session resumption counters |
| `lifespan:{ip}` | Sorted Set of floats (ms) | 1800s (30m) | Proxy | Connection lifespan samples for median calculation |
| `concurrent:{ip}` | Integer (INCR on accept, DECR on close) | 60s | Proxy | Concurrent connection count; rolling TTL |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy | Return visitor trust scoring |

## Config

```yaml
tcp_analyzer:
  enabled: true
  tcp_fingerprinting:
    enabled: true
    score: 30              # Risk score when JA4T OS differs from JA4-implied OS. Default: 30.
  session_resumption:
    enabled: true
    min_connections: 10    # Minimum connections before scoring resumption rate. Default: 10.
    score: 15              # Risk score when resumption rate is zero. Default: 15.
  connection_lifespan:
    enabled: true
    threshold_ms: 500      # Median lifespan below which score is added. Default: 500.
    min_connections: 5     # Minimum connections before scoring lifespan. Default: 5.
    score: 20              # Risk score when median lifespan is below threshold. Default: 20.
  concurrent_connections:
    enabled: true
    thresholds: { moderate: 20, high: 50, severe: 100 }
    risk_scores:  { moderate: 10, high: 25, severe: 40 }
  return_visitor:
    enabled: true
    trusted_days: 7
    trusted_allow_rate: 0.90
    score_reduction_pct: 20
  tls_alerts:
    enabled: true
    rate_threshold: 5      # Alerts per minute triggering the signal. Default: 5.
    score: 20              # Risk score when alert rate exceeds threshold. Default: 20.
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused during concurrent counter INCR | Fail open; counter not leaked; connection tarpitted normally |
| Redis: connection refused during session resumption write | No crash; session signal not emitted for this connection |
| Client disconnects abruptly mid-connection | Concurrent counter DECR still executes; no leak |
| mTLS CA cert file missing at startup | FATAL error logged with file path; process exits cleanly |
| TLS alert burst (>100 alerts/s from one IP) | Rate limiting applies; metric incremented; no crash |

## Acceptance Criteria

### Functional
- [ ] `TCPAnalyzer.analyze(conn) -> list[RiskSignal]` returns both positive and negative signals
- [ ] JA4T extracted from PROXY protocol; documented limitation if passthrough proxy cannot expose it
- [ ] Session resumption tracked per IP+JA4; `no_resumption` signal after ≥ `min_connections`
- [ ] Connection lifespan Sorted Set; `short_lived` signal when median below `threshold_ms`
- [ ] Concurrent connection counter: INCR on accept, DECR on close; no leaks on abrupt disconnect
- [ ] `high_concurrency` signal when concurrent count exceeds configured threshold
- [ ] `return_visitor` trust signal: reduces composite score; result never below 0
- [ ] TLS alert rate: `tls_alert_rate` signal when rate exceeds `rate_threshold` per minute
- [ ] mTLS: valid client cert → ALLOW bypass when `security_policy.mtls_bypass.enabled: true`
- [ ] mTLS: bypass disabled → cert still verified; connection scored normally
- [ ] mTLS: `require_client_cert: true` → connections without cert rejected before scoring
- [ ] mTLS: `cert_cn_allowlist` non-empty → cert CN checked against list; mismatch rejects

### Configuration
- [ ] All sub-module scores, thresholds, and `min_connections` values loaded from config; hot reload applies
- [ ] `mtls.enabled: false` → mTLS handler inactive; no cert verification attempted

### Observability
- [ ] Prometheus gauge:   `ja4proxy_concurrent_connections` — current concurrent connections (max observed)
- [ ] Prometheus counter: `ja4proxy_mtls_verified_total` — connections with verified mTLS client certificate
- [ ] Prometheus counter: `ja4proxy_tcp_signal_total{signal}` — TCP signal fires by signal name
- [ ] `docs/REDIS_SCHEMA.md` updated with all Phase 5 key patterns

### Unit Tests  (`tests/unit/test_tcp_analyzer.py`, `tests/unit/test_mtls.py`)
- [ ] `TCPAnalyzer`: JA4T OS mismatch → ja4t_mismatch signal
- [ ] `TCPAnalyzer`: JA4T OS matches JA4 → no signal
- [ ] `TCPAnalyzer`: zero resumption after `min_connections` → no_resumption signal
- [ ] `TCPAnalyzer`: non-zero resumption → no signal
- [ ] `TCPAnalyzer`: median lifespan below threshold → short_lived signal
- [ ] `TCPAnalyzer`: median lifespan above threshold → no signal
- [ ] `TCPAnalyzer`: concurrent count at threshold → high_concurrency signal
- [ ] `TCPAnalyzer`: concurrent counter DECR on close; no leak after disconnect
- [ ] `TCPAnalyzer`: return visitor with clean history → negative score; composite never below 0
- [ ] `MTLSHandler`: valid cert against configured CA → bypass added to ALLOW list
- [ ] `MTLSHandler`: invalid cert → connection rejected
- [ ] `MTLSHandler`: cert CN not in allowlist → connection rejected
- [ ] `MTLSHandler`: bypass disabled → valid cert still verified; connection goes to scorer

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] Full pipeline: mTLS client cert → ALLOW regardless of score and dial

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [ ] Redis unreachable during concurrent counter INCR: fail open; counter not leaked
- [ ] Redis unreachable during session resumption write: no crash; signal not emitted
