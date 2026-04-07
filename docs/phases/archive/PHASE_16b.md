# Phase 16b — Extended Fingerprinting & Adaptive Rate Limiting Supplement

## Status: OPEN

## Purpose

This document supplements `PHASE_16.md`. Read that document first. This supplement adds:

1. ADR-016a: JA4X — why, when, and the certificate forgery threat model
2. ADR-016b: Adaptive rate limiting — EWMA vs alternatives
3. Structured JSON log schemas for new events (JA4X, adaptive threshold, OTel, Admin CLI)
4. Grafana dashboard panel specifications for new Phase 16 features
5. Admin CLI security model (authentication, audit logging, access control)
6. Kubernetes deployment troubleshooting runbook
7. OTel span attribute sanitisation (PII/sensitive data guidance)
8. Security threat model for JA4X forgery
9. Full TDD checklist with category breakdown

---

## 1. ADR-016a: JA4X Extended Certificate Fingerprinting

**File:** `docs/decisions/ADR-016a.md`

```markdown
# ADR-016a: JA4X Extended Certificate Fingerprinting

## Status: Accepted

## Context

JA4 fingerprints the TLS handshake parameters (cipher suites, extensions, ALPN). It
does not capture anything about the X.509 certificate chain presented during the
handshake. Two completely different clients can produce identical JA4 fingerprints if
they use the same TLS stack configuration.

JA4X hashes the issuer, subject, and SAN fields of the certificates visible in the
handshake. In passthrough mode the proxy sees the server certificate presented to the
client. When mTLS is enabled, the proxy also sees the client certificate.

## Why Phase 16 (Not Earlier)

JA4X requires reliable access to the certificate chain from the raw TLS record stream.
In Python, this requires parsing DER-encoded ASN.1 from the raw bytes seen during
ClientHello capture — the proxy never decrypts, so it does not use Python's ssl module
for this. The parser was not robust enough until Phase 3 and Phase 5 proved the TLS
passthrough approach. Adding JA4X earlier would have been premature.

## Options Considered

**Option A: JA4X on server cert only**
The server cert is always visible in passthrough mode (it is in the unencrypted
ServerHello / Certificate messages). Low complexity. Selected as the default.

**Option B: JA4X on client cert only (mTLS mode)**
Client cert is only available when mTLS is configured. Higher value for detecting
certificate-based C2 frameworks. Added as an optional feature gated on mtls.enabled.

**Option C: No JA4X**
JA4 alone is sufficient for most use cases. The marginal benefit of JA4X is detecting
shared infrastructure certificates across different TLS stacks.
Rejected: the use case (C2 framework detection, certificate-based bot herds) is real
and the implementation cost is low once the cert parsing is done.

## Decision

Implement JA4X on the server cert by default (Option A). When `mtls.enabled=true`,
also compute JA4X on the client cert (Option B). Gate on `fingerprinting.ja4x.enabled`
(default true).

## Threat Model: Can JA4X Be Forged?

An attacker who knows their JA4X fingerprint is in the proxy's blacklist can attempt
to change it. The attack surface:

| Field | Forgery difficulty | Notes |
|-------|--------------------|-------|
| Issuer | Easy — use a different CA | Self-signed cert has arbitrary issuer |
| Subject | Easy — change CN/O fields | No validation at the proxy level |
| SANs | Easy — add/change domains | Self-signed cert can have any SAN |

**Conclusion:** JA4X can be trivially forged by anyone who controls their own
certificate. It is NOT a reliable identification mechanism against a sophisticated
adversary.

**What JA4X IS good for:**
- Detecting mass campaigns sharing the same certificate infrastructure (C2 frameworks
  that ship with a default certificate)
- Correlating traffic from a specific certificate fingerprint across time
- Candidates for investigation, not for automated blocking

**Policy implication:** JA4X fingerprints should contribute to risk score (same as JA4)
but should generally NOT be used for hard block (bypass-level) without additional
corroborating signals.

This is reflected in the default `blacklist_score: 80` — high but not a guarantee of
block unless combined with other signals.

## Consequences

1. JA4X adds ~0.2ms per connection for ASN.1 parsing. Disable if latency is critical
   and certificate-based detection is not needed.

2. JA4X on server cert requires the proxy to buffer the Certificate TLS record. This
   adds ~1–4KB memory per in-flight connection during the handshake window. Negligible.

3. JA4X blacklist/whitelist uses identical Redis SET structure to JA4. The management
   UI fingerprint pages can be extended to show JA4X candidates with minimal change.

## Revisit If

- Strict latency SLA makes the 0.2ms parsing overhead unacceptable (disable by default)
- TLS 1.3 encrypted handshake prevents server cert visibility (currently visible in 1.3)
```

---

## 2. ADR-016b: Adaptive Rate Limiting

**File:** `docs/decisions/ADR-016b.md`

```markdown
# ADR-016b: Adaptive Rate Limiting via Per-Subnet EWMA

## Status: Accepted

## Context

The current sliding-window rate limiter uses static thresholds configured in
`config/proxy.yml`. These thresholds are appropriate for average traffic but fail in
two scenarios:

1. **DDoS burst**: threshold is too permissive; attack traffic passes the rate check
   before the score rises high enough to block.

2. **Legitimate surge**: periodic events (marketing campaign, flash sale) cause genuine
   traffic spikes that trigger rate limiting for legitimate users.

## Options Considered

**Option A: Static thresholds (current)**
Simple, predictable. Fails for both scenarios above.
Retained as fallback — adaptive reads this when no adaptive data is available.

**Option B: EWMA per /24 subnet (selected)**
Analytics node computes the recent rate for each /24 subnet using exponential weighted
moving average. Updates every 60s. Proxy reads and uses if confidence ≥ 0.7.

Trade-offs:
- Adapts to subnet-level traffic patterns, not just global patterns
- 60s lag means it takes ~60s to adapt to a new pattern
- Requires analytics node to be running (fail-safe: falls back to static)

**Option C: Per-IP rate tracking with ML model**
Analytics node trains a model on historical per-IP rates.
Rejected: high operational complexity; model drift; requires labelled training data.

**Option D: Manual override only**
Admin sets per-subnet thresholds via management UI.
Useful for known subnets but does not help with new attack sources.
Retained as future phase (management UI threshold override).

## Decision

EWMA per /24 subnet (Option B). Default: disabled. Enable only when analytics node is
running and `rate_limiter.adaptive.enabled = true`.

## EWMA Parameters

The analytics node computes:

```
threshold_rps(t) = α × observed_rps(t) + (1-α) × threshold_rps(t-1)
```

Where:
- `α = 0.3` (weight for most recent observation — higher = more responsive, less stable)
- `observed_rps(t)` = requests per second from that subnet in the last 60s window
- Initial value: `static config threshold`

The `confidence` field reflects how many data points have been seen for this subnet:
- `confidence = min(1.0, datapoints / 10)` — reaches full confidence after 10 observations

The proxy uses the adaptive threshold only when `confidence ≥ 0.7` (7+ observations).
Below this threshold, the proxy uses the static config value.

## Fail-Open Behaviour

If the analytics node is unavailable or the `rate:adaptive:{subnet}` key expires:
1. Proxy falls back to static config threshold silently
2. DEBUG log: `{"event":"adaptive_rate_fallback","subnet":"...","reason":"key_expired"}`
3. No metric increment (fallback to static is expected, not an error)

If the analytics node sends `confidence < 0.7`:
1. Same behaviour — static fallback
2. No log at DEBUG level (too noisy for normal startup period)

## Security Consideration

Adaptive thresholds could be manipulated by an attacker who controls a /24 subnet:
- Attacker sends traffic just below the static threshold for 10 minutes
- Adaptive threshold lowers to match the "observed" rate
- Attacker bursts — adaptive threshold allows the burst

Mitigations:
1. `min_threshold_rps: 5` — threshold can never drop below 5 req/s regardless of EWMA
2. `max_threshold_rps: 1000` — threshold can never rise above 1000 req/s
3. Static threshold acts as floor: EWMA minimum is `max(static_threshold × 0.5, min_threshold_rps)`
   — prevents attacker from lowering threshold by more than 50% below static config

## Revisit If

- Analytics node cannot keep up with subnet computation (> 100,000 active /24s)
  → partition analytics by subnet hash prefix across multiple analytics instances
- α=0.3 is too slow/fast for typical traffic patterns → make α configurable
```

---

## 3. Structured JSON Log Schemas

### 3a. JA4X Computed

```json
{
  "type": "connection",
  "level": "DEBUG",
  "subsystem": "fingerprinting",
  "event": "ja4x_computed",
  "client_ip": "1.2.3.4",
  "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
  "ja4x": "aabbccddeeff_112233445566_aabbccddeeff",
  "cert_source": "server",
  "issuer_cn": "Let's Encrypt Authority X3",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

When `emit_in_logs: false` in config, this event is not emitted. The `ja4x` field still
appears in the main connection log:

```json
{
  "type": "connection",
  "level": "INFO",
  "subsystem": "pipeline",
  "event": "connection_scored",
  "client_ip": "1.2.3.4",
  "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
  "ja4x": "aabbccddeeff_112233445566_aabbccddeeff",
  "score": 45,
  "action": "flag",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3b. Adaptive Threshold Applied

```json
{
  "type": "connection",
  "level": "DEBUG",
  "subsystem": "rate_limiter",
  "event": "adaptive_threshold_applied",
  "subnet": "192.168.1.0/24",
  "static_threshold_rps": 100,
  "adaptive_threshold_rps": 73,
  "confidence": 0.92,
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3c. Adaptive Threshold Fallback

```json
{
  "type": "connection",
  "level": "DEBUG",
  "subsystem": "rate_limiter",
  "event": "adaptive_rate_fallback",
  "subnet": "192.168.1.0/24",
  "reason": "key_expired",
  "fallback_threshold_rps": 100,
  "timestamp": "2026-03-10T14:23:00Z"
}
```

### 3d. Admin CLI Operation

Every `ja4proxy-admin` command that mutates state must produce a structured log entry
in addition to writing to the management audit log. This log must be emitted by the CLI
tool itself (not the server — the CLI contacts Redis directly).

```json
{
  "type": "admin",
  "level": "INFO",
  "subsystem": "admin_cli",
  "event": "ban_added",
  "operator_host": "ops-workstation-01.example.com",
  "operator_user": "jsmith",
  "client_ip": "185.220.101.5",
  "ttl_s": 86400,
  "reason": "manual ban from ops review",
  "redis_url_host": "redis.internal",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

Fields:
- `operator_host`: `socket.gethostname()` on the machine running the CLI
- `operator_user`: `os.environ.get("USER", "unknown")`
- `redis_url_host`: hostname portion of REDIS_URL (never password or full URL)

### 3e. OpenTelemetry Startup

```json
{
  "type": "system",
  "level": "INFO",
  "subsystem": "telemetry",
  "event": "tracing_initialised",
  "endpoint": "http://jaeger:4317",
  "sample_rate": 0.01,
  "timestamp": "2026-03-10T14:23:00Z"
}
```

When OTEL endpoint is unreachable at startup:

```json
{
  "type": "system",
  "level": "WARN",
  "subsystem": "telemetry",
  "event": "tracing_endpoint_unreachable",
  "endpoint": "http://jaeger:4317",
  "error": "connection refused",
  "effect": "spans will be dropped silently; proxy performance unaffected",
  "timestamp": "2026-03-10T14:23:00Z"
}
```

---

## 4. Grafana Dashboard Panel Specifications

Add the following panels to the existing proxy dashboard.

### Panel: JA4X Fingerprint Classification

```
Title: JA4X Blacklist Matches (last 5m)
Type: Stat
Query: rate(ja4proxy_fingerprint_matches_total{list="ja4x_blacklist"}[5m]) * 300
Unit: matches/5min
Thresholds: 0 = green, > 0 = yellow, > 10 = red
```

```
Title: JA4X Certificate Sources
Type: Pie
Queries:
  - sum by (cert_source) (ja4proxy_ja4x_computed_total)
    labels: server cert, client cert
```

### Panel: Adaptive Rate Limiting

```
Title: Adaptive Threshold vs Static (last 1h)
Type: Time series
Queries:
  - avg(ja4proxy_adaptive_rate_threshold) by (subnet_prefix) label="Adaptive"
  - <static_config_value as constant>                          label="Static"
Unit: req/s
Description: "Adaptive threshold per subnet; below static = congested; above = quiet"
```

```
Title: Adaptive Rate Fallbacks
Type: Stat
Query: rate(ja4proxy_adaptive_rate_fallback_total[5m]) * 60
Unit: fallbacks/min
Thresholds: 0 = green, > 5/min = yellow, > 20/min = red (analytics node may be down)
```

### New Prometheus Metrics for Phase 16 (add to OBSERVABILITY_STANDARDS.md)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ja4proxy_ja4x_computed_total` | Counter | `cert_source=server\|client` | JA4X computations |
| `ja4proxy_adaptive_rate_threshold` | Gauge | `subnet` | Current adaptive threshold per subnet |
| `ja4proxy_adaptive_rate_fallback_total` | Counter | `reason=key_expired\|low_confidence\|disabled` | Times static fallback was used |
| `ja4proxy_admin_cli_operations_total` | Counter | `operation=ban\|unban\|dial_set\|...` | Admin CLI mutations |
| `ja4proxy_otel_spans_dropped_total` | Counter | — | OTel spans dropped (endpoint unreachable) |

### AlertManager Rules

Add to `monitoring/alertmanager/rules/security.rules.yml`:

```yaml
- alert: AdaptiveRateLimitingUnavailable
  expr: rate(ja4proxy_adaptive_rate_fallback_total{reason="key_expired"}[5m]) > 0.5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Adaptive rate limiting falling back to static (analytics node may be down)"
    description: "{{ $value | humanize }}/s fallbacks. Check analytics node health."

- alert: JA4XComputationStopped
  expr: rate(ja4proxy_ja4x_computed_total[5m]) == 0 and ja4proxy_connections_total > 0
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "JA4X fingerprinting has stopped while connections are active"
    description: "JA4X may be disabled or cert parsing is failing."
```

---

## 5. Admin CLI Security Model

`PHASE_16.md §16k` specifies the admin CLI commands. This section specifies the
security properties required. These are acceptance criteria, not optional guidance.

### Authentication

The admin CLI reads `REDIS_URL` from the environment. `REDIS_URL` must include the
Redis password:

```
redis://:password@redis.internal:6379/0
```

The CLI must **never** accept the Redis password as a command-line argument
(`--redis-password`) — it would appear in `ps aux` output. Only environment variable.

If `REDIS_URL` is not set or does not contain authentication, the CLI must refuse:

```
ERROR: REDIS_URL not set or missing password. Set REDIS_URL=redis://:pass@host:port/db
```

### Authorisation

The admin CLI has no separate authorisation layer beyond Redis access. Whoever has
`REDIS_URL` can run any command. This is intentional for Phase 16 — RBAC is Phase 17+.

**Consequence:** `REDIS_URL` must be treated as a high-privilege secret. It grants full
read/write access to the proxy's entire state. Restrict access to the environment
variable to operators only.

### Audit Logging

Every destructive command (`ban`, `unban`, `dial set`, `blacklist add/remove`,
`whitelist add/remove`, `flush`) must:

1. Write a structured JSON log entry to stdout (format in §3d)
2. Write an audit entry to `management:audit_log` in Redis (same format as management UI)

Commands that only read state (`inspect`, `suspect list`, `status`) do not audit log.

### Confirmation Flag

Destructive commands require `--confirm`:

```bash
ja4proxy-admin ban 1.2.3.4 --ttl 3600           # Fails: missing --confirm
ja4proxy-admin ban 1.2.3.4 --ttl 3600 --confirm  # Succeeds
```

Non-interactive pipelines can pipe "yes":
```bash
echo "yes" | ja4proxy-admin ban 1.2.3.4 --ttl 3600 --interactive=false
```

### Rate Limiting

The CLI has no built-in rate limiting. It relies on Redis AUTH for access control.
Implement network-level ACLs if the CLI is exposed to less-trusted users.

### Acceptance Criteria for Admin CLI Security

- [ ] `REDIS_URL` without password: CLI exits with error code 1 and clear message
- [ ] Password not accepted as CLI argument (no `--redis-password` flag)
- [ ] Every destructive operation writes audit entry to `management:audit_log`
- [ ] `--confirm` required for all destructive operations; missing → exit code 1
- [ ] CLI unit tests verify audit log entries are written for each destructive command

---

## 6. Kubernetes Deployment Troubleshooting Runbook

**File:** `docs/runbooks/kubernetes_operations.md`

```markdown
# Kubernetes Deployment Troubleshooting

## Prerequisites

- `kubectl` configured with access to the ja4proxy namespace
- `helm` installed
- Access to Grafana and Prometheus

## Common Issues

### Pods Not Starting

**Symptom**: `kubectl get pods -n ja4proxy` shows `CrashLoopBackOff` or `Pending`

**Check pod logs:**
```bash
kubectl logs -n ja4proxy -l app=ja4proxy --previous
```

Common causes:
- `UI_API_KEY` secret not set → `FATAL: UI_API_KEY_not_set`
- `REDIS_URL` secret not set → `FATAL: redis_connection_failed`
- Redis not reachable from pod → check `redis.external` in Helm values
- Image pull failure → check `imagePullSecrets` in Helm values

### HPA Not Scaling

**Symptom**: Connection count exceeds 500 per pod but no new pods appear

**Check HPA status:**
```bash
kubectl describe hpa -n ja4proxy ja4proxy-hpa
```

Common causes:
- Metric `ja4proxy_connections_active` not available → check Prometheus ServiceMonitor
- HPA at `maxReplicas` → increase `hpa.maxReplicas` in Helm values
- Anti-affinity prevents scheduling → check node count vs maxReplicas

**Verify the metric is available:**
```bash
kubectl get --raw "/apis/custom.metrics.k8s.io/v1beta1/namespaces/ja4proxy/pods/*/ja4proxy_connections_active"
```

### Pods Being Evicted

**Symptom**: Pods evicted; `kubectl get events -n ja4proxy` shows OOMKilled

**Check resource usage:**
```bash
kubectl top pods -n ja4proxy
```

Increase memory limit in Helm values:
```yaml
resources:
  limits:
    memory: "1Gi"   # Increase from 512Mi
```

Or reduce `tarpit.max_concurrent_connections` (each tarpitted connection uses ~8KB).

### PodDisruptionBudget Preventing Maintenance

**Symptom**: `kubectl drain <node>` stalls; events show "cannot evict pod"

**Check PDB:**
```bash
kubectl get pdb -n ja4proxy
kubectl describe pdb -n ja4proxy ja4proxy-pdb
```

If `minAvailable: 1` and only 1 pod is running (e.g., after crash), PDB prevents drain.

**Recovery:**
```bash
# Temporarily suspend PDB (requires cluster admin)
kubectl patch pdb -n ja4proxy ja4proxy-pdb -p '{"spec":{"minAvailable":0}}'
# Drain the node
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
# Restore PDB
kubectl patch pdb -n ja4proxy ja4proxy-pdb -p '{"spec":{"minAvailable":1}}'
```

### Rolling Upgrade Stalls

**Symptom**: `helm upgrade` in progress; old pod not terminating

**Check rollout status:**
```bash
kubectl rollout status deployment/ja4proxy -n ja4proxy
```

The proxy uses graceful shutdown with connection draining. The old pod will not
terminate until in-flight connections drain (default: 30s timeout). If connections
are long-lived (e.g., tarpitted), this can take longer.

**Force terminate (use only if draining is stuck):**
```bash
kubectl delete pod -n ja4proxy <stuck-pod-name> --grace-period=0
```

### Redis Not Reachable from Pods

**Symptom**: Pods running but proxying fails; logs show `redis_connection_failed`

**Diagnose from a running pod:**
```bash
kubectl exec -n ja4proxy <pod> -- redis-cli -u $REDIS_URL ping
```

Common causes:
- `redis.external` URL wrong in Helm values
- Redis not in same namespace/network policy
- Redis port blocked by NetworkPolicy

### Checking Connection Capacity

**How many connections can the cluster handle?**
```
max_connections = replicaCount × resource_limits.max_connections
```

With default values (2 replicas × 10,000 connections = 20,000 simultaneous connections).

**Check live connection count:**
```bash
kubectl exec -n ja4proxy <pod> -- curl -s localhost:8080/metrics | grep ja4proxy_connections_active
```

## Upgrade Procedure

```bash
# 1. Check current release
helm history ja4proxy -n ja4proxy

# 2. Diff new values against current
helm diff upgrade ja4proxy deploy/helm/ja4proxy/ -n ja4proxy -f values.prod.yaml

# 3. Apply upgrade (rolling)
helm upgrade ja4proxy deploy/helm/ja4proxy/ -n ja4proxy -f values.prod.yaml

# 4. Monitor rollout
kubectl rollout status deployment/ja4proxy -n ja4proxy --timeout=5m

# 5. Verify post-upgrade
kubectl get pods -n ja4proxy
curl -s http://proxy-service/health | jq .
```

## Rollback Procedure

```bash
# Roll back to previous release
helm rollback ja4proxy -n ja4proxy

# Or to a specific revision
helm rollback ja4proxy 3 -n ja4proxy

# Verify rollback
helm history ja4proxy -n ja4proxy
kubectl rollout status deployment/ja4proxy -n ja4proxy
```
```

---

## 7. OpenTelemetry Span Attribute Sanitisation

OpenTelemetry spans will be sent to an external collector (Jaeger, Tempo, etc.). These
spans must not contain PII or sensitive operational data.

### Attributes That Must NOT Appear in Spans

| Field | Reason | Mitigation |
|-------|--------|------------|
| Full `client_ip` | PII (GDPR/CCPA in some jurisdictions) | Hash IP: `sha256(ip)[:16]` as `client.ip_hash` |
| Redis connection string | Contains password | Use `redis_host` label only, never full URL |
| JA4 fingerprint | Could fingerprint legitimate users | Include only when score ≥ 50 (likely bad actor) |
| API keys (AbuseIPDB, etc.) | Secret | Never include in span attributes |
| Specific Redis key names with IP values | Reveals internal schema | Use generic `redis.key_type` label |

### Span Attribute Schema

```python
# Allowed span attributes for pipeline.process span
span.set_attribute("ja4proxy.action", action)          # allow/block/flag/etc.
span.set_attribute("ja4proxy.score", score)
span.set_attribute("ja4proxy.client.country", country)  # ISO-2, not IP
span.set_attribute("ja4proxy.client.asn_type", asn_type)
span.set_attribute("ja4proxy.ja4_prefix", ja4[:8])     # First 8 chars only, not full fingerprint
# NOT: span.set_attribute("client.ip", client_ip)       -- PII
# NOT: span.set_attribute("ja4", ja4)                   -- full fingerprint
```

### Acceptance Criteria for OTel Sanitisation

- [ ] Unit test: pipeline span does not contain `client.ip` attribute
- [ ] Unit test: pipeline span does not contain full JA4 fingerprint
- [ ] Unit test: Redis sub-span does not contain connection string
- [ ] Integration test: exported span examined by mock OTLP collector; no forbidden attributes present

---

## 8. TDD Category Checklist

Phase 16 specifies test files in detail (`PHASE_16.md §Unit Tests`, `§Integration Tests`,
etc.), but does not explicitly require all 7 categories. This checklist makes it explicit.

- [ ] **Unit tests**: `tests/adversarial/`, `tests/fp_corpus/`, `tests/unit/security/test_ja4x.py`,
      `tests/unit/test_admin_cli.py` — minimum 35 tests across all new Phase 16 units
- [ ] **Integration tests**: `../../tests/integration/test_fingerprinting.py`, `test_adaptive_rate.py` — minimum 4 tests
- [ ] **Chaos tests**: `../../tests/chaos/test_external_api_failure.py` with all 3 class scenarios — minimum 8 tests
- [ ] **Adversarial tests**: `tests/adversarial/test_tls_parser_adversarial.py`,
      `../../tests/adversarial/test_ja4_adversarial.py` — minimum 10 + 8 corpus/degenerate tests
- [ ] **FP corpus tests**: `../../tests/fp_corpus/test_dga_fp_rate.py`, `../../tests/fp_corpus/test_beaconing_fp_rate.py`,
      `../../tests/fp_corpus/test_asn_fp_rate.py` — minimum 3 tests with rate assertions
- [ ] **Performance tests**: `../../tests/performance/test_bench_pipeline.py`, `../../tests/performance/test_bench_cidr_lookup.py` —
      minimum 3 tests with regression gate
- [ ] **E2E tests** (where applicable): JA4X emitted in pipeline log; adaptive threshold
      applied when analytics key present — minimum 2 E2E tests

TDD process requirement:
- [ ] `../../tests/unit/security/test_ja4x.py` written before `ja4x` field is added to `ConnectionContext`
- [ ] `test_adaptive_rate.py` written before `get_rate_threshold()` is modified
- [ ] `../../tests/unit/test_admin_cli.py` written before CLI commands are implemented

---

## 9. Acceptance Criteria (Supplement)

These extend the acceptance criteria in `PHASE_16.md`. Both sets must pass.

### ADRs

- [ ] `docs/decisions/ADR-016a.md` exists with JA4X forgery threat model and cert source options
- [ ] `docs/decisions/ADR-016b.md` exists with EWMA parameters and manipulation mitigation

### Logging

- [ ] All five new log event schemas (§3a–§3e) produce valid JSON matching field specs
- [ ] Admin CLI writes audit log entry to `management:audit_log` for every destructive command
- [ ] OTel span attributes do not contain client IP, full JA4, or Redis connection string

### Grafana

- [ ] Three new Grafana panels added: JA4X classification, adaptive threshold comparison,
      adaptive fallback rate
- [ ] Two new AlertManager rules pass `promtool check rules`
- [ ] Five new Prometheus metrics registered in `docs/OBSERVABILITY_STANDARDS.md`

### Admin CLI Security

- [ ] `REDIS_URL` without password → CLI exits code 1 with clear error
- [ ] Every destructive operation writes audit entry to `management:audit_log`
- [ ] No `--redis-password` CLI argument exists (password only via env var)
- [ ] Span attributes verified by unit test: no PII fields present

### Documentation

- [ ] `docs/decisions/ADR-016a.md` and `ADR-016b.md` exist
- [ ] `docs/runbooks/kubernetes_operations.md` exists with complete troubleshooting guide
- [ ] `docs/OBSERVABILITY_STANDARDS.md` updated with 5 new metrics
