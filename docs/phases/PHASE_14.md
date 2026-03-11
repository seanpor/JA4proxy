# Phase 14 — Production Hardening

## Goal
Address all gaps identified in `docs/DMZ_DEPLOYMENT_READINESS.md` and
`docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`. Read both documents fully first.

## 14a. Secrets Management

Docker secrets (minimum) or Vault stub. UI API key and AbuseIPDB key never logged.
Auto-rotate Redis password on deployment. All secrets loaded from environment
variables — never written to `docker-compose.prod.yml` in plaintext.

## 14b. Redis Security

AUTH in `docker-compose.prod.yml`. Bind Redis to internal Docker network — not
`0.0.0.0`. TLS for cross-host replication if used. Verify `maxmemory` and
`allkeys-lru` set. Confirm Redis not reachable from outside the compose network.

## 14c. Resource Limits

CPU and memory limits on all containers. Health checks for all services.
Graceful shutdown: drain in-flight connections on SIGTERM before process exit.
Set `ulimit -n` appropriately for expected concurrent connection count.

**Default Values:**
- CPU limit: 2 cores per container
- Memory limit: 4GB per container
- File descriptor limit: 65536
- Connection queue size: 1000
- Max connections: 10000

## 14d. Rate Limit Self-Protection

Max-tracked-IPs cap on beaconing detector and sliding window rate limiter.
Prevents unbounded Redis growth under sustained attack. Max stream length on
`ja4proxy:events` stream (`stream_max_length` in analytics config).

## 14e. Observability

Structured JSON logging for SIEM integration. Alertmanager rules covering:
high block rate, AbuseIPDB quota exhaustion, Spamhaus download failure, analytics
stream lag above threshold, proxy instance crash, Redis memory above 80%, dial change.
See `docs/OBSERVABILITY_STANDARDS.md §4` for the full rule set.

**Alertmanager Rule Files:**
- `monitoring/alertmanager/rules/proxy.rules.yml` - Proxy-specific alerts
- `monitoring/alertmanager/rules/redis.rules.yml` - Redis monitoring alerts
- `monitoring/alertmanager/rules/security.rules.yml` - Security event alerts

## 14f. Ansible Hardening

Firewall rules restricting proxy port to HAProxy only. TCP SYN cookie sysctl
(`net.ipv4.tcp_syncookies=1`). fail2ban integration for SSH. Kernel parameter
hardening (`net.ipv4.conf.all.rp_filter=1`, `net.ipv6.conf.all.disable_ipv6=0`).

## 14g. Tarpit Self-Protection

**Problem:** the tarpit is a finite resource. Each tarpitted connection holds a file
descriptor and a small amount of memory for the 1-byte/sec drain loop. An attacker who
learns they're being tarpitted (by noticing the slow response rather than an RST) can
deliberately generate thousands of simultaneous tarpitted connections to exhaust the
proxy's file descriptors or memory.

**Implementation:**

```yaml
tarpit:
  max_concurrent_connections: 500    # Hard cap on simultaneous tarpit slots
  max_per_ip: 3                       # Max concurrent tarpit connections from one IP
  overflow_action: "block"            # When cap reached: block instead of tarpit
                                      # Options: block | rst | allow (fail open)
  overflow_log: true                  # Log overflow events for analysis
```

When `max_concurrent_connections` is reached, new connections that would be tarpitted
are instead given the `overflow_action`. Default is `block` (clean RST) — this is
slightly more informative to the attacker than tarpit but preserves proxy resources.

Track concurrent tarpit count with a Redis counter (same INCR/DECR pattern as
concurrent connections in Phase 5). Keep in-process for speed — Redis is the
cross-instance view if needed but the per-instance cap applies per instance.

**Resource sizing guidance** (add to `docs/SECOPS_OPERATIONS.md`):
- Each tarpitted connection uses ~8KB memory + 1 file descriptor
- Default Linux `ulimit -n` is 1024; prod should be 65536+
- At `max_concurrent: 500`, memory impact is ~4MB — negligible
- File descriptors at 500 tarpit + N legitimate connections: size ulimit accordingly

**Acceptance criteria additions:**
- [ ] `max_concurrent_connections` cap enforced; new tarpit connections → overflow_action when full
- [ ] `max_per_ip` cap enforced per source IP
- [ ] Overflow action configurable: block | rst | allow
- [ ] Overflow events logged and counted in Prometheus
- [ ] In-process counter (fast path) with Redis cross-instance gauge for monitoring
- [ ] `SECOPS_OPERATIONS.md` updated with resource sizing guidance
- [ ] Tests: cap reached → overflow action taken
- [ ] per-IP cap
- [ ] counter cleanup on connection close
- [ ] Prometheus gauge:   `ja4proxy_tarpit_concurrent` — current concurrent tarpitted connections
- [ ] Prometheus counter: `ja4proxy_tarpit_overflow_total{action}` — connections that hit tarpit capacity cap

## Redis Key Schema

Phase 14 adds no new Redis keys. Production hardening configures existing infrastructure.

## Config

```yaml
production:
  tls:
    enabled: true               # Default: true in production. Terminate TLS on the proxy.
    cert_path: ""               # Path to TLS certificate. Set via PROXY_TLS_CERT env var.
    key_path: ""                # Path to TLS private key. Set via PROXY_TLS_KEY env var.

  secrets:
    rotate_redis_password: true # Default: true. Auto-rotate Redis password on deployment.
    log_api_keys: false         # Default: false. Never log API keys. Override for debugging only.

  resource_limits:
    max_connections: 10000      # Default: 10000. Hard cap on simultaneous connections.
    connection_queue_size: 1000 # Default: 1000. Queue depth before refusing new connections.

  observability:
    json_logging: true          # Default: true in production. Structured JSON output for SIEM.
    log_level: INFO             # Default: INFO. Options: DEBUG | INFO | WARN | ERROR.
    siem_forwarding: false      # Default: false. Enable to forward logs to external SIEM.
    siem_endpoint: ""           # Set via SIEM_ENDPOINT env var.

  validation:
    # Configuration validation settings
    strict_mode: true           # Default: true. Fail on invalid configuration values.
    warn_on_deprecated: true    # Default: true. Log warnings for deprecated config options.
    auto_correct: false         # Default: false. Automatically correct common misconfigurations.
```

## Configuration Validation

**Validation Rules:**
- All numeric values must be positive integers
- File paths must be absolute or relative to config directory
- TLS certificates must be valid PEM format
- Redis connection strings must include authentication
- Resource limits must not exceed system capabilities

**Error Handling:**
- Invalid configurations cause immediate startup failure
- Deprecation warnings logged but don't prevent startup
- Configuration errors include detailed error messages
- Validation runs on config load and hot-reload

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| SIGTERM during active connections | Graceful drain: in-flight connections complete; new connections refused; process exits after drain timeout |
| Memory limit reached | OOM kill by container runtime; process restarts via Docker restart policy; no data corruption |
| Redis password rotated while proxy running | Hot reload with new `REDIS_URL` env var; existing connections re-authenticated |
| Tarpit cap reached | Overflow action taken; `ja4proxy_tarpit_overflow_total` incremented; global cap does not affect non-tarpit connections |

## Acceptance Criteria

### Functional
- [ ] All secrets (API keys, Redis password) loaded from environment variables; none in `docker-compose.prod.yml` plaintext
- [ ] Redis AUTH configured in `docker-compose.prod.yml`; proxy connects with password
- [ ] CPU and memory limits set on all containers in `docker-compose.prod.yml`
- [ ] Graceful shutdown: in-flight connections drained before process exit; SIGTERM handled
- [ ] Structured JSON logging enabled; all log lines valid JSON; verified by parsing test
- [ ] Tarpit max concurrent cap enforced; overflow action (`block | rst | allow`) taken; counter incremented
- [ ] Tarpit per-IP cap enforced independently of global cap
- [ ] Tarpit connection counter DECR on connection close; no counter leak on abrupt disconnect

### Configuration
- [ ] `tarpit.max_concurrent_connections`, `tarpit.max_per_ip`, `tarpit.overflow_action` configurable
- [ ] `tls_termination.enabled`, `rotate_redis_password`, `max_connections` configurable
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart
- [ ] `tls_termination` and Redis AUTH settings require restart; tarpit limits and resource caps are hot-reloadable

### Observability
- [ ] Prometheus gauge:   `ja4proxy_tarpit_concurrent` — current concurrent tarpitted connections
- [ ] Prometheus counter: `ja4proxy_tarpit_overflow_total{action}` — connections that hit tarpit capacity cap
- [ ] Alertmanager rules file covers all failure modes documented in Phases 0–13
- [ ] `docs/security/SECURITY_CHECKLIST.md` updated with all production hardening items

- [ ] JSON log: all proxy log output is valid JSON; parsing 1000 log lines produces zero parse errors (verified by test)
- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"proxy","event":"shutdown_initiated"}` emitted on SIGTERM with `active_connections` count

### Unit Tests  (`tests/unit/test_tarpit.py`)
- [ ] Tarpit cap reached: next candidate receives `overflow_action` (block/rst/allow per config)
- [ ] Per-IP cap: IP at `max_per_ip` receives overflow action; other IPs unaffected
- [ ] Counter DECR on close: concurrent count returns to correct value after connection closes
- [ ] Abrupt disconnect: counter cleaned up; no leak after disconnect without clean close

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] Graceful shutdown: SIGTERM during 50 active connections → all drain within timeout; no hung connections
- [ ] Redis AUTH: proxy connects with password; wrong password → FATAL logged; process exits
- [ ] Structured JSON logging: 100 connections processed → all log lines parse as valid JSON

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [ ] Redis unavailable during tarpit counter INCR: fail open; counter not leaked; connection tarpitted

### Performance Tests  (`tests/performance/bench_pipeline.py`)
- [ ] Tarpit counter operations: p99 < 1ms under 500 concurrent tarpitted connections
