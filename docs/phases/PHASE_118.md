# Phase 118 — Connection Lifecycle Hardening & Operational Security

> **Status:** PROPOSED
> **Size:** LARGE (8-12 engineer-days)
> **Triggered by:** Independent Red Team White-Box Assessment (2026-04-17)
> **Report:** `docs/reports/2026-04-17_REDTEAM_WHITEBOX_ASSESSMENT.md`

---

## Goal

Fix 17 vulnerabilities found by independent white-box assessment, focusing on the
Go proxy connection lifecycle (goroutine leaks, missing limits, timeout gaps),
unauthenticated operational endpoints, credential hygiene, and Python proxy
input validation gaps.

---

## 118a. Goroutine Leak in forward() and tarpit() [RT-001] — CRITICAL

### Problem
Both `forward()` and `tarpit()` spawn two goroutines for bidirectional copy but
only `<-done` once. The second goroutine leaks, holding its buffer indefinitely.
Under sustained load this causes memory exhaustion and eventual OOM kill.

### Location
`cmd/proxy/main.go:500-502` (forward), `cmd/proxy/main.go:587-589` (tarpit)

### Fix
1. Change `<-done` to `<-done; <-done` in both functions (wait for BOTH goroutines).
2. Alternatively, replace with `sync.WaitGroup` or `errgroup.Group` for clarity.
3. Add a test that verifies both goroutines have exited after `forward()` returns
   (use `runtime.NumGoroutine()` before/after with a `net.Pipe()` connection).

### Acceptance Criteria
- [ ] `forward()` waits for both copy goroutines before returning
- [ ] `tarpit()` waits for both copy goroutines before returning
- [ ] Test: goroutine count after 100 forward() calls returns to baseline
- [ ] Test: goroutine count after 100 tarpit() calls returns to baseline

---

## 118b. Fix `n` vs `len(data)` After PROXY Header Strip [RT-002] — CRITICAL

### Problem
After stripping a PROXY protocol header, `data` is re-sliced but `n` retains the
original `Read()` count. Line 359 checks `n >= 5` but should check `len(data) >= 5`.
This creates a reliable JA4 bypass variant that doesn't require TCP fragmentation —
a single segment with a complete PROXY header and <5 bytes of TLS payload triggers it.

### Location
`cmd/proxy/main.go:359`

### Fix
1. Change `if n >= 5 && data[0] == 0x16 {` to `if len(data) >= 5 && data[0] == 0x16 {`
2. Add test: send a valid PROXY v1 header + 2 bytes of TLS record (`\x16\x03`) in
   a single read. Verify the connection is NOT scored with an empty JA4 (i.e., the
   partial TLS is not misinterpreted as a full ClientHello).

### Acceptance Criteria
- [ ] TLS detection uses `len(data)` not `n` after PROXY header stripping
- [ ] Test: PROXY header + 2-byte TLS stub → connection is NOT treated as valid TLS
- [ ] Test: PROXY header + full ClientHello → JA4 computed correctly (regression)

---

## 118c. Restrict Metrics/Health Endpoints [RT-003] — CRITICAL

### Problem
The metrics HTTP server binds to `:<port>` (all interfaces, default 9090) with no
authentication. `/health/deep` exposes dial setting, active connections, ban count,
tarpit saturation, and cert expiry. `/metrics` exposes full Prometheus scrape. The
config file has `authentication.enabled: false` but the Go code does not implement
the auth config at all — it's dead configuration.

### Location
`cmd/proxy/main.go:254-258`, `cmd/proxy/main.go:676-832`, `config/proxy.yml:218-226`

### Fix
1. Add a `metrics.bind_host` config key (default `127.0.0.1`) and use it in the
   `http.Server.Addr` construction at line 258.
2. Implement the existing `metrics.authentication` config: if enabled, wrap
   `/health/deep`, `/metrics`, and `/metrics/summary` with HTTP Basic Auth
   middleware using the configured username/password.
3. Leave `/health` (shallow) unauthenticated for load balancer probes.
4. Add test: verify `/health/deep` returns 401 when auth is enabled and no creds.
5. Add test: verify metrics server binds to configured `bind_host`.

### Acceptance Criteria
- [ ] Metrics server defaults to `127.0.0.1` bind (not `0.0.0.0`)
- [ ] `metrics.authentication.enabled: true` enforces HTTP Basic Auth on `/health/deep` and `/metrics`
- [ ] `/health` (shallow) remains unauthenticated
- [ ] Test: unauthenticated request to `/health/deep` → 401 when auth enabled
- [ ] Test: authenticated request to `/health/deep` → 200

---

## 118d. Credential Rotation & History Purge [RT-004] — CRITICAL

### Problem
`.env` file with real Redis, Grafana, and UI API key credentials exists in git
history. Even though `.env` is gitignored, the values are recoverable.

### Fix
1. Rotate ALL credentials: Redis password, Grafana password, UI API key.
2. Purge `.env` from git history using `git filter-repo` or BFG Repo-Cleaner.
3. Add a `detect-secrets` pre-commit hook to prevent recurrence.
4. Document the rotation procedure in `docs/runbooks/credential_rotation.md`.

### Acceptance Criteria
- [ ] All three credentials rotated in deployment
- [ ] `git log --all --full-history -- .env` returns no results
- [ ] Pre-commit hook rejects commits containing high-entropy strings in `.env`
- [ ] Credential rotation runbook exists

---

## 118e. Connection Semaphore on Accept Loop [RT-005] — HIGH

### Problem
The main accept loop at line 297 creates unbounded goroutines. Each connection
allocates 3x BufferSize in memory. Combined with RT-001, this enables an amplified
memory exhaustion DoS.

### Location
`cmd/proxy/main.go:285-298`

### Fix
1. Add a `proxy.max_connections` config key (default 10000).
2. Create a semaphore channel: `sem := make(chan struct{}, maxConns)`.
3. Before `go p.handleConn()`, acquire from sem. Release in handleConn's defer.
4. If sem is full, log a warning and close the connection immediately.
5. Expose `ja4proxy_connections_rejected_total{reason="capacity"}` counter.

### Acceptance Criteria
- [ ] `proxy.max_connections` config key exists with default 10000
- [ ] Connections beyond limit are rejected with RST
- [ ] `ja4proxy_connections_rejected_total` counter incremented on rejection
- [ ] Test: semaphore blocks new connections when capacity reached

---

## 118f. Tarpit Timeout Enforcement [RT-006] — HIGH

### Problem
`tarpit()`'s `copyOne` function has no `SetReadDeadline`. An attacker can send 1
byte then hang indefinitely, permanently consuming a tarpit slot. Trivially
exhausts `MaxActiveConnections` with ~100 source IPs.

### Location
`cmd/proxy/main.go:572-584`

### Fix
1. Add `src.SetReadDeadline(time.Now().Add(tarpitInactivityTimeout))` in the
   `copyOne` loop, matching the pattern in `forward()`'s `copyConn`.
2. Add `tarpit.inactivity_timeout` config key (default 60 seconds).
3. When timeout fires, close the connection and release the tarpit slot.

### Acceptance Criteria
- [ ] `tarpit.inactivity_timeout` config key exists (default 60s)
- [ ] Idle tarpit connections are closed after inactivity timeout
- [ ] Tarpit slot is released on timeout
- [ ] Test: connection sending 1 byte then silence is closed after timeout

---

## 118g. Replace KEYS With SCAN in CountKeys [RT-007] — HIGH

### Problem
`CountKeys()` uses the O(N) `KEYS` command, blocking Redis for all clients. Called
on every unauthenticated `/health/deep` request. An attacker polling the endpoint
can continuously degrade Redis performance.

### Location
`internal/redis/client.go:387-393`

### Fix
Option A: Replace `KEYS` with incremental `SCAN` (iterate with cursor, count matches).
Option B: Maintain an atomic counter key `ja4proxy:ban:count` — increment on ban
SET, decrement on ban DELETE/expire. Read the counter in CountKeys. (Preferred — O(1).)

### Acceptance Criteria
- [ ] `CountKeys()` no longer uses the `KEYS` command
- [ ] Test: `CountKeys` returns correct count with 0, 1, and 100 keys
- [ ] Test: verify no `KEYS` command in Redis command log during health check

---

## 118h. Trusted CIDR Validation [RT-008] — HIGH

### Problem
Python proxy's trusted CIDR list accepts `0.0.0.0/0` and `::/0`, which makes ALL
source IPs trusted for PROXY protocol and X-Forwarded-For. No validation at config
load time.

### Location
`proxy.py:2130-2134`, config validation at `proxy.py:674-718`

### Fix
1. In config validation, reject trusted CIDRs with prefix length < /8 (v4) or < /32 (v6).
2. Warn on RFC1918/loopback ranges in trusted CIDRs (these are unusual in production).
3. Log `CRITICAL` if effective trust set covers more than a /16 equivalent.
4. Add the same validation to the Go proxy's `setTrustedCIDRs()`.

### Acceptance Criteria
- [ ] Config load rejects `0.0.0.0/0`, `0.0.0.0/1`, `::/0` as trusted CIDRs
- [ ] Warning logged for RFC1918 ranges in trusted CIDRs
- [ ] Test: config with `/0` CIDR raises validation error
- [ ] Test: config with valid `/24` CIDR loads successfully

---

## 118i. Redis Key Sanitisation for SNI/Fingerprints [RT-009] — HIGH

### Problem
Redis keys are constructed with unsanitised SNI hostnames and fingerprints.
Attacker-controlled SNI containing colons can cross Redis key namespaces.

### Location
`src/security/behavioral.py:81,108`, `src/security/tcp_analyzer.py:144`,
`src/security/deception.py:236`

### Fix
1. Validate SNI against RFC 6066 hostname format before use in Redis keys.
2. For Redis key construction, either:
   a. Hash the SNI: `sha256(sni)[:16]` as the key component, or
   b. Replace non-alphanumeric characters (except `.` and `-`) with `_`
3. Apply the same treatment to JA4 fingerprints used in keys (the JA4 format is
   well-defined so regex validation suffices: `^[tq]\d+[di]\d+\d+[a-z0-9_]+$`).

### Acceptance Criteria
- [ ] SNI in Redis keys validated or hashed
- [ ] Test: SNI containing `:` does not create cross-namespace keys
- [ ] Test: SNI containing `*` does not affect SCAN patterns
- [ ] Valid SNI/JA4 values produce correct Redis keys (regression)

---

## 118j. Python Backend Connection Timeout [RT-010] — HIGH

### Problem
`asyncio.open_connection()` for backend has no timeout. If backend is unresponsive,
all handler coroutines block for the OS TCP timeout (~2 minutes). The tarpit
connection correctly uses a 5-second timeout.

### Location
`proxy.py:2702-2704`

### Fix
1. Wrap with `asyncio.wait_for(..., timeout=connection_timeout)`.
2. Use `proxy.connection_timeout` config key (default 5 seconds, matching tarpit).
3. On timeout, log warning and close client connection (fail-open — client retries).

### Acceptance Criteria
- [ ] Backend connection attempt times out after `connection_timeout` seconds
- [ ] `proxy.connection_timeout` config key exists (default 5s)
- [ ] Test: unresponsive backend → connection closed within timeout + 1s
- [ ] Test: responsive backend → normal forwarding (regression)

---

## 118k. Management API Cookie Secure Flag [RT-011] — HIGH

### Problem
JWT session cookie has `secure=False` hardcoded. In production behind HTTPS, the
cookie is still sent over HTTP, allowing network interception.

### Location
`management/api/auth.py:494`

### Fix
1. Change to: `secure=os.environ.get("ENVIRONMENT") == "production"`
2. Or: default to `True`, only set `False` when `MANAGEMENT_DEV_MODE=1`.

### Acceptance Criteria
- [ ] Cookie `secure=True` when `ENVIRONMENT=production`
- [ ] Cookie `secure=False` only in explicit dev mode
- [ ] Test: production config sets secure flag on cookie

---

## 118l. Log Sanitisation Hardening [RT-012] — MEDIUM

### Problem
`_sanitize_log()` only strips `\r\n`. Null bytes, ANSI escapes, and C0/C1 control
characters pass through. Additionally, SNI and JA4 from HTTP headers are logged
without any sanitisation.

### Location
`proxy.py:2140-2144`, `proxy.py:2218-2219`

### Fix
1. Extend `_sanitize_log()` to strip all characters with `ord(c) < 0x20` except `\t`.
2. Apply `_sanitize_log()` to ALL client-controlled fields before logging (SNI, JA4,
   country, error messages containing client data).

### Acceptance Criteria
- [ ] Null bytes stripped from logged values
- [ ] ANSI escape sequences stripped from logged values
- [ ] SNI and JA4 pass through `_sanitize_log()` before logging
- [ ] Test: SNI with ANSI escape → log line contains sanitised version

---

## 118m. Bound behavioral:known_ja4 Set [RT-013] — MEDIUM

### Problem
`behavioral:known_ja4` Redis SET grows indefinitely. An attacker sending randomised
ClientHellos can add ~1 fingerprint/second.

### Location
`src/security/behavioral.py` (Redis SET, no TTL)

### Fix
1. Add 90-day TTL to `behavioral:known_ja4` by converting from SET to ZSET with
   timestamp scores, or by using per-member expiry (Redis 7.4+).
2. Alternatively, cap the set at 100K members and reject additions beyond that.

### Acceptance Criteria
- [ ] `behavioral:known_ja4` has bounded growth
- [ ] Old entries are evicted after 90 days or set is capped
- [ ] Test: verify old entries are cleaned up

---

## 118n. Redis XADD Backpressure [RT-014] — MEDIUM

### Problem
Every connection decision spawns a goroutine with `context.Background()` for Redis
XADD. If Redis is slow, goroutines and their JSON payloads accumulate without bound.

### Location
`cmd/proxy/main.go:418-441`

### Fix
1. Use a buffered channel (capacity 1000) as a send queue.
2. A single writer goroutine drains the channel and calls XADD.
3. If the channel is full, drop the event and increment
   `ja4proxy_events_dropped_total` counter.
4. Use a context with 1-second timeout on the XADD call.

### Acceptance Criteria
- [ ] Event publishing uses a bounded channel, not per-connection goroutines
- [ ] Events are dropped (not blocked) when Redis is slow
- [ ] `ja4proxy_events_dropped_total` counter exists
- [ ] Test: slow Redis → events dropped, proxy continues serving

---

## 118o. OIDC Token Signature Verification [RT-015] — MEDIUM

### Problem
OIDC callback extracts ID token claims without verifying the JWT signature against
the IdP's JWKS endpoint. Currently relies on HTTPS + client secret.

### Location
`management/api/routes/oidc.py:420`

### Fix
1. Fetch JWKS from discovery document's `jwks_uri`.
2. Cache JWKS with 1-hour TTL (refresh on `kid` miss).
3. Verify ID token signature (RS256 or ES256) before trusting claims.
4. Reject tokens with `alg: none` or unsupported algorithms.

### Acceptance Criteria
- [ ] ID token signature verified against JWKS before claims extraction
- [ ] JWKS cached and refreshed on `kid` miss
- [ ] `alg: none` tokens rejected
- [ ] Test: token with invalid signature → authentication failure

---

## 118p. TLS Parser Memory Isolation [RT-016] — MEDIUM

### Problem
Python TLS parsing switched from `ProcessPoolExecutor` to `ThreadPoolExecutor`,
removing memory isolation. Malformed packets can consume unlimited memory in the
main proxy process.

### Location
`proxy.py:1279-1281`

### Fix
1. Add a maximum input size check before passing to Scapy (cap at 16KB — max TLS
   record size).
2. Consider reverting to `ProcessPoolExecutor` for the parsing path only, or
   using a memory-capped subprocess.

### Acceptance Criteria
- [ ] TLS input truncated to 16KB before Scapy parsing
- [ ] Test: 64KB input is truncated, does not cause excessive memory use

---

## 118q. Stop Echoing Passwords in Scripts [RT-017] — MEDIUM

### Problem
`scripts/start-poc.sh` echoes Redis and Grafana passwords to stdout.

### Location
`scripts/start-poc.sh:40-41`

### Fix
1. Replace password echo with confirmation: `echo "  Redis password: [generated]"`
2. Passwords should only be written to the `.env` file, not displayed.

### Acceptance Criteria
- [ ] No passwords appear in script stdout
- [ ] Passwords still written to `.env` file correctly

---

## Estimated Effort

| Sub-phase | Estimate | Priority |
|-----------|----------|----------|
| 118a Goroutine leak | 1h | CRITICAL |
| 118b n vs len(data) | 30min | CRITICAL |
| 118c Metrics auth | 3-4h | CRITICAL |
| 118d Credential rotation | 2h | CRITICAL |
| 118e Connection semaphore | 2h | HIGH |
| 118f Tarpit timeouts | 1h | HIGH |
| 118g KEYS → SCAN | 1-2h | HIGH |
| 118h Trusted CIDR validation | 2h | HIGH |
| 118i Redis key sanitisation | 2-3h | HIGH |
| 118j Backend timeout | 30min | HIGH |
| 118k Cookie secure flag | 30min | HIGH |
| 118l Log sanitisation | 1-2h | MEDIUM |
| 118m Bound known_ja4 | 1h | MEDIUM |
| 118n XADD backpressure | 2-3h | MEDIUM |
| 118o OIDC token verify | 3-4h | MEDIUM |
| 118p TLS parser isolation | 1h | MEDIUM |
| 118q Script password echo | 15min | MEDIUM |

**Total: ~24-30 hours of implementation work.**

---

## Out of Scope

- Findings already captured in Phases 109-117 (unless amplified here)
- New feature development
- Python proxy deprecation (Go is production per CLAUDE.md)
- Architectural changes to the pipeline
