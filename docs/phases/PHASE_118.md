<<<<<<< HEAD
# Phase 118 — Connection Lifecycle Hardening & Operational Security

> **Status:** PROPOSED
> **Size:** LARGE (8-12 engineer-days)
> **Triggered by:** Independent Red Team White-Box Assessment (2026-04-17)
> **Report:** `docs/reports/2026-04-17_REDTEAM_WHITEBOX_ASSESSMENT.md`
=======
# Phase 118 — Pentest Remediation: Attack Surface & Data Leakage Hardening

> **Status:** PROPOSED
> **Size:** XXLARGE (50-60 engineer-days) — 16+ sub-phases
> **Triggered by:** `docs/reports/2026-04-16_LEADER_PENTEST_CAMPAIGN.md`
> **Extended by:** `docs/reports/2026-04-17_RED_TEAM_AUDIT.md` (4 rounds: supply chain, backup/crypto, TLS, session, analytics, export, TI, Redis, SSO, DoS)
>>>>>>> 1b456a6 (feat(security): Phase 118 - Pentest Remediation (18 sub-phases))

---

## Goal

<<<<<<< HEAD
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
=======
Remediate all critical and high-severity findings from the external pentest campaign, harden the attack surface against protocol smuggling and fragmentation bypasses, and eliminate data leakage vectors from supporting systems (Redis, management API, config files).

---

## Scope

| File | Change Type |
|------|----------|
| `cmd/proxy/main.go` | Fix L1-018, L1-019, metrics auth |
| `proxy.py` | Fix L4-028 |
| `management/api/routes/webhooks.py` | Add SSRF validation |
| `management/api/routes/auth.py` | Redis-backed rate limiting |
| `internal/redis/client.go` | Add fail-closed validation |
| `internal/webhook/delivery.go` | SSRF prevention |
| `config/docker-compose.poc.yml` | Add Redis ACLs |
| `docs/REDIS_SCHEMA.md` | Document Redis security |

---

## 118a. PROXY Protocol Anti-Smuggling (Go Proxy)

### Problem
Attackers can smuggle a second `PROXY` header immediately after the legitimate one stripped by JA4proxy. The remaining payload is forwarded to the backend, enabling DMZ scanning via the backend webserver acting as an open proxy.

### Location
`cmd/proxy/main.go:332-347` — after PROXY header stripping

### Fix
1. After stripping the PROXY header (either v1 or v2), explicitly check if the remaining `data` buffer begins with:
   - v1: byte string `PROXY ` (7 bytes)
   - v2: signature bytes `\x0D\x0A\x12` (first 3 bytes of v2 magic)
2. If detected, immediately close the connection and log a security alert: `"PROXY protocol smuggling attempt detected"`
3. Increment a metric: `security_proxysmuggling_total`

### Test Criteria
- [ ] Send `PROXY TCP4 1.2.3.4 192.168.1.50 1234 80\r\nPROXY TCP4 5.5.5.5 10.0.0.1 9999 80\r\n` — connection dropped
- [ ] Send valid PROXY header followed by TLS handshake — connection proceeds normally
- [ ] Metric incremented on smuggling attempt

### Size
SMALL (2-3 engineer-hours)

### Dependencies
None

---

## 118b. TLS Record Reassembly & Protocol Lockdown (Go Proxy)

### Problem
Attackers can bypass JA4 fingerprinting by fragmenting the TLS ClientHello across multiple TCP packets. When `tlsparse.ParseClientHello` returns `ErrTruncated`, the proxy falls through to `forward()` action without calculating a JA4 fingerprint. This completely bypasses JA4-based blocklists and rate limits.

### Location
`cmd/proxy/main.go:310-314` — single `Read()` into 8KB buffer

### Fix
1. **Reassembly Loop**: Replace the single `Read()` with a buffered read loop:
   ```go
   // Read exactly 5 bytes (TLS record header)
   header := make([]byte, 5)
   _, err := io.ReadFull(clientConn, header)
   // Extract TLS record length from bytes 3-4 (big-endian)
   recordLen := int(header[3])<<8 | int(header[4])
   if recordLen > 16384 { // Max TLS record size
       log("TLS record oversized"); return
   }
   // Read remaining record bytes
   body := make([]byte, recordLen)
   io.ReadFull(clientConn, body)
   data := append(header, body...)
   ```
2. **Protocol Lockdown ("The Seal")**: Immediately after reassembly and header stripping, validate the first byte:
   - If `data[0] != 0x16` (TLS Handshake), drop connection immediately
   - This prevents HTTP smuggling, SSH injection, or raw PROXY headers
3. **Timeout**: Apply strict `200ms` deadline during reassembly to prevent Slowloris

### Test Criteria
- [ ] Fragmented ClientHello (5-byte header in packet 1, body in packet 2) — JA4 correctly computed
- [ ] Send `GET / HTTP/1.1\r\nHost: example.com` — connection dropped (non-0x16)
- [ ] Send smuggled PROXY header after TLS header — dropped via anti-smuggling check
- [ ] Slowloris with fragmented input — dropped at 200ms timeout
- [ ] Benchmark: No more than 10% throughput reduction on normal traffic

### Size
MEDIUM (4-6 engineer-hours)

### Dependencies
118a (conceptually similar hardening pattern)

---

## 118c. X-Forwarded-For Hardening (Python Proxy)

### Problem
The Python proxy extracts the FIRST IP from `X-Forwarded-For` header (split by comma, take index 0), allowing attackers to spoof their IP by sending their own XFF header. HAProxy appends the real IP at the end, but the proxy reads the attacker's spoofed IP first.

### Location
`proxy.py:2476` — `_extract_client_ip_from_http()`

### Fix
1. Change the extraction logic from:
   ```python
   ip = line.split(":", 1)[1].strip().split(",")[0].strip()  # WRONG: first IP
   ```
   to:
   ```python
   ip = line.split(":", 1)[1].strip().split(",")[-1].strip()  # CORRECT: last IP
   ```
2. Add a comment explaining why the rightmost IP is trusted (the one appended by our HAProxy)

### Test Criteria
- [ ] Send `X-Forwarded-For: 1.2.3.4, 10.0.0.1` from client — proxy extracts `10.0.0.1` (rightmost)
- [ ] Send `X-Forwarded-For: 127.0.0.1` alone — proxy extracts `127.0.0.1`
- [ ] Verify HAProxy's behavior matches: HAProxy appends, not prepends

### Size
XS (1 engineer-hour)

### Dependencies
None

---

## 118d. Redis Hardening: ACLs & Network Isolation

### Problem
Redis is used for rate tracking, blocklists, and session storage. If Redis is compromised or misconfigured, an attacker can:
- Read/write rate tracking data
- Modify blocklists to allow malicious IPs
- Hijack session tokens

### Location
`config/docker-compose.poc.yml` — Redis service config

### Fix
1. **Redis ACLs**: Add ACL configuration to the Redis container:
   ```yaml
   redis:
     image: redis:7-alpine
     command: redis-server --aclfile /usr/local/etc/redis/redis.acl
     volumes:
       - ./redis.acl:/usr/local/etc/redis/redis.acl:ro
   ```
   Create `redis.acl`:
   ```
   user ja4proxy on ~cached:* ~ratelimit:* ~blocklist:* -@all +@read +@write +@list +@set +@sortedset +@slowlog +@cluster
   user management on ~session:* -@all +@read +@write +@list +@set +@sortedset
   user readonly on ~* -@all +@read
   ```
2. **Network Isolation**: Ensure Redis only binds to the Docker internal network:
   ```yaml
   redis:
     ports:
       - "127.0.0.1:6379:6379"  # Only localhost accessible
   ```
3. **Credential Rotation**: Document in `docs/phases/PHASE_118.md` that Redis passwords should be rotated every 90 days via CI pipeline

### Test Criteria
- [ ] Redis accepts connections only from ja4proxy and management containers
- [ ] Redis rejects `CONFIG GET *` from ja4proxy user (ACL blocks)
- [ ] Redis rejects raw `KEYS *` pattern matching (use `SCAN` instead)
- [ ] Redis is not exposed on host network interface

### Size
SMALL (2-3 engineer-hours)

### Dependencies
None

---

## 118e. Management API Auth Hardening

### Problem
The management API (`/login`, `/auth` endpoints) lacks rate limiting and account lockout, enabling brute force attacks on admin credentials.

### Location
`management/api/routes/auth.py` or equivalent

### Fix
1. **Rate Limiting**: Add per-IP rate limiting to auth routes:
   ```python
   # Apply to /login and /auth POST
   @app.middleware("http")
   async def rate_limit_auth(request, call_next):
       if request.url.path in ("/login", "/auth") and request.method == "POST":
           key = f"ratelimit:auth:{request.client.host}"
           count = await redis.incr(key)
           if count == 1:
               await redis.expire(key, 300)  # 5 minute window
           if count > 5:  # 5 attempts per 5 minutes
               return JSONResponse({"error": "rate limited"}, status_code=429)
       return await call_next(request)
   ```
2. **Account Lockout**: After 5 failed attempts, lock the account for 15 minutes:
   ```python
   # After authentication failure
   failed_key = f"auth:failed:{username}"
   count = await redis.incr(failed_key)
   if count >= 5:
       await redis.setex(f"auth:locked:{username}", 900, "1")  # 15 min
   ```

### Test Criteria
- [ ] 6 POSTs to `/login` from same IP within 5 minutes → 429 response
- [ ] 5 failed auth attempts → account locked for 15 minutes
- [ ] Successful auth after lockout → still rejected until lockout expires

### Size
SMALL (2-3 engineer-hours)

### Dependencies
118d (optional — Redis must be available)

---

## 118f. Config Security Documentation

### Problem
No documented security guidance for config file handling, secrets rotation, or exposure risks.

### Location
`docs/REDIS_SCHEMA.md`, new section in `docs/SECURITY.md`

### Fix
1. Add "Security Considerations" section to `REDIS_SCHEMA.md`:
   - Document that no API keys or secrets should be stored in Redis
   - Document Redis password rotation policy (90 days)
   - Document Redis ACL requirements
2. Add "Config File Security" section to `docs/STYLE_GUIDE.md`:
   - Config files must not contain secrets (use env vars or secrets manager)
   - Config files must be world-unreadable (`chmod 600`)
   - Validate JSON Schema on config reload

### Test Criteria
- [ ] `docs/REDIS_SCHEMA.md` includes security section
- [ ] New `docs/CONFIG_SECURITY.md` exists with hardening guidance

### Size
XS (1-2 engineer-hours)

### Dependencies
None

---

## Implementation Order

| Sub-phase | Effort | Blocked By |
|----------|--------|------------|
| 118f (Docs) | XS | Nothing |
| 118c (Python XFF) | XS | Nothing |
| 118a (PROXY Smuggling) | SMALL | Nothing |
| 118b (TLS Reassembly) | MEDIUM | 118a (similar pattern) |
| 118i (Redis Fail-Closed) | XS | Nothing |
| 118g (SSRF Webhooks) | SMALL | Nothing |
| 118h (Metrics Auth) | XS | Nothing |
| 118d (Redis ACLs) | SMALL | 118f (needs docs first) |
| 118e (Mgmt Auth) | SMALL | 118i (needs Redis) |

---

## Acceptance Criteria

- [ ] All three pentest findings (L1-018, L1-019, L4-028) remediated
- [ ] SSRF validation on webhooks (118g)
- [ ] Metrics endpoints require authentication (118h)
- [ ] Redis fail-closed on startup (118i)
- [ ] Redis ACLs documented and deployed (118d)
- [ ] Management API has Redis-backed rate limiting (118e)
- [ ] Config security documentation added (118f)
- [ ] Backup header encryption status leak fixed (118j)
- [ ] Integration TLS verification added (118k)
- [ ] Config path traversal prevented (118l)
- [ ] EDL IP ACL bypass prevented (118m)
- [ ] Syslog CRLF injection prevented (118n)
- [ ] Go proxy connection semaphore (118o)
- [ ] Slowloris protection (118p)
- [ ] Redis pub/sub full verification (118q)
- [ ] OIDC/SAML test mode disabled (118r)
- [ ] `make test` passes 100%
- [ ] `make parity-check` passes (verify Go and Python produce identical decisions)
- [ ] Phase 117 marked as superseded (update manifest.yaml)
>>>>>>> 1b456a6 (feat(security): Phase 118 - Pentest Remediation (18 sub-phases))

---

## Out of Scope

<<<<<<< HEAD
- Findings already captured in Phases 109-117 (unless amplified here)
- New feature development
- Python proxy deprecation (Go is production per CLAUDE.md)
- Architectural changes to the pipeline
=======
- K8s deployment hardening (Phase 119)
- WAF integration (separate effort)
- DDoS mitigation service (Phase 120)
- TLS 1.3-only enforcement (Phase 121)

---

---

## 118j. Backup Encryption Status Leak Prevention

### Problem
The backup format header (magic bytes, version, flags) is prepended AFTER encryption, leaking whether the backup is encrypted (FLAG_ENCRYPTED=0x04) and whether it's full/incremental. Attackers can identify valuable encrypted backups.

### Location
`src/backup/worker.py:288-291`, `src/backup/format.py:52-64`

### Fix
1. Change the encoding order: encrypt first, then prepend a minimal UNENCRYPTED wrapper:
   ```python
   # WRONG (current): header leaks encryption status
   backup_data = encode_header("full", format_flags) + encrypted_data
   
   # CORRECT: encrypt everything first, then add minimal wrapper
   encrypted_data = self.encryption.encrypt(backup_data)
   # Minimal wrapper: just version (1-2 bytes), NOT flags
   wrapper = struct.pack("!HH", FORMAT_VERSION, len(encrypted_data))
   backup_data = wrapper + encrypted_data
   ```
2. Remove FLAG_ENCRYPTED from the unencrypted wrapper

### Test Criteria
- [ ] Backup file opened in hex editor shows no FLAG_ENCRYPTED bit
- [ ] Attacker cannot determine if backup is encrypted without decrypting
- [ ] Restore still works with new format

### Size
SMALL (2-3 engineer-hours)

### Dependencies
None

---

## 118m. EDL IP ACL Bypass Prevention

### Problem
EDL server trusts `X-Real-IP` header without verifying it was set by a reverse proxy. Attackers can bypass IP-based access control by spoofing this header.

### Location
`src/tap/export/edl_server.py:192-196`

### Fix
Validate that X-Real-IP was set by trusted proxy:
```python
# Option 1: Only accept from localhost (assuming reverse proxy handles IP extraction)
client_ip = request.remote if request.remote != "127.0.0.1" else request.headers.get("X-Real-IP", "")

# Option 2: Check for trusted proxy prefix
x_real_ip = request.headers.get("X-Real-IP", "")
if x_real_ip and not x_real_ip.startswith(("10.", "172.", "192.168.")):
    # Invalid - not from trusted range
    client_ip = request.remote
else:
    client_ip = x_real_ip
```

### Test Criteria
- [ ] Request with `X-Real-IP: 1.2.3.4` from external IP → 403 rejected
- [ ] Request with `X-Real-IP: 10.0.0.1` from internal network → allowed
- [ ] Request from allowed IP directly → 200

### Size
XS (1-2 engineer-hours)

### Dependencies
None

---

## 118o. Go Proxy Connection Semaphore

### Problem
Go proxy has no semaphore limiting concurrent connections. Each accepted connection spawns a goroutine immediately. Under DDoS, this spawns thousands of goroutines, exhausting memory and crashing.

### Location
`cmd/proxy/main.go:285-298`

### Fix
Add connection semaphore:
```go
var connSem = make(chan struct{}, p.cfg.Proxy.MaxConcurrent)

// In Accept loop:
for {
    conn, err := ln.Accept()
    if err != nil {
        continue
    }
    connSem <- 1  // Acquire slot or block
    go func() {
        defer func() { <-connSem }()  // Release on done
        p.handleConn(ctx, conn)
    }()
}
```

### Test Criteria
- [ ] Concurrent connections limited to configured max
- [ ] Connections beyond limit get immediate rejection
- [ ] No goroutine explosion under load test

### Size
SMALL (2 engineer-hours)

### Dependencies
None

---

## 118p. Slowloris Protection

### Problem
No idle timeout on connections. Attacker can hold connections indefinitely with slow data, exhausting connection slots.

### Locations
- `proxy.py:2161-2171`
- `cmd/proxy/main.go`

### Fix
Add keepalive timeout:
```go
// In connection handler:
conn.SetReadDeadline(time.Now().Add(p.cfg.Proxy.ReadTimeout))

// Add keepalive:
conn.SetKeepAlive(true)
conn.SetKeepAlivePeriod(30 * time.Second)
```

### Test Criteria
- [ ] Idle connection dropped after keepalive_timeout
- [ ] Slow data transfer connection dropped

### Size
XS (1-2 engineer-hours)

### Dependencies
None

---

## 118q. Redis Pub/Sub Message Verification

### Problem
Only 4 pub/sub message types verified with HMAC. Other types (whitelist_remove, ban_release) have no verification. Compromised instance can manipulate others.

### Location
`src/pubsub.py:165-185`

### Fix
Verify ALL message types:
```python
CRITICAL_ACTIONS = {
    "ja4_blacklist_add", "dial_change", "config_reload", "cidr_ban_add",
    "whitelist_remove", "ban_release", "ja4_blacklist_remove",  # Add all
}

def _handle_message(self, msg: dict) -> None:
    msg_type = msg.get("type", "")
    if msg_type in CRITICAL_ACTIONS:
        if not self._verify_signature(...):
            return  # Reject ALL
```

### Size
XS (1 engineer-hour)

### Dependencies
None

---

## 118r. OIDC/SAML Test Mode Prevention

### Problem
`MANAGEMENT_TEST_MODE` and `MANAGEMENT_SAML_STRICT=false` can disable signature verification.

### Location
- `management/api/routes/oidc.py:210-222`
- `management/api/routes/saml.py:78-104`

### Fix
Remove test mode from production:
```python
# REMOVE these code paths entirely or add production guard:
# def _extract_claims(id_token, jwks_uri):
#     - REMOVE test mode bypass
#     - ALWAYS verify signature in production
```

### Test Criteria
- [ ] ID tokens ALWAYS verified regardless of env vars
- [ ] SAML STRICT cannot be disabled without errors

### Size
SMALL (2-3 engineer-hours)

### Dependencies
None (118e already covers auth hardening)

---

## 118n. Syslog CRLF Injection Prevention

### Problem
User-controlled fields (IP, JA4) in syslog output can contain `\r\n` to inject additional log messages or forge content.

### Location
`src/tap/export/syslog_exporter.py:115-148`

### Fix
Sanitize user-controlled fields:
```python
def _sanitize(value: str) -> str:
    """Remove CRLF to prevent log injection."""
    return value.replace("\r", "").replace("\n", "")

# In format functions:
ja4_part = f" ja4={_sanitize(ja4)}" if ja4 else ""
ext = f"src={_sanitize(ip)}{ja4_part} score={score} action={_sanitize(action)}"
```

### Test Criteria
- [ ] IP with `\r\n` in ban record → sanitized to single line
- [ ] JA4 with injected newlines → sanitized
- [ ] Normal ban records → unchanged

### Size
XS (1 engineer-hour)

### Dependencies
None

---

## 118l. Configuration Path Traversal Prevention

### Problem
The ConfigLoader accepts a `config_path` parameter that could allow path traversal if user-controllable. File paths are not validated, potentially allowing read of sensitive files.

### Location
`src/config/loader.py:76-77`

### Fix
Add path validation:
```python
def __init__(self, config_path: str = "config/proxy.yml") -> None:
    path = Path(config_path).resolve()
    # Validate it's within the project root
    root = Path(__file__).parent.parent.resolve()
    if not str(path).startswith(str(root)):
        raise ConfigError(f"config path must be within {root}")
    self._path = path
```

### Test Criteria
- [ ] `config_path=../../etc/passwd` → ConfigError
- [ ] `config_path=~/.aws/credentials` → ConfigError (if outside root)
- [ ] `config_path=config/proxy.yml` → succeeds

### Size
XS (1 engineer-hour)

### Dependencies
None

---

## 118k. Integration TLS Verification

### Problem
Splunk, Nagios, and Dynatrace integrations use `urllib.request.urlopen()` without TLS certificate verification.

### Location
- `deploy/integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py:103-114`
- `deploy/nagios/check_ja4proxy.py:44-48`
- `deploy/dynatrace/ja4proxy-extension/plugin.py:129-134`

### Fix
Add certificate verification:
```python
import ssl
# Create verified context
ctx = ssl.create_default_context()
# Or for self-signed:
# ctx.check_hostname = False
# ctx.verify_mode = ssl.CERT_OPTIONAL

response = urllib.request.urlopen(url, data=data, context=ctx)
```

### Test Criteria
- [ ] MITM proxy test: connection rejected without valid cert
- [ ] Valid cert: connection succeeds

### Size
XS (1-2 engineer-hours)

### Dependencies
None

---

## 118g. SSRF Prevention: Webhook URL Validation

### Problem
Attackers with Operator role can create webhooks pointing to internal services (Redis, AWS metadata, internal APIs), exfiltrating the webhook secret and performing SSRF attacks.

### Location
`management/api/routes/webhooks.py:86-130`

### Fix
1. Add URL validation function:
   ```python
   def validate_webhook_url(url: str) -> bool:
       """Block internal, localhost, and link-local URLs."""
       parsed = urlparse(url)
       host = parsed.hostname or ""
       # Block localhost
       if host in ("localhost", "127.0.0.1", "::1"):
           return False
       # Block link-local (169.254.0.0/16,  metadata)
       if host.startswith("169.254."):
           return False
       # Block internal RFC1918 (not exhaustive)
       if re.match(r"^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.", host):
           return False
       return True
   ```
2. Apply validation before saving webhook

### Test Criteria
- [ ] POST /api/v1/webhooks with `url: http://localhost:6379` → 422 rejection
- [ ] POST /api/v1/webhooks with `url: http://169.254.169.254/` → 422 rejection
- [ ] POST /api/v1/webhooks with `url: http://10.0.0.1/` → 422 rejection
- [ ] POST /api/v1/webhooks with `url: https://example.com/` → 201 success

### Size
SMALL (2-3 engineer-hours)

### Dependencies
None

---

## 118h. Metrics Endpoint Authentication

### Problem
Unauthenticated `/metrics`, `/health`, and `/health/deep` endpoints on the Go proxy expose:
- Active connection counts (reveal attack volume)
- Block rates (reveal security effectiveness)
- Dial settings and active bans
- TLS certificate expiry timestamps
- Full pipeline configuration

This provides complete reconnaissance for attackers before launching attacks.

### Location
`cmd/proxy/main.go:250-270, 656-832`

### Fix
1. Add a simple shared secret for metrics endpoints:
   ```go
   var metricsAuth = os.Getenv("JA4PROXY_METRICS_SECRET")
   // Middleware
   func authMetrics(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/metrics") ||
              strings.HasPrefix(r.URL.Path, "/health") {
               secret := r.Header.Get("X-Metrics-Secret")
               if secret != metricsAuth && metricsAuth != "" {
                   http.Error(w, "unauthorized", http.StatusUnauthorized)
                   return
               }
           }
           next.ServeHTTP(w, r)
       })
   }
   ```
2. Document the secret in `.env.example`
3. Require the secret in production

### Test Criteria
- [ ] GET /metrics without secret → 401 response
- [ ] GET /metrics with wrong secret → 401 response
- [ ] GET /metrics with correct secret → 200 + metrics
- [ ] GET /health without secret → 401 response

### Size
XS (1-2 engineer-hours)

### Dependencies
None

---

## 118i. Redis Fail-Closed Validation

### Problem
If Redis is misconfigured without a password, the proxy continues operating (fail-open), connecting to unauthenticated Redis and exposing all security state to the network.

### Location
`internal/redis/client.go:51-65`

### Fix
Add startup validation:
```go
func buildStandaloneOptions(cfg Config) *goredis.Options {
    opts := &goredis.Options{
        Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
        Username: cfg.Username,
        Password: cfg.Password,
    }
    // Fail-closed: require password for non-localhost
    if cfg.Host != "localhost" && cfg.Host != "127.0.0.1" && cfg.Password == "" {
        log.Fatal("Redis password required for non-localhost connections")
    }
    return opts
}
```

### Test Criteria
- [ ] Redis configured with non-localhost IP + no password → startup fatal error
- [ ] Redis configured with localhost + no password → starts (dev mode)
- [ ] Redis configured with password → starts normally

### Size
XS (1 engineer-hour)

### Dependencies
None

---

## Risk Summary (Updated)

| Finding | Severity | Probability | Impact | Priority |
|---------|----------|-------------|--------|----------|
| L1-018 PROXY Smuggling | Critical (CVSS 9.8) | Medium | DMZ pivot | P1 |
| L1-019 Fragmentation Bypass | Critical (CVSS 9.1) | Medium | JA4 bypass | P1 |
| SSRF Webhooks (R-001) | Critical | Medium | Internal compromise | P1 |
| Unauth Metrics (R-002) | Critical | High | Reconnaissance | P1 |
| Redis Fail-Open (R-003) | Critical | Low | Security bypass | P1 |
| L4-028 XFF Spoofing | High (CVSS 7.5) | High | Ban evasion | P2 |
| Redis No ACLs | Medium | Low | Data tampering | P2 |
| In-Memory Rate Limit | High | Medium | Brute force | P2 |
| No Auth Rate Limit | Medium | Medium | Brute force | P3 |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Vulnerabilities remaining | 0 Critical, 0 High |
| Attack surface (open ports) | Reduce by 20% |
| JA4 fingerprint coverage | 100% of TLS connections |
| Auth brute force success rate | 0% (blocked at threshold) |

---

## Parallel Test Strategy

Each sub-phase requires:

1. **Unit tests** in `tests/unit/`
2. **Integration tests** in `tests/integration/` (where applicable)
3. **Fuzz tests** in `tests/fuzz/` (for protocol parsing)

Test files to create/update:
- `tests/unit/test_proxy_smuggling.py` — 118a
- `tests/unit/test_tls_reassembly.py` — 118b
- `tests/unit/test_xff_extraction.py` — 118c
- `tests/integration/test_redis_acl.py` — 118d
- `tests/integration/test_auth_rate_limit.py` — 118e
- `tests/unit/test_webhook_ssrf.py` — 118g
- `tests/unit/test_metrics_auth.py` — 118h
- `tests/unit/test_redis_failclosed.py` — 118i
>>>>>>> 1b456a6 (feat(security): Phase 118 - Pentest Remediation (18 sub-phases))
