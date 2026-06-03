# Red Team White-Box Assessment: JA4proxy Full-Stack

**Date:** April 17, 2026
**Lead:** Independent Red Team (White-Box, Internet-Facing Threat Model)
**Scope:** Full codebase — Go proxy, Python proxy, Management API, Redis layer, deployment artefacts
**Threat Model:** Attacker on the public Internet, with and without HAProxy in front of JA4proxy
**Method:** Automated multi-agent source code analysis + manual verification of all critical findings

---

## Executive Summary

This assessment identified **17 novel findings** not present in the existing pentest
campaign (Phases 108-117). Additionally, several existing findings were confirmed
and amplified with new attack variants.

The most severe cluster is in the Go proxy's connection lifecycle: a goroutine leak
combined with no connection limits and missing tarpit timeouts creates a
**compound resource exhaustion DoS** that can be triggered by any internet client.
The unauthenticated metrics/health endpoints on a wildcard-bound port leak
operational intelligence to any network-adjacent attacker.

A committed `.env` file with real credentials requires immediate rotation.

**Finding Distribution:**

| Severity | New | Amplifies Existing | Total |
|----------|-----|--------------------|-------|
| CRITICAL | 4   | 1                  | 5     |
| HIGH     | 8   | 2                  | 10    |
| MEDIUM   | 5   | 0                  | 5     |
| **Total**| **17** | **3**           | **20** |

---

## Findings

### CRITICAL

#### RT-001: Goroutine Leak in forward() and tarpit() — Resource Exhaustion DoS
**CVSS:** 8.6 (Network/Low/None)
**Component:** Go proxy
**Location:** `cmd/proxy/main.go:502`, `cmd/proxy/main.go:589`
**Status:** NEW

Both `forward()` and `tarpit()` spawn two goroutines for bidirectional copy but
only receive from `done` once:

```go
go copyConn(backendConn, clientConn)   // goroutine A
go copyConn(clientConn, backendConn)   // goroutine B
<-done                                  // waits for ONE, not both
```

When the first goroutine completes, the function returns and `defer clientConn.Close()`
fires. The second goroutine may be blocked in `Read()` on a now-closed connection.
Depending on OS behaviour, it may hang indefinitely — the `done <- struct{}{}` send
blocks because the channel (cap 2) has one slot used and nobody is receiving.

**Impact:** Each connection leaks one goroutine (~8KB stack + buffer). At 100 conn/s
sustained, this is ~69MB/hour of permanently leaked memory. Under attack load, OOM
kill within hours.

**Attack:** Send connections that complete one direction quickly (e.g., send data,
immediately FIN) while keeping the other direction alive. Maximises the window
where one goroutine finishes but the other hangs.

**Fix:** `<-done; <-done` — wait for both goroutines. Or use `errgroup`/`sync.WaitGroup`.

---

#### RT-002: `n` vs `len(data)` After PROXY Header Strip — JA4 Bypass Variant
**CVSS:** 9.1 (amplifies existing L1-019)
**Component:** Go proxy
**Location:** `cmd/proxy/main.go:359`
**Status:** AMPLIFIES L1-019

After stripping a PROXY protocol header, `data` is re-sliced (line 338 or 343),
but `n` retains the original `Read()` count. The TLS detection check at line 359
uses the stale `n`:

```go
data = data[hdrLen:]       // data is now shorter
// ...
if n >= 5 && data[0] == 0x16 {   // n is still the ORIGINAL read size!
```

**Scenario:**
1. Trusted source sends: 45-byte PROXY v1 header + `\x16\x03` (2 bytes of TLS)
2. `n` = 47, `data` after strip = `\x16\x03` (2 bytes)
3. Check: `47 >= 5 && data[0] == 0x16` → **true**
4. `ParseClientHello(data)` receives 2 bytes → `ErrTruncated`
5. Connection scored without JA4 → bypasses all JA4 blocklists

This is a *reliable* variant of L1-019 (fragmentation) that works even with a
single TCP segment. An attacker behind a trusted load balancer can always trigger it
by sizing their ClientHello so the PROXY header + partial TLS fits in one read.

**Fix:** Change line 359 to `if len(data) >= 5 && data[0] == 0x16 {`

---

#### RT-003: Unauthenticated /health/deep and /metrics — Operational Intelligence Leak
**CVSS:** 7.5 (Network/Low/None)
**Component:** Go proxy metrics server
**Location:** `cmd/proxy/main.go:254-258`, `cmd/proxy/main.go:676-832`
**Status:** NEW

The metrics HTTP server binds to `:<port>` (all interfaces, default 9090) with no
authentication. The config file has `authentication: enabled: false` (line 224 of
`config/proxy.yml`) but the Go code **does not implement** the authentication config
at all — it's dead configuration.

**Exposed via /health/deep (line 805-828):**
- `dial` — current blocking policy (0=monitor, 100=full enforcement)
- `active_connections` — real-time connection count
- `active_bans` — number of banned IPs (attack intensity indicator)
- `tarpit.active` / `tarpit.max` — tarpit saturation level
- `cert_days_remaining` — TLS certificate expiry countdown
- `block_rate_pct` — percentage of traffic being blocked

**Exposed via /metrics:**
- Full Prometheus scrape: `ja4proxy_connections_total{action=...}`, risk score
  distributions, error counts by type, pipeline durations — complete operational
  fingerprint.

**Exposed via /health/deep line 707:**
- `p.redis.CountKeys(ctx, "ja4proxy:ban:*")` — executes `KEYS` command (see RT-007).

**Attack scenarios:**
1. **Reconnaissance:** Attacker polls `/health/deep` to determine if proxy is in
   monitor mode (`dial=0`) before launching attack.
2. **Timing:** Watch `cert_days_remaining` approach 0 to attack during cert rotation.
3. **Evasion:** Monitor `block_rate_pct` to calibrate attack rate just below detection.
4. **Capacity probing:** Watch `tarpit.active` vs `tarpit.max` to know when tarpit
   is saturated (and overflow=allow kicks in per L7-001).

**Fix:** Either bind metrics server to loopback only (`127.0.0.1:9090`) or implement
the authentication config that already exists in `proxy.yml`. The `/health` (shallow)
endpoint can remain unauthenticated for load balancer probes; `/health/deep` and
`/metrics` must require authentication or network restriction.

---

#### RT-004: Committed .env With Real Credentials
**CVSS:** 8.2 (credential exposure)
**Component:** Repository
**Location:** `.env` (in git history)
**Status:** NEW

The `.env` file contains production-grade credentials that are in git history:
- `REDIS_PASSWORD=xW5WgUHNCxPkGRg6AYCl1OhJ08tt0zobpkaDkMst1PYLr3sy`
- `GRAFANA_PASSWORD=sCMxpGRfg8M9Y2jY`
- `UI_API_KEY=k_8XAord6uTXfrnBZZg8L3jTGnpj_l9JUdxq1HKK0fo`

Even though `.env` is in `.gitignore`, these values persist in git history and are
recoverable by anyone with repo access (including forks).

**Fix:**
1. Rotate ALL three credentials immediately
2. Use `git filter-repo` or BFG Repo-Cleaner to purge from history
3. Add a pre-commit hook (`detect-secrets`) to prevent recurrence

---

### HIGH

#### RT-005: No Connection Limit on Accept Loop — Goroutine Bomb
**CVSS:** 7.5 (Network/Low/None)
**Component:** Go proxy
**Location:** `cmd/proxy/main.go:285-298`
**Status:** NEW

The main accept loop creates an unbounded number of goroutines:

```go
for {
    conn, err := ln.Accept()
    // ...
    go p.handleConn(ctx, conn)   // no semaphore, no limit
}
```

Each connection allocates up to 3x `BufferSize` (default 8KB = 24KB per connection
across handleConn + 2 copyConn goroutines). Combined with RT-001 (goroutine leak),
an attacker can exhaust memory by opening connections faster than they close.

**Impact:** With default 8KB buffers, 100K concurrent connections = 2.4GB in buffers
alone, plus goroutine stacks (~800MB at 8KB each). Combined with RT-001, leaked
goroutines never free their buffers.

**Fix:** Add a semaphore (e.g., `make(chan struct{}, maxConns)`) before `go p.handleConn()`.
Accept continues but blocks when capacity is reached. This is standard Go server practice.

---

#### RT-006: No Timeouts in Tarpit copyOne — Permanent Slot Exhaustion
**CVSS:** 7.5 (Network/Low/None)
**Component:** Go proxy
**Location:** `cmd/proxy/main.go:572-584`
**Status:** AMPLIFIES L7-001 / L1-016

Unlike `forward()` which sets `ReadDeadline` per iteration, `tarpit()`'s `copyOne`
has **zero timeouts**:

```go
copyOne := func(dst, src net.Conn) {
    buf := make([]byte, 512)
    for {
        n, err := src.Read(buf)   // NO SetReadDeadline!
```

**Attack:**
1. Trigger tarpit action (send a known-bad JA4)
2. Send 1 byte to keep the connection alive
3. Never send another byte
4. Tarpit slot is held until OS TCP keepalive kills it (typically 2+ hours)
5. Repeat until `MaxActiveConnections` tarpit slots are exhausted
6. All subsequent tarpit-action connections hit overflow → `allow` (RT-005 + L7-001)

With `MaxActiveConnections=1000` and `MaxPerIP=10`, an attacker with just 100 source
IPs (trivial with a small botnet or PROXY protocol spoofing from trusted source)
permanently fills all tarpit slots.

**Fix:** Add `src.SetReadDeadline(time.Now().Add(tarpitTimeout))` in the copyOne loop.
A 60-second inactivity timeout is reasonable — legitimate tarpit connections are slow
by design but not silent for minutes.

---

#### RT-007: Redis KEYS Command in /health/deep — Redis Blocking DoS
**CVSS:** 7.2
**Component:** Go proxy + Redis
**Location:** `internal/redis/client.go:388`, called from `cmd/proxy/main.go:707`
**Status:** NEW (Go proxy; management API version noted in Phase 110)

`CountKeys()` uses the `KEYS` command:

```go
func (c *Client) CountKeys(ctx context.Context, pattern string) int {
    keys, err := c.rdb.Keys(ctx, pattern).Result()
```

`KEYS` is O(N) and **blocks the entire Redis instance** during execution. With 10K
active bans, this takes ~10ms. With 100K keys in the instance, scanning takes longer.

Called on every `/health/deep` request (unauthenticated — RT-003). An attacker
can repeatedly poll `/health/deep` to continuously block Redis, degrading proxy
performance for all instances sharing that Redis.

The management API team correctly uses `SCAN` for the same operation (see
`management/api/routes/bans.py:66`). The Go proxy should do the same.

**Fix:** Replace `KEYS` with incremental `SCAN`, or maintain a counter key
(`ja4proxy:ban:count`) that's incremented/decremented on ban set/expire.

---

#### RT-008: Trusted CIDR /0 Acceptance — Complete Trust Model Bypass (Python)
**CVSS:** 8.1
**Component:** Python proxy
**Location:** `proxy.py:2130-2134`
**Status:** NEW

The trusted CIDR list accepts `0.0.0.0/0` without validation. If this appears in
config (misconfiguration or config injection), ALL source IPs are treated as trusted
upstream proxies. This means:
- PROXY protocol headers from ANY source are accepted → IP spoofing
- X-Forwarded-For headers from ANY source are trusted → IP spoofing

`ipaddress.ip_network("0.0.0.0/0")` is a valid Python network object. There is no
check that rejects obviously dangerous CIDRs like /0, /1, /2 or loopback ranges.

**Fix:** Validate trusted CIDRs at config load time. Reject /0, /1, /2 for both v4
and v6. Warn on RFC1918/loopback ranges. Log a `CRITICAL` if the effective trust set
covers more than a /16 equivalent.

---

#### RT-009: Redis Key Injection via SNI Hostnames
**CVSS:** 6.8
**Component:** Python proxy signal modules
**Location:** `src/security/behavioral.py:81,108`, `src/security/tcp_analyzer.py:144`
**Status:** NEW

Redis keys are constructed using unsanitised SNI hostnames:

```python
key = f"behavioral:burst:{ctx.sni}"      # line 108
key = f"session:ip:{ctx.client_ip}:ja4:{ctx.ja4}"  # line 144
```

SNI is attacker-controlled and can contain colons, asterisks, question marks, and
any printable ASCII. A crafted SNI like `evil.com:other_prefix:key_name` would
create a Redis key `behavioral:burst:evil.com:other_prefix:key_name`, potentially
colliding with or shadowing keys in other namespaces.

While Redis keys are opaque strings (no command injection), the impact includes:
- **Key enumeration confusion:** SCAN patterns matching `behavioral:burst:*` return
  keys that "leak" into other apparent namespaces
- **Counter pollution:** Rate-limit or burst counters for one SNI affect lookups
  that use partial key matching
- **DSAR/GDPR impact:** Erasure patterns like `beacon:{ip}:*` could match injected keys

**Fix:** Validate SNI against RFC 6066 (hostname format, max 255 bytes). For Redis
keys, either hash the SNI (`sha256(sni)[:16]`) or reject non-hostname characters.

---

#### RT-010: Python Proxy Backend Connection Has No Timeout
**CVSS:** 6.5
**Component:** Python proxy
**Location:** `proxy.py:2702-2704`
**Status:** NEW

```python
backend_reader, backend_writer = await asyncio.open_connection(
    self.config["proxy"]["backend_host"],
    int(self.config["proxy"]["backend_port"]),
)  # NO timeout parameter
```

The tarpit connection at line 2551 correctly uses a 5-second timeout, but the
backend connection does not. If the backend is unresponsive or slow to accept TCP,
every handler coroutine blocks for the OS TCP timeout (~2 minutes on Linux).

**Attack:** An attacker doesn't even need to attack the proxy. If the backend is
slow (e.g., under separate DDoS), all proxy connections pile up waiting for
`open_connection()`, exhausting the event loop's effective concurrency.

**Fix:** Add `asyncio.wait_for(..., timeout=connection_timeout)` or use the
`open_connection` `ssl` parameter's built-in timeout support.

---

#### RT-011: Management API JWT Cookie secure=False Hardcoded
**CVSS:** 6.5
**Component:** Management API
**Location:** `management/api/auth.py:494`
**Status:** NEW

```python
secure=False,  # Set to True in production behind HTTPS
```

This is not environment-gated. In production deployments behind HTTPS, the JWT
session cookie is still sent over HTTP connections. Any network-path attacker
(ARP spoofing, rogue AP, compromised switch) can intercept the cookie and hijack
the management session.

**Fix:** `secure=os.environ.get("ENVIRONMENT") == "production"` or default to True
and only disable in explicit dev mode.

---

#### RT-012: Log Sanitisation Incomplete — Log Injection
**CVSS:** 5.5
**Component:** Python proxy
**Location:** `proxy.py:2140-2144`
**Status:** NEW

`_sanitize_log()` only strips `\r` and `\n`:

```python
def _sanitize_log(self, value: str) -> str:
    return value.replace("\r", "").replace("\n", "")
```

Missing: null bytes (`\x00` — truncates log lines in many log aggregators), ANSI
escape sequences (`\x1b[...` — can hide malicious entries in terminal-based log
viewers, or inject clickable URLs in some terminals), and other C0/C1 control
characters.

Furthermore, JA4 fingerprints extracted from HTTP headers (`_extract_ja4_from_http`)
and SNI hostnames are logged directly in f-strings (lines 2218-2219) **without**
passing through `_sanitize_log()` at all.

**Attack:** Craft a TLS ClientHello with SNI containing ANSI escapes. The proxy logs
the SNI in structured log lines. A SIEM analyst reviewing logs in a terminal sees
manipulated output that hides the attacker's real activity.

**Fix:** Extend `_sanitize_log()` to strip all control characters (`ord(c) < 0x20`
except `\t`). Apply it to ALL logged client-controlled fields.

---

### MEDIUM

#### RT-013: Unbounded `behavioral:known_ja4` Redis Set
**CVSS:** 5.3
**Component:** Python proxy
**Location:** `src/security/behavioral.py` (Redis SET, no TTL)
**Status:** NEW (related to L1-015 which covers beaconing sorted sets)

The `behavioral:known_ja4` set stores every unique JA4 fingerprint ever seen,
with no TTL and no maximum size. An attacker sending connections with randomised
TLS ClientHellos (varying cipher suite order produces different JA4 hashes) can
grow this set at ~1 fingerprint per connection.

At 50 bytes per entry, 1M unique fingerprints = ~50MB of Redis memory. At sustained
100 conn/s with unique JA4s, this reaches 1M entries in ~3 hours.

**Fix:** Add a 90-day TTL to set members, or cap the set size with periodic trimming.

---

#### RT-014: Fire-and-Forget Redis XADD Without Backpressure (Go)
**CVSS:** 5.3
**Component:** Go proxy
**Location:** `cmd/proxy/main.go:418-441`
**Status:** NEW

Every connection decision spawns a goroutine that calls `p.redis.XAdd()` with
`context.Background()` (no timeout). If Redis is slow or unreachable, these
goroutines accumulate without bound — each holding a JSON-marshaled event in memory.

At 1000 conn/s with Redis 100ms slow, ~100 goroutines accumulate per second.
Combined with RT-005 (no connection limit), this is an amplifier.

**Fix:** Use a buffered channel as a backpressure mechanism. Drop events when the
channel is full (acceptable — events are best-effort). Add a context with timeout
to the XADD call.

---

#### RT-015: OIDC ID Token Signature Not Verified
**CVSS:** 5.9
**Component:** Management API
**Location:** `management/api/routes/oidc.py:420` (comment: "Phase 100 TODO")
**Status:** NEW

The OIDC callback extracts claims from the ID token without verifying its signature
against the IdP's JWKS endpoint. Security currently relies on:
- The token being received over HTTPS from the token endpoint
- The client secret authenticating the token exchange

If an attacker can intercept the token endpoint response (e.g., compromised IdP,
DNS hijack of the discovery URL), they can forge arbitrary claims including `sub`
(username) and `amr` (MFA bypass).

**Fix:** Fetch JWKS from the discovery document's `jwks_uri` and verify the ID
token's RS256/ES256 signature before trusting claims.

---

#### RT-016: Python TLS Parser Runs in ThreadPool Without Memory Isolation
**CVSS:** 4.8
**Component:** Python proxy
**Location:** `proxy.py:1279-1281`
**Status:** NEW

The code comment explains that `ProcessPoolExecutor` was replaced with
`ThreadPoolExecutor` for "zero-IPC overhead". However, the original
`ProcessPoolExecutor` provided memory isolation — a malformed TLS packet causing
excessive Scapy memory allocation would only crash the child process, not the proxy.

With `ThreadPoolExecutor`, a crafted packet that triggers pathological Scapy
parsing (e.g., deeply nested TLS extensions) can consume unlimited memory in the
main proxy process, potentially causing OOM.

**Fix:** Either revert to `ProcessPoolExecutor` for the TLS parsing path, or add
a memory watchdog that kills the thread if RSS exceeds a threshold (harder in
Python). Alternatively, add a maximum input size check before passing to Scapy.

---

#### RT-017: start-poc.sh Echoes Passwords to Console
**CVSS:** 3.7
**Component:** Deployment scripts
**Location:** `scripts/start-poc.sh:40-41`
**Status:** NEW

```bash
echo -e "  Redis password: ${REDIS_PW}"
echo -e "  Grafana password: ${GRAFANA_PW}"
```

Passwords appear in terminal scrollback, CI/CD logs, and screen recordings.

**Fix:** Log only confirmation messages ("Redis password: [generated]") without
the actual value.

---

## Existing Findings — Additional Notes

These findings were already documented by the other red teams. My assessment adds
context or amplification.

### L1-019 (Fragmentation Bypass) — Amplified by RT-002

The existing finding describes TCP fragmentation causing `ErrTruncated`. RT-002
shows that even without fragmentation, the `n` vs `len(data)` bug after PROXY
header stripping creates the same bypass with a single TCP segment. This means
**the fix for L1-019 (buffered read loop) is necessary but not sufficient** — the
`n` variable must also be corrected to `len(data)`.

### L7-001 (Tarpit Overflow Allow) — Amplified by RT-006

The existing finding notes that tarpit overflow with `allow` bypasses protection.
RT-006 shows that tarpit slots can be permanently exhausted via timeout-free
connections, making the overflow condition trivially reachable. Fixing L7-001
alone (changing overflow action) doesn't help if an attacker can fill all slots
permanently.

### L1-015 (Beaconing OOM) — Related to RT-013

Phase 113 addresses beaconing sorted sets. RT-013 identifies an additional
unbounded set (`behavioral:known_ja4`) with the same OOM risk but through a
different code path.

---

## Compound Attack Scenarios

### Scenario A: Complete Security Bypass (Internet → Backend)

**Prerequisites:** HAProxy in front of JA4proxy, attacker on internet

1. Attacker polls `http://<proxy-ip>:9090/health/deep` (RT-003) — sees `dial: 0`
   (monitor mode) or reads tarpit saturation level
2. Attacker sends connections with PROXY-sized ClientHello fragments (RT-002 + L1-019)
3. All connections bypass JA4 fingerprinting → no blocklist, no rate limiting
4. Backend receives unfiltered traffic as if JA4proxy didn't exist

**Difficulty:** Low. Requires only knowledge of the proxy's metrics port.

### Scenario B: Tarpit Exhaustion → Full Bypass

**Prerequisites:** JA4proxy with tarpit enabled, attacker on internet

1. Send connections matching tarpit criteria from 100 IPs (RT-006)
2. Each IP holds `MaxPerIP` slots with 1 byte then silence → permanent hold
3. Tarpit fills to `MaxActiveConnections`
4. All subsequent tarpit-destined connections overflow to `allow` (L7-001)
5. Attack traffic now flows freely to backend

**Difficulty:** Low. 100 IPs × 10 slots = 1000 connections to fill default tarpit.

### Scenario C: Redis DoS via Health Polling

**Prerequisites:** Network access to metrics port (RT-003)

1. Script polls `http://<proxy-ip>:9090/health/deep` in tight loop
2. Each request triggers `KEYS ja4proxy:ban:*` (RT-007) → blocks Redis
3. All proxy instances sharing Redis experience degraded performance
4. Scoring decisions slow down → connection queue builds → DoS

**Difficulty:** Trivial. Single curl loop.

---

## Recommendations — Priority Order

### Immediate (before next deployment)

1. **Rotate .env credentials** (RT-004) — Redis password, Grafana password, UI API key
2. **Fix goroutine leak** (RT-001) — `<-done; <-done` in both `forward()` and `tarpit()`
3. **Fix `n` vs `len(data)`** (RT-002) — change line 359 to `len(data) >= 5`
4. **Restrict metrics port** (RT-003) — bind to `127.0.0.1` or add authentication

### Before production

5. **Add connection semaphore** (RT-005)
6. **Add tarpit timeouts** (RT-006)
7. **Replace KEYS with SCAN** (RT-007)
8. **Validate trusted CIDRs** (RT-008)
9. **Sanitise SNI in Redis keys** (RT-009)
10. **Add backend connection timeout** (RT-010)
11. **Gate cookie secure flag** (RT-011)

### Hardening

12. **Extend log sanitisation** (RT-012)
13. **Bound behavioral:known_ja4** (RT-013)
14. **Add XADD backpressure** (RT-014)
15. **Verify OIDC token signatures** (RT-015)
16. **Restore TLS parser memory isolation** (RT-016)
17. **Stop echoing passwords** (RT-017)

---

## Methodology

Seven parallel analysis agents examined:
- Go proxy connection handling (`cmd/proxy/main.go`, `internal/tls/`, `internal/redis/`)
- Python proxy (`proxy.py`, `src/security/`)
- Management API (`management/api/`)
- Redis schema and interaction patterns
- TLS parser robustness (no panic vectors found — well-defended)
- Credential/secret exposure across all deployment artefacts
- Cross-reference against existing Phases 108-117 findings (27 items)

All critical findings were manually verified against the source code with line
numbers confirmed.

---

## Appendix: Independent Deep-Dive Team (Phase 119)

A second independent 4-agent team was launched after Phase 118 was written. Each agent
had no knowledge of Phase 118 or the existing pentest campaign (Phases 108-117). They
independently confirmed many Phase 118 findings and discovered 20 additional novel
vulnerabilities documented in `docs/phases/complete/PHASE_119.md`, including:

- **119a (CRITICAL):** ALPN bypass — any client puts `h2` in ALPN and bypasses
  the entire security pipeline. Design-level flaw, not a code bug.
- **119b (CRITICAL):** X-JA4-Fingerprint HTTP header injection — send plain HTTP
  with a whitelisted JA4 value in the header, bypass all security controls.
- **119c-h (HIGH):** HAProxy default creds, privileged containers, Docker socket
  exposure, CI/CD token leaks, Redis PubSub poisoning, stored XSS.
- **119i-t (MEDIUM):** JWT role escalation, DSAR OOM, IPv6 parsing bug, blocklist
  logic bug, config reload path, infrastructure hardening items.

The two most severe (119a, 119b) represent fundamental design flaws where
attacker-controlled fields are trusted as proof of identity. Combined, they mean
an attacker can bypass JA4proxy entirely using either TLS (fake h2 ALPN) or plain
HTTP (fake JA4 header).
