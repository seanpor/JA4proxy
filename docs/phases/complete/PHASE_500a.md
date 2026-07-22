---
phase: 500a
title: "Bug Hunt Guide — Go Production Proxy"
parent: 500
created: 2026-06-22
audience: [developer, security]
---

# Bug Hunt Guide — Go Production Proxy

This guide covers sub-phases **500a–500f**: protocol parsing, concurrency, access
control, cryptography, resource exhaustion, and information exposure in the Go proxy.

## Before you start

```bash
# Make sure the codebase builds and tests pass
go build ./...
go test ./...
go vet ./...
```

---

## 500a — Protocol Parsing & Input Validation

**CWE-20: Improper Input Validation**

### What to look for

Bugs where the code reads bytes from the network and trusts them without checking
bounds, length, or format. Think: buffer over-read, integer overflow in length fields,
truncated input causing unexpected behaviour.

### Files to read

| File | What to check |
|------|--------------|
| `internal/tls/parser.go` | Every `pos += N` must be followed by a bounds check before reading at `pos`. Look for cases where `pos` could exceed `len(data)`. |
| `internal/proxy/proxy_protocol.go` | v1 parser: does it reject lines without `\r\n`? v2 parser: is `addrLen` capped? Does it handle unknown command bytes? |
| `cmd/ja4pd/main.go` (reassembly section) | The 16KB record cap and 65KB connection cap — are they enforced before allocation? |
| `internal/tap/tlsparse.go` | TLS record walking — what happens with 0-length records? Overlapping records? |

### Grep commands

```bash
# Find all byte-slicing in the TLS parser — each one needs a bounds check nearby
rg 'data\[' internal/tls/parser.go -n

# Find all pos += patterns — verify each is followed by a bounds check
rg 'pos \+=' internal/tls/parser.go -n

# Find all length reads from network data — verify they are validated
rg 'binary\.(Big|Little)Endian\.(Uint16|Uint24|Uint32)' internal/tls/ internal/proxy/ -n

# Find all make([]byte, ...) calls from network-derived lengths — check for integer overflow
rg 'make\(\[\]byte' internal/tls/ internal/proxy/ cmd/ja4pd/ -n
```

### Checklist

- [ ] Every `pos +=` in `parser.go` is followed by `if pos > len(data) { return error }`
- [ ] `recordLen` is checked against 16384 before allocation
- [ ] `helloLen` is checked against remaining bytes before iteration
- [ ] PROXY v2 `addrLen` is capped at 256
- [ ] PROXY v1 rejects lines without `\r\n` terminator
- [ ] No `data[idx]` access without prior bounds check on `idx`
- [ ] Session ID skip (`pos += sidLen`) checks `sidLen` fits in remaining bytes
- [ ] Extension loop checks `extLen` fits before consuming

### Example bug (from prior findings)

```
JA4PROXY-2026-0003: TLS ClientHello Fragmentation Bypass — crafted fragmented
ClientHello records bypassed JA4 fingerprinting, removing all JA4-based
security controls. Fix: enforce 16KB record cap and 65KB connection cap.
```

### Regression test template

```go
func TestParseClientHello_TruncatedSessionID(t *testing.T) {
    // Build a ClientHello with session_id_length = 255 but only 10 bytes of body
    // Expected: error, not panic or OOB read
    data := buildMalformedClientHello(sessionIDLen: 255, actualBodyLen: 10)
    _, err := ParseClientHello(data)
    if err == nil {
        t.Fatal("expected error for truncated session ID")
    }
}
```

### Finding template

```yaml
- id: JA4PROXY-2026-NNNN   # use next sequential 4-digit ID from findings.yaml
  severity: HIGH
  cwe: CWE-20
  file: internal/tls/parser.go:123
  title: "One-line description of the bug"
  description: >
    Detailed description of the bug and why it matters.
  impact: >
    What an attacker could achieve by exploiting this.
  regression_test: internal/tls/parser_test.go:TestXxx
  remediation: >
    What the fix does (one line).
  status: OPEN
  phase: 500a
  similar_to: null  # or: JA4PROXY-2026-NNNN if this is a propagation sweep find
```

---

## 500b — Concurrency & Race Conditions

**CWE-362: Race Condition / CWE-667: Improper Locking**

### What to look for

Two goroutines accessing the same variable without synchronization. Common patterns:
`map` read/write without mutex, `go func()` capturing a loop variable, channel send
without checking if receiver is ready, lock not deferred.

### Files to read

| File | What to check |
|------|--------------|
| `internal/security/pipeline.go` | `asyncScoringWorkers` pool: are workers properly shut down? Is `workChan` closed? |
| `internal/redis/client.go` | `HealthCheck()` double-checked locking: is the `sync.RWMutex` used correctly? |
| `internal/redis/pubsub.go` | Reconnect loop: does it respect context cancellation? Any goroutine leak? |
| `internal/security/cache.go` | Full-map eviction: is `mu` held during the clear? |
| `cmd/ja4pd/main.go` | `acceptSem` channel: is it properly drained on shutdown? |
| `internal/security/beaconing_detector.go` | `suspects` map: protected by mutex? |

### Grep commands

```bash
# Find all goroutine spawns — verify each one's lifecycle is bounded
rg 'go func' internal/ cmd/ -n

# Find all map declarations — verify they have a mutex or are sync.Map
rg 'map\[.*\]' internal/ -n --type go | grep -v '_test.go'

# Find all sync.Mutex / sync.RWMutex — verify they are always unlocked (defer or explicit)
rg 'sync\.(RW)?Mutex' internal/ -n --type go

# Find all channels — verify no unbounded send without select/default
rg 'make\(chan' internal/ cmd/ -n --type go
```

### Checklist

- [ ] `go test -race ./...` passes with zero races
- [ ] Every `go func()` has a context or channel to stop it
- [ ] Every `map[x]y` accessed from goroutines has a mutex
- [ ] Every `mutex.Lock()` has a matching `defer mutex.Unlock()` (or explicit unlock on every return)
- [ ] No channel send blocks forever (check for `select` with `default` or `ctx.Done()`)
- [ ] `acceptSem` is drained during shutdown (no goroutine stuck waiting for semaphore)
- [ ] PubSub reconnect loop exits when context is cancelled

### Regression test template

```go
func TestCache_ConcurrentAccess(t *testing.T) {
    c := NewDecisionCache(100)
    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            c.Get(fmt.Sprintf("ja4-%d", i))
            c.Set(fmt.Sprintf("ja4-%d", i), Decision{Score: i})
        }(i)
    }
    wg.Wait()
    // Run with -race flag
}
```

---

## 500c — Authentication & Access Control

**CWE-284: Improper Access Control / CWE-287: Improper Authentication**

### What to look for

Code paths where an untrusted input can bypass an authentication or authorization
check. Think: can someone send a request that skips the bearer token check? Can a
Redis message bypass HMAC verification? Can the dial value be tampered with?

### Files to read

| File | What to check |
|------|--------------|
| `cmd/ja4pd/main.go` (metrics server) | `/metrics`, `/health`, `/health/deep` — which require auth? Can loopback exemption be exploited? |
| `internal/redis/client.go` (`GetDial`) | Is the HMAC verified? What happens if `integrityKeyFile` is empty? |
| `internal/redis/pubsub.go` | What happens when `hmacSecret` is empty? Which channels are signed? Which are not? |
| `internal/backup/backup.go` | Is the distributed lock (`SetNX`) correctly implemented? Can it be bypassed? |
| `internal/proxy/proxy_protocol.go` | `IsTrustedProxySource()` — can an attacker spoof a trusted source IP? |
| `internal/config/loader.go` | `ValidateRedisAuth()` — what happens with empty password on localhost? |

### Grep commands

```bash
# Find all bearer token checks — verify constant-time comparison
rg 'bearer|Bearer|Authorization' internal/ -n --type go

# Find all HMAC operations — verify they use hmac.Equal (not ==)
rg 'hmac\.' internal/ -n --type go

# Find all Redis PUBLISH calls — which are signed? Which are not?
rg '\.Publish\(' internal/ -n --type go

# Find all TrustProxy / trusted source checks — verify fail-closed
rg 'TrustedProxy|IsTrustedProxy' internal/ -n --type go
```

### Checklist

- [ ] Metrics endpoints require bearer token when bind is not loopback
- [ ] Bearer token comparison uses `subtle.ConstantTimeCompare`
- [ ] PubSub HMAC is verified on all critical channels (config:reload, blacklist, dial)
- [ ] When `hmacSecret` is empty, critical commands are rejected (or logged as WARNING)
- [ ] `GetDial()` fails to monitor mode (dial=0) when integrity key is missing
- [ ] Backup lock cannot be bypassed (Set NX EX)
- [ ] PROXY protocol from untrusted sources is stripped (not forwarded)
- [ ] Redis ACL validation refuses unauthenticated remote connections

---

## 500d — Cryptographic Practices

**CWE-327: Broken Crypto / CWE-326: Inadequate Encryption Strength**

### What to look for

Weak or incorrect use of cryptographic primitives. Think: keys derived from weak
passwords, hardcoded secrets, non-constant-time comparison, incorrect AES-GCM usage.

### Files to read

| File | What to check |
|------|--------------|
| `internal/backup/crypto.go` | PBKDF2 iterations (100K is OK), salt/nonce from `crypto/rand`, GCM tag verification |
| `internal/redis/client.go` (HMAC section) | Key loaded from file — what permissions? Is `hmac.Equal` used? |
| `internal/config/loader.go` (integrity key) | Key file permissions, format validation, missing-key default |
| `internal/tls/` | No crypto operations beyond SHA-256 for fingerprinting (OK) |

### Grep commands

```bash
# Find all crypto operations — verify correct usage
rg 'crypto/' internal/ -n --type go

# Find all hardcoded strings that could be secrets
rg '"[A-Za-z0-9+/=]{20,}"' internal/ -n --type go

# Find all comparisons of secrets — must use constant-time compare
rg '==.*secret|==.*key|==.*token|==.*password' internal/ -n --type go
```

### Checklist

- [ ] PBKDF2 uses ≥100,000 iterations
- [ ] Salt and nonce are from `crypto/rand` (not `math/rand`)
- [ ] AES-GCM tag is verified before decrypting (fail-closed)
- [ ] Empty passphrase is rejected
- [ ] HMAC comparison uses `hmac.Equal` or `subtle.ConstantTimeCompare`
- [ ] No hardcoded keys, passwords, or tokens in source code
- [ ] Key files have restrictive permissions (0600 or 0400)

---

## 500e — Resource Exhaustion & DoS

**CWE-400: Uncontrolled Resource Consumption / CWE-770: Allocation Without Limits**

### What to look for

Code that allocates memory, spawns goroutines, or accumulates state based on
untrusted input without any bound. Think: can an attacker connect 10,000 times and
exhaust memory? Can they send a unique JA4 per connection and blow up the cache?

### Files to read

| File | What to check |
|------|--------------|
| `internal/security/pipeline.go:548` | `go p.auditDecision(...)` — spawned per scored connection. Is it bounded? |
| `cmd/ja4pd/main.go` | Accept loop: `acceptSem` capacity = `MaxConnections`. Is it enforced? |
| `internal/metrics/` | `CardinalityGuard` — 1000 unique values. Is the cap enforced? |
| `internal/security/cache.go` | Full-map eviction when limit hit — does it cause a latency spike? |
| `internal/tap/` | `maxBufferedPagesTotal = 4096` — is it enforced? |
| `internal/security/feed_downloader.go` | 64 MiB max download — is it enforced before allocation? |

### Grep commands

```bash
# Find all goroutine spawns without obvious bounds
rg 'go func' internal/ cmd/ -n --type go | grep -v '_test.go'

# Find all unbounded make() calls
rg 'make\(\[\]|make\(map' internal/ cmd/ -n --type go | grep -v '_test.go'

# Find all sync.Pool usage — verify Put on all error paths
rg 'sync\.Pool' internal/ cmd/ -n --type go

# Find all channel makes — verify capacity is set
rg 'make\(chan' internal/ cmd/ -n --type go
```

### Checklist

- [ ] `go p.auditDecision()` goroutine has a bounded worker pool or context timeout
- [ ] `acceptSem` is sized to `MaxConnections` and cannot grow beyond it
- [ ] `CardinalityGuard` evicts oldest entry when cap reached (not OOM)
- [ ] Decision cache has a maximum size and does eviction (not unbounded growth)
- [ ] TAP sensor respects `maxBufferedPagesTotal` and `maxBufferedPagesPerConn`
- [ ] Feed downloader enforces 64 MiB limit before reading entire body
- [ ] `forward()` returns pooled buffers on ALL error paths (no buffer leak)

---

## 500f — Information Exposure & Logging

**CWE-200: Information Exposure / CWE-532: Insertion of Sensitive Information into Log File**

### What to look for

Code that logs or returns sensitive data: API keys, passwords, Redis connection
strings, full stack traces, internal state that should be hidden.

### Files to read

| File | What to check |
|------|--------------|
| `cmd/ja4pd/main.go` | All `log.Printf` calls — do any print passwords, tokens, or keys? |
| `internal/redis/` | Error messages — do they include the Redis URL (which contains the password)? |
| `internal/security/` | Log levels — are debug-level messages safe in production? |
| `cmd/ja4pd/main.go` (health) | `/health/deep` — does it expose internal Redis state, config values, or connected clients? |
| `internal/config/loader.go` | Env var expansion logging — does it log the expanded values (which may contain secrets)? |

### Grep commands

```bash
# Find all log calls — check for credential leakage
rg 'log\.(Printf|Println|Print|Fatal)' internal/ cmd/ -n --type go

# Find all fmt.Print* in non-test code — should use structured logging
rg 'fmt\.Print' internal/ cmd/ -n --type go | grep -v '_test.go'

# Find all error strings that might contain sensitive data
rg 'fmt\.Errorf.*password|fmt\.Errorf.*secret|fmt\.Errorf.*key' internal/ -n --type go

# Find all Redis URL handling — verify password is redacted in logs
rg 'redis.*url|REDIS_URL|redisUrl' internal/ -n --type go
```

### Checklist

- [ ] No `log.Printf` output contains passwords, API keys, or HMAC secrets
- [ ] Redis error messages do not include the connection URL (which has the password)
- [ ] `/health/deep` only returns documented fields (redis, tarpit, geoip status)
- [ ] No `fmt.Print` in production code (only in CLI output)
- [ ] Env var expansion does not log expanded secret values
- [ ] Webhook payloads have secrets redacted before logging
- [ ] Production log level does not emit per-connection debug details

---

## How to write a regression test

Every finding needs a regression test. The test should:

1. **Set up** the condition that triggers the bug
2. **Call** the function with adversarial input
3. **Assert** the correct behaviour (error, panic-free, bounded resource use)
4. **Run** with `go test -race` to catch races

### Template

```go
func TestFunctionName_AdversarialInput(t *testing.T) {
    // Arrange: build the malformed/adversarial input
    input := buildAdversarialInput(...)

    // Act: call the function under test
    result, err := FunctionName(input)

    // Assert: verify correct behaviour
    if err == nil {
        t.Fatal("expected error for adversarial input")
    }
    // OR: verify no crash/panic (use t.Run with subtests for each case)
}
```

### Where to put tests

| Finding location | Test location |
|-----------------|---------------|
| `internal/tls/parser.go` | `internal/tls/parser_test.go` |
| `internal/proxy/proxy_protocol.go` | `internal/proxy/proxy_protocol_test.go` |
| `internal/redis/client.go` | `internal/redis/client_test.go` |
| `internal/security/pipeline.go` | `internal/security/pipeline_test.go` |
| `cmd/ja4pd/main.go` | `cmd/ja4pd/pentest_*.go` (existing pattern) |
| `internal/backup/` | `internal/backup/*_test.go` |

---

## How to register a finding in findings.yaml

Add an entry like this to `docs/security/findings.yaml`:

```yaml
- id: JA4PROXY-2026-NNNN   # use next sequential 4-digit ID from findings.yaml
  severity: HIGH
  cwe: CWE-20
  file: internal/tls/parser.go:123
  title: "One-line summary of the bug"
  description: >
    Detailed description of the bug and why it matters.
  impact: >
    What an attacker could achieve by exploiting this.
  regression_test: internal/tls/parser_test.go:TestParseClientHello_TruncatedSessionID
  remediation: >
    What the fix does (one line).
  status: OPEN
  phase: 500a
  similar_to: null  # or: JA4PROXY-2026-XXXX if this is a propagation sweep find
```
