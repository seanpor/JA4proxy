# Phase 15 Go Rewrite — Execution Subplan

## How to use this document

This subplan is written to be followed by a less-experienced model or developer with
no context beyond what is written here. Every task names the exact file to create or
edit, the exact function signature, the exact test names, and the exact values.

**Before doing anything:** run all tests to confirm baseline is green.
```bash
GOROOT=/snap/go/current go test ./...   # must show: ok for all packages
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -q
```

**GOROOT note:** The snap Go installation sets GOROOT to `/usr/share/go` which does
not exist. Every `go` command in this document must be prefixed with
`GOROOT=/snap/go/current`. Permanently fix it once with:
```bash
echo 'export GOROOT=/snap/go/current' >> ~/.bashrc && source ~/.bashrc
```

---

## Plan Overview

| # | Task group | Status |
|---|-----------|--------|
| 0 | Foundation | ✅ Done |
| 1 | TLS infrastructure | ✅ Done (JA4T missing) |
| 2 | Signal modules (TLS enforcer + SNI) | ⬜ Not started |
| 3 | Signal modules (TCP + mTLS + Rate limiting) | ⬜ Not started |
| 4 | Signal modules (ASN + DNS + Blocklists) | ⬜ Not started |
| 5 | Signal modules (Beaconing + AbuseIPDB + RDAP + Analytics) | ⬜ Not started |
| 6 | Pipeline wiring + missing bypass checks | ⬜ Not started |
| 7 | Infrastructure (Prometheus + health + PROXY protocol + pubsub reconnect) | ⬜ Not started |
| 8 | Binary TLS fixtures + JA4 parity tests | ⬜ Not started |
| 9 | Cross-language parity tests | ⬜ Not started |
| 10 | Chaos + adversarial + performance tests | ⬜ Not started |
| 11 | Documentation + switching mechanism | ⬜ Not started |

Complete each group fully before starting the next.
After each group: `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 0: Foundation ✅ DONE

Nothing to do. All files exist and compile.

---

## Group 1: TLS Infrastructure ✅ DONE (one gap)

Everything is done except `internal/tls/ja4t.go`.

### 1a. Create `internal/tls/ja4t.go`

**File to create:** `internal/tls/ja4t.go`

JA4T is a TLS alert fingerprint. For Phase 15 it is a stub — the Go proxy does not
yet capture TLS alerts from the wire (that requires hooking into the TLS state machine
at a lower level). Implement it as a zero-value stub that always returns empty string.

```go
package tls

// ComputeJA4T returns the JA4T fingerprint from a list of TLS alert codes.
// JA4T format: comma-separated decimal alert codes, sorted ascending.
// Returns "" if alertCodes is empty.
func ComputeJA4T(alertCodes []uint8) string {
    return ""
}
```

**File to create:** `internal/tls/ja4t_test.go`

```go
package tls

import "testing"

func TestJA4T_Empty(t *testing.T) {
    if got := ComputeJA4T(nil); got != "" {
        t.Errorf("ComputeJA4T(nil) = %q; want empty string", got)
    }
}

func TestJA4T_NoAlerts(t *testing.T) {
    if got := ComputeJA4T([]uint8{}); got != "" {
        t.Errorf("ComputeJA4T([]) = %q; want empty string", got)
    }
}
```

---

## Group 2: Signal Modules — TLS Enforcer + SNI Analyzer

### Overview

Each signal module in this group follows the same pattern:

1. Create `internal/security/{module}.go`
2. Create `internal/security/{module}_test.go`
3. Add the module to `internal/security/pipeline.go` signal collection block

The signal collection block in `pipeline.go` currently reads:
```go
var signals []RiskSignal // populated by signal modules below (future phases)
```
Each group will add calls here.

### 2a. Create `internal/security/tls_enforcer.go`

**File to create:** `internal/security/tls_enforcer.go`

This is a direct port of `src/security/tls_enforcer.py`.

**What it does:**
- Checks TLS version against policy
- Checks cipher list against weak cipher list
- Returns `([]RiskSignal, bool)` where bool=true means hard block (immediately block, skip scoring)

**Exact signals it produces:**

| Signal name | Score | When |
|-------------|-------|------|
| `"tls_version"` | 40 | TLS 1.0 (0x0301) or 1.1 (0x0302) AND `TLSVersionBypass.Enabled == false` |
| `"tls_12"` | 10 | TLS 1.2 (0x0303) AND `FlagTLS12 == true` |
| `"weak_cipher"` | 20 | Any cipher in `WeakCiphers` set AND `BlockWeakCiphers == false` |

**Hard blocks (return nil signals, hardBlock=true):**
- SSLv3 (version 0x0300): always hard block, no config toggle
- TLS 1.0/1.1: hard block when `TLSVersionBypass.Enabled == true` AND (`BlockTLS10` or `BlockTLS11`)
- Weak cipher present: hard block when `BlockWeakCiphers == true`

**Config struct fields needed (add to `PipelineConfig`):**
```go
// TLS enforcement (Phase 3)
TLSVersionBypassEnabled bool
BlockTLS10              bool
BlockTLS11              bool
FlagTLS12               bool
BlockWeakCiphers        bool
WeakCiphers             map[uint16]bool
```

**Weak cipher set (these exact values — same as Python `WEAK_CIPHERS`):**
```go
var weakCipherSet = map[uint16]bool{
    0x0001: true, // TLS_RSA_WITH_NULL_MD5
    0x0002: true, // TLS_RSA_WITH_NULL_SHA
    0x0004: true, // TLS_RSA_WITH_RC4_128_MD5
    0x0005: true, // TLS_RSA_WITH_RC4_128_SHA
    0x000A: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002F: true, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x003C: true, // TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003D: true, // TLS_RSA_WITH_AES_256_CBC_SHA256
    0x0018: true, // TLS_DHE_RSA_WITH_RC4_128_SHA (EXPORT)
    0x0033: true, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0039: true, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
}
```

**Function signature:**
```go
// TLSEnforcer checks TLS version and cipher list against policy.
type TLSEnforcer struct {
    cfg *TLSEnforcerConfig
    log *logrus.Logger
}

type TLSEnforcerConfig struct {
    TLSVersionBypassEnabled bool
    BlockTLS10              bool
    BlockTLS11              bool
    FlagTLS12               bool
    BlockWeakCiphers        bool
}

func NewTLSEnforcer(cfg *TLSEnforcerConfig, log *logrus.Logger) *TLSEnforcer

// Check returns signals and whether to hard-block.
// hardBlock=true means block immediately without scoring.
// On hardBlock=true, signals will be nil.
// Fail open: any unexpected state returns (nil, false).
func (e *TLSEnforcer) Check(tlsVersion uint16, ciphers []uint16) (signals []RiskSignal, hardBlock bool)
```

**File to create:** `internal/security/tls_enforcer_test.go`

Minimum 8 tests:
```
TestTLSEnforcer_SSLv3_AlwaysHardBlock
TestTLSEnforcer_TLS10_HardBlock_WhenBypassEnabled
TestTLSEnforcer_TLS10_Signal_WhenBypassDisabled
TestTLSEnforcer_TLS11_HardBlock_WhenBypassEnabled
TestTLSEnforcer_TLS12_FlaggedWhenEnabled
TestTLSEnforcer_TLS13_NoSignal
TestTLSEnforcer_WeakCipher_Signal_WhenNotBlocking
TestTLSEnforcer_WeakCipher_HardBlock_WhenBlockEnabled
TestTLSEnforcer_NoWeakCiphers_NoSignal
```

Each test: create a `TLSEnforcer` with specific config, call `Check()`, assert exact
`len(signals)`, exact `signals[0].Name`, exact `signals[0].Score`, exact `hardBlock` value.

---

### 2b. Create `internal/security/sni_analyzer.go`

**File to create:** `internal/security/sni_analyzer.go`

Port of `src/security/sni_analyzer.py`.

**What it does:** Analyzes the SNI hostname from ClientHello for risk indicators.

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"missing_sni"` | 30 | `sni == ""` AND `MissingSNIEnabled == true` |
| `"ip_literal_sni"` | 25 | SNI is a valid IP address (use `net.ParseIP(sni) != nil`) AND `IPLiteralSNIEnabled == true` |
| `"dga"` | 0–40 (formula below) | DGA score > 0 AND `DGAEnabled == true` |
| `"unexpected_sni"` | 15 | SNI not in `ExpectedHostnames` set AND len(ExpectedHostnames) > 0 AND `UnexpectedSNIEnabled == true` |

**DGA score formula:**
```
confidence = dgaConfidence(sni)      // returns float64 0.0–1.0
score = int(confidence * DGAScoreCap) // DGAScoreCap default 40
```
Only emit signal if `score > 0`.

**DGA confidence algorithm** (port exactly from Python):
```
Start with confidence = 0.0
1. Compute Shannon entropy of domain label (just the leftmost label, before first dot).
   entropy = -sum(freq * log2(freq) for each character frequency)
   If entropy > 3.5: confidence += 0.35
   If entropy > 4.0: confidence += 0.15  (cumulative, so high entropy → +0.50)
2. Count vowel ratio in label: vowels = {a,e,i,o,u}
   vowel_ratio = count_vowels / len(label)
   If vowel_ratio < 0.10: confidence += 0.30
3. Check label length:
   If len(label) > 15: confidence += 0.15
4. Count consecutive consonant runs (no vowel for 4+ chars):
   If any run of 4+ consecutive non-vowel chars: confidence += 0.20
5. Count digit ratio: digits / len(label)
   If digit_ratio > 0.30: confidence += 0.20
Cap confidence at 1.0.
```

**Config struct fields needed (add to `PipelineConfig`):**
```go
// SNI analysis (Phase 4)
MissingSNIEnabled   bool
MissingSNIScore     int  // default 30
IPLiteralSNIEnabled bool
IPLiteralSNIScore   int  // default 25
DGAEnabled          bool
DGAScoreCap         int  // default 40
UnexpectedSNIEnabled bool
UnexpectedSNIScore  int  // default 15
ExpectedHostnames   map[string]bool
```

**Function signature:**
```go
type SNIAnalyzer struct {
    cfg *SNIAnalyzerConfig
    log *logrus.Logger
}

type SNIAnalyzerConfig struct {
    MissingSNIEnabled   bool
    MissingSNIScore     int
    IPLiteralSNIEnabled bool
    IPLiteralSNIScore   int
    DGAEnabled          bool
    DGAScoreCap         int
    UnexpectedSNIEnabled bool
    UnexpectedSNIScore  int
    ExpectedHostnames   map[string]bool
}

func NewSNIAnalyzer(cfg *SNIAnalyzerConfig, log *logrus.Logger) *SNIAnalyzer

// Analyze returns risk signals for the given SNI value.
// sni is the empty string when no SNI extension was present.
// Never returns an error; fails open (returns empty slice on any panic).
func (a *SNIAnalyzer) Analyze(sni string) []RiskSignal
```

**File to create:** `internal/security/sni_analyzer_test.go`

Minimum 10 tests:
```
TestSNIAnalyzer_MissingSNI_SignalFired
TestSNIAnalyzer_MissingSNI_DisabledNoSignal
TestSNIAnalyzer_IPLiteral_IPv4_SignalFired
TestSNIAnalyzer_IPLiteral_IPv6_SignalFired
TestSNIAnalyzer_NormalHostname_NoIPSignal
TestSNIAnalyzer_DGA_HighEntropy_Scored
TestSNIAnalyzer_DGA_NormalDomain_NotScored  // e.g. "google.com"
TestSNIAnalyzer_UnexpectedSNI_NotInList
TestSNIAnalyzer_UnexpectedSNI_InList_NoSignal
TestSNIAnalyzer_ExpectedHostnames_EmptyList_NoUnexpectedSignal
```

Known DGA test cases to use (verified against Python):
- `"xn--d1abbgf6aiiy.xn--p1ai"` → low DGA score (IDN, but has vowels)
- `"google.com"` → confidence 0.0 (short, vowels present, low entropy)
- `"a8f3bc2d19e74f6a.io"` → high DGA score (digits, no vowels, high entropy)

### 2c. Wire Group 2 into `internal/security/pipeline.go`

**File to edit:** `internal/security/pipeline.go`

**Step 1:** Add `TLSEnforcer` and `SNIAnalyzer` fields to `Pipeline` struct:
```go
type Pipeline struct {
    cfg         *PipelineConfig
    scorer      *RiskScorer
    decider     *ActionDecider
    redis       RedisReader
    log         *logrus.Logger
    tlsEnforcer *TLSEnforcer   // add
    sniAnalyzer *SNIAnalyzer   // add
}
```

**Step 2:** Initialize them in `NewPipeline()` — add after existing initialization:
```go
p.tlsEnforcer = NewTLSEnforcer(buildTLSEnforcerConfig(cfg), log)
p.sniAnalyzer = NewSNIAnalyzer(buildSNIAnalyzerConfig(cfg), log)
```

**Step 3:** Add two builder functions at the bottom of `pipeline.go`:
```go
func buildTLSEnforcerConfig(cfg *PipelineConfig) *TLSEnforcerConfig {
    return &TLSEnforcerConfig{
        TLSVersionBypassEnabled: cfg.TLSVersionBypassEnabled,
        BlockTLS10:              cfg.BlockTLS10,
        BlockTLS11:              cfg.BlockTLS11,
        FlagTLS12:               cfg.FlagTLS12,
        BlockWeakCiphers:        cfg.BlockWeakCiphers,
    }
}

func buildSNIAnalyzerConfig(cfg *PipelineConfig) *SNIAnalyzerConfig {
    return &SNIAnalyzerConfig{
        MissingSNIEnabled:    cfg.MissingSNIEnabled,
        MissingSNIScore:      defaultInt(cfg.MissingSNIScore, 30),
        IPLiteralSNIEnabled:  cfg.IPLiteralSNIEnabled,
        IPLiteralSNIScore:    defaultInt(cfg.IPLiteralSNIScore, 25),
        DGAEnabled:           cfg.DGAEnabled,
        DGAScoreCap:          defaultInt(cfg.DGAScoreCap, 40),
        UnexpectedSNIEnabled: cfg.UnexpectedSNIEnabled,
        UnexpectedSNIScore:   defaultInt(cfg.UnexpectedSNIScore, 15),
        ExpectedHostnames:    cfg.ExpectedHostnames,
    }
}

func defaultInt(v, def int) int {
    if v == 0 {
        return def
    }
    return v
}
```

**Step 4:** Replace the signal collection stub in `Process()`:
```go
// OLD (remove this):
var signals []RiskSignal // populated by signal modules below (future phases)

// NEW (replace with):
var signals []RiskSignal

// TLS enforcement (hard block check first)
if tlsSigs, hardBlock := p.tlsEnforcer.Check(uint16(conn.TLSVersion), uint16s(conn.CipherList)); hardBlock {
    return &PipelineResult{Action: "block", Score: 100, BypassReason: "tls_enforcement"}
} else {
    signals = append(signals, tlsSigs...)
}

// SNI analysis
signals = append(signals, p.sniAnalyzer.Analyze(conn.SNI)...)
```

**Step 5:** Add helper at bottom of `pipeline.go`:
```go
// uint16s converts []int to []uint16. CipherList in ConnectionContext is []int.
func uint16s(in []int) []uint16 {
    out := make([]uint16, len(in))
    for i, v := range in {
        out[i] = uint16(v)
    }
    return out
}
```

**Step 6:** Add new fields to `PipelineConfig` (in `pipeline.go`) for TLS enforcer and SNI analyzer. Add them after the existing `Thresholds` field:
```go
// TLS enforcement (Group 2)
TLSVersionBypassEnabled bool
BlockTLS10              bool
BlockTLS11              bool
FlagTLS12               bool
BlockWeakCiphers        bool

// SNI analysis (Group 2)
MissingSNIEnabled    bool
MissingSNIScore      int
IPLiteralSNIEnabled  bool
IPLiteralSNIScore    int
DGAEnabled           bool
DGAScoreCap          int
UnexpectedSNIEnabled bool
UnexpectedSNIScore   int
ExpectedHostnames    map[string]bool
```

**Step 7:** Update `buildPipelineConfig()` in `cmd/proxy/main.go` to populate the new fields from `cfg`:
```go
TLSVersionBypassEnabled: cfg.SecurityPolicy.TLSVersionBypass.Enabled,
BlockTLS10:              cfg.TLSEnforcer.BlockTLS10,
BlockTLS11:              cfg.TLSEnforcer.BlockTLS11,
FlagTLS12:               cfg.TLSEnforcer.FlagTLS12,
BlockWeakCiphers:        cfg.TLSEnforcer.BlockWeakCiphers,
MissingSNIEnabled:       cfg.SNIAnalyzer.MissingSNI.Enabled,
MissingSNIScore:         cfg.SNIAnalyzer.MissingSNI.Score,
IPLiteralSNIEnabled:     cfg.SNIAnalyzer.IPLiteralSNI.Enabled,
IPLiteralSNIScore:       cfg.SNIAnalyzer.IPLiteralSNI.Score,
DGAEnabled:              cfg.SNIAnalyzer.DGADetection.Enabled,
DGAScoreCap:             cfg.SNIAnalyzer.DGADetection.ScoreCap,
UnexpectedSNIEnabled:    cfg.SNIAnalyzer.UnexpectedSNI.Enabled,
UnexpectedSNIScore:      cfg.SNIAnalyzer.UnexpectedSNI.Score,
ExpectedHostnames:       stringSliceToSet(cfg.SNIAnalyzer.ExpectedHostnames),
```

**Step 8:** Add config structs to `internal/config/loader.go` for the new sections. Add them to the `Config` struct and add sub-structs:
```go
// in Config struct, add:
TLSEnforcer TLSEnforcerConfigYAML `yaml:"tls_enforcer"`
SNIAnalyzer SNIAnalyzerConfigYAML `yaml:"sni_analyzer"`

// new sub-structs:
type TLSEnforcerConfigYAML struct {
    BlockTLS10      bool `yaml:"block_tls_10"`
    BlockTLS11      bool `yaml:"block_tls_11"`
    FlagTLS12       bool `yaml:"flag_tls_12"`
    BlockWeakCiphers bool `yaml:"block_weak_ciphers"`
}

type SNIAnalyzerConfigYAML struct {
    MissingSNI  struct {
        Enabled bool `yaml:"enabled"`
        Score   int  `yaml:"score"`
    } `yaml:"missing_sni"`
    IPLiteralSNI struct {
        Enabled bool `yaml:"enabled"`
        Score   int  `yaml:"score"`
    } `yaml:"ip_literal_sni"`
    DGADetection struct {
        Enabled  bool `yaml:"enabled"`
        ScoreCap int  `yaml:"score_cap"`
    } `yaml:"dga_detection"`
    UnexpectedSNI struct {
        Enabled bool `yaml:"enabled"`
        Score   int  `yaml:"score"`
    } `yaml:"unexpected_sni"`
    ExpectedHostnames []string `yaml:"expected_hostnames"`
}
```

**After Group 2:** Run `GOROOT=/snap/go/current go test ./...` — all tests must pass.

---

## Group 3: Signal Modules — TCP Analyzer + Rate Limiting

### 3a. Create `internal/security/rate_limiter.go`

**File to create:** `internal/security/rate_limiter.go`

This ports the `MultiStrategyRateTracker` from `src/security/pipeline.py`.

**What it does:** Calls the Lua sliding-window script for 3 strategies; returns a
signal if 2+ strategies agree on a threat level (majority vote).

**Strategies:**
- `by_ip`: Redis key `ratelimit:ip:{client_ip}`
- `by_ja4`: Redis key `ratelimit:ja4:{ja4}` (skip if ja4 is "")
- `by_ip_ja4`: Redis key `ratelimit:ip_ja4:{client_ip}:{ja4}` (skip if ja4 is "")

**Redis interface needed — add to `RedisReader` interface in `pipeline.go`:**
```go
// SlidingWindowCount calls the sliding window Lua script for the given key.
// window is in seconds. Returns count of events in window, 0 on error.
SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int
```

**Also add to `internal/redis/client.go`:**
```go
// SlidingWindowCount executes the sliding_window.lua EVALSHA.
// KEYS[1]=key, KEYS[2]=key+":ctr", ARGV[1]=now, ARGV[2]=window, ARGV[3]=ttl
// Returns 0 on error (fail open).
func (c *Client) SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int {
    if c.slidingWinSHA == "" {
        return 0
    }
    now := float64(time.Now().UnixNano()) / 1e9
    result, err := c.rdb.EvalSha(ctx, c.slidingWinSHA,
        []string{key, key + ":ctr"},
        now, window, ttl,
    ).Int()
    if err != nil {
        c.log.WithError(err).WithField("key", key).Debug("redis: EVALSHA failed")
        return 0
    }
    return result
}
```

**Threshold defaults (match Python `config/proxy.yml` defaults):**
- `by_ip`: suspicious=50, block=200, ban=500; window=1s; ttl=300s
- `by_ja4`: suspicious=20, block=100, ban=200; window=1s; ttl=300s
- `by_ip_ja4`: suspicious=20, block=50, ban=100; window=1s; ttl=300s

**Exact signals returned:**

| Signal name | Score | When |
|-------------|-------|------|
| `"rate_limit_suspicious"` | 20 | 2+ strategies at suspicious level |
| `"rate_limit_block"` | 60 | 2+ strategies at block level |
| `"rate_limit_ban"` | 90 | 2+ strategies at ban level OR any single strategy at ban |

**Return:** `[]RiskSignal` (at most one signal — the highest matching level).

**Function signature:**
```go
type RateLimiter struct {
    cfg   *RateLimiterConfig
    redis RedisReader
    log   *logrus.Logger
}

type RateLimiterConfig struct {
    Enabled   bool
    ByIP      StrategyConfig
    ByJA4     StrategyConfig
    ByIPJA4   StrategyConfig
}

type StrategyConfig struct {
    Enabled    bool
    Suspicious int
    Block      int
    Ban        int
    Window     float64
    TTL        int
}

func NewRateLimiter(cfg *RateLimiterConfig, redis RedisReader, log *logrus.Logger) *RateLimiter

// Check records this connection and returns a risk signal if thresholds are exceeded.
// Returns nil slice if rate limiting is disabled or no threshold reached.
func (r *RateLimiter) Check(ctx context.Context, clientIP, ja4 string) []RiskSignal
```

**File to create:** `internal/security/rate_limiter_test.go`

Use a `mockRedisCounter` that implements `RedisReader` with `SlidingWindowCount`
returning configurable values.

Minimum 8 tests:
```
TestRateLimiter_Disabled_NoSignal
TestRateLimiter_BelowThreshold_NoSignal
TestRateLimiter_SingleStrategy_Suspicious_NoSignal  // only 1 strategy hit, majority=2 required
TestRateLimiter_MajoritySuspicious_SignalFired
TestRateLimiter_MajorityBlock_SignalFired
TestRateLimiter_AnyBan_SignalFired                  // single strategy at ban level → signal
TestRateLimiter_EmptyJA4_SkipsJA4Strategies
TestRateLimiter_HighestLevelWins                    // if block+ban both hit, return ban signal
```

### 3b. Create `internal/security/tcp_analyzer.go`

**File to create:** `internal/security/tcp_analyzer.go`

Port of `src/security/tcp_analyzer.py`. **Important:** TCP behavior metrics (session
resumption, connection lifespan, JA4T matching, return visitor trust) require data
from Redis that is written by the Python proxy's per-connection tracking. In the Go
proxy these signals rely on the same Redis keys; the Go proxy reads them exactly as
the Python proxy writes them.

**Redis keys read (already written by Python proxy):**
- `session:{client_ip}` → Hash fields `total`, `resumed` (HINCRBY)
- `return_visitor:{client_ip}` → Hash fields `first_seen`, `total`, `allowed`, `blocked`
- `concurrent:{client_ip}` → String (INCR/DECR counter)

**Redis interface additions — add to `RedisReader`:**
```go
HGetAll(ctx context.Context, key string) map[string]string
Get(ctx context.Context, key string) string
```

**Add `HGetAll` and `Get` (returning string, not error) to `internal/redis/client.go`:**
```go
func (c *Client) HGetAll(ctx context.Context, key string) map[string]string {
    result, err := c.rdb.HGetAll(ctx, key).Result()
    if err != nil {
        c.log.WithError(err).WithField("key", key).Debug("redis: HGETALL failed")
        return nil
    }
    return result
}

// GetString retrieves a string value. Returns "" if absent or on error.
// (Note: Get already exists but returns (string, error). Add a convenience wrapper.)
func (c *Client) GetString(ctx context.Context, key string) string {
    v, _ := c.Get(ctx, key)
    return v
}
```

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"no_session_resumption"` | 15 | `resumed/total < 0.05` AND `total >= MinConnectionsForSessionCheck` (default 10) |
| `"short_connection_lifespan"` | 20 | `conn.ConnectionLifespanMS > 0` AND `< ShortLifespanThresholdMS` (default 500ms) |
| `"moderate_concurrency"` | 10 | concurrent connections ≥ `ConcurrencyModerate` (default 20) |
| `"high_concurrency"` | 25 | concurrent connections ≥ `ConcurrencyHigh` (default 50) |
| `"severe_concurrency"` | 40 | concurrent connections ≥ `ConcurrencySevere` (default 100) |
| `"return_visitor_trust"` | -1 | returning visitor with ≥ 90% allow rate over ≥ 7 days |

Note: only the highest concurrency tier fires (not cumulative).

**Function signature:**
```go
type TCPAnalyzer struct {
    cfg   *TCPAnalyzerConfig
    redis RedisReader
    log   *logrus.Logger
}

type TCPAnalyzerConfig struct {
    Enabled                     bool
    SessionResumptionEnabled    bool
    MinConnectionsForSessionCheck int // default 10
    ShortLifespanEnabled        bool
    ShortLifespanThresholdMS    int  // default 500
    ConcurrencyEnabled          bool
    ConcurrencyModerate         int  // default 20
    ConcurrencyHigh             int  // default 50
    ConcurrencySevere           int  // default 100
    ReturnVisitorEnabled        bool
    ReturnVisitorMinDays        int  // default 7
    ReturnVisitorMinAllowRate   float64 // default 0.90
}

func NewTCPAnalyzer(cfg *TCPAnalyzerConfig, redis RedisReader, log *logrus.Logger) *TCPAnalyzer

// Analyze returns risk signals for TCP/connection-level behavior.
// Never returns an error; fails open.
func (a *TCPAnalyzer) Analyze(ctx context.Context, conn *ConnectionContext) []RiskSignal
```

**File to create:** `internal/security/tcp_analyzer_test.go`

Minimum 8 tests using `mockRedis` that returns configurable values from `HGetAll` and `GetString`:
```
TestTCPAnalyzer_Disabled_NoSignals
TestTCPAnalyzer_SessionResumption_LowRate_Signal
TestTCPAnalyzer_SessionResumption_GoodRate_NoSignal
TestTCPAnalyzer_ShortLifespan_Signal
TestTCPAnalyzer_ModerateConcurrency_Signal
TestTCPAnalyzer_SevereConcurrency_OnlyHighestFires
TestTCPAnalyzer_ReturnVisitor_HighAllowRate_NegativeSignal
TestTCPAnalyzer_NoRedisData_NoSignal   // HGetAll returns nil → fail open
```

### 3c. Create `internal/security/mtls.go`

**File to create:** `internal/security/mtls.go`

Port of `src/security/mtls.py`. The mTLS bypass is already wired in `pipeline.go`
(`conn.HasValidClientCert` check). This file provides the certificate verifier that
sets `HasValidClientCert` in `ConnectionContext`.

For Phase 15, this is a **stub** — certificate parsing happens at the TCP level before
the pipeline runs, which is not yet implemented in `cmd/proxy/main.go`. Implement the
verifier interface so it can be wired in later.

```go
package security

import "crypto/x509"

// MTLSVerifier verifies TLS client certificates against a trusted CA pool.
type MTLSVerifier struct {
    pool *x509.CertPool
}

// NewMTLSVerifier loads trusted CAs from pemPath.
// If pemPath is empty or the file cannot be read, returns a verifier that
// always returns false (fail open — no certs trusted).
func NewMTLSVerifier(pemPath string) *MTLSVerifier

// Verify returns true if certDER is a valid certificate signed by a trusted CA.
// Returns false on any error (fail open).
func (v *MTLSVerifier) Verify(certDER []byte) bool
```

**File to create:** `internal/security/mtls_test.go`

Minimum 3 tests:
```
TestMTLSVerifier_EmptyPEMPath_AlwaysFalse
TestMTLSVerifier_InvalidCert_ReturnsFalse
TestMTLSVerifier_NilCert_ReturnsFalse
```

### 3d. Wire Group 3 into `pipeline.go` and `main.go`

**Edit `internal/security/pipeline.go`:**

Add fields to `Pipeline` struct:
```go
rateLimiter  *RateLimiter
tcpAnalyzer  *TCPAnalyzer
```

Add to `NewPipeline()`:
```go
p.rateLimiter = NewRateLimiter(buildRateLimiterConfig(cfg), redis, log)
p.tcpAnalyzer = NewTCPAnalyzer(buildTCPAnalyzerConfig(cfg), redis, log)
```

Add to signal collection in `Process()` after SNI:
```go
signals = append(signals, p.rateLimiter.Check(ctx, conn.ClientIP, conn.JA4)...)
signals = append(signals, p.tcpAnalyzer.Analyze(ctx, conn)...)
```

Add builder functions and new `PipelineConfig` fields (see pattern from Group 2).

**Add to `buildPipelineConfig()` in `cmd/proxy/main.go`** the corresponding config
population from `cfg.Security.RateLimitStrategies` and `cfg.TCPAnalyzer`.

Add config structs to `internal/config/loader.go` for `TCPAnalyzerConfigYAML` and
populate `defaultConfig()` with the defaults listed in 3a/3b above.

**After Group 3:** `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 4: Signal Modules — ASN + DNS + Blocklists

### 4a. Add GeoIP dependency

**File to edit:** `go.mod`

Run:
```bash
GOROOT=/snap/go/current go get github.com/oschwald/geoip2-golang
GOROOT=/snap/go/current go mod tidy
```

This adds `github.com/oschwald/geoip2-golang` to `go.mod`. Commit the updated
`go.mod` and `go.sum`.

### 4b. Create `internal/security/asn_classifier.go`

**File to create:** `internal/security/asn_classifier.go`

Port of `src/security/asn_classifier.py`.

**What it does:** Opens a MaxMind GeoLite2-ASN database file, looks up the IP's ASN,
classifies it as datacenter / Tor / VPN / residential / mobile / unknown, and returns
a risk signal.

**Database file path:** Read from config. Default: `"GeoLite2-ASN.mmdb"` (Docker mounts
it at `/app/GeoLite2-ASN.mmdb`). If the file does not exist, fail open (return no signal).

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"asn_tor"` | 40 | IP found in Tor exit list (see below) |
| `"asn_datacenter"` | 20 | ASN org name matches datacenter list AND not Tor |
| `"asn_vpn"` | 10 | ASN org name matches VPN pattern AND not datacenter/Tor |
| `"asn_unknown"` | 5 | ASN lookup returned empty org name |

No signal for `"residential"` or `"mobile"` (score 0).

**Tor exit list:** Read from `config/proxy.yml` field `asn_classifier.tor_exit_list_path`
(default `"config/tor_exit_nodes.txt"`). File has one IP per line. Load into a
`map[string]bool` at startup. If file absent, Tor detection disabled (fail open).

**Datacenter detection:** ASN org name (from MaxMind) matched against the list in
`config/asn_datacenter_list.yml`. That file has a `datacenter_asns` list of ASN numbers
and a `datacenter_org_patterns` list of strings to match against org names.

**VPN detection:** Org name contains any of: `"vpn"`, `"proxy"`, `"tunnel"`, `"anonymiz"`,
`"hide"`, `"private internet"`, `"nordvpn"`, `"expressvpn"`, `"surfshark"` (case-insensitive).

**Function signature:**
```go
type ASNClassifier struct {
    db          *geoip2.Reader   // nil if DB file absent
    torExits    map[string]bool
    datacenterASNs map[uint]bool
    datacenterOrgs []string
    vpnPatterns    []string
    cfg         *ASNClassifierConfig
    log         *logrus.Logger
}

type ASNClassifierConfig struct {
    Enabled          bool
    DBPath           string
    TorExitListPath  string
    DatacenterScore  int  // default 20
    TorScore         int  // default 40
    VPNScore         int  // default 10
    UnknownScore     int  // default 5
}

func NewASNClassifier(cfg *ASNClassifierConfig, log *logrus.Logger) *ASNClassifier

// Classify returns risk signals for the given IP address.
// Returns empty slice if DB absent or IP lookup fails (fail open).
func (c *ASNClassifier) Classify(clientIP string) []RiskSignal
```

**File to create:** `internal/security/asn_classifier_test.go`

Tests must mock the GeoIP lookup — do not require a real DB file in unit tests.
Create a `testASNClassifier` constructor that accepts a mock lookup function.

Minimum 7 tests:
```
TestASNClassifier_NoDB_NoSignal
TestASNClassifier_TorIP_Signal
TestASNClassifier_DatacenterOrg_Signal
TestASNClassifier_VPNOrg_Signal
TestASNClassifier_ResidentialOrg_NoSignal
TestASNClassifier_UnknownOrg_Signal
TestASNClassifier_IPv6_NoError
```

### 4c. Create `internal/security/dns_enrichment.go`

**File to create:** `internal/security/dns_enrichment.go`

Port of `src/security/dns_enrichment.py`. In the Python proxy this is async with a
worker queue. In Go, use a goroutine with a channel. On the hot path, call
`go dns.Enrich(clientIP)` (fire-and-forget) — never block the connection decision.

**What it does:** Does a PTR lookup on the client IP. If PTR exists, does a forward
A/AAAA lookup to verify (FCrDNS). Writes the result to Redis for use in future
connections from the same IP.

**Redis key:** `dns:fcrdns:{client_ip}` → String value, one of:
`"confirmed_residential"`, `"confirmed_datacenter"`, `"confirmed_unknown"`,
`"no_ptr"`, `"fcrdns_failed"`

TTL: 1 hour (3600 seconds).

**Exact signals (read from Redis, written by prior enrichment):**

| Redis value | Signal name | Score |
|-------------|-------------|-------|
| `"no_ptr"` | `"no_ptr"` | 15 |
| `"fcrdns_failed"` | `"fcrdns_failed"` | 20 |
| `"confirmed_residential"` | `"residential_ptr"` | -10 (negative — reduces score) |
| `"confirmed_datacenter"` | no signal | 0 |
| `"confirmed_unknown"` | no signal | 0 |
| not in Redis | enqueue lookup, return no signal this connection | 0 |

**Browser traffic guard:** Never enqueue enrichment if `conn.ALPN == "h2"` or `"h1"`.

**Function signature:**
```go
type DNSEnrichment struct {
    redis   RedisReader
    cfg     *DNSEnrichmentConfig
    log     *logrus.Logger
    queue   chan string  // IPs waiting for PTR lookup
}

type DNSEnrichmentConfig struct {
    Enabled bool
    Workers int   // default 4
    NoPTRScore        int  // default 15
    FCrDNSFailedScore int  // default 20
    ResidentialScore  int  // default -10 (stored as positive, applied as negative)
    TTL               int  // default 3600
}

func NewDNSEnrichment(cfg *DNSEnrichmentConfig, redis RedisReader, log *logrus.Logger) *DNSEnrichment

// Start launches worker goroutines. Call once at startup.
// Workers stop when ctx is cancelled.
func (d *DNSEnrichment) Start(ctx context.Context)

// GetSignal returns the cached DNS risk signal for clientIP.
// If no result is cached, enqueues a lookup and returns nil (fail open).
// Never blocks; never returns an error.
func (d *DNSEnrichment) GetSignal(ctx context.Context, conn *ConnectionContext) *RiskSignal
```

**Also add `Set` to `RedisReader` interface** (needed to write enrichment results):
```go
Set(ctx context.Context, key, value string, ttlSeconds int)
```

Add to `internal/redis/client.go`:
```go
func (c *Client) Set(ctx context.Context, key, value string, ttlSeconds int) {
    if err := c.rdb.Set(ctx, key, value, time.Duration(ttlSeconds)*time.Second).Err(); err != nil {
        c.log.WithError(err).WithField("key", key).Warn("redis: SET failed")
    }
}
```

**File to create:** `internal/security/dns_enrichment_test.go`

Minimum 7 tests:
```
TestDNSEnrichment_Disabled_NoSignal
TestDNSEnrichment_CachedNoPTR_Signal
TestDNSEnrichment_CachedFCrDNSFailed_Signal
TestDNSEnrichment_CachedResidential_NegativeSignal
TestDNSEnrichment_NotCached_NoSignalEnqueues
TestDNSEnrichment_BrowserALPN_NeverEnqueued
TestDNSEnrichment_RedisDown_FailOpen
```

### 4d. Create `internal/security/blocklists.go`

**File to create:** `internal/security/blocklists.go`

Port of `src/security/blocklists.py`. Uses an in-process IP trie (radix tree) for
O(1) CIDR matching. The Python version uses `pytricia`. In Go, implement a simple
binary trie or use a package.

**Trie package:** Use `github.com/yl2chen/cidranger` (add to `go.mod`) or implement
a minimal radix trie. The trie must support IPv4 and IPv6 CIDRs.

Add the package:
```bash
GOROOT=/snap/go/current go get github.com/yl2chen/cidranger
GOROOT=/snap/go/current go mod tidy
```

**What it does:** Loads CIDR lists at startup. On each connection, looks up client IP.
Returns a risk signal if matched. Spamhaus DROP/EDROP feeds are hard-block feeds
(return a hard block, not a signal). Custom feeds return configurable risk scores.

**Redis keys read:** Feed data is stored in Redis as sorted sets by the Python analytics
container. The Go proxy reads `blocklist:{feed_name}` keys. For Phase 15, load feeds
from the local config file only — Redis-based dynamic feeds are a future enhancement.

**Config:** Reads `config/proxy.yml` section `blocklists.feeds`. Each feed has:
```yaml
blocklists:
  feeds:
    - name: spamhaus_drop
      enabled: true
      path: "config/spamhaus_drop.txt"
      is_bypass: true      # true = hard block; false = signal
      score: 80            # used if is_bypass: false
```

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"blocklist_{feed_name}"` | feed.score | IP matched a feed with `is_bypass: false` |

Hard block (is_bypass=true): return `(nil, true)` — block immediately.

**Function signature:**
```go
type BlocklistManager struct {
    feeds []blocklistFeed
    log   *logrus.Logger
}

type blocklistFeed struct {
    name      string
    isBlock   bool  // true = hard block
    score     int
    ranger    cidranger.Ranger
}

type BlocklistConfig struct {
    Feeds []BlocklistFeedConfig
}

type BlocklistFeedConfig struct {
    Name      string `yaml:"name"`
    Enabled   bool   `yaml:"enabled"`
    Path      string `yaml:"path"`
    IsBlock   bool   `yaml:"is_bypass"`
    Score     int    `yaml:"score"`
}

func NewBlocklistManager(cfg *BlocklistConfig, log *logrus.Logger) *BlocklistManager

// Check returns (signals, hardBlock).
// hardBlock=true means immediately block; signals will be nil.
// Returns (nil, false) if no feed matched (fail open).
func (m *BlocklistManager) Check(clientIP string) (signals []RiskSignal, hardBlock bool)
```

**File to create:** `internal/security/blocklists_test.go`

Minimum 6 tests:
```
TestBlocklists_NoFeeds_NoBlock
TestBlocklists_IPInHardBlockFeed_HardBlock
TestBlocklists_IPInScoredFeed_Signal
TestBlocklists_IPv6_Matched
TestBlocklists_IPNotInAnyFeed_Clean
TestBlocklists_DisabledFeed_NotChecked
```

### 4e. Wire Group 4 into pipeline and main

Follow the same pattern as Groups 2 and 3:

1. Add `asnClassifier`, `dnsEnrichment`, `blocklists` fields to `Pipeline` struct
2. Initialize in `NewPipeline()`
3. In `Process()`, add blocklist check **before** the signal collection (it can hard-block):
   ```go
   if blSigs, hardBlock := p.blocklists.Check(conn.ClientIP); hardBlock {
       return &PipelineResult{Action: "block", Score: 100, BypassReason: "blocklist"}
   } else {
       signals = append(signals, blSigs...)
   }
   signals = append(signals, p.asnClassifier.Classify(conn.ClientIP)...)
   if sig := p.dnsEnrichment.GetSignal(ctx, conn); sig != nil {
       signals = append(signals, *sig)
   }
   ```
4. Add config fields to `PipelineConfig`
5. Add builder functions
6. Update `buildPipelineConfig()` in `main.go`
7. Add YAML config structs to `loader.go`
8. Call `dnsEnrichment.Start(ctx)` in `main.go` after building the proxy

**After Group 4:** `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 5: Signal Modules — Beaconing + AbuseIPDB + RDAP + Analytics

### 5a. Create `internal/security/beaconing_detector.go`

**File to create:** `internal/security/beaconing_detector.go`

Port of `src/security/beaconing_detector.py`.

**Redis keys used:**
- Write: `beacon:{client_ip}:{ja4}` → Sorted Set, score=timestamp, member=`"{timestamp}:{uuid8}"`
- Read count via `ZCARD beacon:{client_ip}:{ja4}`
- Trim old entries: `ZREMRANGEBYSCORE beacon:{client_ip}:{ja4} 0 {cutoff}`
- Leaderboard: `beacon:suspects` → Sorted Set, score=beacon_score, member=`"{ip}:{ja4}"`

**Redis interface additions — add to `RedisReader`:**
```go
ZAdd(ctx context.Context, key string, score float64, member string)
ZRemRangeByScore(ctx context.Context, key string, min, max float64)
ZRange(ctx context.Context, key string, start, stop int64) []string
ZCard(ctx context.Context, key string) int64
ZAddAndTrim(ctx context.Context, key string, score float64, member string, cutoff float64, maxMembers int64)
```

Add implementations to `internal/redis/client.go` — all fail open (log warning, return
zero/nil on error).

**Algorithm:**
1. `GetSignal(ctx, conn)` is called BEFORE `maybe_record()`. Do not record on this call.
2. Look up timestamps for `beacon:{client_ip}:{ja4}` sorted set.
3. Filter to short window (1 hour = 3600s) and long window (24 hours).
4. Compute inter-arrival times (IAT) from the timestamp list.
5. Compute coefficient of variation (CV) = stdev(IAT) / mean(IAT).
6. Score based on CV:
   - CV < 0.15 → beacon_score = 0.9
   - CV < 0.40 → beacon_score = 0.5
   - CV < 0.70 → beacon_score = 0.2
   - CV ≥ 0.70 → no signal
7. Final signal score = `int(beacon_score * ScoreCap)` where `ScoreCap` default 35.
8. Minimum `MinObservations` (default 5) required to fire any signal.

**Guards — never fire signal if:**
- `conn.ALPN == "h2"` or `"h1"`
- IP+JA4 combination is in local cache whitelist decisions

**`MaybeRecord(ctx, conn)` — called AFTER action is decided:**
- Skip if action is `"block"` or `"ban"`
- Skip if `conn.ALPN == "h2"` or `"h1"`
- Add timestamp to `beacon:{client_ip}:{ja4}` sorted set
- Trim entries older than 24h
- Update leaderboard if beacon_score > 0

**Function signature:**
```go
type BeaconingDetector struct {
    cfg   *BeaconingConfig
    redis RedisReader
    log   *logrus.Logger
}

type BeaconingConfig struct {
    Enabled        bool
    ScoreCap       int     // default 35
    MinObservations int    // default 5
    ShortWindowSec  float64 // default 3600
    LongWindowSec   float64 // default 86400
    MaxSuspects     int    // default 10000
}

func NewBeaconingDetector(cfg *BeaconingConfig, redis RedisReader, log *logrus.Logger) *BeaconingDetector

func (d *BeaconingDetector) GetSignal(ctx context.Context, conn *ConnectionContext) *RiskSignal
func (d *BeaconingDetector) MaybeRecord(ctx context.Context, conn *ConnectionContext, action string)
```

**File to create:** `internal/security/beaconing_detector_test.go`

Minimum 8 tests:
```
TestBeaconing_Disabled_NoSignal
TestBeaconing_TooFewObservations_NoSignal
TestBeaconing_LowCV_StrongSignal
TestBeaconing_HighCV_NoSignal
TestBeaconing_BrowserALPN_NoSignal
TestBeaconing_MaybeRecord_BlockAction_DoesNotRecord
TestBeaconing_MaybeRecord_AllowAction_Records
TestBeaconing_RedisDown_FailOpen
```

### 5b. Create `internal/security/abuseipdb.go`

**File to create:** `internal/security/abuseipdb.go`

Port of `src/security/abuseipdb.py`. Makes HTTP calls to the AbuseIPDB API.

**Important:** On the hot path (`GetSignal`), ONLY read from cache — never make an HTTP
call. HTTP calls happen in a background goroutine queue (fire-and-forget from hot path).

**Three-tier cache:**
1. Local in-process LRU (`internal/cache`) — 30 min TTL
2. Redis cache — key `abuseipdb:{ip}`, value = confidence score (integer string), 24h TTL
3. API call (background, not on hot path)

**Redis key for bloom filter:** `bloom:abuseipdb_enriched` — use Redis SET with SISMEMBER
as a simple dedup guard. If IP is in the set, skip re-enqueueing.

**Score formula:**
```
if confidence >= SharedIPThreshold (default 50):
    score = round(confidence / 100 * ScoreCap)
else:
    score = round(confidence / SharedIPThreshold * 15)
```
Signal name: `"abuseipdb"`. Only emit if `score > 0`.

**Function signature:**
```go
type AbuseIPDB struct {
    cfg        *AbuseIPDBConfig
    localCache *cache.LRU
    redis      RedisReader
    http       *http.Client
    queue      chan string
    log        *logrus.Logger
}

type AbuseIPDBConfig struct {
    Enabled          bool
    APIKey           string
    ScoreCap         int     // default 40
    SharedIPThreshold int    // default 50
    LocalCacheSize   int     // default 10000
    Workers          int     // default 2
    DailyQuota       int     // default 1000
}

func NewAbuseIPDB(cfg *AbuseIPDBConfig, redis RedisReader, log *logrus.Logger) *AbuseIPDB

// Start launches background worker goroutines for API calls.
func (a *AbuseIPDB) Start(ctx context.Context)

// GetSignal reads from cache only. Returns nil if no cached result.
// Never makes a network call. Never blocks.
func (a *AbuseIPDB) GetSignal(clientIP string) *RiskSignal
```

**File to create:** `internal/security/abuseipdb_test.go`

Use a `httptest.Server` for API mock. Minimum 7 tests:
```
TestAbuseIPDB_Disabled_NoSignal
TestAbuseIPDB_LocalCacheHit_NoHTTPCall
TestAbuseIPDB_RedisCacheHit_Score
TestAbuseIPDB_HighConfidence_ScaledScore
TestAbuseIPDB_LowConfidence_SharedIPCapped
TestAbuseIPDB_ZeroConfidence_NoSignal
TestAbuseIPDB_APIError_FailOpen
```

### 5c. Create `internal/security/rdap_enrichment.go`

**File to create:** `internal/security/rdap_enrichment.go`

Port of `src/security/rdap_enrichment.py`. Like AbuseIPDB, RDAP calls are background
only. Hot path reads from Redis cache.

**Redis keys read:**
- `rdap:{ip}` → Hash with fields `org`, `netblock`, `registered_date`
- `known_bad_org:{org_name}` → String (existence check via SISMEMBER on a set)
- `ban_cidr:{cidr}` → String (existence check — already blocked)

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"rdap_known_bad_org"` | 45 | Org found in `config/known_bad_orgs.yml` |
| `"rdap_new_netblock"` | 20 | Netblock registered within `NewNetblockMaxAgeDays` (default 90) |

**CIDR block expansion** is a side effect, not a signal. When conditions are met, write
`ban_cidr:{cidr}` to Redis with appropriate TTL. Guards (same as Python):
1. `TriggerScore >= MinTriggerScore` (default 75)
2. Prefix ≤ /24 (IPv4) or /48 (IPv6)
3. Not browser traffic (ALPN h2/h1)
4. Org in known-bad list (if `RequireKnownBadOrg: true`)

**Function signature:**
```go
type RDAPEnricher struct {
    cfg   *RDAPConfig
    redis RedisReader
    http  *http.Client
    queue chan rdapJob
    log   *logrus.Logger
}

type RDAPConfig struct {
    Enabled              bool
    MinTriggerScore      int  // default 75
    NewNetblockMaxAgeDays int // default 90
    NewNetblockScore     int  // default 20
    KnownBadOrgScore     int  // default 45
    RequireKnownBadOrg   bool // default true
    BlockExpansionEnabled bool
    KnownBadOrgsFile     string // default "config/known_bad_orgs.yml"
}

func NewRDAPEnricher(cfg *RDAPConfig, redis RedisReader, log *logrus.Logger) *RDAPEnricher

func (r *RDAPEnricher) Start(ctx context.Context)

// GetSignals reads cached RDAP data and returns signals.
// Enqueues lookup if no cached data. Never blocks.
func (r *RDAPEnricher) GetSignals(ctx context.Context, conn *ConnectionContext, triggerScore int) []RiskSignal
```

**File to create:** `internal/security/rdap_enrichment_test.go`

Minimum 6 tests:
```
TestRDAP_Disabled_NoSignals
TestRDAP_KnownBadOrg_Signal
TestRDAP_NewNetblock_Signal
TestRDAP_NotCached_NoSignalEnqueues
TestRDAP_BlockExpansion_WritesRedisKey
TestRDAP_BlockExpansion_IPv6_MaxPrefix48
```

### 5d. Create `internal/security/analytics_signals.go`

**File to create:** `internal/security/analytics_signals.go`

Port of `Pipeline._get_analytics_signals()` from `src/security/pipeline.py`.

**What it does:** Reads Redis keys written by the Python analytics container and
returns pre-computed risk signals. Fails open — if any key is absent or Redis is
down, returns empty slice (never partial results).

**Redis keys read:**
- `analytics:campaign:{subnet}` → key existence means campaign detected
  - subnet = IPv4 `/24` like `"1.2.3.0/24"`, or IPv6 `/48` like `"2001:db8::/48"`
- `analytics:slowscan:{subnet}` → key existence means slow-scan detected

**Subnet derivation:**
- IPv4: mask to /24 → `ip & 0xFFFFFF00`/24, e.g. `"192.168.1.0/24"`
- IPv6: mask to /48 → zero last 80 bits, e.g. `"2001:db8:1::/48"`

**Exact signals:**

| Signal name | Score | When |
|-------------|-------|------|
| `"analytics_campaign"` | 35 | `analytics:campaign:{subnet}` key exists in Redis |
| `"analytics_slowscan"` | 30 | `analytics:slowscan:{subnet}` key exists in Redis |

**Redis interface addition — add to `RedisReader`:**
```go
Exists(ctx context.Context, key string) bool
```

Add to `internal/redis/client.go`:
```go
func (c *Client) Exists(ctx context.Context, key string) bool {
    n, err := c.rdb.Exists(ctx, key).Result()
    if err != nil {
        return false
    }
    return n > 0
}
```

**Function signature:**
```go
// GetAnalyticsSignals returns risk signals from pre-computed analytics findings.
// Always returns a complete slice or empty slice — never partial (fail open).
func GetAnalyticsSignals(ctx context.Context, redis RedisReader, clientIP string, log *logrus.Logger) []RiskSignal
```

**File to create:** `internal/security/analytics_signals_test.go`

Minimum 5 tests:
```
TestAnalyticsSignals_NeitherKey_NoSignal
TestAnalyticsSignals_CampaignKey_Signal
TestAnalyticsSignals_SlowscanKey_Signal
TestAnalyticsSignals_BothKeys_TwoSignals
TestAnalyticsSignals_RedisDown_EmptyNotPanic
```

### 5e. Wire Group 5 into pipeline

Follow the same pattern as Groups 2–4.

Add to `Process()` signal collection, in this order (after Group 4 signals):
```go
if sig := p.beaconing.GetSignal(ctx, conn); sig != nil {
    signals = append(signals, *sig)
}
if sig := p.abuseipdb.GetSignal(conn.ClientIP); sig != nil {
    signals = append(signals, *sig)
}
signals = append(signals, p.rdap.GetSignals(ctx, conn, assessment.TotalScore)...)
signals = append(signals, GetAnalyticsSignals(ctx, p.redis, conn.ClientIP, p.log)...)
```

Note: `rdap.GetSignals` needs the composite score. Compute score before calling it:
```go
// Compute intermediate score for RDAP trigger decision
interimAssessment := p.scorer.Score(signals)
signals = append(signals, p.rdap.GetSignals(ctx, conn, interimAssessment.TotalScore)...)
// Final score
assessment := p.scorer.Score(signals)
```

After the action is decided, fire-and-forget beaconing record:
```go
go p.beaconing.MaybeRecord(ctx, conn, action)
```

In `cmd/proxy/main.go` `newProxy()`, call `.Start(ctx)` for all background-worker modules:
```go
p.pipeline.StartBackgroundWorkers(ctx)
```

Add `StartBackgroundWorkers(ctx context.Context)` to `Pipeline` in `pipeline.go`:
```go
func (p *Pipeline) StartBackgroundWorkers(ctx context.Context) {
    p.dnsEnrichment.Start(ctx)
    p.abuseipdb.Start(ctx)
    p.rdap.Start(ctx)
}
```

**After Group 5:** `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 6: Pipeline Wiring — Missing Bypass Checks

### 6a. Edit `internal/security/pipeline.go`

Two bypass checks exist in the Python proxy that are not yet in the Go `checkBypasses()`
and `checkHardBlocks()` functions.

**Add to `checkBypasses()` — Static IP allowlist:**
```go
// Static IP allowlist bypass
if p.cfg.StaticIPAllowlistEnabled {
    if p.cfg.StaticIPAllowlist[conn.ClientIP] {
        return true, "static_ip"
    }
}
```

Add to `PipelineConfig`:
```go
StaticIPAllowlistEnabled bool
StaticIPAllowlist        map[string]bool
```

**Add to `checkHardBlocks()` — Country blacklist:**
```go
// Country blacklist bypass
if p.cfg.CountryBlacklistBypass && conn.Country != "" {
    if p.cfg.CountryBlacklist[conn.Country] {
        return true, "country_blacklist"
    }
}
```

Add to `PipelineConfig`:
```go
CountryBlacklist map[string]bool
```

(Note: `CountryBlacklistBypass bool` already exists in `PipelineConfig`.)

**Add GeoIP country lookup to `cmd/proxy/main.go` `handleConn()`:**
```go
// After parsing TLS, before calling pipeline.Process():
if p.geoIP != nil {
    country, err := p.geoIP.Country(net.ParseIP(connCtx.ClientIP))
    if err == nil {
        connCtx.Country = country.Country.IsoCode
    }
}
```

Add `geoIP *geoip2.Reader` field to `proxy` struct. Initialize in `newProxy()` from
`cfg.GeoIP.DBPath`. If file absent, `p.geoIP = nil` (fail open — country check skipped).

**Also add `DialManager`-equivalent seed logic to `redis/client.go`:**

In `New()`, after creating the client, check if `config:dial` key exists. If not, seed it
from `cfg.MonitorMode.Dial`:
```go
// In newProxy(), after creating redis client:
rc.SeedDialIfAbsent(ctx, cfg.MonitorMode.Dial)
```

Add to `internal/redis/client.go`:
```go
// SeedDialIfAbsent writes the dial value to Redis only if config:dial is not already set.
// This seeds the first-start state from the config file without overwriting a running proxy's dial.
func (c *Client) SeedDialIfAbsent(ctx context.Context, dial int) {
    ok, err := c.rdb.SetNX(ctx, "config:dial", strconv.Itoa(dial), 0).Result()
    if err != nil {
        c.log.WithError(err).Warn("redis: failed to seed config:dial")
        return
    }
    if ok {
        c.log.WithField("dial", dial).Info("redis: seeded config:dial from config file")
    }
}
```

**After Group 6:** `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 7: Infrastructure — Prometheus + Health + PROXY Protocol + PubSub Reconnect

### 7a. Add Prometheus metrics

**File to edit:** `go.mod` — add dependency:
```bash
GOROOT=/snap/go/current go get github.com/prometheus/client_golang/prometheus
GOROOT=/snap/go/current go get github.com/prometheus/client_golang/prometheus/promhttp
GOROOT=/snap/go/current go mod tidy
```

**File to create:** `internal/metrics/metrics.go`

Define all metrics using the exact same names as the Python proxy
(see `docs/OBSERVABILITY_STANDARDS.md` for the full registry).

Minimum required metrics to match Python:
```go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    ConnectionsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "ja4proxy_connections_total"},
        []string{"action"},
    )
    ActiveConnections = prometheus.NewGauge(
        prometheus.GaugeOpts{Name: "ja4proxy_active_connections"},
    )
    RiskScoreHistogram = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "ja4proxy_risk_score_distribution",
            Buckets: []float64{0, 10, 20, 35, 55, 70, 85, 100},
        },
    )
    DialSetting = prometheus.NewGauge(
        prometheus.GaugeOpts{Name: "ja4proxy_dial_setting"},
    )
    SecurityEventsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "ja4proxy_security_events_total"},
        []string{"event_type"},
    )
    TarpitConcurrent = prometheus.NewGauge(
        prometheus.GaugeOpts{Name: "ja4proxy_tarpit_concurrent"},
    )
    TarpitOverflowTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "ja4proxy_tarpit_overflow_total"},
        []string{"action"},
    )
    ConfigReloadsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{Name: "ja4proxy_config_reloads_total"},
    )
)

func Register() {
    prometheus.MustRegister(
        ConnectionsTotal, ActiveConnections, RiskScoreHistogram,
        DialSetting, SecurityEventsTotal, TarpitConcurrent,
        TarpitOverflowTotal, ConfigReloadsTotal,
    )
}
```

**File to edit:** `cmd/proxy/main.go`

Add metrics HTTP server in `newProxy()` / `serve()`:
```go
// In serve(), after starting the TCP listener, start the metrics server:
go func() {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/health", p.handleHealth)
    addr := fmt.Sprintf(":%d", p.cfg.Metrics.Port)
    p.log.WithField("addr", addr).Info("proxy: metrics server listening")
    srv := &http.Server{Addr: addr, Handler: mux}
    go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
    srv.ListenAndServe()
}()
```

Add `handleHealth` method to `proxy`:
```go
func (p *proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
    defer cancel()
    redisStatus := "ok"
    if err := p.redis.Ping(ctx); err != nil {
        redisStatus = "error"
    }
    status := "ok"
    if redisStatus != "ok" {
        status = "degraded"
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    json.NewEncoder(w).Encode(map[string]string{
        "status": status,
        "redis":  redisStatus,
    })
}
```

Add `Ping` to `RedisReader` interface. It already exists on `Client` — add it to the interface.

**Wire metrics into `handleConn()`:**
```go
metrics.ActiveConnections.Inc()
defer metrics.ActiveConnections.Dec()
// after result:
metrics.ConnectionsTotal.WithLabelValues(result.Action).Inc()
metrics.RiskScoreHistogram.Observe(float64(result.Score))
```

**File to create:** `internal/metrics/metrics_test.go`

Minimum 3 tests verifying metric names match Python:
```
TestMetricNames_ConnectionsTotal
TestMetricNames_ActiveConnections
TestMetricNames_RiskScoreHistogram
```

### 7b. Add PROXY protocol support

**File to edit:** `cmd/proxy/main.go`

When `cfg.Proxy.ProxyProtocol == true`, before reading TLS data, try to read and parse
the PROXY protocol v1 header (text format — `PROXY TCP4 1.2.3.4 5.6.7.8 1234 8080\r\n`).

```go
// In handleConn(), before reading TLS:
if p.cfg.Proxy.ProxyProtocol {
    if realIP, ok := readProxyProtocol(buf[:n]); ok {
        connCtx.ClientIP = realIP
        // Advance data past the PROXY header
        // (proxy protocol header ends at first \r\n)
        headerEnd := bytes.Index(buf[:n], []byte("\r\n"))
        if headerEnd >= 0 {
            data = buf[headerEnd+2 : n]
        }
    }
}
```

**File to create:** `internal/proxy/proxy_protocol.go`

```go
package proxy

import (
    "net"
    "strings"
)

// ReadProxyProtocol parses a PROXY protocol v1 header from buf.
// Returns (realClientIP, true) if the header is valid.
// Returns ("", false) if not a PROXY protocol header (plain TLS connection).
// Never panics. Fails open: if parsing fails, returns ("", false) so the
// caller uses the TCP source IP.
func ReadProxyProtocol(buf []byte) (clientIP string, ok bool) {
    s := string(buf)
    if !strings.HasPrefix(s, "PROXY ") {
        return "", false
    }
    parts := strings.SplitN(s[:strings.Index(s, "\r\n")], " ", 6)
    // PROXY TCP4 <client_ip> <proxy_ip> <client_port> <proxy_port>
    if len(parts) < 3 {
        return "", false
    }
    if parts[1] == "UNKNOWN" {
        return "", false
    }
    ip := net.ParseIP(parts[2])
    if ip == nil {
        return "", false
    }
    return ip.String(), true
}
```

**File to create:** `internal/proxy/proxy_protocol_test.go`

Minimum 6 tests:
```
TestProxyProtocol_TCP4_Valid
TestProxyProtocol_TCP6_Valid
TestProxyProtocol_UNKNOWN_ReturnsFalse
TestProxyProtocol_NotProxyHeader_ReturnsFalse
TestProxyProtocol_Truncated_ReturnsFalse
TestProxyProtocol_InvalidIP_ReturnsFalse
```

### 7c. Fix PubSub reconnect

**File to edit:** `internal/redis/pubsub.go`

Replace the existing `Run()` body with a reconnect loop:
```go
func (h *PubSubHandler) Run(ctx context.Context) {
    backoff := time.Second
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        h.runOnce(ctx)
        select {
        case <-ctx.Done():
            return
        case <-time.After(backoff):
            backoff = min(backoff*2, 30*time.Second)
        }
    }
}

func (h *PubSubHandler) runOnce(ctx context.Context) {
    sub := h.client.rdb.Subscribe(ctx, ChannelConfigReload, ChannelDialChange)
    defer sub.Close()
    ch := sub.Channel()
    for {
        select {
        case <-ctx.Done():
            return
        case msg, ok := <-ch:
            if !ok {
                h.log.Warn("pubsub: channel closed; will reconnect")
                return
            }
            h.handleMessage(msg)
        }
    }
}
```

**After Group 7:** `GOROOT=/snap/go/current go test ./...` must pass.

---

## Group 8: Binary TLS Fixtures + JA4 Parity Tests

### 8a. Create ClientHello fixtures

**Directory to create:** `tests/fixtures/clienthello/`

The fixtures are real TLS ClientHello bytes captured from live browsers/tools.
Use the script below to capture them:

**File to create:** `scripts/capture_clienthello.py`

```python
#!/usr/bin/env python3
"""
Capture TLS ClientHello bytes from connections.
Run: python3 scripts/capture_clienthello.py
Then connect with: curl --tlsv1.3 https://localhost:9443/
                   python3 -c "import ssl,socket; ..."
Saves raw ClientHello bytes to tests/fixtures/clienthello/<name>.bin
"""
import socket, ssl, sys, pathlib

FIXTURES = pathlib.Path("tests/fixtures/clienthello")
FIXTURES.mkdir(parents=True, exist_ok=True)

def capture(name: str, port: int = 9443):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    print(f"Listening on :{port} — connect to capture '{name}'")
    conn, addr = sock.accept()
    data = conn.recv(8192)
    out = FIXTURES / f"{name}.bin"
    out.write_bytes(data)
    print(f"Saved {len(data)} bytes to {out}")
    conn.close()
    sock.close()
```

**Minimum fixtures required:**
- `chrome_tls13.bin` — Chrome connecting with TLS 1.3
- `firefox_tls13.bin` — Firefox connecting with TLS 1.3
- `curl_tls13.bin` — `curl --tlsv1.3`
- `curl_tls12.bin` — `curl --tlsv1.2`
- `no_sni.bin` — openssl s_client with `-noservername`

**File to create:** `tests/fixtures/clienthello/README.md`

Document the expected JA4 for each fixture. Format:
```
| File | Expected JA4 | Tool | TLS version |
|------|-------------|------|-------------|
| chrome_tls13.bin | t13d1516h2_8daaf6152771_02713d6af862 | Chrome 120 | TLS 1.3 |
```

### 8b. Add parity test

**File to edit:** `internal/tls/ja4_test.go`

Add a test that reads each `.bin` fixture, parses it with `ParseClientHello`,
computes `ComputeJA4`, and verifies against the expected value in the README:

```go
// TestJA4_FixturesParity verifies Go JA4 output matches the expected values
// documented in tests/fixtures/clienthello/README.md.
// Skips if the fixtures directory does not exist (CI environments without captures).
func TestJA4_FixturesParity(t *testing.T) {
    // expected is the ground truth documented in README.md
    expected := map[string]string{
        "chrome_tls13": "t13d1516h2_8daaf6152771_02713d6af862",
        // add remaining fixtures after capture
    }
    dir := "../../tests/fixtures/clienthello"
    for name, wantJA4 := range expected {
        path := filepath.Join(dir, name+".bin")
        data, err := os.ReadFile(path)
        if os.IsNotExist(err) {
            t.Skipf("fixture %s not found; run scripts/capture_clienthello.py", path)
        }
        info, err := ParseClientHello(data)
        if err != nil {
            t.Errorf("%s: parse error: %v", name, err)
            continue
        }
        got := ComputeJA4(info)
        if got != wantJA4 {
            t.Errorf("%s: JA4 = %q; want %q", name, got, wantJA4)
        }
    }
}
```

**After Group 8:** `GOROOT=/snap/go/current go test ./internal/tls/...` passes.

---

## Group 9: Cross-Language Parity Tests

These tests verify Go and Python produce identical decisions for identical inputs.
They live in the Python test suite (`tests/`) and require both proxies running.

### 9a. Create `tests/integration/test_go_python_parity.py`

This file requires:
- A `go_proxy` pytest fixture that builds and starts the Go binary on port 8082
- The Python proxy running on port 8080 (already covered by existing fixtures)

**File to create:** `tests/integration/test_go_python_parity.py`

```python
"""
Cross-language parity tests: Go proxy vs Python proxy must make identical
decisions for identical inputs.

Requires: Go binary at bin/ja4proxy (build with: GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy)
Mark with: pytest -m go_parity (skip if Go binary not built)
"""
import pytest, subprocess, os, socket, time

GO_PROXY_PORT = 8082
GO_BINARY = "bin/ja4proxy"

@pytest.fixture(scope="module")
def go_proxy():
    if not os.path.exists(GO_BINARY):
        pytest.skip(f"Go binary not found at {GO_BINARY}; run: GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy")
    proc = subprocess.Popen(
        [GO_BINARY, "--port", str(GO_PROXY_PORT), "--config", "config/proxy.yml"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1)  # wait for startup
    yield proc
    proc.terminate()
    proc.wait(timeout=5)

def test_go_proxy_starts(go_proxy):
    """Go proxy must start and accept connections."""
    with socket.create_connection(("127.0.0.1", GO_PROXY_PORT), timeout=2) as s:
        pass

def test_go_proxy_health(go_proxy):
    """Go proxy /health must return 200 and {"status":"ok"}."""
    import requests
    r = requests.get(f"http://127.0.0.1:9092/health", timeout=2)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_go_proxy_metrics_present(go_proxy):
    """Go proxy /metrics must expose ja4proxy_ prefixed metrics."""
    import requests
    r = requests.get(f"http://127.0.0.1:9092/metrics", timeout=2)
    assert "ja4proxy_connections_total" in r.text
    assert "ja4proxy_active_connections" in r.text

def test_h2_alpn_bypass_identical(go_proxy):
    """h2 ALPN connections must be allowed by both proxies without scoring."""
    # Send synthetic ClientHello with h2 ALPN to Go proxy on 8082
    # Verify connection is forwarded (not RST)
    # Implementation: craft raw ClientHello bytes with h2 ALPN and send to port
    pass  # TODO: implement with raw socket after binary is running

def test_known_bad_ja4_block_identical(go_proxy):
    """Known-bad JA4 in blacklist must be blocked by Go proxy."""
    pass  # TODO

def test_dial_zero_monitor_mode(go_proxy):
    """At dial=0, Go proxy must allow all scored connections."""
    pass  # TODO
```

**Note:** The `pass` tests are stubs. Fill them in after the Go binary runs end-to-end.

### 9b. Create `tests/chaos/test_go_proxy_chaos.py`

**File to create:** `tests/chaos/test_go_proxy_chaos.py`

```python
"""
Chaos tests for the Go proxy.
These require the Go binary to be built (see test_go_python_parity.py).
"""
import pytest, subprocess, os, signal, time, socket

pytestmark = pytest.mark.skipif(
    not os.path.exists("bin/ja4proxy"),
    reason="Go binary not built"
)

def test_go_proxy_adversarial_clienthello_no_panic():
    """Every adversarial corpus file must not cause a goroutine panic."""
    import glob
    corpus = glob.glob("tests/adversarial/corpus/*.bin")
    if not corpus:
        pytest.skip("no adversarial corpus files")
    for path in corpus:
        with open(path, "rb") as f:
            data = f.read()
        # Send data to Go proxy, verify no panic in stderr
        # (Go panics print "goroutine ... [running]" and "panic:" to stderr)
        proc = subprocess.run(
            ["bin/ja4proxy-parser", path],  # test-only binary that only parses, does not serve
            capture_output=True, timeout=5
        )
        assert b"panic:" not in proc.stderr, f"panic for {path}:\n{proc.stderr.decode()}"
        assert b"runtime error:" not in proc.stderr

def test_go_proxy_redis_fail_open():
    """When Redis is unreachable, Go proxy must allow connections (dial defaults to 0)."""
    pass  # TODO: Start Go proxy with invalid Redis URL; verify connections are allowed

def test_go_proxy_sigterm_drain():
    """SIGTERM during active connections must drain within timeout."""
    pass  # TODO
```

**After Group 9:** Python test suite still passes. Go parity tests pass where implemented.

---

## Group 10: Performance Benchmarks

### 10a. Create `tests/performance/test_bench_go_proxy.py`

**File to create:** `tests/performance/test_bench_go_proxy.py`

```python
"""
Performance benchmarks comparing Go proxy vs Python proxy throughput.
Requires both proxies running.

Run with: python3 -m pytest tests/performance/test_bench_go_proxy.py -v -s
"""
import pytest, time, socket, threading, os

pytestmark = pytest.mark.skipif(
    not os.path.exists("bin/ja4proxy"),
    reason="Go binary not built"
)

PYTHON_PORT = 8080
GO_PORT = 8082
DURATION_SECONDS = 10

def _count_connections(port: int, duration: float) -> int:
    """Open as many TCP connections as possible in duration seconds."""
    count = 0
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                count += 1
        except (ConnectionRefusedError, OSError):
            pass
    return count

def test_go_throughput_5x_python():
    """Go proxy must handle ≥5× connections/second vs Python at same load."""
    py_conns = _count_connections(PYTHON_PORT, DURATION_SECONDS)
    go_conns = _count_connections(GO_PORT, DURATION_SECONDS)
    py_rate = py_conns / DURATION_SECONDS
    go_rate = go_conns / DURATION_SECONDS
    assert go_rate >= py_rate * 5, (
        f"Go rate {go_rate:.0f} conn/s not ≥5× Python rate {py_rate:.0f} conn/s"
    )

def test_go_allow_bypass_latency():
    """h2 ALPN bypass: p99 latency must be < 1ms."""
    pass  # TODO: measure per-connection latency with timestamped raw sockets
```

---

## Group 11: Documentation + Switching Mechanism

### 11a. Create `docs/decisions/ADR-015.md`

Move the content from `docs/phases/PHASE_15b.md §4` into a real ADR file.

**File to create:** `docs/decisions/ADR-015.md`

Copy the content of the `## 4. ADR-015: Why Go Not Rust` section from
`docs/phases/PHASE_15b.md` into this file, using the standard ADR format already
established in `docs/decisions/ADR-001.md`.

### 11b. Create `docs/runbooks/go_proxy_migration.md`

Move the content from `docs/phases/PHASE_15b.md §5` into a real runbook.

**File to create:** `docs/runbooks/go_proxy_migration.md`

Copy the content of the `## 5. Operator Migration Runbook` section from
`docs/phases/PHASE_15b.md`.

### 11c. Create `docs/runbooks/go_proxy_operations.md`

Move the content from `docs/phases/PHASE_15b.md §7` into a real runbook.

**File to create:** `docs/runbooks/go_proxy_operations.md`

Copy the content of the `## 7. GC Tuning Guidance` section from `docs/phases/PHASE_15b.md`.

### 11d. Create `docker-compose.go.yml`

**File to create:** `docker-compose.go.yml`

This compose file runs the Go proxy alongside the existing Python proxy stack. It extends
`docker-compose.poc.yml` and replaces only the proxy service.

```yaml
# docker-compose.go.yml — runs Go proxy on port 8082 for parallel validation.
# Usage: docker compose -f docker-compose.poc.yml -f docker-compose.go.yml up
#
# Go proxy listens on :8082; Python proxy remains on :8080.
# HAProxy can route traffic to either via weight configuration.

services:
  go-proxy:
    build:
      context: .
      dockerfile: Dockerfile-go
      network: host
    ports:
      - "8082:8080"   # Go proxy on host port 8082
      - "9092:9090"   # Go proxy metrics on host port 9092
    environment:
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
      BACKEND_HOST: "${BACKEND_HOST:-backend}"
      BACKEND_PORT: "${BACKEND_PORT:-443}"
      ENVIRONMENT: "${ENVIRONMENT:-development}"
    depends_on:
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9090/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

### 11e. Update README.md

**File to edit:** `README.md`

Add a section after the existing "Quick Start" section:

```markdown
## Running the Go Proxy

The Go proxy is a drop-in replacement for the Python proxy with identical behaviour
and ≥5× throughput. It reads the same `config/proxy.yml` and uses the same Redis schema.

### Build

```bash
GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy
./bin/ja4proxy  # reads config/proxy.yml
```

### Parallel Validation (recommended before cutover)

Run Python and Go proxies side-by-side:

```bash
# Start full stack with both proxies
docker compose -f docker-compose.poc.yml -f docker-compose.go.yml up

# Python proxy:  localhost:8080
# Go proxy:      localhost:8082
# Go metrics:    localhost:9092/metrics
# Go health:     localhost:9092/health
```

Run parity tests:
```bash
python3 -m pytest tests/integration/test_go_python_parity.py -v
```

### Switching HAProxy to Go Proxy

Edit `haproxy.cfg` backend block:
```
backend proxy_backend
    server go-proxy go-proxy:8080 weight 100
    # server python-proxy proxy:8080 weight 0
```

### Rollback

Change HAProxy weights back. Python proxy stays warm throughout parallel validation.

### Permanently Fixing GOROOT

The snap Go installation points GOROOT at a non-existent path. Fix once:
```bash
echo 'export GOROOT=/snap/go/current' >> ~/.bashrc && source ~/.bashrc
```
```

### 11f. Update `CHANGELOG.md`

**File to edit:** `CHANGELOG.md`

Add an entry following the existing format. Fill in the performance numbers after
Group 10 benchmarks are complete:

```markdown
## [15.0.0] - 2026-MM-DD - Go Proxy Rewrite

### Added
- Go proxy (`cmd/proxy/`) replacing Python `proxy.py` as the primary proxy binary
- All Phase 0–14 security signals ported to Go: TLS enforcer, SNI analyzer, TCP
  analyzer, ASN classifier, DNS enrichment, blocklists, beaconing detector,
  AbuseIPDB, RDAP enrichment, analytics signals, rate limiter
- Prometheus metrics HTTP server on `:9090` with identical metric names/labels to Python
- `/health` endpoint with Redis connectivity check
- PROXY protocol v1 support for real client IP extraction
- `Dockerfile-go` multi-stage build (runtime image ≤ 10MB)
- `docker-compose.go.yml` for parallel Python + Go validation

### Performance
- Throughput: XX,XXX conn/s (Go) vs XXX conn/s (Python) = XX× improvement
- p99 latency (allow bypass): XXXµs

### Unchanged
- Python analytics container (`analytics/`) — stays Python; scipy ecosystem
- Redis key schema — identical; Python and Go share one Redis instance
- `config/proxy.yml` schema — unchanged; Go reads the same file
```

---

## Final Acceptance Checklist

Before marking Phase 15 complete, every item in this list must be verified:

### Functional
- [ ] `GOROOT=/snap/go/current go build ./...` completes with zero errors
- [ ] `GOROOT=/snap/go/current go test ./...` shows `ok` for all packages
- [ ] Go proxy reads `config/proxy.yml` without error
- [ ] All signal modules produce non-zero scores for known-bad inputs
- [ ] TLS 1.0/1.1 connections are hard-blocked when `block_tls_10/11: true`
- [ ] h2/h1 ALPN connections are always allowed (bypass before scoring)
- [ ] Known-bad JA4 fingerprints in blacklist are hard-blocked
- [ ] At `dial=0`, ALL non-hard-blocked connections return action=allow

### Parity
- [ ] JA4 binary parity: all `.bin` fixtures produce identical output to Python
- [ ] `tests/integration/test_go_python_parity.py` passes all non-stub tests
- [ ] Prometheus metric names match Python (no `ja4_` prefix, all have `ja4proxy_`)

### Infrastructure
- [ ] `/health` returns `{"status":"ok","redis":"ok"}` when Redis is up
- [ ] `/metrics` exposes `ja4proxy_connections_total` and `ja4proxy_active_connections`
- [ ] PROXY protocol v1 header correctly extracts client IP
- [ ] PubSub reconnects after Redis disconnect (chaos test passes)
- [ ] SIGTERM drains connections within `drain_timeout_seconds`
- [ ] `docker compose -f docker-compose.poc.yml -f docker-compose.go.yml up` works

### Documentation
- [ ] `docs/decisions/ADR-015.md` exists
- [ ] `docs/runbooks/go_proxy_migration.md` exists with rollback procedure
- [ ] `docs/runbooks/go_proxy_operations.md` exists with GC tuning guidance
- [ ] `CHANGELOG.md` entry with measured performance numbers
- [ ] README has "Running the Go Proxy" section

### Performance
- [ ] Go throughput ≥5× Python at equivalent Redis load
- [ ] p99 GC pause <1ms at 1,000 conn/s sustained load

---

## End of Subplan
