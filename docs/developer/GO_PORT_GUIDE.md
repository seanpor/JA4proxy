<!--
title: Go_Port_Guide
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Go Port Guide

> **Audience:** Developers writing security signals and working on the Go proxy core
> **Purpose:** Comprehensive guide for Go proxy development
> **Last Reviewed:** 2026-06-09
> **Status:** Production-Ready (Go proxy daemon is the sole runtime)
> **Related:** [Go Proxy Operations](../runbooks/go_proxy_operations.md)

---

## Executive Summary

This guide provides developer context for working on the Go proxy daemon (`ja4pd`) and the `ja4p` CLI. The Go proxy daemon achieves maximum performance and sub-millisecond connection handling latency.

**Key Resources:**
- 📁 **Go Code:** `cmd/ja4pd/`, `cmd/ja4p/`, and `internal/`
- 🧪 **Tests:** `tests/`
- 📊 **Benchmarks:** `docs/reports/PERFORMANCE_BENCHMARK.md`

---

## Getting Started

### Prerequisites

```bash
# Install Go (snap recommended)
sudo snap install go --classic

# Set GOROOT (snap Go fix)
echo 'export GOROOT=/snap/go/current' >> ~/.bashrc
source ~/.bashrc

# Verify installation
GOROOT=/snap/go/current go version
```

### Build and Run

```bash
# Initialize the development environment
make init

# Build Go proxy daemon and CLI
make build

# Run Go proxy daemon locally
./bin/ja4pd

# Docker build
docker compose -f deploy/docker/docker-compose.poc.yml build proxy
```

### Development Workflow

```bash
# Format code
go fmt ./...

# Run tests
GOROOT=/snap/go/current go test ./...

# Run specific test
GOROOT=/snap/go/current go test -v ./internal/security -run TestRiskScorer

# Lint code
golangci-lint run

# Check race conditions
GOROOT=/snap/go/current go test -race ./...
```

---

## Go Project Structure

```
cmd/
└── proxy/
    ├── main.go          # Entry point
    └── config/          # Configuration loading

internal/
├── tls/               # TLS parsing (ClientHello, JA4, JA4T)
│   ├── parser.go       # Raw byte parser
│   ├── ja4.go         # JA4 fingerprinting
│   └── ja4t.go         # JA4T fingerprinting
│
├── security/          # Security signal modules
│   ├── models.go       # Data models (ConnectionContext, etc.)
│   ├── pipeline.go     # Signal pipeline
│   ├── risk_scorer.go  # Scoring logic
│   ├── action_decider.go # Dial and action logic
│   ├── tls_enforcer.go # TLS version enforcement
│   ├── sni_analyzer.go # SNI analysis
│   ├── tcp_analyzer.go # TCP behavior analysis
│   ├── asn_classifier.go # ASN classification
│   ├── dns_enricher.go # DNS enrichment
│   ├── blocklist_manager.go # Blocklist management
│   ├── beaconing_detector.go # Beaconing detection
│   ├── abuseipdb_enricher.go # AbuseIPDB integration
│   └── rdap_enricher.go # RDAP enrichment
│
├── redis/             # Redis client
│   ├── client.go       # Basic client
│   ├── lua.go          # Lua script management
│   └── pubsub.go       # Pub/Sub
│
├── cache/             # Local caching
│   └── local.go        # LRU cache
│
└── config/            # Configuration
    └── loader.go       # YAML config loader
```

---

## Porting a Python Signal to Go

### Step 1: Study Python Reference

**Example: TLS Enforcer**

```python
# Python: src/security/tls_enforcer.py
class TLSEnforcer:
    def __init__(self, config):
        self.min_version = config.get("tls", {}).get("min_version", "TLSv1_2")
        self.blocked_ciphers = config.get("tls", {}).get("blocked_ciphers", [])
    
    def get_signal(self, conn):
        if conn.tls_version < self.min_version:
            return RiskSignal(
                name="tls_version_too_old",
                score=85,
                reason=f"TLS {conn.tls_version} < {self.min_version}",
                confidence=95
            )
        return None
```

### Step 2: Create Go Signal Module

```bash
# Create new file
touch internal/security/my_signal.go
```

**Go Implementation:**

```go
// internal/security/my_signal.go
package security

import (
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type MySignal struct {
	config      Config
	redisClient *redis.Client
	logger      *zap.Logger
}

// NewMySignal creates a new MySignal instance
func NewMySignal(config Config, redisClient *redis.Client, logger *zap.Logger) *MySignal {
	return &MySignal{
		config:      config,
		redisClient: redisClient,
		logger:      logger,
	}
}

// GetSignal analyzes connection and returns risk signal if threat detected
func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	if !s.config.MySignal.Enabled {
		return nil
	}

	// Implement detection logic
	if s.isMalicious(conn) {
		return &RiskSignal{
			Name:      "my_signal",
			Score:     float64(s.config.MySignal.Threshold),
			Reason:    "Detected [threat] from " + conn.IP,
			Confidence: 90,
			Evidence: map[string]interface{}{
				"ip":     conn.IP,
				"ja4":    conn.JA4,
				"detail": "[specific evidence]",
			},
		}
	}

	return nil
}

func (s *MySignal) isMalicious(conn *ConnectionContext) bool {
	// Implement Go detection logic
	// Match Python behavior exactly for parity
	return false
}
```

### Step 3: Register in Pipeline

**Edit `internal/security/pipeline.go`:**

```go
// Add to NewPipeline constructor
func NewPipeline(config Config, redisClient *redis.Client, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		config:      config,
		redisClient: redisClient,
		logger:      logger,
		signals: []SignalModule{
			// Existing signals...
			NewTLSEnforcer(config, redisClient, logger),
			NewMySignal(config, redisClient, logger), // Add your signal
		},
	}
}
```

### Step 4: Add Configuration

**Edit `internal/config/config.go`:**

```go
// Add to Config struct
type Config struct {
	// ... existing fields ...
	
	MySignal struct {
		Enabled   bool     `yaml:"enabled"`
		Threshold int      `yaml:"threshold"`
		CacheTTL  int      `yaml:"cache_ttl"`
		Sensitivity string `yaml:"sensitivity"`
		Whitelist []string `yaml:"whitelist"`
	} `yaml:"my_signal"`
}

// Add defaults
func (c *Config) ApplyDefaults() {
	// ... existing defaults ...
	
	if c.MySignal.Threshold == 0 {
		c.MySignal.Threshold = 75
	}
	if c.MySignal.CacheTTL == 0 {
		c.MySignal.CacheTTL = 3600
	}
	if c.MySignal.Sensitivity == "" {
		c.MySignal.Sensitivity = "medium"
	}
}
```

### Step 5: Add Prometheus Metrics

**Edit `internal/security/my_signal.go`:**

```go
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	mySignalDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ja4proxy_my_signal_detected_total",
			Help: "Number of connections with my_signal detected",
		},
		[]string{"action"},
	)
	
	mySignalProcessingTime = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ja4proxy_my_signal_processing_seconds",
			Help:    "Time spent processing my_signal",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		},
	)
)

// Update GetSignal method
func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("MySignal panic", zap.Any("recover", r))
			mySignalDetected.WithLabelValues("panic").Inc()
		}
	}()

	start := time.Now()
	defer func() {
		mySignalProcessingTime.Observe(time.Since(start).Seconds())
	}()

	if !s.config.MySignal.Enabled {
		mySignalDetected.WithLabelValues("disabled").Inc()
		return nil
	}

	// ... detection logic ...

	if signal != nil {
		mySignalDetected.WithLabelValues("detected").Inc()
	} else {
		mySignalDetected.WithLabelValues("clean").Inc()
	}

	return signal
}
```

**Update `docs/OBSERVABILITY_STANDARDS.md`:**

```markdown
### MySignal Metrics (Go)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ja4proxy_my_signal_detected_total` | Counter | `action` | Connections with signal detected |
| `ja4proxy_my_signal_processing_seconds` | Histogram | - | Processing time distribution |
```

---

## Key Differences: Python vs Go

### Language Differences

| Aspect | Python | Go | Notes |
|--------|--------|----|-------|
| **Error Handling** | `try/except` | Multiple returns | Go uses error returns, not exceptions |
| **Concurrency** | Threading/GIL | Goroutines | Go has true parallelism |
| **Dependencies** | pip | go.mod | Go has built-in dependency management |
| **Typing** | Dynamic | Static | Go is strictly typed |
| **Null** | `None` | `nil` | Different null representations |
| **Maps** | `dict` | `map[string]interface{}` | Go maps are strongly typed |
| **Lists** | `list` | `slice` | Go slices have fixed capacity |
| **String Formatting** | f-strings | `fmt.Sprintf` | No f-strings in Go |
| **Logging** | `logging` | `zap` | Structured logging in Go |

### Common Python → Go Translations

| Python | Go Equivalent |
|--------|--------------|
| `if x is None:` | `if x == nil {` |
| `try: ... except:` | `result, err := func(); if err != nil {` |
| `for item in list:` | `for _, item := range list {` |
| `dict.get(key, default)` | `val, ok := map[key]; if !ok { val = default }` |
| `list.append(item)` | `slice = append(slice, item)` |
| `f"Hello {name}"` | `fmt.Sprintf("Hello %s", name)` |
| `logging.info("msg")` | `logger.Info("msg")` |
| `raise Exception("msg")` | `return nil, errors.New("msg")` |
| `class MyClass:` | `type MyClass struct {` |
| `def method(self):` | `func (m *MyClass) Method() {` |

### Redis Client Differences

**Python:**
```python
import redis
r = redis.Redis(host='redis', password='pass')
r.get('key')
r.set('key', 'value', ex=3600)
```

**Go:**
```go
import "github.com/redis/go-redis/v9"
rdb := redis.NewClient(&redis.Options{
	Addr:     "redis:6379",
	Password: "pass",
	DB:       0,
})
val, err := rdb.Get(ctx, "key").Result()
err = rdb.Set(ctx, "key", "value", time.Hour).Err()
```

**Key Differences:**
- Go requires `context.Context` for all operations
- Go uses explicit error returns
- Go methods return `(result, error)` tuples
- Go has stronger typing for Redis responses

---

## Parity Testing

### Binary ClientHello Fixtures

**Capture real browser fingerprints:**
```bash
# Run capture script
python3 scripts/capture_clienthello.py

# Captures to tests/fixtures/clienthello/
# Format: chrome_123.bin, firefox_456.bin, etc.
```

**Use in tests:**
```go
// tests/parity/clienthello_test.go
func TestMySignalParity(t *testing.T) {
	// Load Python and Go implementations
	pySignal := python.NewMySignal(pyConfig)
	goSignal := go.NewMySignal(goConfig)
	
	// Load test fixtures
	fixtures, err := filepath.Glob("tests/fixtures/clienthello/*.bin")
	require.NoError(t, err)
	
	for _, fixture := range fixtures {
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		
		// Parse ClientHello
		conn, err := tls.ParseClientHello(data)
		require.NoError(t, err)
		
		// Get signals from both implementations
		pySignal := pySignal.GetSignal(conn)
		goSignal := goSignal.GetSignal(conn)
		
		// Compare scores
		if pySignal != nil && goSignal != nil {
			assert.Equal(t, pySignal.Score, goSignal.Score, "Score mismatch for %s", fixture)
		} else if pySignal != goSignal {
			t.Fatalf("Detection mismatch for %s: Python=%v, Go=%v", fixture, pySignal, goSignal)
		}
	}
}
```

### Run Parity Tests

```bash
# Run all parity tests
GOROOT=/snap/go/current go test -v ./tests/parity/

# Run specific test
GOROOT=/snap/go/current go test -v ./tests/parity -run TestMySignalParity

# Check coverage
GOROOT=/snap/go/current go test -cover ./tests/parity/
```

---

## Performance Optimization

### Go-Specific Optimizations

**1. Avoid Allocations in Hot Path:**
```go
// Bad: Creates new map on every call
func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	evidence := map[string]interface{}{
		"ip": conn.IP,
		"ja4": conn.JA4,
	}
	// ...
}

// Good: Reuse sync.Pool
var evidencePool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 4)
	},
}

func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	evidence := evidencePool.Get().(map[string]interface{})
	evidence["ip"] = conn.IP
	evidence["ja4"] = conn.JA4
	defer evidencePool.Put(evidence)
	// ...
}
```

**2. Use sync.Pool for Reusable Objects:**
```go
var signalPool = sync.Pool{
	New: func() interface{} {
		return &RiskSignal{}
	},
}

func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	signal := signalPool.Get().(*RiskSignal)
	signal.Name = "my_signal"
	// ... set other fields
	return signal
}
```

**3. Optimize String Operations:**
```go
// Bad: Creates many intermediate strings
reason := "Detected threat from " + conn.IP + " with JA4 " + conn.JA4

// Good: Use strings.Builder
var b strings.Builder
b.WriteString("Detected threat from ")
b.WriteString(conn.IP)
b.WriteString(" with JA4 ")
b.WriteString(conn.JA4)
reason := b.String()
```

**4. Minimize Redis Round Trips:**
```go
// Bad: Multiple round trips
val1, _ := rdb.Get(ctx, "key1").Result()
val2, _ := rdb.Get(ctx, "key2").Result()

// Good: Use pipeline
pipe := rdb.Pipeline()
cmd1 := pipe.Get(ctx, "key1")
cmd2 := pipe.Get(ctx, "key2")
_, err := pipe.Exec(ctx)
if err != nil {
	// handle error
}
val1, _ := cmd1.Result()
val2, _ := cmd2.Result()
```

---

## Debugging Go Code

### Common Issues and Fixes

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| **`undefined: symbol`** | Import missing | Check imports match case |
| **`cannot use nil`** | Nil type mismatch | Use proper typed nil |
| **`missing Go sum entry`** | Dependency issue | `go mod tidy` |
| **`GOROOT not set`** | Snap Go issue | `export GOROOT=/snap/go/current` |
| **Race conditions** | Intermittent failures | `go test -race` |
| **Memory leaks** | Growing memory | Use `pprof` to profile |
| **Deadlocks** | Goroutines hanging | Check channel usage |

### Debugging Tools

**CPU Profiling:**
```bash
# Start server with profiling
./ja4proxy --config config/proxy.yml --pprof :6060

# Capture profile
GOROOT=/snap/go/current go tool pprof http://localhost:6060/debug/pprof/profile

# Interactive analysis
(pprof) top10
(pprof) list MySignal.GetSignal
(pprof) web
```

**Memory Profiling:**
```bash
# Capture heap profile
GOROOT=/snap/go/current go tool pprof http://localhost:6060/debug/pprof/heap

# Check allocations
(pprof) top
(pprof) list MySignal
```

**Block Profiling:**
```bash
# Capture blocking operations
GOROOT=/snap/go/current go tool pprof http://localhost:6060/debug/pprof/block

# Find contention
(pprof) top
```

**Trace Analysis:**
```bash
# Capture execution trace
wget http://localhost:6060/debug/pprof/trace?seconds=5 -O trace.out

# Analyze trace
GOROOT=/snap/go/current go tool trace trace.out
```

---

## Testing Go Code

### Unit Tests

**Example Test Structure:**
```go
// internal/security/my_signal_test.go
package security

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestMySignal(t *testing.T) {
	// Setup
	logger, _ := zap.NewProduction()
	config := Config{
		MySignal: MySignalConfig{
			Enabled:   true,
			Threshold: 75,
		},
	}
	
	signal := NewMySignal(config, nil, logger)
	
	// Test cases
	t.Run("disabled", func(t *testing.T) {
		config.MySignal.Enabled = false
		signal := NewMySignal(config, nil, logger)
		conn := &ConnectionContext{IP: "1.2.3.4"}
		assert.Nil(t, signal.GetSignal(conn))
	})
	
	t.Run("detected", func(t *testing.T) {
		conn := &ConnectionContext{
			IP:   "1.2.3.4",
			JA4:  "malicious_fingerprint",
		}
		result := signal.GetSignal(conn)
		require.NotNil(t, result)
		assert.Equal(t, "my_signal", result.Name)
		assert.Equal(t, float64(75), result.Score)
	})
	
	t.Run("not_detected", func(t *testing.T) {
		conn := &ConnectionContext{
			IP:   "1.2.3.4",
			JA4:  "legitimate_fingerprint",
		}
		assert.Nil(t, signal.GetSignal(conn))
	})
}
```

### Integration Tests

**Test with Redis:**
```go
func TestMySignalWithRedis(t *testing.T) {
	// Setup test Redis
	rdb := miniredis.NewMiniRedis()
	defer rdb.Close()
	
	redisClient := redis.NewClient(&redis.Options{
		Addr: rdb.Addr(),
	})
	
	config := Config{
		MySignal: MySignalConfig{
			Enabled: true,
			Threshold: 75,
			CacheTTL: 3600,
		},
	}
	
	signal := NewMySignal(config, redisClient, zap.NewNop())
	conn := &ConnectionContext{IP: "1.2.3.4"}
	
	// Test Redis interaction
	result := signal.GetSignal(conn)
	assert.NotNil(t, result)
	
	// Verify Redis was called
	val, err := redisClient.Get(ctx, "my_signal:1.2.3.4").Result()
	require.NoError(t, err)
	require.NotEmpty(t, val)
}
```

### Benchmark Tests

**Add performance benchmarks:**
```go
func BenchmarkMySignal(b *testing.B) {
	config := Config{
		MySignal: MySignalConfig{
			Enabled: true,
			Threshold: 75,
		},
	}
	
	signal := NewMySignal(config, nil, zap.NewNop())
	conn := &ConnectionContext{
		IP:   "192.0.2.1",
		JA4:  "abc123def456",
		SNI:  "example.com",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signal.GetSignal(conn)
	}
}

# Run benchmark
GOROOT=/snap/go/current go test -bench=BenchmarkMySignal -benchmem
```

---

## Contribution Workflow

### Fork and Branch

```bash
# Fork repository on GitHub
# Clone your fork
git clone git@github.com:yourusername/ja4proxy.git
cd ja4proxy

# Create feature branch
git checkout -b feat/go-port-my-signal
```

### Implement and Test

```bash
# Implement signal
# Write tests
# Run tests
GOROOT=/snap/go/current go test ./internal/security -v

# Run all tests
GOROOT=/snap/go/current go test ./... -v

# Check linting
golangci-lint run

# Build binary
GOROOT=/snap/go/current go build -o bin/ja4pd ./cmd/ja4pd/
```

### Run Parity Tests

```bash
# Test against Python implementation
python3 -m pytest tests/parity/ -v

# Compare scores
python3 tools/compare_scores.py tests/fixtures/clienthello/
```

### Submit PR

```bash
# Commit changes
git add internal/security/my_signal.go
GOROOT=/snap/go/current go test ./...  # Verify all tests pass
git commit -m "feat(go): Port my_signal to Go"

# Push to your fork
git push origin feat/go-port-my-signal

# Create PR on GitHub
# Target: main branch
# Title: "Port my_signal to Go (Phase 15)"
# Description: Include benchmark results and parity test results
```

### PR Checklist

- [ ] ✅ Go signal module implemented
- [ ] ✅ Registered in pipeline
- [ ] ✅ Configuration added
- [ ] ✅ Prometheus metrics added
- [ ] ✅ Unit tests written (20+ tests)
- [ ] ✅ Integration tests written
- [ ] ✅ Benchmark tests added
- [ ] ✅ Parity tests pass
- [ ] ✅ Score parity with Python
- [ ] ✅ Performance ≥ Python baseline
- [ ] ✅ Documentation updated
- [ ] ✅ Code formatted (`go fmt`)
- [ ] ✅ Linting passes (`golangci-lint`)
- [ ] ✅ All tests pass

---

## Advanced Topics

### Goroutines for Parallel Processing

**Safe concurrent signal processing:**
```go
func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	// Use wait group for parallel operations
	var wg sync.WaitGroup
	var result *RiskSignal
	var mu sync.Mutex
	
	// Check cache
	wg.Add(1)
	go func() {
		defer wg.Done()
		cached, err := s.redisClient.Get(ctx, "my_signal:"+conn.IP).Result()
		if err == nil && cached == "1" {
			mu.Lock()
			result = &RiskSignal{
				Name:      "my_signal",
				Score:     float64(s.config.MySignal.Threshold),
				Reason:    "Cached detection",
				Confidence: 90,
			}
			mu.Unlock()
		}
	}()
	
	// Check external API
	wg.Add(1)
	go func() {
		defer wg.Done()
		if result == nil {  // Only if not cached
			// Call external API
			isBad, err := s.checkExternalAPI(conn)
			if err == nil && isBad {
				mu.Lock()
				result = &RiskSignal{
					Name:      "my_signal",
					Score:     float64(s.config.MySignal.Threshold),
					Reason:    "External API confirmed threat",
					Confidence: 95,
				}
				mu.Unlock()
			}
		}
	}()
	
	wg.Wait()
	
	if result != nil {
		// Cache result
		s.redisClient.Set(ctx, "my_signal:"+conn.IP, "1", 
			time.Duration(s.config.MySignal.CacheTTL)*time.Second)
	}
	
	return result
}
```

### Context Management

**Proper context handling:**
```go
func (s *MySignal) GetSignal(ctx context.Context, conn *ConnectionContext) *RiskSignal {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	
	// Pass context to Redis calls
	val, err := s.redisClient.Get(ctx, "key").Result()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.logger.Warn("MySignal timeout", zap.Error(err))
			mySignalDetected.WithLabelValues("timeout").Inc()
			return nil
		}
		// Handle other errors
	}
	
	// ... rest of logic
}
```

### Structured Logging

**Best practices for logging:**
```go
func (s *MySignal) GetSignal(conn *ConnectionContext) *RiskSignal {
	s.logger.Debug("Processing connection",
		zap.String("ip", conn.IP),
		zap.String("ja4", conn.JA4),
		zap.String("sni", conn.SNI))
	
	start := time.Now()
	defer func() {
		s.logger.Debug("Processing complete",
			zap.String("ip", conn.IP),
			zap.Duration("duration", time.Since(start)))
	}()
	
	// ... logic ...
	
	if result != nil {
		s.logger.Info("Threat detected",
			zap.String("ip", conn.IP),
			zap.Float64("score", result.Score),
			zap.String("reason", result.Reason))
	}
	
	return result
}
```

---

## Resources

### Go Learning Resources

**Official Documentation:**
- [Go Tour](https://tour.golang.org/) — Interactive introduction
- [Effective Go](https://golang.org/doc/effective_go.html) — Best practices
- [Go Blog](https://blog.golang.org/) — Official blog
- [Go Documentation](https://golang.org/doc/) — Complete docs

**Books:**
- "The Go Programming Language" — Donovan & Kernighan
- "Go in Action" — Kennedy
- "Concurrency in Go" — Katherine Cox-Buday

**Courses:**
- [Ultimate Go](https://github.com/hoanhan101/ultimate-go) — Advanced Go
- [Go by Example](https://gobyexample.com/) — Practical examples
- [Exercism Go Track](https://exercism.io/tracks/go) — Hands-on practice

### JA4proxy-Specific Resources

**Code References:**
- `internal/security/tls_enforcer.go` — Simple signal example
- `internal/security/abuseipdb_enricher.go` — External API example
- `internal/tls/parser.go` — Complex parsing example
- `internal/redis/client.go` — Redis client example

**Tools:**
- `tools/parity_test.py` — Score comparison tool
- `scripts/capture_clienthello.py` — Capture real traffic
- `tools/benchmark_go_vs_python.py` — Performance comparison

**Community:**
- GitHub Discussions: [github.com/ja4proxy/discussions](https://github.com/ja4proxy/discussions)
- Slack: #ja4proxy-go
- Office Hours: Thursdays 3-4pm UTC (Go-specific)

---

## Glossary

| Term | Definition |
|------|-----------|
| **Goroutine** | Lightweight thread managed by Go runtime |
| **Channel** | Typed conduit for communication between goroutines |
| **Context** | Request-scoped cancellation and deadlines |
| **Interface** | Set of method signatures (implicit implementation) |
| **Struct** | Collection of fields (like a class without methods) |
| **Receiver** | Method associated with a type (like `self` in Python) |
| **Slice** | Dynamically-sized view into an array |
| **Map** | Hash table (like Python dict) |
| **Defer** | Schedule function call to run after current function returns |
| **Panic** | Unrecoverable error (like unhandled exception) |
| **Recover** | Catch a panic (like try/catch) |
| **Race Condition** | Bug where output depends on timing of goroutines |

---

**Document Status:** ✅ Enterprise Standard (2026-03-27)
**Next Review:** 2026-06-27 (Quarterly)
**Maintainer:** Go Development Team

*Contribute: Help port signals to Go — every contribution accelerates Phase 15 completion!*