<!--
title: Testing_Go
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# Testing the Go Proxy — Comparison with Python Tests

This document describes how Go tests differ from the Python test suite, and what
coverage responsibility each suite carries. Read `docs/TESTING_STRATEGY.md` for
the overarching testing strategy.

---

## Where Tests Live

| Layer | Python | Go |
|-------|--------|----|
| Unit tests | `tests/unit/test_*.py` | `internal/*/`_`*_test.go` (alongside source) |
| Integration | `tests/integration/test_*.py` | `tests/integration/test_go_python_parity.py` (Python) |
| Chaos / resilience | `tests/chaos/test_*.py` | `tests/chaos/test_go_proxy_chaos.py` (Python) |
| Performance | `tests/performance/test_bench_pipeline.py` | `tests/performance/test_bench_go_proxy.py` (Python) |
| Adversarial | `tests/adversarial/` | Go parser fuzz via `go test -fuzz` |

The Python integration, chaos, and performance tests run against the **live binary**
in Docker. This is why they are Python even for the Go proxy — they exercise the
running system, not individual packages.

---

## Unit Tests: Go vs Python

### What is the same

Both test suites verify **identical behaviour** for each signal module:
- Same signal names (`rate_limit_ban`, `sni_missing`, `tls_weak_cipher`, etc.)
- Same score values (matching the subplan spec)
- Same fail-open contract: disabled module → nil/empty signal; Redis error → nil signal

### What is different

#### Test location

Python unit tests are in a separate `tests/unit/` directory. Go unit tests live in the
same package directory as the code they test (`_test.go` suffix). This is idiomatic Go
and avoids import cycles.

```
Python: tests/unit/test_rate_limiter.py   ← tests src/security/rate_limiter.py
Go:     internal/security/rate_limiter_test.go  ← tests internal/security/rate_limiter.go
```

#### Test structure

Python uses `pytest` with fixtures and parametrize decorators:

```python
@pytest.mark.parametrize("tls_version,expected_block", [
    (0x0300, True),   # SSLv3
    (0x0301, True),   # TLS 1.0
    (0x0304, False),  # TLS 1.3
])
def test_tls_version_block(tls_version, expected_block):
    enforcer = TLSEnforcer(cfg=TLSEnforcerConfig(block_old_tls=True))
    _, hard_block = enforcer.check(tls_version=tls_version, ciphers=[])
    assert hard_block == expected_block
```

Go uses table-driven tests with `t.Run`:

```go
func TestTLSEnforcer_VersionBlock(t *testing.T) {
    cases := []struct {
        name      string
        version   uint16
        wantBlock bool
    }{
        {"SSLv3",  0x0300, true},
        {"TLS1.0", 0x0301, true},
        {"TLS1.3", 0x0304, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            enforcer := NewTLSEnforcer(&TLSEnforcerConfig{BlockOldTLS: true}, logrus.New())
            _, block := enforcer.Check(tc.version, nil)
            if block != tc.wantBlock {
                t.Errorf("got block=%v, want %v", block, tc.wantBlock)
            }
        })
    }
}
```

#### Mocking dependencies

Python uses `unittest.mock` or `pytest-mock`:

```python
def test_rate_limiter_ban(mocker):
    mock_redis = mocker.MagicMock()
    mock_redis.sliding_window_count.return_value = 200
    limiter = RateLimiter(cfg=..., redis=mock_redis)
    signals = limiter.check(ip="1.2.3.4", ja4="t13d...")
    assert any(s.name == "rate_limit_ban" for s in signals)
```

Go uses interface injection with hand-written mock structs:

```go
type mockRedis struct {
    slidingWindowCounts map[string]int
}

func (m *mockRedis) SlidingWindowCount(_ context.Context, key string, _, _ float64) int {
    return m.slidingWindowCounts[key]
}

func TestRateLimiter_BanThreshold(t *testing.T) {
    mock := &mockRedis{slidingWindowCounts: map[string]int{"ratelimit:ip:1.2.3.4": 200}}
    limiter := NewRateLimiter(&RateLimiterConfig{Enabled: true, ByIP: StrategyConfig{Enabled: true, Ban: 100}}, mock, nil)
    sigs := limiter.Check(context.Background(), "1.2.3.4", "")
    if len(sigs) == 0 || sigs[0].Name != "rate_limit_ban" {
        t.Fatalf("expected rate_limit_ban signal")
    }
}
```

The `mockRedis` struct in `../internal/security/pipeline_test.go` implements the full `RedisReader` interface.
All individual module tests that need Redis use the same mock.

#### Async behaviour

Python tests can `await` coroutines directly. Go tests use synchronous calls; background
goroutines are tested indirectly by checking their side effects (Redis writes) after a
brief `time.Sleep` or by draining a channel:

```go
// Trigger background lookup
abuseipdb.GetSignal("1.2.3.4")
// Drain the lookup channel
select {
case ip := <-capturedLookups:
    if ip != "1.2.3.4" { t.Fatal("wrong IP") }
case <-time.After(100 * time.Millisecond):
    t.Fatal("lookup not enqueued")
}
```

#### No conftest.py

Python tests share fixtures through `tests/conftest.py`. Go has no equivalent. Shared
test helpers are plain functions in the `_test.go` file or a `testutil_test.go` in the
same package.

---

## Running Tests

### Go unit tests (fast, no Docker)

```bash
# All packages
GOROOT=/snap/go/current go test ./...

# Single package
GOROOT=/snap/go/current go test -v ./internal/security/

# Single test
GOROOT=/snap/go/current go test -v -run TestRateLimiter_BanThreshold ./internal/security/

# Race detector (slow, use in CI)
GOROOT=/snap/go/current go test -race ./...

# Via Makefile
make go-test
```

### Python unit tests (fast, no Docker)

```bash
python3 -m pytest tests/unit/ -n auto --dist=loadfile
make test-unit
```

### Cross-language parity tests (requires both proxies running)

```bash
make go-start                                # start Go proxy on :8082
# wait ~10s for startup
make go-parity                               # runs test_go_python_parity.py
```

### Chaos tests for Go proxy (requires running Docker stack)

```bash
python3 -m pytest tests/chaos/test_go_proxy_chaos.py -v
```

---

## Coverage Responsibility

| Scenario | Python test? | Go test? |
|----------|-------------|----------|
| Signal names and scores match spec | ✓ | ✓ |
| Fail-open on Redis error | ✓ | ✓ |
| Fail-open on GeoIP DB absent | ✓ | ✓ |
| JA4 byte-for-byte parity with Python | ✓ parity test | ✓ unit vectors |
| PROXY protocol parsing | — | ✓ |
| Prometheus metric registration | — | ✓ |
| Full pipeline with real Redis | ✓ integration | — (parity test covers) |
| Docker stack health check | ✓ integration | ✓ chaos |
| Redis failure mid-traffic | ✓ chaos | ✓ go_proxy_chaos |
| Throughput ≥ 5× Python | — | ✓ bench_go_proxy.py |

---

## What "Almost Identical, But Not Quite" Means

The Go and Python test suites cover the same *behaviour* but differ in:

1. **Location**: Go tests are colocated with source; Python tests are in `tests/`.
2. **Fixtures**: Python uses pytest fixtures and conftest; Go uses table-driven tests
   and inline construction.
3. **Async**: Python tests await coroutines; Go tests check channel/side-effect outputs.
4. **Infrastructure tests**: Docker stack tests (health check, parity, chaos) are Python
   even for the Go proxy, because they test the deployed binary, not the library.
5. **Fuzz tests**: Go has a native fuzzer (`go test -fuzz`). The TLS parser adversarial
   test in `tests/adversarial/` is Python; the Go equivalent uses `go test -fuzz=FuzzParseTLS`.
