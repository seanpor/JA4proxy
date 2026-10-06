# State Store & Distributed Rate-Limiting Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's rate limiting, token bucket, and Redis-backed distributed state management (`internal/ratelimit/` and `scripts/sliding_window.lua`). Establish formal mathematical guarantees that token counters never become negative under concurrent worker contention, that token refills are strictly monotonic and bounded by capacity, that sliding window state decays accurately over time, and that Redis disconnection events deterministically trigger the configured fallback policy with appropriate metric emission.

---

## Scope
1. **Target Packages**:
   - `internal/ratelimit/` (Token bucket algorithms, sliding window state, Redis client interface).
   - `scripts/sliding_window.lua` (Redis atomic Lua script for rate limiting).
2. **New Test Files**:
   - `internal/ratelimit/ratelimit_invariant_test.go`
3. **Formal Invariants to Enforce**:
   - **Invariant 1 (Token Non-Negativity)**:
     For a bucket with capacity $C$ and refill rate $R$:
     $$\forall t \ge 0, \quad \text{AvailableTokens}(t) \ge 0$$
     No race condition or concurrent request burst may ever cause the available token count to drop below zero.
   - **Invariant 2 (Monotonic Refill & Bounded Capacity)**:
     In the absence of consumption between times $t_1 < t_2$:
     $$\text{Tokens}(t_1) \le \text{Tokens}(t_2) \le C$$
     $$\text{Tokens}(t_2) = \min(C, \; \text{Tokens}(t_1) + R \times (t_2 - t_1))$$
   - **Invariant 3 (Sliding Window Expiry & Conservation)**:
     In a sliding window of duration $W$:
     A request recorded at time $t$ must contribute exactly 1 to window counts for all $t' \in [t, t + W)$, and strictly 0 for all $t' \ge t + W$.
   - **Invariant 4 (Redis Disconnect Determinism & Telemetry)**:
     When the backing Redis store becomes unreachable or times out:
     - The rate limiter must execute the configured fallback policy (e.g., fail-open or fail-closed) deterministically for 100% of subsequent requests.
     - The metric `ratelimit_redis_errors_total` must increment on every encountered failure (zero silent swallows).

---

## Junior Developer Implementation Guide

### Step 1: Set up Test Harness & Miniredis
In `internal/ratelimit/ratelimit_invariant_test.go`:
```go
package ratelimit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/seanpor/ja4proxy/internal/ratelimit"
)
```

### Step 2: Implement Invariant 1 Test (Token Non-Negativity under Concurrent Contention)
```go
func TestInvariant_TokenNonNegativity(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Rate limiter with capacity 10, refill 0 (pure exhaustion test)
	limiter := ratelimit.NewLimiter(rdb, ratelimit.Config{
		Capacity: 10,
		Rate:     0,
	})

	const numWorkers = 50
	var allowedCount int64
	var deniedCount int64
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			allowed, err := limiter.Allow(context.Background(), "test-client-ip")
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			} else {
				atomic.AddInt64(&deniedCount, 1)
			}
		}()
	}

	wg.Wait()

	if allowedCount != 10 {
		t.Fatalf("Token non-negativity violated: allowed %d tokens, expected exactly 10", allowedCount)
	}
	if deniedCount != 40 {
		t.Fatalf("Excess tokens granted: denied %d, expected 40", deniedCount)
	}

	// Verify balance stored in Redis is 0 (never negative)
	tokens := limiter.GetTokens(context.Background(), "test-client-ip")
	if tokens < 0 {
		t.Fatalf("Balance became negative: %f", tokens)
	}
}
```

### Step 3: Implement Invariant 2 Test (Monotonic Refill)
1. Initialize bucket with capacity 100, empty it completely.
2. Fast-forward clock by $\Delta t_1$, verify tokens equal $R \times \Delta t_1$.
3. Fast-forward clock by $\Delta t_2$, verify tokens equal $\min(C, R \times (\Delta t_1 + \Delta t_2))$.
4. Fast-forward clock by large duration ($10 \times C / R$), verify tokens strictly equal $C$ and never exceed capacity.

### Step 4: Implement Invariant 3 Test (Sliding Window Expiry)
1. Send 5 requests at $t = 0$.
2. Advance time to $t = W - 1\text{ms}$, assert rate count is 5.
3. Advance time to $t = W + 1\text{ms}$, assert rate count is 0 (all previous requests expired).

### Step 5: Implement Invariant 4 Test (Redis Down Fallback)
1. Close `mr.Close()`.
2. Configure `FailOpen: true`.
3. Call `limiter.Allow()`. Assert `allowed == true`, error logged, and error metric incremented.
4. Switch to `FailOpen: false`. Assert `allowed == false`, error logged, and error metric incremented.

---

## Test Strategy
- Run rate-limiting invariant suite:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/ratelimit -run RateLimitInvariant`
- Run with race detector to catch any concurrency violations:
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -race -v ./internal/ratelimit`

---

## Acceptance Criteria
- [ ] `internal/ratelimit/ratelimit_invariant_test.go` implemented and passing.
- [ ] Token non-negativity mathematically held across 50 concurrent goroutines.
- [ ] Refill monotonicity and capacity upper bound verified.
- [ ] Sliding window timestamp expiration verified without residual leak.
- [ ] Redis disconnection deterministically follows configured fail-open/fail-closed behavior.
- [ ] `make test-unit` and `make preflight` pass 100% green.

---

## Out of Scope
- Threat intelligence feed loading (covered in 606f).
- Management UI rate limit configuration routes (covered in 606g).
