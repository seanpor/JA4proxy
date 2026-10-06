# State Store & Distributed Rate-Limiting Invariants

## Goal
Implement property-based invariant test suites for JA4proxy's Redis state store and atomic Lua sliding-window rate limiter (`internal/redis`). Establish formal guarantees using `miniredis` that atomic rate-limiting scripts prevent race conditions under concurrent worker contention, that requests expire deterministically after window duration $W$, that key TTLs strictly enforce data minimisation, and that embedded Lua scripts remain identical across repository locations.

---

## Read These First
- `internal/redis/lua.go` (embedded sliding window script and SHA management)
- `internal/redis/scripts/sliding_window.lua` (atomic rate limiting Lua script)
- `internal/redis/client.go` (Redis client interface)
- `internal/redis/lua_test.go` (existing miniredis unit tests)

---

## Verified API Surface
- `//go:embed scripts/sliding_window.lua` — `internal/redis/lua.go:9`
- `(*Client).SlidingWindowSHA()` — `internal/redis/client.go`
- `miniredis.RunT(t)` — `github.com/alicebob/miniredis/v2`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-REDIS-001` | Atomic Sliding Window Count | $\text{Exec}(N \text{ concurrent at } t) \implies \text{Count} == N$ | Prevents race conditions from granting unauthorized requests during high-concurrency rate-limit bursts. |
| `INV-REDIS-002` | Timestamp Expiration | $\forall t' \ge t + W, \quad \text{Contribution}(req_t, t') == 0$ | Guarantees expired rate-limit counts drop off cleanly without residual enforcement penalty. |
| `INV-REDIS-003` | GDPR TTL Enforcement | $\forall K \in \text{KeysWritten}, \quad \text{TTL}(K) \le \text{ARGV}[3]$ | Enforces GDPR data minimisation by guaranteeing client IP state automatically expires from Redis. |
| `INV-REDIS-004` | Lua Script Embedded Parity | $\text{Hash}(\text{scripts/}) \equiv \text{Hash}(\text{internal/redis/scripts/})$ | Prevents configuration drift or accidental desynchronization between root and internal Redis scripts. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/redis/lua_invariant_test.go`
```go
package redis_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/seanpor/ja4proxy/internal/redis"
	"pgregory.net/rapid"
)

func TestInvariant_Redis_AtomicSlidingWindowCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		defer rdb.Close()

		sha, err := rdb.ScriptLoad(context.Background(), redis.SlidingWindowScript).Result()
		if err != nil {
			t.Fatalf("ScriptLoad failed: %v", err)
		}

		numWorkers := rapid.IntRange(5, 30).Draw(t, "numWorkers")
		key := fmt.Sprintf("test-ip-%d", rapid.Int().Draw(t, "ipID"))
		counterKey := key + ":count"
		now := float64(time.Now().Unix())

		var wg sync.WaitGroup
		wg.Add(numWorkers)

		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				_, _ = rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, now, 60, 120).Result()
			}()
		}
		wg.Wait()

		res, err := rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, now, 60, 120).Result()
		if err != nil {
			t.Fatalf("EvalSha failed: %v", err)
		}

		count, ok := res.(int64)
		if !ok {
			t.Fatalf("Unexpected EvalSha return type: %T", res)
		}
		if count != int64(numWorkers+1) {
			t.Fatalf("Atomic window count mismatch: got %d, want %d", count, numWorkers+1)
		}
	})
}
```

---

## Make It Fail First

| Invariant ID | Temporary Code Mutation | Expected Test Failure |
|---|---|---|
| `INV-REDIS-001` | Remove `ZADD` or atomic transaction from `sliding_window.lua` | `TestInvariant_Redis_AtomicSlidingWindowCount` fails count assertion |
| `INV-REDIS-002` | Remove `ZREMRANGEBYSCORE` call from `sliding_window.lua` | Expiration invariant test retains expired elements |
| `INV-REDIS-003` | Omit `EXPIRE` call at end of `sliding_window.lua` | TTL test detects non-expiring key (`TTL == -1`) |
| `INV-REDIS-004` | Add a comment to `scripts/sliding_window.lua` | `TestInvariant_Redis_ScriptEmbeddedParity` fails byte comparison |

---

## Test Commands

- **Run Redis Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/redis -run '^TestInvariant_Redis_'`
- **Run Invariant Suite:**
  `make test-invariants`

---

## Coverage Target

- **Package `internal/redis` Baseline:** 91.7%
- **Target Coverage:** $\ge 95.0\%$

---

## Acceptance Criteria

- [x] `internal/redis/lua_invariant_test.go` created and all 4 invariants passing.
- [x] Invariants registered in `docs/testing/invariants.yaml`.
- [x] Package `internal/redis` coverage verified $\ge 95.0\%$.
- [x] Mutation check table verified.
- [x] News fragment created in `docs/fragments/phase-606d-redis-invariants.md`.
- [x] `make preflight` passes 100% green.

---

## Out of Scope
- Security score calculation (covered in Phase 606f).
- Proxy connection handling (covered in Phase 606b).
