# Phase 160: High-Concurrency Throughput Unblocking

> **Status:** PROPOSED
> **Size:** LARGE
> **Depends on:** Phase 159
> **Owner:** Gemini CLI

## Goal
Implement a high-performance, asynchronous architecture to break the 350 CPS ceiling and reach >1,000 CPS on a single host. We will achieve this by eliminating GC thrashing and removing synchronous I/O stalls from the traffic path.

---

## 🛠️ Implementation Guide: Detailed Technical Steps

### Step 1: Buffer Pooling (`sync.Pool`)
**Goal:** Reuse memory to stop the Garbage Collector from competing with TLS crypto math for CPU cycles.

**Files to modify:** `cmd/ja4pd/main.go`

1.  **Define the Pool**: Add a global `sync.Pool` at the top of the file (near other globals like `metrics`).
    ```go
    var bufferPool = sync.Pool{
        New: func() interface{} {
            // Allocate a slice with the configured buffer size
            // Default is usually 16KB (cfg.Proxy.BufferSize)
            return make([]byte, 32768) // Use a safe upper bound or dynamic size
        },
    }
    ```
2.  **Acquire from Pool**: Inside `func handleConn(...)`, replace the manual allocation:
    ```go
    // OLD: buf := make([]byte, cfg.Proxy.BufferSize)
    
    // NEW:
    bufInterface := bufferPool.Get()
    buf := bufInterface.([]byte)
    
    // Ensure we return it when done
    defer bufferPool.Put(bufInterface)
    ```
3.  **Safety Reset**: Before putting the buffer back in the pool, you MUST ensure it doesn't leak data.
    ```go
    // In the defer block above:
    defer func() {
        // Optional: clear the buffer if security requires it
        // for i := range buf { buf[i] = 0 }
        bufferPool.Put(bufInterface)
    }()
    ```

---

### Step 2: Local LRU Cache for Nanosecond Decisions
**Goal:** Avoid the 2ms Redis round-trip for connections we have already seen.

**Files to create:** `internal/security/cache.go`
**Files to modify:** `internal/security/pipeline.go`

1.  **Create the Cache Component**: Use a thread-safe map or a library like `golang-lru`.
    ```go
    type DecisionCache struct {
        cache *lru.Cache // map[ja4]disposition
    }
    ```
2.  **Integrate into Pipeline**: Add `Cache *DecisionCache` to the `Pipeline` struct in `internal/security/pipeline.go`.
3.  **The "Fast Decision" Logic**: Modify `pipeline.Process()` to check the cache immediately.
    ```go
    func (p *Pipeline) Process(ctx context.Context, conn *ConnectionContext) *PipelineResult {
        if res, hit := p.cache.Get(conn.JA4); hit {
            return res // Return in < 100ns
        }
        // ... proceed to background scoring if miss
    }
    ```

---

### Step 3: Asynchronous Scoring Loop
**Goal:** Move the "Waiting for Redis" part out of the client's critical path.

**Files to modify:** `internal/security/pipeline.go`, `cmd/ja4pd/main.go`

1.  **Define the Work Channel**: Add a `workChan chan *ConnectionContext` to the `Pipeline`.
2.  **Fire and Forget**: In `pipeline.Process()`, if there is a cache miss:
    - Return an immediate `Action: "allow"` (speculative).
    - Send the `conn` object into `p.workChan`.
3.  **The Background Worker**: In `ja4pd/main.go`, spawn a worker goroutine at startup:
    ```go
    go func() {
        for conn := range pipeline.WorkChan {
            // Perform synchronous Redis lookups here
            result := pipeline.PerformDeepScoring(conn)
            // Update the local cache with the new knowledge
            pipeline.Cache.Add(conn.JA4, result)
        }
    }()
    ```

---

### Step 4: Redis Pipelining (The "Batch" Fix)
**Goal:** Reduce the number of network packets between the Proxy and Redis.

**Files to modify:** `internal/redis/client.go`

1.  **Consolidate Calls**: Replace individual `Exists`, `Get`, `Incr` calls with a `redis.Pipeliner`.
    ```go
    pipe := r.rdb.Pipeline()
    dialCmd := pipe.Get(ctx, "config:dial")
    blackCmd := pipe.SIsMember(ctx, "blacklist", ja4)
    whiteCmd := pipe.SIsMember(ctx, "whitelist", ja4)
    _, err := pipe.Exec(ctx)
    ```
2.  **Parse Results**: Extract values from `dialCmd`, `blackCmd`, etc., after the `Exec()`. This reduces 4 round-trips to 1.

---

## ✅ Acceptance Criteria & Verification

### 1. Throughput Verification
Run the high-speed benchmark with 100 workers.
```bash
make bench ARGS="-good-rate 100 -bad-rate 900 -workers 100"
```
**Success:** Total CPS must exceed **1,000**.

### 2. Latency Verification
Check the `p99` latency in the benchmark output.
**Success:** Must be **< 10ms** (down from 800ms+).

### 3. Memory Stability
Monitor the proxy process during a 5-minute load test.
```bash
docker stats ja4proxy-proxy-1
```
**Success:** `MEM USAGE` stays flat (proving the buffer pool works and isn't leaking).

---

## 💡 Junior Engineer Tip: "Race Condition Safety"
When implementing the **Local Cache** and **Background Worker**, remember that Go maps are NOT thread-safe. Use `sync.RWMutex` or a validated LRU library to prevent panics under high concurrency.

---

## Strategic Intent
This phase transforms JA4proxy from a "Linear Proxy" to a "Scalable Security Engine". By trusting the local cache for 99% of decisions, we unlock the true power of the i9-9900K hardware.
