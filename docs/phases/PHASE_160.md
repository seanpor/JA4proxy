# Phase 160: High-Concurrency Throughput Unblocking

> **Status:** PROPOSED
> **Size:** LARGE
> **Depends on:** Phase 159
> **Owner:** Gemini CLI

## Goal
Implement a high-performance, asynchronous connection handling architecture to break the 350 CPS ceiling and reach >1,000 CPS on a single host. We will achieve this by eliminating garbage collection thrashing and removing synchronous I/O stalls from the traffic path.

---

## Implementation Guide: Step-by-Step

### Step 1: Buffer Pooling (`sync.Pool`)
**The Problem:** Every new connection currently allocates a 16KB buffer. At 1,000 CPS, we are allocating 16MB per second, forcing the Go Garbage Collector (GC) to run constantly, which steals CPU time from the TLS handshake math.

**The Fix:** Use a reusable pool of buffers.
1. Define a global `sync.Pool` in `cmd/ja4pd/main.go`.
2. In the `handleConn` loop, instead of `make([]byte, size)`, call `pool.Get()`.
3. Ensure the buffer is returned to the pool using `defer pool.Put()` once the connection is closed.
4. **Crucial:** Always zero-out or reset the buffer length before reuse to prevent data leakage between connections.

### Step 2: Asynchronous Security Pipeline
**The Problem:** The proxy currently waits ~2ms for Redis to respond before it allows a connection to proceed. This "stalls" the worker thread and prevents parallel handling of the 15ms TLS handshakes.

**The Fix:** Decouple "Forwarding" from "Scoring".
1. **Local Cache**: Implement a small, thread-safe LRU cache (e.g., 10,000 entries) inside the Proxy to store recently seen JA4 dispositions (Allow/Block).
2. **The Logic Pivot**:
    - **Parse**: Extract JA4 from the ClientHello.
    - **Lookup**: Check the **Local Cache** first (nanosecond speed).
    - **Decision**:
        - If JA4 is in cache and marked **BLOCK** -> Drop connection immediately.
        - If JA4 is in cache and marked **ALLOW** -> Forward to backend immediately.
        - If **Cache Miss** -> Forward to backend immediately AND send the connection metadata to a background Go Channel.
3. **Background Worker**: A dedicated goroutine listens to the channel, performs the heavy Redis lookups, and updates the Local Cache.

### Step 3: Pipelined Redis Access
**The Problem:** We perform 4 separate round-trips to Redis per connection.

**The Fix:** Consolidate.
1. Use `redis.Pipeliner` or a single LUA script to check the Dial, Blacklist, and Whitelist in one network round-trip.
2. This ensures the background worker can keep up with the 1,000+ CPS traffic stream.

---

## Acceptance Criteria
- [ ] **Throughput**: Running `make bench` with 100 workers and 5% Good traffic reaches **>1,000 CPS** consistently.
- [ ] **Latency**: p99 latency for whitelisted traffic remains **< 10ms** under heavy load.
- [ ] **Memory**: RSS memory usage stays stable under 50MB (no leaks from the buffer pool).
- [ ] **Security**: A blocked JA4 fingerprint is successfully rejected by the Local Cache within 1 second of its first appearance.

---

## Strategic Intent
This refactor transitions JA4proxy from a "Linear Proxy" to a "Scalable Security Engine". By trusting the local cache for the majority of connections, we allow the Go runtime to focus its CPU cycles on the critical path: the TLS handshakes.
