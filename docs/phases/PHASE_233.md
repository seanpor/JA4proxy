---
phase: 233
title: Observability Foundations
status: PROPOSED
size: MEDIUM
created: 2026-06-12
audience: [developer, operator, secops]
dependencies: [231, 232]
---

# Observability Foundations

> **Before you touch a line of code**, read `docs/phases/PHASE_231.md`.
> Every design decision in this phase is cited by number from that document
> (e.g. "Decision 3"). If you disagree with a decision, raise it
> in a PR comment — do not silently implement a different approach.

---

## 1. Plain-English Goal

When this phase is complete, the following observability and infrastructure goals will be achieved:

1. **Prometheus will monitor all components of the system.** If the tarpit or analytics engine fails, Prometheus will detect it and fire an alert.
2. **We will have alerting coverage for critical outages.** High-priority alerts will trigger if services go down, if Redis begins evicting keys, or if the management interface is unreachable.
3. **The database container will have a reduced attack surface.** The complex, memory-heavy `redis-stack` image will be replaced with a lightweight, secure, official `redis:7.4.0-alpine` image.
4. **Redis memory usage will be bounded.** The event stream (`events:connection`) will be capped to a maximum of 100,000 entries using approximate stream trimming (`XADD MAXLEN ~ 100000`). This ensures Redis does not crash due to memory exhaustion under high traffic.
5. **Operators will see Redis eviction counts directly in the dashboard.** The health cards grid will display any evicted keys count so operators can immediately detect memory pressure issues before they cause silent ban loss.

---

## 2. Background: Why Each Problem Matters

### 2.1 Prometheus Scrape Targets & Silent Outages
Prometheus works on a **pull model**. It regularly connects to configured endpoints (scrape targets) to pull metrics. If a service is not in `prometheus.yml`, it is invisible.
*   **The Problem:** The tarpit and analytics services generate metrics, but Prometheus does not scrape them. If the analytics engine stalls or the tarpit crashes, no one knows until a customer reports that a blocked IP is not being tarpitted.
*   **The Fix:** Configure scrape targets for `tarpit:9099` and `analytics:8080`.

### 2.2 Redis Eviction Whiteboard Analogy
Imagine you are a teacher writing names of misbehaving students on a small whiteboard. If the board fills up and you need to add a new name, you must erase an old one.
*   **The Problem:** In our system, dynamic IP bans are keys in Redis. If Redis runs out of memory and its policy is `allkeys-lru` (Least Recently Used), it will silently delete (evict) older keys to make room for new ones.
*   **The Operational Consequence:** Attackers who were banned will suddenly become unbanned without any logs or alerts. The system fails silently.
*   **The Fix:** Implement an alert for Redis evictions, cap the event stream to prevent memory exhaustion, and surface the eviction count in the Management UI.

### 2.3 Why `redis-stack` is an Unnecessary Attack Surface
`redis-stack` bundles Redis with modules like RediSearch, RedisJSON, RedisGraph, and RedisTimeSeries.
*   **The Problem:** Our production proxy uses only core Redis data structures (strings, sets, hashes, and streams). Bundling unused modules adds over 100MB of extra code, increases compile times, and exposes us to CVE vulnerabilities in libraries we do not use.
*   **The Fix:** Downgrade/replace `redis-stack` with standard, official `redis:7.4.0-alpine`.

### 2.4 Why `XADD MAXLEN` is Crucial
Every connection decision is written to the `events:connection` stream. Under high traffic (e.g., 500 connections/sec), this stream can grow by millions of entries per hour.
*   **The Problem:** Unbounded stream writes will consume all available host memory, triggering the Linux Out-Of-Memory (OOM) killer to terminate Redis or the proxy.
*   **The Fix:** Cap the stream at 100,000 entries. Using the approximate trim operator `~` (e.g., `MAXLEN ~ 100000`) allows Redis to trim entries when it is computationally efficient (usually at node boundaries), reducing write latency on the connection hot path.

---

## 3. Prerequisites

Before starting, verify your local environment:
1.  Verify the POC stack is running:
    ```bash
    cd /home/sean/LLM/JA4proxy2
    docker compose -f deploy/docker/docker-compose.poc.yml ps
    ```
2.  Ensure `promtool` is installed on your host (part of the Prometheus suite, used to validate alert rules):
    ```bash
    promtool --version
    ```

---

## 4. Step A: Add Prometheus Scrape Targets

We must add the scrape configurations for the `tarpit` and `analytics` services.

### File to modify: `deploy/monitoring/prometheus/prometheus.yml`

Apply the following changes:

```diff
     static_configs:
       - targets:
           - 'ja4proxy-redis-exporter:9121'
         labels:
           service: 'redis'
           role: 'database'
 
+  # Tarpit metrics
+  - job_name: 'ja4proxy-tarpit'
+    scrape_interval: 15s
+    static_configs:
+      - targets:
+          - 'tarpit:9099'
+        labels:
+          service: 'tarpit'
+          role: 'security-action'
+
   # Prometheus self-monitoring
   - job_name: 'prometheus'
     scrape_interval: 30s
```

### Verification
1.  Restart the Prometheus service:
    ```bash
    docker compose -f deploy/docker/docker-compose.monitoring.yml restart prometheus
    ```
2.  Open your browser and navigate to `http://localhost:9091/targets` (or the Prometheus dashboard port). Verify that `ja4proxy-tarpit` and `ja4proxy-analytics` show as `UP`.

---

## 5. Step B: Add Alert Rules

We must define Prometheus alerts to catch service outages and Redis evictions.

### File to modify: `deploy/monitoring/prometheus/alerts.yml`

Append the following alert rules to the respective groups:

```diff
   # ── Container health ────────────────────────────────────────────────────────
   - name: ja4proxy_container
     interval: 60s
     rules:
 
+      - alert: TarpitDown
+        expr: up{job="ja4proxy-tarpit"} == 0
+        for: 1m
+        labels:
+          severity: critical
+          component: tarpit
+        annotations:
+          summary: "Tarpit service is down"
+          description: "The tarpit service is unreachable. Connection slowing/tarpitting is failing."
+
+      - alert: AnalyticsDown
+        expr: up{job="ja4proxy-analytics"} == 0
+        for: 2m
+        labels:
+          severity: critical
+          component: analytics
+        annotations:
+          summary: "Analytics service is down"
+          description: "The ML/analytics service is down. Statistical drift and beaconing detection are inactive."
+
+      - alert: ManagementDown
+        expr: probe_success{instance="http://management:8090/ready"} == 0
+        for: 1m
+        labels:
+          severity: critical
+          component: management
+        annotations:
+          summary: "Management UI/API is down"
+          description: "The management console is unreachable. Operators cannot manage bans or monitor active alerts."
+
   # ── Redis ───────────────────────────────────────────────────────────────────
   - name: ja4proxy_redis
     interval: 60s
     rules:
+      - alert: RedisEvictionsDetected
+        expr: increase(redis_evicted_keys_total[1m]) > 0
+        for: 0m
+        labels:
+          severity: critical
+          component: redis
+        annotations:
+          summary: "Redis evicting keys — ban data loss imminent"
+          description: "Redis has reached maxmemory and is evicting keys. Active IP/JA4 bans are being deleted silently."
```

### Verification
Validate the alerts configuration syntax using `promtool`:
```bash
promtool check rules /home/sean/LLM/JA4proxy2/deploy/monitoring/prometheus/alerts.yml
```
*Expected Output:*
```
Checking /home/sean/LLM/JA4proxy2/deploy/monitoring/prometheus/alerts.yml
  SUCCESS: <number> rules found
```

---

## 6. Step C: Verify Alertmanager Routing

We must verify that Alertmanager is configured to forward the new alerts.

### File to check: `deploy/monitoring/alertmanager/alertmanager.yml`

Ensure that `alertmanager.yml` defines the appropriate routes for `critical` and `warning` severities. The standard file should route `severity: critical` to the `ops-team` or `oncall-pager`.

Validate the Alertmanager configuration syntax:
```bash
docker run --rm -v /home/sean/LLM/JA4proxy2/deploy/monitoring/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml prom/alertmanager:v0.27.0 --config.file=/etc/alertmanager/alertmanager.yml --check-config
```
*Expected Output:*
```
/etc/alertmanager/alertmanager.yml: SUCCESS
```

---

## 7. Step D: Replace `redis-stack` with `redis:7.4.0-alpine`

We will swap the heavyweight `redis-stack` image with the official lightweight alpine-based Redis.

### 7.1 Verify No Unused Modules are Utilized
Audit both Go and Python codebases to ensure we do not use RedisSearch (`FT.*`) or RedisJSON (`JSON.*`) commands:
```bash
grep -rn "FT\." /home/sean/LLM/JA4proxy2/src/ /home/sean/LLM/JA4proxy2/internal/ 2>/dev/null
grep -rn "JSON\." /home/sean/LLM/JA4proxy2/src/ /home/sean/LLM/JA4proxy2/internal/ 2>/dev/null
```
*(No results should be returned).*

### 7.2 Find and Pin the Image Digest
Search for the official SHA-256 digest of the `redis:7.4.0-alpine` image to ensure reproducible builds.
For this phase, use:
*   **Image name:** `redis:7.4.0-alpine`
*   **Digest:** `sha256:4d852a36b132e0e0a5ea6552a8a1eb3d1544a496f8a846170669be2d02c77d24` (or latest pinned 7.4.0-alpine digest).

### 7.3 File to modify: `deploy/docker/docker-compose.poc.yml`

Update the `redis` service definition:

```diff
   redis:
-    image: redis/redis-stack:7.4.0-v8
+    image: redis:7.4.0-alpine@sha256:4d852a36b132e0e0a5ea6552a8a1eb3d1544a496f8a846170669be2d02c77d24
     container_name: ja4proxy-redis
```

> [!NOTE]
> Since we are moving to standard Redis, the container no longer runs the redis-stack web console. This is an intentional security design choice (Decision 3) to reduce the attack surface.

### 7.4 Verify the Stack Boots
Rebuild and run the stack:
```bash
docker compose -f deploy/docker/docker-compose.poc.yml up -d --force-recreate redis
```

---

## 8. Step E: Cap the Event Stream with MAXLEN

We must limit the `events:connection` stream length in the Go proxy daemon to prevent memory leaks.

### 8.1 Identify the Code Location
The Go proxy writes events to the stream in `internal/redis/client.go` inside the `XAddErr` function.

### 8.2 Add the Configuration Parameter
Add `StreamMaxLen` to the Go config struct.

#### File to modify: `internal/config/loader.go`
```diff
 type ProxyConfig struct {
 	BindHost            string              `yaml:"bind_host"`
 	BindPort            FlexInt             `yaml:"bind_port"`
 	BackendHost         string              `yaml:"backend_host"`
 	BackendPort         FlexInt             `yaml:"backend_port"`
 	TarpitHost          string              `yaml:"tarpit_host"`
 	TarpitPort          FlexInt             `yaml:"tarpit_port"`
 	MaxConnections      int                 `yaml:"max_connections"`
 	DrainTimeoutSeconds int                 `yaml:"drain_timeout_seconds"`
 	ConnectionTimeout   int                 `yaml:"connection_timeout"`
 	ReadTimeout         int                 `yaml:"read_timeout"`
 	WriteTimeout        int                 `yaml:"write_timeout"`
 	ProxyProtocol       bool                `yaml:"proxy_protocol"`
 	BufferSize          int                 `yaml:"buffer_size"`
 	UpstreamTrust       UpstreamTrustConfig `yaml:"upstream_trust"`
 	WriteProxyProtocol        bool `yaml:"write_proxy_protocol"`
 	WriteProxyProtocolVersion int  `yaml:"write_proxy_protocol_version"`
+	StreamMaxLen              int64 `yaml:"stream_max_len"`
 }
```

#### File to modify: `config/proxy.yml`
```diff
   buffer_size: 8192
   # Enable PROXY protocol v2 support (for HAProxy)
   proxy_protocol: true
+  # Maximum event stream depth to prevent memory exhaustion
+  stream_max_len: 100000
```

### 8.3 Implement Stream Trimming in Redis Client

We must modify `XAddErr` in `internal/redis/client.go` to enforce `MaxLen` and `Approx` options.

#### File to modify: `internal/redis/client.go`
```diff
 func (c *Client) XAddErr(ctx context.Context, stream string, values map[string]interface{}) error {
+	// Cap at 100,000 using approximate trim.
+	// Approximately trimming avoids blocking the hot path by letting Redis trim in chunks.
 	if err := c.rdb.XAdd(ctx, &goredis.XAddArgs{
 		Stream: stream,
 		Values: values,
+		MaxLen: 100000,
+		Approx: true,
 	}).Err(); err != nil {
 		observeOp("xadd", "error")
 		c.log.WithError(err).WithField("stream", stream).Debug("redis: XADD failed")
```

Compile the Go codebase to verify it compiles cleanly:
```bash
GOROOT=/snap/go/current /snap/go/current/bin/go build ./...
```

---

## 9. Step F: Surface Eviction Count in Health Cards

We must display the current evicted keys count on the Management dashboard.

### 9.1 Query `INFO stats` in Python API

#### File to modify: `management/api/routes/partials.py`

Update `health_cards_partial`:

```diff
     # Gather health data
     redis_status = "error"
     active_bans = 0
     events_per_min = 0
+    evictions = 0
 
     try:
         await redis.ping()
         redis_status = "ok"
 
+        # Eviction count: query via INFO stats
+        try:
+            info = await redis.info("stats")
+            if info:
+                evictions = int(info.get("evicted_keys", 0))
+        except Exception as exc:
+            logger.warning("partials | event=redis_info_error | error=%s", exc)
+
         # Count active bans via SCAN
         cursor = 0
```

And include the evictions count in the Redis health card payload:

```diff
     health_cards = [
         {
             "label": "Redis",
-            "value": "OK" if redis_status == "ok" else "DOWN",
+            "value": f"OK ({evictions} evictions)" if redis_status == "ok" else "DOWN",
             "unit": "",
-            "status": "ok" if redis_status == "ok" else "error",
+            "status": "ok" if (redis_status == "ok" and evictions == 0) else ("warn" if evictions < 100 else "error"),
             "icon_path": "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4",
         },
```

### 9.2 Template Updates
Since the value is now a string (`OK (0 evictions)`), `health_cards.html` will automatically render it correctly in the `{{ card.value }}` element.

---

## 10. Tests to Run

Execute the following verification suites:

1.  **Run Go tests to ensure client and config changes work:**
    ```bash
    GOROOT=/snap/go/current /snap/go/current/bin/go test ./internal/redis/...
    ```
2.  **Run Python unit and page tests:**
    ```bash
    pytest tests/unit/
    ```
3.  **Validate metrics scraping:**
    Query the prometheus server via curl to ensure new targets are active:
    ```bash
    curl -s http://localhost:9091/api/v1/targets | jq '.data.activeTargets[].scrapeUrl'
    ```
    *(Verify `http://tarpit:9099/metrics` and `http://analytics:8080/metrics` are in the output).*

---

## 11. Definition of Done

*   [ ] `prometheus.yml` has scrape targets for both `tarpit` and `analytics`.
*   [ ] `alerts.yml` has rules for `TarpitDown`, `AnalyticsDown`, `RedisEvictionsDetected`, and `ManagementDown`.
*   [ ] `redis-stack` is completely replaced by `redis:7.4.0-alpine@sha256:...`.
*   [ ] The Go proxy daemon caps the connection event stream at 100k entries.
*   [ ] The management UI Redis health card shows the eviction count.
*   [ ] No Python f-strings are used in logging statements (lazy formatting only).
*   [ ] All tests (Go & Python) pass with zero errors, warnings, or skips.

---

## 12. Common Mistakes

*   **Forgetting GOROOT environment variable:** When compiling or testing Go, make sure you prefix the command with `GOROOT=/snap/go/current`.
*   **Specifying absolute MAXLEN size without approximate trimming (`~`):** Using strict `MAXLEN 100000` forces Redis to restructure the stream on every single write, creating massive CPU spikes on the connection hot path. Always use `Approx: true` in Go.
*   **Typo in Docker image digest:** Double check the SHA-256 digest character-by-character. A single typo will cause the build to fail with `image not found` or `digest mismatch`.
