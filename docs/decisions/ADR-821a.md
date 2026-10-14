# ADR-821a: Management Console Prometheus Client Architecture, SSRF Inversion, and Concurrency Model

## Status

Accepted (Phase 821a)

## Context

The JA4proxy management console historically displayed operational data queried almost entirely from Redis keys (`proxy:heartbeat:*`, `config:dial`, `tarpit:active_count`). However, the Go proxy exports over 90 rich Prometheus metrics that remained unexposed in the console UI. Prior monitoring required external access to Grafana or direct Prometheus querying.

In design, several architectural and security constraints required formalization:

1. **Proxy Fail-Open vs. Console Fail-Visibly:** The core Go proxy is designed to fail open and shed load under saturation to preserve traffic flow. The management console, however, must **fail visibly**: when an external dependency (Prometheus) is unreachable or times out, the UI must report `Unavailable` alongside the last known timestamp, rather than silently failing open or rendering healthy zeroes.
2. **SSRF Policy Inversion:** `management/api/routes/webhooks.py` enforces a strict anti-SSRF policy rejecting private and loopback IP addresses. The console's Prometheus client must connect to `http://prometheus:9090` (an internal, private service on the management network). This creates an architectural SSRF policy inversion that must be strictly scoped to prevent general SSRF vulnerabilities.
3. **Absence of Initial Counter Series vs. False Positives:** Unlike `ConnectionsTotal` (which pre-initialises its label vectors), Prometheus counters in Go omit series entirely until their first non-zero increment. On a clean, healthy startup, counters such as `ja4proxy_audit_jobs_dropped_total` return empty query vectors. Conflating empty vectors with `Unavailable` causes a healthy system to report broken observability (a console false positive).
4. **Single-Flight Deduplication & Concurrency:** The console queries Prometheus on periodic UI polling cycles. Multiple simultaneous operators viewing the dashboard could trigger redundant query storms against Prometheus.

## Decision

1. **Three-State Query Representation:** Implement an explicit 3-state domain model:
   - `Ok(value, fetched_at)`: Query succeeded with data.
   - `Empty(fetched_at)`: Query completed successfully with an empty vector (emitted as a real 0 in the UI for counters).
   - `Unavailable(reason, last_ok_at)`: Prometheus unreachable or timed out (rendered as an explicit warning badge with last-known timestamp).
2. **Closed Allowlist of Declarative Tile IDs:** The console never accepts user-supplied PromQL strings or arbitrary query parameters from the browser. Requests invoke declarative Tile IDs resolved statically on the server from `management/api/metric_catalogue.py`.
3. **Hardcoded Outbound SSRF Target:** The Prometheus client target is restricted to `PROMETHEUS_URL` configured in the container environment (defaulting to `http://prometheus:9090`), validated at startup with scheme restricted to `http`/`https` and userinfo forbidden. `httpx.AsyncClient` is configured with `follow_redirects=False` to prevent redirect-based SSRF pivot attacks.
4. **10-Second Cache with Single-Flight Deduplication:** The client caches query results for 10 seconds (matching the proxy's scrape interval) and uses `asyncio.Future` single-flight coalescing so that $N$ concurrent browser requests result in exactly 1 upstream query.
5. **Coupling to `--workers 1`:** The in-memory cache and single-flight map are per-process. `Dockerfile.management` executes Uvicorn with `--workers 1`. If `--workers N` is ever configured, each worker will maintain independent caches, scaling Prometheus query load by $N$.

## Consequences

### Positive

- **Accurate Posture Visibility:** Enterprise SecOps operators immediately distinguish between zero degradation events (`Empty` $\rightarrow$ 0) and observability outages (`Unavailable`).
- **Security Invariance:** Zero user-controllable PromQL injection surface. Zero redirect SSRF hazard.
- **Resource Protection:** Bounded 2.0s timeouts, 10s TTL caching, and single-flight deduplication insulate Prometheus from operator query spikes.
- **Self-Observability:** Console queries are tracked by `ja4proxy_console_prometheus_queries_total{result="ok"|"empty"|"error"|"timeout"}`.

### Negative

- **Multi-Worker Scaling Constraint:** Horizontal scaling of the management container beyond 1 worker requires externalizing the query cache (e.g. into Redis) to prevent cache divergence across worker processes.
