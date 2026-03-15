# Phase 12a — Analytics Node Foundation

## Status: MOSTLY DONE — 2 blocking gaps remain

Implementation exists in `src/analytics/`. 89 tests pass.

---

## What Is Already Implemented

### Container (`src/analytics/Dockerfile`, `entrypoint.sh`)
- Python 3.11-slim base, isolated from proxy container ✓
- `entrypoint.sh` waits for Redis before starting ✓
- Exposes port 8080 ✓
- **Gap**: `requirements-analytics.txt` is referenced in the Dockerfile but does not exist — Docker build will fail. Must be created.

### Event Ingestion (`src/analytics/stream_consumer.py`)
- Reads from `ja4proxy:events` Redis Stream via consumer group `analytics` ✓
- Consumer group replays unprocessed events on restart (no data loss) ✓
- Batch processing with configurable `batch_size` and `timeout_ms` ✓
- HMAC validation of incoming events (optional, controlled by `hmac_required` config) ✓

### Proxy-side publishing (`src/security/pipeline.py`)
- `_emit_stream_event()` fires via `asyncio.create_task()` — truly non-blocking ✓
- Uses synchronous `xadd()` — acceptable at current scale; upgrade to async in Phase 15 ✓
- Writes: `ip`, `ja4`, `risk_score`, `action_taken`, `dial_setting`, counterfactual fields ✓
- Stream key: `ja4proxy:events`, maxlen=100,000 (approximate trim) ✓

### Event Validation (`src/analytics/event_schemas.py`, `validation.py`)
- JSON Schema validation on incoming events ✓
- Field sanitisation, length limits, IP format checks ✓

### Cross-Instance Aggregation (`src/analytics/aggregation.py`)
- 5-minute rolling window per IP, IPv4 /24, IPv6 /48 ✓
- Metrics: request count, block rate, score stats ✓
- HyperLogLog unique IP counting per subnet (`pfadd`/`pfcount`) ✓
- Written to `analytics:agg:{window}:{subnet}` (TTL 300s) ✓

### Configuration (`src/analytics/config.py`, `config/analytics.yaml`)
- Full YAML config covering all 12a settings ✓
- Stream key, consumer group, batch size, HMAC, aggregation window all configurable ✓

### Prometheus Metrics (`src/analytics/monitoring.py`)
- `ja4proxy_analytics_events_received_total` ✓
- `ja4proxy_analytics_events_valid_total` ✓
- `ja4proxy_analytics_events_invalid_total` ✓
- `ja4proxy_analytics_processing_duration_seconds` ✓
- **Gap**: Metrics are instantiated but not exposed on an HTTP port. No HTTP server exists. `/health`, `/ready`, `/metrics` endpoints are methods only — nothing listens for incoming requests.

### Main Entry Point (`src/analytics/main.py`)
- `AnalyticsNode` class with shutdown signal handling ✓
- `health_check()` method ✓
- **Gap**: No HTTP server. `health_check()` is never called externally.

---

## Blocking Gaps — RESOLVED (2026-03-15)

### 1. HTTP server — DONE
`main.py` now runs an aiohttp server on port 8080 alongside the stream consumer.
Routes: `GET /health`, `GET /ready`, `GET /metrics`.
- `/health` — calls `health_check()`; 200 if Redis reachable, 503 otherwise
- `/ready` — pings Redis; 200 if connected, 503 otherwise
- `/metrics` — serves `generate_latest(monitoring_system.registry)`

### 2. `requirements-analytics.txt` — DONE
Rewritten at project root with correct pinned deps: redis, aioredis, aiohttp,
prometheus-client, pyyaml, jsonschema, numpy. Removed bloat (pandas, scipy,
structlog, cryptography, testing deps) from the previous broken version.

### 3. Docker-compose entry — DONE
`analytics` service added to `docker-compose.poc.yml` (replaces deleted
`management-ui`). Port `127.0.0.1:8082:8080`. Health check via wget.
`scripts/start-poc.sh` updated. `config.py` now reads `REDIS_HOST`,
`REDIS_PORT`, `REDIS_PASSWORD` from environment variables.

---

## Acceptance Criteria

### Functional
- [x] Independent analytics container — Dockerfile exists, correct base, no proxy bloat
- [x] Proxy publishes events to Redis Stream without blocking
- [x] Consumer group processes events with replay on restart
- [x] Event schema validation implemented
- [x] Basic aggregation writes to Redis
- [x] HyperLogLog counting operational
- [x] HTTP `/health` endpoint responds correctly
- [x] HTTP `/ready` endpoint responds correctly
- [x] HTTP `/metrics` endpoint serves Prometheus metrics
- [x] Docker image builds successfully (`requirements-analytics.txt` present)
- [x] Analytics service defined in docker-compose

### Observability
- [x] Prometheus metrics defined
- [x] Prometheus metrics exposed on HTTP port
- [x] JSON logging for all major events
- [x] Processing duration histograms

### Testing
- [x] Unit tests: event validation (7 passing)
- [x] Unit tests: aggregation logic (6 passing)
- [x] Integration test: proxy → stream → analytics (5 passing)
- [x] Unit tests: HMAC authentication (8 passing)
- [ ] Chaos test: analytics container stopped — proxy continues on stale data, no errors

## Next Steps
- Fix the 3 blocking gaps above
- Then proceed to Phase 12b (detection modules — also mostly done)
