# Phase 12a — Analytics Node Foundation

## Goal
Establish the core analytics node infrastructure with basic event ingestion and cross-instance aggregation capabilities.

## Foundation Components

### 12a.1 Container Setup
- **Dockerfile.analytics**: Independent Python container
- **Dependencies**: numpy, pandas, scipy (no shared layers with proxy)
- **Isolation**: Separate network namespace, resource limits
- **Health checks**: `/health` endpoint, readiness probes

### 12a.2 Event Ingestion Pipeline

**Redis Stream Configuration:**
- **Stream key**: `ja4proxy:events`
- **Max length**: 500,000 entries (auto-trimmed)
- **Consumer group**: `analytics` with replay capability

**Proxy Integration:**
```python
# Non-blocking event publishing in proxy
async def publish_event(event_data):
    await asyncio.create_task(
        redis.xadd(
            "ja4proxy:events",
            event_data,
            maxlen=500000,
            approximate=True
        )
    )
```

**Event Schema Validation:**
```python
EVENT_SCHEMA = {
    "required": ["timestamp", "src_ip", "ja4", "action", "score"],
    "properties": {
        "timestamp": {"type": "number"},
        "src_ip": {"type": "string", "format": "ip"},
        "ja4": {"type": "string", "maxLength": 64},
        "action": {"enum": ["allow", "block", "monitor", "tarpit"]},
        "score": {"type": "number", "minimum": 0, "maximum": 100}
    }
}
```

### 12a.3 Basic Cross-Instance Aggregation

**Rolling Window Aggregation:**
- 5-minute windows per IP, /24 (IPv4), /48 (IPv6)
- Metrics: request count, block rate, score distribution
- **Redis key**: `analytics:agg:{window}:{subnet}` (TTL: 300s)

**HyperLogLog Implementation:**
```python
# Unique IP counting per subnet
def update_subnet_unique_ips(subnet, ip):
    redis.pfadd(f"analytics:hll:{subnet}", ip)
    
# Read approximate count
count = redis.pfcount(f"analytics:hll:{subnet}")
```

## Security Foundation

### 12a.4 Event Validation
- **Schema validation** on all incoming events
- **Rate limiting**: 10,000 events/second per proxy instance
- **IP reputation check**: Drop events from unregistered proxy IPs
- **Field sanitization**: Strip control characters, validate lengths

### 12a.5 Authentication
- **Shared secret**: HMAC validation of event payloads
- **Proxy registration**: Whitelist of valid proxy IDs
- **Event signing**: `HMAC-SHA256(secret, event_data)`

## Observability

### 12a.6 Basic Monitoring

**Prometheus Metrics:**
- `ja4proxy_analytics_events_received_total` (counter)
- `ja4proxy_analytics_events_valid_total` (counter)
- `ja4proxy_analytics_events_invalid_total` (counter)
- `ja4proxy_analytics_processing_duration_seconds` (histogram)

**Logging:**
```json
{
  "type": "event",
  "level": "INFO",
  "subsystem": "analytics",
  "event": "stream_processed",
  "events_processed": 500,
  "duration_ms": 45
}
```

**Health Endpoints:**
- `/health`: Overall node health
- `/ready`: Readiness for processing
- `/metrics`: Prometheus endpoint

## Configuration

```yaml
analytics_node:
  enabled: true
  stream_max_length: 500000
  batch_size: 500
  processing_interval: 10
  validation:
    enabled: true
    rate_limit: 10000
    hmac_required: true
  aggregation:
    window_seconds: 300
    subnet_masks:
      ipv4: 24
      ipv6: 48
```

## Acceptance Criteria

### Functional
- [ ] Independent analytics container builds and runs
- [ ] Proxy publishes events to Redis Stream without blocking
- [ ] Consumer group processes events with replay on restart
- [ ] Event schema validation implemented
- [ ] Basic aggregation writes to Redis
- [ ] HyperLogLog counting operational

### Security
- [ ] Event validation rejects malformed events
- [ ] Rate limiting prevents flood attacks
- [ } HMAC validation authenticates proxy events
- [ ] Unregistered proxy events rejected

### Observability
- [ ] Prometheus metrics exposed
- [ ] Health endpoints respond correctly
- [ ] JSON logging for all major events
- [ ] Processing duration histograms

### Testing
- [ ] Unit tests: event validation
- [ ] Unit tests: aggregation logic
- [ ] Integration test: proxy → stream → analytics
- [ ] Security test: invalid event rejection
- [ ] Performance test: 10K events/second handling

## Next Steps
- Phase 12b: Advanced detection modules
- Phase 12c: Score drift monitoring
- Phase 12d: Security hardening