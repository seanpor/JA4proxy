# Performance Testing

Performance testing for JA4 Proxy using Locust.

## Quick Start

### Run a quick performance test (30 seconds, 10 users):
```bash
./perf-test.sh
```

### Run with custom parameters:
```bash
./perf-test.sh <users> <spawn-rate> <duration>

# Examples:
./perf-test.sh 50 5 60     # 50 users, spawn 5/sec, 60 seconds
./perf-test.sh 100 10 120  # 100 users, spawn 10/sec, 120 seconds
./perf-test.sh 200 20 300  # 200 users, spawn 20/sec, 300 seconds
```

### Run with web UI (for interactive testing):
```bash
./perf-test.sh 0 0 0 web
```
Then open http://localhost:8089 in your browser.

## Test Scenarios

The performance tests simulate three types of users:

### 1. BackendUser (Primary Load)
Simulates normal API usage:
- Homepage requests (most frequent)
- Health checks
- Echo endpoint (GET/POST)
- Delayed operations
- Various HTTP status codes

### 2. ProxyMetricsUser (Monitoring)
Simulates monitoring systems:
- Checks Prometheus metrics every 5-15 seconds
- Validates metrics format

### 3. MixedWorkloadUser (Realistic Pattern)
Simulates real-world mixed workload:
- 95% backend API requests
- 5% metrics checks

## Reports

Performance test reports are saved in `performance/reports/`:
- HTML report: `perf_TIMESTAMP.html`
- CSV stats: `perf_TIMESTAMP_stats.csv`
- CSV failures: `perf_TIMESTAMP_failures.csv`

## Key Metrics

The tests measure:
- **Requests/sec**: Throughput
- **Response time**: Average, min, max, percentiles (p50, p95, p99)
- **Failure rate**: Percentage of failed requests
- **Concurrent users**: Number of simulated users

## Interpreting Results

### Good Performance Indicators:
- Response time p95 < 100ms for simple endpoints
- Response time p95 < 500ms for complex operations
- Failure rate < 1%
- Requests/sec scales linearly with users (up to saturation point)

### Warning Signs:
- Response times increasing exponentially with load
- Failure rate > 5%
- Memory or CPU usage approaching limits
- Degraded performance under moderate load

## Monitoring During Tests

While tests are running, monitor:

1. **System resources**:
```bash
docker stats
```

2. **Proxy logs**:
```bash
docker logs -f ja4proxy
```

3. **Metrics**:
```bash
curl http://localhost:9090/metrics | grep ja4_
```

4. **Prometheus**:
Open http://localhost:9091 for time-series graphs

## Advanced Usage

### Test specific user types:
```bash
docker compose -f docker-compose.poc.yml run --rm test \
  locust -f /app/performance/locustfile.py \
  --users=100 \
  --spawn-rate=10 \
  --run-time=60s \
  --headless
```

### Custom host:
```bash
./perf-test.sh 50 5 60 headless http://custom-host:8080
```

## Troubleshooting

### Tests fail immediately:
- Ensure services are running: `./start-poc.sh`
- Check service health: `docker compose -f docker-compose.poc.yml ps`

### Low throughput:
- Check if services are resource-constrained: `docker stats`
- Increase spawn rate gradually
- Check for bottlenecks in logs

### High failure rate:
- Check backend logs: `docker logs ja4proxy-backend`
- Verify network connectivity
- Reduce load and test again

## Benchmarking Guidelines

### Baseline Test (Warm-up):
```bash
./perf-test.sh 10 2 30
```

### Load Test (Normal operation):
```bash
./perf-test.sh 50 5 120
```

### Stress Test (Find limits):
```bash
./perf-test.sh 100 10 300
./perf-test.sh 200 20 300
./perf-test.sh 500 50 300
```

### Spike Test (Sudden load):
```bash
./perf-test.sh 100 50 60  # Spawn all 100 users in 2 seconds
```

### Endurance Test (Long duration):
```bash
./perf-test.sh 50 5 3600  # 1 hour at moderate load
```

## Performance Tuning

If you need better performance, consider:

1. **Increase worker processes** (proxy.py configuration)
2. **Tune Redis connection pool**
3. **Adjust timeout values**
4. **Scale horizontally** (multiple proxy instances)
5. **Optimize database queries**
6. **Add caching layer**

## CI/CD Integration

Add to your CI/CD pipeline:
```bash
# Quick smoke test (30s)
./perf-test.sh 10 2 30

# Fail if p95 response time > 200ms
# (Add threshold checking logic)
```
