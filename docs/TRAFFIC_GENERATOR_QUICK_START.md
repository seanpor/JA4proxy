# TLS Traffic Generator - Quick Start

Generate realistic performance test traffic for JA4proxy with a mix of legitimate and malicious clients.

## One-Line Start

```bash
./generate-tls-traffic.sh
```

This runs a 60-second test with 15% legitimate traffic and 85% attack traffic using 50 concurrent workers.

## Custom Tests

```bash
# Syntax: ./generate-tls-traffic.sh <duration_seconds> <good_percent> <workers>

# Light test - 30 seconds, 20% good
./generate-tls-traffic.sh 30 20 10

# Moderate test - 2 minutes, 15% good  
./generate-tls-traffic.sh 120 15 50

# Heavy test - 5 minutes, 10% good (90% attacks)
./generate-tls-traffic.sh 300 10 100

# Stress test - 10 minutes, 5% good (95% attacks)
./generate-tls-traffic.sh 600 5 200
```

## What It Does

The traffic generator simulates:

### Legitimate Clients (Good Traffic)
- Chrome on Windows
- Firefox on macOS
- Safari on iOS
- Realistic browsing patterns (0.3-0.5 requests/sec)

### Malicious Clients (Attack Traffic)
- **Mirai Botnet**: DDoS attacks (50 req/s)
- **Credential Stuffers**: Login attacks (20 req/s)
- **Web Scrapers**: Aggressive scraping (10 req/s)
- **Vulnerability Scanners**: Security scanning (5 req/s)
- **API Abusers**: Rate limit violations (30 req/s)

Each client has unique:
- JA4 TLS fingerprints
- User-Agent strings  
- IP address ranges
- Request patterns

## Monitoring During Tests

### Real-Time Metrics
```bash
# Watch metrics update every second
watch -n 1 'curl -s http://localhost:9090/metrics | grep ja4_'

# View proxy logs
docker compose -f docker-compose.poc.yml logs -f proxy
```

### Dashboards
- **Grafana**: http://localhost:3001 (admin/admin)
- **Prometheus**: http://localhost:9091
- **Metrics**: http://localhost:9090/metrics

## Expected Output

The generator shows:
- Configuration summary
- Real-time request logging (5% sample)
- Blocked requests highlighted
- Final statistics with breakdown by client type

### Sample Output

```
╔════════════════════════════════════════════════════════════════════╗
║          JA4proxy TLS Traffic Generator & Performance Test         ║
╚════════════════════════════════════════════════════════════════════╝

Configuration:
  Backend:           localhost:8081
  Duration:          60s
  Good Traffic:      15%
  Bad Traffic:       85%
  Worker Threads:    50

Spawning clients:
  ✓ 8 legitimate clients
  ✗ 42 malicious clients

✓ Chrome_Windows (203.0.113.1) -> /
✗ BLOCKED Mirai_Botnet (192.168.1.50) -> /admin/login
✓ Safari_iOS (198.51.100.5) -> /api/health
...

================================================================================
Traffic Generation Statistics (Elapsed: 60.2s)
================================================================================

Overall:
  Total Requests:  12,543
  Successful:      8,234 (65.6%)
  Blocked:         3,892 (31.0%)
  Errors:          417 (3.3%)
  Requests/sec:    208.36

By Client Profile:
Mirai_Botnet (Malicious)     - 4,521 requests, 2,234 blocked
APIAbuser (Malicious)        - 2,834 requests, 1,201 blocked
Chrome_Windows (Legitimate)  - 1,012 requests, 0 blocked
...
```

## Success Criteria

### Good Performance
- **Throughput**: 100+ requests/second
- **Block Rate**: 30-50% for attack traffic
- **False Positives**: 0% (no legitimate clients blocked)
- **Response Time**: <200ms average

### Great Performance  
- **Throughput**: 500+ requests/second
- **Block Rate**: 70%+ for attack traffic
- **Response Time**: <100ms average

## Troubleshooting

### No Traffic Generated
```bash
# Check if backend is accessible
curl http://localhost:8081/api/health

# Verify POC stack is running
docker compose -f docker-compose.poc.yml ps
```

### All Requests Failing
```bash
# Check proxy logs
docker compose -f docker-compose.poc.yml logs proxy | tail -50

# Verify Redis
redis-cli -h localhost -p 6379 -a changeme PING
```

### No Blocks Happening
```bash
# Verify security is enabled
docker compose -f docker-compose.poc.yml exec proxy \
  env | grep ENABLE_SECURITY

# Check rate limits
cat config/security-config.yaml
```

## Next Steps

After running traffic:

1. **View Metrics**
   ```bash
   curl http://localhost:9090/metrics | grep ja4_
   ```

2. **Check Grafana Dashboard**
   - Open http://localhost:3001
   - Login: admin/admin
   - Navigate to JA4proxy Security Overview

3. **Analyze Results**
   ```bash
   # Check what got blocked
   ./test-ja4-blocking.sh
   ```

4. **Tune Configuration** (if needed)
   - Edit `config/security-config.yaml`
   - Restart services
   - Re-run tests

## Full Documentation

See [TLS_TRAFFIC_GENERATOR.md](TLS_TRAFFIC_GENERATOR.md) for complete documentation including:
- Detailed client profiles
- Performance benchmarks
- CI/CD integration examples
- Advanced usage
