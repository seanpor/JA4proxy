# TLS Traffic Generator for JA4proxy

This tool generates realistic mixed traffic to performance test JA4proxy with a combination of legitimate customers and malicious attackers.

## Overview

The traffic generator simulates:
- **Legitimate Users (10-20%)**: Normal browsing behavior with realistic JA4 fingerprints
  - Chrome on Windows
  - Firefox on macOS  
  - Safari on iOS
  
- **Malicious Attackers (80-90%)**: Various attack patterns
  - DDoS botnets (50 req/s)
  - Credential stuffing (20 req/s)
  - Web scrapers (10 req/s)
  - Vulnerability scanners (5 req/s)
  - API abusers (30 req/s)

## Quick Start

### Prerequisites

```bash
# Ensure POC stack is running
./start-poc.sh

# Wait for services to be healthy
./poc-status-check.sh
```

### Run Traffic Generator

```bash
# Default: 60 seconds, 15% good traffic, 50 workers
./generate-tls-traffic.sh

# Custom: 5 minutes, 10% good traffic, 100 workers
./generate-tls-traffic.sh 300 10 100

# Syntax: ./generate-tls-traffic.sh <duration> <good_percent> <workers>
```

## Usage Examples

### Light Load Test (Development)
```bash
./generate-tls-traffic.sh 30 20 10
# 30 seconds, 20% legitimate, 10 workers
```

### Moderate Load Test  
```bash
./generate-tls-traffic.sh 120 15 50
# 2 minutes, 15% legitimate, 50 workers
```

### Heavy Load Test (Production Simulation)
```bash
./generate-tls-traffic.sh 300 10 100
# 5 minutes, 10% legitimate (90% attacks), 100 workers
```

### Stress Test (DDoS Simulation)
```bash
./generate-tls-traffic.sh 600 5 200
# 10 minutes, 5% legitimate (95% attacks), 200 workers
```

### Mostly Legitimate Traffic (Baseline Testing)
```bash
./generate-tls-traffic.sh 120 90 50
# 2 minutes, 90% legitimate, 50 workers
```

## Client Profiles

### Legitimate Clients

| Client | JA4 Fingerprint | User-Agent | Rate | IP Range |
|--------|----------------|------------|------|----------|
| Chrome_Windows | `t13d1516h2_8daaf6152771_02713d6af862` | Chrome 120/Windows | 0.5/s | 203.0.113.x |
| Firefox_MacOS | `t13d1715h2_9c79135e478e_cd85d2e88c81` | Firefox 121/macOS | 0.3/s | 198.51.100.x |
| Safari_iOS | `t13d1516h2_3b5074b1b5a0_626360150d4b` | Safari 17/iOS | 0.4/s | 198.51.100.x |

### Malicious Clients

| Client | JA4 Fingerprint | Attack Type | Rate | IP Range |
|--------|----------------|-------------|------|----------|
| Mirai_Botnet | `t10d151415_deadbeef1337_attackertools` | DDoS | 50/s | 192.168.x.x |
| CredentialStuffer | `t12d090909_ba640532068b_b186095e22b6` | Credential Stuffing | 20/s | 10.0.x.x |
| AggressiveScraper | `t13d1516h2_scraperbot99_norespect4robots` | Scraping | 10/s | 172.16.x.x |
| VulnScanner | `t13d1516h2_scanner666_exploitkid` | Scanning | 5/s | 192.168.x.x |
| APIAbuser | `t13d1516h2_apiabuse123_ratelimitignored` | API Abuse | 30/s | 10.0.x.x |

## Monitoring During Tests

### Real-Time Metrics
```bash
# Watch metrics update
watch -n 1 'curl -s http://localhost:9090/metrics | grep ja4_'

# View proxy logs
docker compose -f docker-compose.poc.yml logs -f proxy
```

### Grafana Dashboard
```bash
# Open Grafana (admin / password from .env)
open http://localhost:3001

# Navigate to: JA4proxy Security Overview
```

### Prometheus Queries
```bash
# Open Prometheus
open http://localhost:9091

# Example queries:
rate(ja4_requests_total[1m])
ja4_blocks_total
ja4_bans_active
```

## Output

### During Test
```
╔════════════════════════════════════════════════════════════════════╗
║          JA4proxy TLS Traffic Generator & Performance Test         ║
╚════════════════════════════════════════════════════════════════════╝

Configuration:
  Backend:           localhost:8443
  Duration:          60s
  Good Traffic:      15%
  Bad Traffic:       85%
  Worker Threads:    50
  Legitimate Clients: 3
  Malicious Clients:  5

Spawning clients:
  ✓ 8 legitimate clients
  ✗ 42 malicious clients

Traffic generation started...
Press Ctrl+C to stop early

✓ Chrome_Windows (203.0.113.1) -> /
✗ BLOCKED Mirai_Botnet (192.168.1.50) -> /admin/login
✓ Safari_iOS (198.51.100.5) -> /api/health
...
```

### Final Statistics
```
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

Profile                        Type            Requests     Success      Blocked      Errors      
------------------------------------------------------------------------------------------
Mirai_Botnet                   Malicious       4,521        2,103        2,234        184         
APIAbuser                      Malicious       2,834        1,523        1,201        110         
CredentialStuffer              Malicious       1,923        943          892          88          
AggressiveScraper              Malicious       1,234        821          389          24          
Chrome_Windows                 Legitimate      1,012        1,010        0            2           
VulnScanner                    Malicious       643          421          198          24          
Firefox_MacOS                  Legitimate      234          233          0            1           
Safari_iOS                     Legitimate      142          140          0            2           

================================================================================
```

## Python API Usage

You can also use the Python script directly:

```python
from tls_traffic_generator import TrafficGenerator

# Create generator
generator = TrafficGenerator(
    backend_host="localhost",
    backend_port=8443,
    duration=60,
    good_traffic_percent=15,
    workers=50
)

# Run test
generator.run()

# Access statistics
print(f"Total requests: {sum(s['requests'] for s in generator.stats.values())}")
```

## Command-Line Options

```bash
python3 scripts/tls-traffic-generator.py --help

Options:
  --backend-host BACKEND_HOST   Backend hostname (default: localhost)
  --backend-port BACKEND_PORT   Backend port (default: 8443)
  --duration DURATION           Test duration in seconds (default: 60)
  --good-percent GOOD_PERCENT   % of legitimate traffic (default: 15)
  --workers WORKERS             Concurrent workers (default: 50)
```

## Interpreting Results

### Expected Behavior

#### Legitimate Traffic (Whitelisted)
- Should have ~0% blocks
- All requests should succeed (200 status)
- Low error rate (<1%)

#### Malicious Traffic  
- High block rate (30-90% depending on config)
- Should trigger rate limiting
- Should be added to ban lists
- May see connection errors after banning

### Key Metrics to Watch

1. **Block Rate**: Percentage of requests blocked
   - Good: 30-50% for mixed traffic
   - Excellent: 70%+ for mostly malicious traffic

2. **False Positive Rate**: Legitimate users blocked
   - Should be near 0%
   - Any blocks of legitimate users indicate misconfiguration

3. **Throughput**: Requests per second handled
   - Baseline: 100-500 req/s
   - Good: 500-1000 req/s  
   - Excellent: 1000+ req/s

4. **Response Time**: Avg response time
   - Good: <50ms
   - Acceptable: 50-200ms
   - Poor: >200ms

## Troubleshooting

### No Traffic Being Generated
```bash
# Check if backend is accessible
curl -sk https://localhost:8443/api/health

# Check if POC stack is running
docker compose -f docker-compose.poc.yml ps
```

### All Requests Failing
```bash
# Check proxy logs for errors
docker compose -f docker-compose.poc.yml logs proxy

# Verify Redis is working
docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" PING
```

### No Blocks Happening
```bash
# Check if security is enabled
docker compose -f docker-compose.poc.yml exec proxy \
  python -c "import os; print(os.getenv('ENABLE_SECURITY'))"

# Should print: true

# Check rate limit configuration
cat config/proxy.yml
```

### High Error Rate
```bash
# Reduce concurrent workers
./generate-tls-traffic.sh 60 15 10

# Check system resources
docker stats

# Check for network issues
docker compose -f docker-compose.poc.yml logs proxy | grep -i error
```

## Performance Benchmarks

Target performance on modern hardware (4 CPU, 8GB RAM):

| Scenario | Workers | Duration | Requests | Blocked | Req/s | Avg Response |
|----------|---------|----------|----------|---------|-------|--------------|
| Light | 10 | 30s | ~600 | ~200 | 20 | <50ms |
| Moderate | 50 | 60s | ~12,000 | ~4,000 | 200 | <100ms |
| Heavy | 100 | 300s | ~120,000 | ~40,000 | 400 | <200ms |
| Stress | 200 | 600s | ~360,000 | ~120,000 | 600 | <300ms |

## Next Steps

After running traffic tests:

1. **Review Grafana Dashboards**
   - Check JA4proxy Security Overview
   - Look for anomalies or patterns
   
2. **Analyze Blocked Clients**
   ```bash
   ./test-ja4-blocking.sh
   ```

3. **Tune Rate Limits** (if needed)
   - Edit `config/proxy.yml`
   - Restart services
   - Re-run tests

4. **Export Results**
   - Screenshots from Grafana
   - Metrics from Prometheus
   - Logs from Docker

## Integration with CI/CD

```yaml
# Example GitHub Actions workflow
- name: Performance Test
  run: |
    ./start-poc.sh
    ./generate-tls-traffic.sh 120 15 50
    
- name: Check Performance Metrics
  run: |
    # Verify block rate is acceptable
    BLOCKS=$(curl -s http://localhost:9090/metrics | grep ja4_blocks_total | awk '{print $2}')
    REQUESTS=$(curl -s http://localhost:9090/metrics | grep ja4_requests_total | awk '{print $2}')
    BLOCK_RATE=$(echo "scale=2; $BLOCKS / $REQUESTS * 100" | bc)
    
    if (( $(echo "$BLOCK_RATE > 30" | bc -l) )); then
      echo "✓ Block rate: ${BLOCK_RATE}%"
    else
      echo "✗ Block rate too low: ${BLOCK_RATE}%"
      exit 1
    fi
```

## See Also

- [POC Quickstart](POC_QUICKSTART.md)
- [Security Configuration](../README.md)
- [Monitoring Setup](MONITORING_SETUP.md)
- [Test JA4 Blocking](../test-ja4-blocking.sh)
