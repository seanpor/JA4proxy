<!--
title: Troubleshooting
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Troubleshooting Guide

> **Audience:** SecOps operators, DevOps engineers, support staff
> **Purpose:** Centralized guide for diagnosing and resolving common JA4proxy issues
> **Last Reviewed:** 2026-03-27
> **Related:** [Incident Response Runbook](../INCIDENT_RESPONSE.md) · [Quick Reference](../QUICK_REFERENCE.md)

---

## Quick Navigation

| Category | Common Issues |
|----------|---------------|
| **[Deployment](#deployment-issues)** | Docker issues, configuration errors, port conflicts |
| **[Runtime](#runtime-issues)** | Crashes, high CPU, memory leaks, connection failures |
| **[Redis](#redis-issues)** | Connection errors, performance, data consistency |
| **[Performance](#performance-issues)** | High latency, low throughput, bottlenecks |
| **[Monitoring](#monitoring-issues)** | Metrics missing, dashboards broken, alerts not firing |
| **[Testing](#testing-issues)** | Test failures, mock server problems, CI/CD issues |
| **[Go Proxy](#go-proxy-issues)** | Go-specific build and runtime issues |
| **[Security](#security-issues)** | TLS errors, authentication failures, audit concerns |

---

## Deployment Issues

### Symptom: Containers fail to start

**Possible Causes & Solutions:**

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Docker network issue** | `docker network inspect` shows errors | `docker network prune && docker-compose up` |
| **Port conflict** | `netstat -tuln | grep <port>` shows conflict | Change ports in `docker-compose.yml` |
| **Volume permission issue** | `docker logs` shows permission denied | `chmod -R 777 data/ logs/` |
| **Missing .env file** | `No such file: .env` in logs | `cp .env.example .env && edit` |
| **Invalid config YAML** | `yaml.scanner.ScannerError` in logs | Validate with `python3 -c "import yaml; yaml.safe_load(open('config/proxy.yml'))"` |

**Debugging Commands:**
```bash
# Check container status
docker-compose ps

# View logs for failing container
docker-compose logs --tail=50 <service>

# Test configuration syntax
docker-compose config

# Check for port conflicts
ss -tulnp | grep ':<port>'
```

### Symptom: "Connection refused" to Redis

**Diagnosis:**
```bash
# Test Redis connectivity from proxy container
docker-compose exec proxy redis-cli PING

# Check Redis logs
docker-compose logs redis

# Test Redis health
docker-compose exec redis redis-cli INFO | grep "uptime_in_seconds"
```

**Solutions:**
1. **Redis not running:** `docker-compose up -d redis`
2. **Wrong Redis host:** Check `config/proxy.yml` `redis.host`
3. **Authentication required:** Set `redis.password` in config
4. **Network isolation:** Ensure containers on same Docker network

### Symptom: Configuration not loading

**Diagnosis:**
```bash
# Check config file exists
docker-compose exec proxy ls -la /app/config/proxy.yml

# Validate YAML syntax
python3 -c "import yaml; print(yaml.safe_load(open('config/proxy.yml')))"

# Check for environment variable expansion
grep '\${' config/proxy.yml
```

**Solutions:**
1. **Missing file:** Ensure `config/proxy.yml` mounted correctly
2. **YAML syntax error:** Fix indentation or quotes
3. **Missing env vars:** Set in `.env` file or export
4. **Permission issue:** `chmod 644 config/proxy.yml`

### Symptom: Docker Compose hangs on startup

**Common Causes:**
1. **Volume mount issue:** Check `docker volume ls` and `docker volume inspect`
2. **Network timeout:** Increase Docker daemon timeout
3. **Resource constraints:** Check `docker stats` for OOM
4. **Dependency cycle:** Review `depends_on` in compose file

**Fix:**
```bash
# Clean up and restart
docker-compose down -v
docker system prune -f
docker-compose up

# If still hanging, start services individually
docker-compose up redis -d
docker-compose up proxy -d
```

---

## Runtime Issues

### Symptom: Proxy crashes repeatedly

**Diagnosis:**
```bash
# Check crash logs
docker-compose logs proxy | grep -i "error\|exception\|traceback"

# Check system logs
journalctl -u docker --since "1 hour ago" | grep -i error

# Check for OOM kills
docker events --since '1h' | grep -i kill
```

**Common Crash Causes:**

| Crash Type | Log Pattern | Solution |
|-----------|-------------|----------|
| **OOM Killer** | `Killed` in docker events | Increase memory limits or optimize queries |
| **Redis connection error** | `ConnectionError: Error 111` | Check Redis health, network connectivity |
| **Config reload error** | `yaml.scanner.ScannerError` | Fix YAML syntax in config |
| **TLS parsing error** | `struct.error: unpack` | Update TLS parser or report bug |
| **Rate limit overflow** | `OverflowError: timestamp` | Check system clock synchronization |

### Symptom: High CPU usage

**Diagnosis:**
```bash
# Check top CPU consumers
docker stats --no-stream

# Profile Python proxy
docker-compose exec proxy py-spy top --pid 1

# Check Redis CPU
redis-cli INFO | grep "used_cpu_sys"
```

**Optimizations:**
1. **Reduce signal modules:** Disable non-critical signals in config
2. **Add Redis pipelining:** Enable `redis.pipeline_enabled: true`
3. **Upgrade to Go proxy:** For Python instances >300 conn/s
4. **Optimize queries:** Review slow Redis commands with `redis-cli --latency`

### Symptom: Memory leak

**Diagnosis:**
```bash
# Monitor memory over time
watch -n 5 'docker stats --no-stream --format "{{.MemUsage}}"' proxy

# Check for growing data structures
redis-cli INFO memory | grep "used_memory"

# Profile memory usage
docker-compose exec proxy py-spy record --rate 100 --pid 1 -o profile.svg
```

**Common Leaks:**
1. **Redis keys not expiring:** Check TTLs with `redis-cli SCAN 0 COUNT 1000 | xargs redis-cli TTL`
2. **Python objects not GC'd:** Use `gc.collect()` in long-running processes
3. **Analytics stream growth:** Trim with `XTRIM analytics:events MAXLEN ~ 100000`

### Symptom: Connections dropping

**Diagnosis:**
```bash
# Check active connections
curl http://localhost:9090/metrics | grep ja4proxy_active_connections

# Check Redis blocked clients
redis-cli INFO clients | grep blocked

# Check for tarpit overflow
redis-cli GET config:tarpit_capacity
redis-cli SCAN 0 COUNT 1000 MATCH "tarpit:*" | wc -l
```

**Solutions:**
1. **Increase tarpit capacity:** Set `tarpit.capacity` in config
2. **Check rate limits:** `redis-cli GET config:rate_limit_window`
3. **Review timeouts:** Adjust `connection_timeout` in config
4. **Check backend health:** Ensure backend servers available

---

## Redis Issues

### Symptom: Redis connection errors

**Error Patterns:**
- `ConnectionError: Error 111 connecting to redis:6379` (Connection refused)
- `ConnectionError: Error 104` (Connection reset by peer)
- `TimeoutError: Timeout reading from socket`

**Diagnosis:**
```bash
# Test Redis connectivity
redis-cli -h redis -p 6379 PING

# Check Redis logs
docker-compose logs redis | tail -20

# Check Redis clients
redis-cli CLIENT LIST

# Check network connectivity
docker-compose exec proxy nc -zv redis 6379
```

**Solutions:**

| Error | Cause | Fix |
|-------|------|-----|
| **Error 111** | Redis not running | `docker-compose up -d redis` |
| **Error 104** | Redis crashed | Check logs, restart Redis |
| **Timeout** | Redis overloaded | Scale Redis or optimize queries |
| **Auth required** | No password set | Set `redis.password` in config |
| **OOM** | Redis memory limit | Increase `maxmemory` or add eviction |

### Symptom: High Redis latency

**Diagnosis:**
```bash
# Check command latency
redis-cli --latency -h redis -p 6379

# Check slow log
redis-cli SLOWLOG GET 10

# Check blocked clients
redis-cli CLIENT LIST | grep -c "blocked"
```

**Optimizations:**
1. **Add pipelining:** `redis.pipeline_enabled: true` in config
2. **Reduce keyspace:** Shorten TTLs or archive old data
3. **Optimize queries:** Avoid `KEYS`, use `SCAN` instead
4. **Scale Redis:** Upgrade instance or implement cluster
5. **Add read replicas:** For read-heavy workloads

### Symptom: Redis memory fragmentation

**Diagnosis:**
```bash
# Check memory stats
redis-cli INFO memory

# Calculate fragmentation
redis-cli INFO | grep -E "used_memory:(rss|dataset)" | awk '{print $2}' | paste -sd " " - | awk '{print $2/$1}'
```

**Solutions:**
1. **Restart Redis:** `docker-compose restart redis` (temporary fix)
2. **Configure allocator:** Set `jemalloc` in Redis config
3. **Reduce fragmentation:** Avoid frequent large key deletions
4. **Monitor regularly:** Set up fragmentation alerts

### Symptom: Data inconsistency

**Diagnosis:**
```bash
# Check replication status (if clustered)
redis-cli INFO replication

# Verify key counts match
redis-cli DBSIZE

# Check for expired keys not deleted
redis-cli SCAN 0 COUNT 1000 | xargs -I {} redis-cli TTL {} | grep "^-2$" | wc -l
```

**Prevention:**
1. **Use transactions:** `MULTI/EXEC` for critical operations
2. **Add validation:** Check data integrity on read
3. **Monitor errors:** Alert on `redis_errors_total` metric
4. **Test failover:** Regularly test Redis failover

---

## Performance Issues

### Symptom: High proxy latency

**Diagnosis:**
```bash
# Check latency metrics
curl http://localhost:9090/metrics | grep "ja4proxy_processing_time"

# Profile CPU usage
docker-compose exec proxy py-spy top --pid 1

# Check Redis latency
redis-cli --latency
```

**Bottleneck Analysis:**

| Component | Check | Optimization |
|-----------|-------|--------------|
| **TLS parsing** | High CPU in parser | Upgrade to Go proxy |
| **Signal collection** | Specific module slow | Disable or optimize module |
| **Redis I/O** | High command latency | Add pipelining, scale Redis |
| **Network** | High RTT to Redis | Co-locate proxy and Redis |
| **Scoring** | Complex rules | Simplify scoring logic |

### Symptom: Low throughput

**Diagnosis:**
```bash
# Check connection rate
curl http://localhost:9090/metrics | grep "ja4proxy_connections_total"

# Check active connections
curl http://localhost:9090/metrics | grep "ja4proxy_active_connections"

# Check Redis commands/sec
redis-cli INFO stats | grep "commands_processed_sec"
```

**Throughput Optimization:**

| Constraint | Solution |
|------------|----------|
| **Python GIL** | Migrate to Go proxy |
| **Single-threaded Redis** | Scale Redis vertically or cluster |
| **Network bandwidth** | Compress data or co-locate |
| **CPU-bound signals** | Disable non-critical signals |
| **I/O-bound** | Add Redis pipelining |

### Symptom: High false positive rate

**Diagnosis:**
```bash
# Check block rate
curl http://localhost:9090/metrics | grep "ja4proxy_risk_actions_total{action=\"block\"}"

# Review recent blocks
redis-cli ZRANGE block_history:recent 0 -1 WITHSCORES

# Check signal contributions
redis-cli HGETALL signal_contributions
```

**Tuning Guide:**
1. **Adjust dial:** Lower `config:dial` gradually
2. **Review signals:** Check `tests/fp_corpus/` for known FPs
3. **Add whitelists:** Whitelist known-good JA4 fingerprints
4. **Adjust thresholds:** Increase individual signal thresholds
5. **Monitor impact:** Watch `ja4proxy_false_positive_rate` metric

### Symptom: Analytics stream lag

**Diagnosis:**
```bash
# Check stream length
redis-cli XLEN analytics:events

# Check consumer group lag
redis-cli XINFO GROUPS analytics:events

# Check pending messages
redis-cli XPENDING analytics:events analytics-workers - + 10 COUNT 100
```

**Solutions:**
1. **Scale analytics:** Add more consumers or increase resources
2. **Optimize processing:** Batch larger chunks (e.g., 1000 instead of 100)
3. **Reduce load:** Filter events before streaming
4. **Monitor regularly:** Alert on `analytics_stream_lag_seconds > 30`

---

## Monitoring Issues

### Symptom: Metrics not appearing in Prometheus

**Diagnosis:**
```bash
# Check Prometheus targets
curl http://prometheus:9090/targets

# Test metrics endpoint
curl http://proxy:9090/metrics

# Check Prometheus logs
docker-compose logs prometheus | grep -i error
```

**Solutions:**
1. **Check scrape config:** Verify `prometheus.yml` has correct target
2. **Test endpoint:** `curl -v http://proxy:9090/metrics`
3. **Check labels:** Ensure metrics have required labels
4. **Restart Prometheus:** `docker-compose restart prometheus`

### Symptom: Dashboard panels broken

**Diagnosis:**
```bash
# Check Grafana logs
docker-compose logs grafana | grep -i error

# Test data source
curl -u admin:password http://grafana:3000/api/datasources/1/health

# Check panel queries
# (Inspect in Grafana UI)
```

**Common Fixes:**
1. **Update data source:** Verify URL and credentials
2. **Fix query syntax:** Check PromQL in panel editor
3. **Refresh dashboard:** Click "Refresh" button
4. **Check time range:** Ensure correct time window selected

### Symptom: Alerts not firing

**Diagnosis:**
```bash
# Check Alertmanager logs
docker-compose logs alertmanager | grep -i error

# Test alert rules
curl -X POST http://prometheus:9090/-/reload

# Check active alerts
curl http://prometheus:9090/api/v1/alerts
```

**Alert Troubleshooting:**
1. **Check rule syntax:** `promtool check rules /etc/prometheus/rules/*.yml`
2. **Verify thresholds:** Adjust alert expressions
3. **Check notifications:** Test Alertmanager configuration
4. **Review silence:** Check for active silences

---

## Testing Issues

### Symptom: Tests failing in CI/CD

**Common Test Failures:**

| Failure Type | Pattern | Solution |
|--------------|---------|----------|
| **Mock server not running** | `ConnectionRefusedError` | Start mock in `conftest.py` |
| **Redis test container** | `redis.exceptions.ConnectionError` | Use `pytest-redis` fixture |
| **Race condition** | Intermittent failures | Add `time.sleep()` or retry logic |
| **Fixture missing** | `fixture 'x' not found` | Add to `conftest.py` |
| **Environment variable** | `KeyError` for env var | Set in CI environment or `.env.test` |

**Debugging:**
```bash
# Run specific test with verbose output
python3 -m pytest tests/unit/test_signal.py::test_high_risk -vvv

# Run with logging
python3 -m pytest --log-cli-level=DEBUG tests/unit/test_signal.py

# Check test coverage
python3 -m pytest --cov=src/security --cov-report=term-missing tests/unit/
```

### Symptom: Mock servers not working

**Diagnosis:**
```bash
# Check mock server logs
python3 tests/mocks/abuseipdb_mock.py

# Test mock endpoint
curl http://localhost:8081/check?ip=1.2.3.4

# Check mock in tests
python3 -c "from tests.mocks.abuseipdb_mock import app; print(app)"
```

**Common Issues:**
1. **Port conflict:** Change mock server port
2. **Mock not started:** Add to `conftest.py` fixtures
3. **Response format wrong:** Update mock to match real API
4. **CORS issues:** Add CORS headers to mock

### Symptom: FP corpus tests failing

**Diagnosis:**
```bash
# Run FP tests
python3 -m pytest tests/fp_corpus/ -v

# Check specific signal
python3 -m pytest tests/fp_corpus/test_tls_enforcer_fp.py -v

# Review FP corpus data
head -20 tests/fixtures/fp_corpus/legitimate_ja4.txt
```

**Solutions:**
1. **Update corpus:** Add new legitimate fingerprints
2. **Adjust signal:** Increase confidence threshold
3. **Add exception:** Whitelist specific JA4 patterns
4. **Review logic:** Check signal implementation

---

## Go Proxy Issues

### Symptom: Go build fails

**Common Errors:**

| Error | Cause | Solution |
|-------|------|----------|
| **`GOROOT not set`** | Snap Go installation | `export GOROOT=/snap/go/current` |
| **`cannot find module`** | Missing dependency | `go mod tidy` |
| **`undefined: symbol`** | Import issue | Check imports match case |
| **`go: missing Go sum entry`** | Sum mismatch | `go mod tidy` |

**Build Commands:**
```bash
# Set GOROOT
export GOROOT=/snap/go/current

# Build binary
GOROOT=/snap/go/current go build -o ja4proxy ./cmd/proxy/

# Run tests
GOROOT=/snap/go/current go test ./...

# Cross-compile
GOROOT=/snap/go/current GOOS=linux GOARCH=amd64 go build -o ja4proxy-linux
```

### Symptom: Go proxy crashes

**Diagnosis:**
```bash
# Check for panics
docker-compose logs go-proxy | grep -i panic

# Get stack trace
GOTRACEBACK=all docker-compose up go-proxy

# Profile CPU
go tool pprof http://localhost:6060/debug/pprof/profile
```

**Common Crashes:**
1. **Nil pointer dereference:** Add nil checks
2. **Slice out of bounds:** Validate indices
3. **Channel deadlock:** Check for unbuffered channels
4. **Race condition:** Use `go run -race` to detect

### Symptom: Go proxy performance lower than expected

**Diagnosis:**
```bash
# CPU profiling
go tool pprof http://localhost:6060/debug/pprof/profile

# Memory profiling
go tool pprof http://localhost:6060/debug/pprof/heap

# Block profiling
go tool pprof http://localhost:6060/debug/pprof/block
```

**Optimizations:**
1. **Reduce allocations:** Reuse objects where possible
2. **Avoid reflections:** Use concrete types
3. **Optimize hot paths:** Focus on TLS parsing and scoring
4. **Add concurrency:** Use `sync.WaitGroup` for independent operations

---

## Security Issues

### Symptom: TLS handshake failures

**Diagnosis:**
```bash
# Check proxy logs
docker-compose logs proxy | grep -i "tls\|handshake\|ssl"

# Test with openssl
openssl s_client -connect proxy:8443 -servername example.com

# Check cipher support
openssl ciphers -v | grep -i "TLSv1_2"
```

**Common Issues:**

| Error | Cause | Solution |
|-------|------|----------|
| **`sslv3 alert handshake failure`** | Old TLS version | Update client or lower `tls.min_version` |
| **`no shared cipher`** | Cipher mismatch | Add cipher to `tls.ciphers` config |
| **`certificate unknown`** | Self-signed cert | Add CA to client trust store |
| **`certificate expired`** | Expired cert | Renew certificate |

### Symptom: Authentication failures

**Diagnosis:**
```bash
# Check Redis ACLs
redis-cli ACL LIST

# Test authentication
redis-cli -a wrongpassword PING

# Check API key
redis-cli GET config:management_ui_api_key
```

**Solutions:**
1. **Redis auth:** Set `redis.password` in config
2. **Management UI:** Set `UI_API_KEY` in secrets
3. **Rate limiting:** Check `redis.rate_limit_enabled`
4. **IP whitelisting:** Verify `allowed_cidr` ranges

### Symptom: Audit logging not working

**Diagnosis:**
```bash
# Check log files
ls -la /var/log/ja4proxy/*.log

# Check log permissions
stat /var/log/ja4proxy/access.log

# Test log rotation
logrotate -f /etc/logrotate.d/ja4proxy
```

**Solutions:**
1. **Check config:** Verify `logging.file` path in config
2. **Permissions:** `chown ja4proxy:ja4proxy /var/log/ja4proxy`
3. **Disk space:** `df -h /var/log`
4. **Log level:** Set `logging.level: DEBUG` temporarily

---

## Common Solutions Reference

### Quick Fixes Cheat Sheet

| Issue | Quick Command |
|-------|---------------|
| **Restart service** | `docker-compose restart <service>` |
| **Clear Redis** | `redis-cli FLUSHALL` (careful!) |
| **Reset dial** | `redis-cli SET config:dial 0` |
| **Check health** | `curl http://localhost:8080/health` |
| **View logs** | `docker-compose logs --tail=50 <service>` |
| **Test config** | `python3 -c "import yaml; yaml.safe_load(open('config/proxy.yml'))"` |
| **Check connections** | `redis-cli INFO clients` |
| **Memory stats** | `redis-cli INFO memory` |

### Configuration Snippets

**Enable debug logging:**
```yaml
# config/proxy.yml
logging:
  level: DEBUG
  file: /var/log/ja4proxy/debug.log
```

**Disable problematic signal:**
```yaml
# config/proxy.yml
signals:
  beaconing:
    enabled: false
```

**Increase timeouts:**
```yaml
# config/proxy.yml
timeouts:
  connection: 30
  redis: 10
  backend: 15
```

**Add whitelist:**
```bash
# Temporary whitelist (24h)
redis-cli SETEX whitelist:1.2.3.4 86400 1

# Permanent whitelist
redis-cli SADD persistent_whitelist 1.2.3.4
```

---

## Escalation Procedures

### When to Escalate

| Situation | Action |
|-----------|--------|
| **P1 Incident** | Page on-call immediately |
| **Data loss** | Escalate to security team |
| **Compliance violation** | Notify DPO within 1 hour |
| **Unknown root cause** | Escalate after 30 minutes |
| **Recurring issue** | Create ticket for root cause analysis |

### Escalation Contacts

| Role | Contact | Method |
|------|---------|--------|
| **On-Call Engineer** | #incidents Slack | `@here P1 incident` |
| **Security Team** | security@example.com | Encrypted email |
| **Data Protection Officer** | dpo@example.com | Phone + Email |
| **Infrastructure Team** | #infrastructure | Slack mention |
| **Development Lead** | dev-lead@example.com | Slack DM |

### Post-Incident Process

1. **Document timeline** in incident report
2. **Capture logs and metrics** for analysis
3. **Conduct retrospective** within 48 hours
4. **Update runbooks** with lessons learned
5. **Implement preventative measures**

---

**Document Status:** ✅ Enterprise Standard (2026-03-27)
**Next Review:** 2026-06-27 (Quarterly)
**Maintainer:** Support Team

*Contribute: Add new issues and solutions as encountered — keep this guide up-to-date!*