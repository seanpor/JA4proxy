<!--
title: Security_Checklist
audience: Security Teams, Auditors
last_reviewed: 2026-03-27
phase: 21
-->

# Security Deployment Checklist

Use this checklist before deploying JA4 Proxy to any environment.

## 🔴 CRITICAL - Must Complete Before Deployment

### Credentials and Secrets
- [ ] Generated strong Redis password (min 32 characters): `openssl rand -base64 32`
- [ ] Set `REDIS_PASSWORD` environment variable
- [ ] Created `.env` file from `.env.example` with all required values
- [ ] Verified `.env` file permissions are 600: `chmod 600 .env`
- [ ] Confirmed `.env` is in `.gitignore` and not committed to version control
- [ ] Set `ENVIRONMENT=production` in production environments

### Configuration Security
- [ ] Reviewed all configuration files for sensitive data
- [ ] Updated `bind_host` to appropriate value for environment
- [ ] Configured proper network firewall rules
- [ ] Set appropriate `max_connections` limits
- [ ] Enabled and configured rate limiting
- [ ] Reviewed and adjusted timeout values

### TLS/SSL Configuration
- [ ] Generated or obtained valid TLS certificates
- [ ] Set proper permissions on private keys (600): `chmod 600 ssl/private/*.key`
- [ ] Set proper permissions on secrets directory (700): `chmod 700 secrets`
- [ ] Verified certificate expiration dates
- [ ] Configured certificate rotation procedures
- [ ] Tested TLS handshake with test clients

## 🟠 HIGH PRIORITY - Should Complete Before Production

### Container Security
- [ ] Reviewed Docker security settings in docker compose files
- [ ] Verified all containers run as non-root users
- [ ] Confirmed security_opt settings are appropriate
- [ ] Checked that unnecessary capabilities are dropped
- [ ] Enabled read-only filesystems where appropriate
- [ ] Configured resource limits (CPU, memory)

### Network Security
- [ ] Configured firewall rules to restrict access
- [ ] Implemented network segmentation
- [ ] Restricted Redis port (6379) to internal network only
- [ ] Restricted metrics port (9090) to authorized networks only
- [ ] Set up VPN or bastion host for administrative access
- [ ] Configured DDoS protection (if applicable)

### Monitoring and Logging
- [ ] Configured centralized logging
- [ ] Set up security event monitoring
- [ ] Configured alerting for critical security events
- [ ] Tested log rotation and retention
- [ ] Verified sensitive data is filtered from logs
- [ ] Set up metrics dashboard (Grafana)

### Access Control
- [ ] Implemented principle of least privilege
- [ ] Configured role-based access control (RBAC)
- [ ] Set up multi-factor authentication (MFA) for admin access
- [ ] Documented access procedures
- [ ] Created incident response contacts list

## 🟡 MEDIUM PRIORITY - Recommended

### Testing and Validation
- [ ] Run security test suite: `pytest tests/security/ -v`
- [ ] Run fuzzing tests: `pytest tests/fuzz/ -v`
- [ ] Perform penetration testing
- [ ] Conduct vulnerability scanning: `bandit -r proxy.py security/`
- [ ] Check dependencies: `safety check`
- [ ] Test disaster recovery procedures
- [ ] Validate backup and restore procedures

### Documentation
- [ ] Reviewed all security documentation
- [ ] Updated deployment procedures
- [ ] Documented incident response procedures
- [ ] Created runbook for common operations
- [ ] Documented all environment-specific configurations

### Compliance
- [ ] Reviewed GDPR compliance requirements
- [ ] Verified PCI-DSS controls (if applicable)
- [ ] Documented SOC 2 controls
- [ ] Completed security risk assessment
- [ ] Created data retention policies
- [ ] Documented data protection measures

## ⚪ LOW PRIORITY - Nice to Have

### Operational Excellence
- [ ] Set up automated backups
- [ ] Configured health check monitoring
- [ ] Implemented auto-scaling (if applicable)
- [ ] Set up canary deployments
- [ ] Configured blue-green deployment strategy
- [ ] Created disaster recovery site

### Advanced Security
- [ ] Integrated with SIEM system
- [ ] Enabled threat intelligence feeds
- [ ] Configured automated incident response
- [ ] Implemented security orchestration (SOAR)
- [ ] Set up honeypots or deception technology
- [ ] Configured advanced analytics

### Performance and Optimization
- [ ] Conducted performance testing
- [ ] Optimized configuration for workload
- [ ] Configured caching strategies
- [ ] Tested under peak load conditions
- [ ] Optimized database queries and indexes

---

## 📝 ENVIRONMENT-SPECIFIC CHECKLISTS

### Development Environment
- [ ] Redis password set (can be simple for dev)
- [ ] Bind to localhost only
- [ ] Enable debug logging
- [ ] Disable tarpit (for faster testing)
- [ ] Use test certificates

### Staging Environment
- [ ] Strong Redis password
- [ ] Production-like configuration
- [ ] Network isolation from production
- [ ] Same monitoring as production
- [ ] Test data only

### Production Environment
- [ ] **ALL CRITICAL items completed**
- [ ] **ALL HIGH PRIORITY items completed**
- [ ] Production-strength credentials
- [ ] Proper network segmentation
- [ ] 24/7 monitoring enabled
- [ ] Incident response team ready
- [ ] Documented escalation procedures
- [ ] Regular security audits scheduled

---

## 🔍 PRE-DEPLOYMENT VALIDATION

Run these commands before deployment:

```bash
# 1. Verify configuration loads successfully
python -c "from proxy import ConfigManager; cm = ConfigManager(); print('✅ Config valid')"

# 2. Test Redis connection
export REDIS_PASSWORD="your_password"
docker compose up -d redis
redis-cli -h localhost -a $REDIS_PASSWORD ping
# Should return: PONG

# 3. Run security tests
pytest tests/security/ -v

# 4. Check for security issues
bandit -r proxy.py security/ -f screen

# 5. Verify dependencies
safety check

# 6. Test Docker build
docker compose -f docker-compose.poc.yml build

# 7. Test deployment
docker compose -f docker-compose.poc.yml up -d
docker compose -f docker-compose.poc.yml ps
# All services should be "Up"

# 8. Test health endpoint
curl http://localhost:9090/metrics
# Should return metrics

# 9. Check logs for errors
docker compose -f docker-compose.poc.yml logs | grep -i error

# 10. Clean up test deployment
docker compose -f docker-compose.poc.yml down -v
```

---

## 🚨 POST-DEPLOYMENT VERIFICATION

After deployment, verify:

```bash
# 1. All services running
docker compose ps

# 2. No critical errors in logs
docker compose logs --tail=100 | grep -i critical

# 3. Metrics endpoint accessible
curl http://localhost:9090/metrics | grep ja4_requests_total

# 4. Health checks passing
docker compose ps | grep -i healthy

# 5. Redis authentication working
redis-cli -h localhost -a $REDIS_PASSWORD ping

# 6. Security events being logged
docker compose logs proxy | grep -i security

# 7. Rate limiting working
# Run multiple requests and verify blocking occurs
```

---

## 📞 EMERGENCY CONTACTS

- **Security Team**: security@example.com
- **On-Call Engineer**: oncall@example.com
- **Incident Response**: +1-XXX-XXX-XXXX
- **Management Escalation**: management@example.com

---

## 📅 REGULAR SECURITY TASKS

### Daily
- [ ] Review security event logs
- [ ] Check monitoring dashboards
- [ ] Verify backups completed successfully

### Weekly
- [ ] Review access logs
- [ ] Check for security updates
- [ ] Review rate limiting metrics

### Monthly
- [ ] Rotate credentials
- [ ] Update dependencies
- [ ] Review security policies
- [ ] Test incident response procedures

### Quarterly
- [ ] Security audit
- [ ] Penetration testing
- [ ] Disaster recovery test
- [ ] Compliance review

---

## Phase 14 — Production Hardening Checklist

### 14a — Startup Secrets
- [x] No `:-changeme` password fallbacks in any compose file (`docker-compose.poc.yml` uses `:?`)
- [x] `ENVIRONMENT=production` + no Redis password → FATAL log + `sys.exit(1)` before any connections accepted
- [x] JSON structured logging enabled in production (`logging.json_enabled: true`)
- [x] `SensitiveDataFilter` applied before JSON formatter — passwords/tokens not in log output

### 14b — Graceful Shutdown
- [x] SIGTERM handler sets shutdown event; proxy stops accepting new connections immediately
- [x] In-flight connections allowed to drain up to `drain_timeout_seconds` (default 30 s)
- [x] `shutdown_initiated` JSON log emitted with `active_connections` count at shutdown moment
- [x] `shutdown_complete` JSON log emitted with `drained_connections` and `forced_close` count
- [x] `drain_timeout_seconds` is hot-reloadable (read from config at shutdown time)

### 14c — Tarpit Self-Protection
- [x] `tarpit.max_concurrent_connections` (default 500) enforced — overflow takes `overflow_action`
- [x] `tarpit.max_per_ip` (default 3) enforced per source IP independently of global cap
- [x] `overflow_action`: `block` | `rst` | `allow` (allow = fail open to backend)
- [x] In-process counters always decremented in `finally` — no leak on abrupt disconnect
- [x] `ja4proxy_tarpit_concurrent` Gauge reflects current in-process count
- [x] `ja4proxy_tarpit_overflow_total{action}` Counter incremented on each overflow
- [x] Tarpit resource sizing guidance in `docs/SECOPS_OPERATIONS.md`

### 14d — Rate Limit Memory Self-Protection
- [x] `beaconing.max_suspects` (default 10 000) caps the `beacon:suspects` leaderboard
- [x] `ZREMRANGEBYRANK` trims lowest-confidence entries when leaderboard exceeds cap
- [x] Sliding window Lua script sets `EXPIRE` on both keys on every call

### 14e — Alert Rules Overhaul
- [x] All alert expressions use real `ja4proxy_*` metric names (no phantom `ja4_*` references)
- [x] `ja4_active_connections` → `ja4proxy_active_connections` (proxy.py, recording_rules.yml, dashboards)
- [x] `monitoring/alertmanager/rules/proxy.rules.yml` created and validated
- [x] `monitoring/alertmanager/rules/redis.rules.yml` created and validated
- [x] `monitoring/alertmanager/rules/security.rules.yml` created and validated
- [x] 43 structural tests in `tests/unit/test_alert_rules.py` validate all four rule files

### 14f — Production Docker Compose
- [x] `docker/docker-compose.prod.yml` references only real files (`docker/Dockerfile`, single Redis)
- [x] Docker Compose secrets used for `redis_password`, `grafana_password`, `abuseipdb_api_key`
- [x] No `:-changeme` or weak-password fallbacks; `BACKEND_HOST` uses `:?` (required, no default)
- [x] `BACKEND_HOST=x docker compose -f docker/docker-compose.prod.yml config` exits 0
- [x] All containers: `read_only`, `no-new-privileges`, `cap_drop: ALL`, memory/CPU limits

---

**Deployment Date**: _______________
**Deployed By**: _______________
**Reviewed By**: _______________
**Approval**: _______________

**Sign-off**: I confirm that all CRITICAL and HIGH PRIORITY items have been completed and verified.

**Signature**: _______________ **Date**: _______________
