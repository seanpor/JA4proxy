# JA4proxy Security Fix Checklist

**Status:** Pre-Fix | **Date:** 2026-02-14

---

## Phase 1: CRITICAL (Week 1) ⚠️ MUST FIX

### ☐ CRIT-1: Hardcoded Passwords
- [ ] Remove `:-changeme` fallbacks from docker-compose files
- [ ] Add strong password generation in quick-start.sh (32+ chars)
- [ ] Add password validation in proxy.py
- [ ] Test: Startup fails without password
- [ ] Test: Weak passwords rejected

### ☐ CRIT-2: Environment Variable Secrets
- [ ] Create Docker secrets in docker-compose.yml
- [ ] Implement `_load_secret()` method in proxy.py
- [ ] Create `scripts/generate-secrets.sh`
- [ ] Update .gitignore for secrets/
- [ ] Test: Secrets not in `docker inspect` output
- [ ] Test: Secrets loaded from /run/secrets/

### ☐ CRIT-3: Backend TLS Validation
- [ ] Add backend_tls config section
- [ ] Implement SSL context creation
- [ ] Add certificate validation
- [ ] Add mTLS support (optional)
- [ ] Test: Reject invalid certificates
- [ ] Test: mTLS authentication works

### ☐ CRIT-4: Request Size Limits
- [ ] Create `ConnectionTracker` class
- [ ] Implement cumulative size tracking in handle_connection()
- [ ] Enforce MAX_REQUEST_SIZE
- [ ] Add max_connection_duration
- [ ] Test: Large requests rejected
- [ ] Test: DoS attack mitigated

### ☐ CRIT-5: Rate Limit Race Condition
- [ ] Create Lua script for atomic rate limiting
- [ ] Register script in SecurityManager.__init__
- [ ] Update _check_rate_limit() to use script
- [ ] Use sorted sets for sliding window
- [ ] Test: Concurrent requests don't bypass limit
- [ ] Test: Fail closed on Redis errors

---

## Phase 2: HIGH (Week 2)

### ☐ HIGH-1: Secure Metrics Endpoint
- [ ] Create nginx reverse proxy config
- [ ] Add basic auth for metrics
- [ ] Change default bind to 127.0.0.1
- [ ] Document firewall requirements

### ☐ HIGH-2: Enhanced Logging Security
- [ ] Add Redis URL pattern to SensitiveDataFilter
- [ ] Add JWT token pattern
- [ ] Add structured logging
- [ ] Implement log rotation

### ☐ HIGH-3: Docker Hardening
- [ ] Enable read-only root filesystem
- [ ] Create custom seccomp profile
- [ ] Drop unnecessary capabilities
- [ ] Create AppArmor profile

### ☐ HIGH-4: Isolate Scapy
- [ ] Create packet-parser service
- [ ] Separate Dockerfile for parser
- [ ] Add parser validation
- [ ] Implement parsing timeouts

### ☐ HIGH-5: Timeout Management
- [ ] Add request-level timeout wrapper
- [ ] Implement idle connection tracking
- [ ] Add max connection duration
- [ ] Graceful cleanup

### ☐ HIGH-6: Redis Connection Pool
- [ ] Create ConnectionPool with limits
- [ ] Add keepalive settings
- [ ] Implement connection monitoring
- [ ] Add pool metrics

---

## Phase 3: MEDIUM (Weeks 3-4)

- [ ] MED-1: JA4 validation improvements
- [ ] MED-2: Config file permission checks
- [ ] MED-3: YAML bomb protection
- [ ] MED-4: Timestamp validation tightening
- [ ] MED-5: IP validation enhancements
- [ ] MED-6: Secure random validation
- [ ] MED-7: Redis TTL atomicity
- [ ] MED-8: Audit log integrity (HMAC)
- [ ] MED-9: Metrics label cardinality
- [ ] MED-10: Process hardening profiles
- [ ] MED-11: Configuration schema validation

---

## Phase 4: LOW (Week 5)

- [ ] LOW-1: Dependency pinning with hashes
- [ ] LOW-2: Add Dependabot config
- [ ] LOW-3: Supply chain verification
- [ ] LOW-4: Add SECURITY.md
- [ ] LOW-5: Security documentation
- [ ] LOW-6: Certificate transparency
- [ ] LOW-7: Rate limit headers

---

## Phase 5: Testing (Week 6)

### Security Tests
- [ ] All unit tests passing (>90% coverage)
- [ ] Integration tests passing
- [ ] Security exploit tests passing
- [ ] Penetration test completed
- [ ] No new vulnerabilities introduced

### Performance Tests
- [ ] Load test baseline captured
- [ ] Post-fix performance <5% degradation
- [ ] Stress test passing
- [ ] Concurrency test passing

### Compliance Tests
- [ ] GDPR compliance validated
- [ ] PCI-DSS requirements met
- [ ] SOC 2 controls documented
- [ ] Audit logs verified

### Documentation
- [ ] README.md updated
- [ ] SECURITY.md created
- [ ] CHANGELOG.md updated
- [ ] Architecture diagrams updated
- [ ] Security policies documented

---

## Pre-Flight Checklist (Before Production)

### Security
- [ ] No hardcoded credentials
- [ ] All secrets in Docker secrets
- [ ] TLS enabled for all connections
- [ ] Rate limiting active
- [ ] Audit logging enabled
- [ ] Metrics secured
- [ ] Containers hardened

### Configuration
- [ ] Strong passwords generated
- [ ] Firewall rules configured
- [ ] Redis authentication enabled
- [ ] TLS certificates valid
- [ ] Log rotation configured
- [ ] Monitoring alerts set up

### Testing
- [ ] Security scan passed (bandit, safety)
- [ ] Penetration test passed
- [ ] Load test passed
- [ ] Failover test passed
- [ ] Backup/restore tested

### Documentation
- [ ] Deployment guide reviewed
- [ ] Security policies documented
- [ ] Incident response plan ready
- [ ] Contact information updated
- [ ] Compliance documentation complete

---

## Success Metrics

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Critical vulnerabilities | 5 | 0 | ❌ |
| High vulnerabilities | 9 | 0 | ❌ |
| Test coverage | ~60% | >90% | ❌ |
| Security scan score | F | A | ❌ |
| Performance degradation | N/A | <5% | ⏳ |

---

## Sign-Off

### Phase 1 Complete
- [ ] All CRITICAL issues fixed
- [ ] Security team approval
- [ ] Code review completed
- [ ] Tests passing
- **Signed:** _________________ **Date:** _______

### Phase 2 Complete
- [ ] All HIGH issues fixed
- [ ] Security team approval
- [ ] Code review completed
- [ ] Tests passing
- **Signed:** _________________ **Date:** _______

### Final Approval
- [ ] All issues resolved
- [ ] Penetration test passed
- [ ] Security audit passed
- [ ] Production deployment approved
- **Signed:** _________________ **Date:** _______

---

**Track progress:** Update checkboxes as work completes  
**Review frequency:** Daily standup during fix phases
