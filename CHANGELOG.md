# Changelog

## [2.0.1] - 2026-02-16 - TRAFFIC GENERATOR FIX

### 🐛 BUG FIXES
- **Fixed traffic generator bypassing proxy** - `generate-tls-traffic.sh` and `scripts/tls-traffic-generator.py` were sending requests directly to the backend (port 8081), completely bypassing the proxy. Prometheus metrics were never incremented, so Grafana dashboards showed no activity. Traffic is now routed through the proxy (port 8080) so that JA4 fingerprinting, security policies, and metrics collection all function correctly.
- **Fixed proxy rejecting non-TLS connections before recording metrics** - `JA4Fingerprint._sanitize_ja4()` raised `ValidationError` on sentinel values `"unknown"` and `"error"`, causing connections to be dropped before `REQUEST_COUNT` was incremented. These sentinel values are now allowed through validation so that all connections — including plain HTTP — are counted in Prometheus metrics and visible in Grafana.
- **Fixed request duration histogram never recording** - `REQUEST_DURATION.observe()` was never called in `handle_connection`, so latency panels always showed empty. Now records duration from data read through security check.
- **Fixed BLOCKED_REQUESTS label mismatches** - `check_access()` called `BLOCKED_REQUESTS.labels()` with only `reason` but the counter requires `reason`, `source_country`, and `attack_type`. Now passes all three labels.

### 📊 DASHBOARD FIXES
- **Fixed Block Rate (%) panel** — was dividing two counters with different label sets yielding NaN; now uses `sum()` on both sides and derives block % from `ja4_requests_total{action="blocked"}`.
- **Fixed Security Events pie chart** — was grouping by nonexistent `tier` label; now groups by `event_type` matching actual `ja4_security_events_total` labels.
- **Fixed Top Blocked table** — was grouping by nonexistent `ja4_fingerprint` label; now shows `reason` and `attack_type` from `ja4_blocked_requests_total`.
- **Fixed Rate Limit panel** — referenced nonexistent `ja4_rate_limit_exceeded_total`; now queries `ja4_security_events_total{event_type="rate_limit_exceeded"}`.
- **Fixed Whitelist/Blacklist panel** — referenced nonexistent `ja4_whitelist_hits_total` / `ja4_blacklist_hits_total`; replaced with "Blocked by Reason" showing `ja4_blocked_requests_total` broken down by `reason`.
- **Fixed Security Overview stat row** — removed nonexistent `ja4_whitelist_size` / `ja4_blacklist_size`; replaced with Block % and Active Connections.
- **Fixed Request Latency panel** — added `sum() by (le)` to histogram_quantile for correct aggregation.
- **Replaced Loki logs panel** — was using LogQL against Prometheus datasource; replaced with TLS Handshake Errors timeseries using `ja4_tls_handshake_errors_total`.
- **Upgraded deprecated `graph` panels to `timeseries`** for Grafana 10.x compatibility.

## [2.0.0] - 2024-02-14 - SECURITY HARDENING RELEASE

### 🔒 CRITICAL SECURITY FIXES
- **Fixed wildcard imports from Scapy** - Replaced with specific imports to prevent namespace pollution
- **Enforced Redis authentication** - Password now required via environment variable, fails in production without auth
- **Added comprehensive configuration validation** - Schema validation prevents configuration injection attacks
- **Secured secrets directories** - Set proper permissions (700) on secrets/ and ssl/private/ directories

### 🛡️ HIGH PRIORITY SECURITY FIXES
- **Changed default bind address** - Now binds to 127.0.0.1 by default instead of 0.0.0.0
- **Implemented fail-closed rate limiting** - Blocks requests on Redis errors instead of allowing
- **Added structured logging with sensitive data filtering** - Automatically redacts passwords, tokens, and PII
- **Enhanced Docker security** - Added seccomp, dropped capabilities, read-only filesystems where possible
- **Improved health checks** - Health check now validates actual service functionality via HTTP

### 🔧 MEDIUM PRIORITY SECURITY FIXES
- **Fixed exception handling** - JA4 generation now raises exceptions instead of returning empty strings
- **Added metrics endpoint security** - Configuration for authentication and network restrictions
- **Made timeouts configurable** - All timeout values now configurable to prevent resource exhaustion
- **Enhanced error handling** - Comprehensive error handling with security event metrics

### ✨ SECURITY FEATURES ADDED
- Environment variable support for secrets (${VAR_NAME} syntax)
- SensitiveDataFilter class for log sanitization
- SecureFormatter for production-safe exception logging
- Enhanced security metrics (SECURITY_EVENTS, TLS_HANDSHAKE_ERRORS, CERTIFICATE_EVENTS)
- Comprehensive .gitignore for sensitive files
- Security documentation and checklists

### 📚 DOCUMENTATION ADDED
- SECURITY_FIXES.md - Detailed security fix documentation
- SECURITY_CHECKLIST.md - Pre-deployment security checklist
- .env.example - Environment variable template with security guidelines
- Enhanced README in secrets/ and ssl/private/ directories

### 🔄 BREAKING CHANGES
- Redis password now REQUIRED in production (set REDIS_PASSWORD environment variable)
- Default bind address changed from 0.0.0.0 to 127.0.0.1
- JA4 generation now raises ValidationError on failure instead of returning empty string
- Configuration validation now enforces strict typing and ranges

### 🐛 BUG FIXES
- Fixed Redis initialization without proper connection testing
- Fixed timeout handling with proper exception types
- Fixed empty fingerprint validation bypass
- Fixed log message format consistency

### ⚠️ DEPRECATED
- Wildcard imports (removed)
- Null Redis passwords in production (blocked)
- Empty string returns on errors (now raises exceptions)

---

## [1.0.0] - 2024-02-14

### Added
- Complete JA4/JA4+ TLS fingerprinting implementation
- High-performance asynchronous proxy server
- Redis-backed security lists (whitelist/blacklist)
- Prometheus metrics integration
- TARPIT functionality for malicious clients
- Docker and Docker Compose support
- Comprehensive test suite (unit, integration, performance)
- Enterprise deployment with high availability
- Security hardening and compliance features
- Monitoring and alerting stack
- Complete documentation and operational procedures

### Security Features
- Non-root container execution
- TLS encryption for all communications
- Input validation and sanitization
- Rate limiting and DDoS protection
- Audit logging and SIEM integration
- Vulnerability management procedures

### Performance Features
- Asynchronous I/O for high throughput
- Connection pooling and keepalive
- Redis clustering for scalability
- Load balancing with HAProxy
- Performance monitoring and optimization

### Enterprise Features
- Multi-zone deployment architecture
- Disaster recovery procedures
- Compliance documentation (SOC 2, PCI DSS, GDPR)
- Operational runbooks and procedures
- Security incident response plan
- Automated deployment and rollback

### Documentation
- Comprehensive README with quick start
- Enterprise deployment guide
- Security architecture documentation
- API reference and configuration guide
- Troubleshooting and maintenance procedures
- Performance tuning recommendations