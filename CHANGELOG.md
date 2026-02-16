# Changelog

## [2.0.1] - 2026-02-16 - TRAFFIC GENERATOR FIX

### 🐛 BUG FIXES
- **Fixed traffic generator bypassing proxy** - `generate-tls-traffic.sh` and `scripts/tls-traffic-generator.py` were sending requests directly to the backend (port 8081), completely bypassing the proxy. Prometheus metrics were never incremented, so Grafana dashboards showed no activity. Traffic is now routed through the proxy (port 8080) so that JA4 fingerprinting, security policies, and metrics collection all function correctly.
- **Fixed proxy rejecting non-TLS connections before recording metrics** - `JA4Fingerprint._sanitize_ja4()` raised `ValidationError` on sentinel values `"unknown"` and `"error"`, causing connections to be dropped before `REQUEST_COUNT` was incremented. These sentinel values are now allowed through validation so that all connections — including plain HTTP — are counted in Prometheus metrics and visible in Grafana.

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