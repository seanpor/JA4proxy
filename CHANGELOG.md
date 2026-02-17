# Changelog

## [3.1.0] - 2026-02-17 - GEOIP, FINGERPRINT NAMES, BAN ESCALATION

### 🌍 GEOIP COUNTRY FILTERING
- **IP2Location LITE** database bundled in container (CC BY-SA 4.0, no registration needed)
- **Country whitelist** — only allow traffic from listed countries (IE, GB, IM, JE, GG, US, CA, AU, NZ, DE, FR, NL)
- **Country blacklist** — block traffic from listed countries (KP, RU, CN, IR)
- Both disabled by default — enable in `config/proxy.yml` → `geoip` section
- Country check runs as Security Layer 0 (before JA4 fingerprint checks)
- Private IPs (Docker NAT) return empty country, bypassing geo filters
- Country shown in logs, Prometheus `source_country` label, and two new Grafana panels

### 🏷️ JA4 FINGERPRINT NAMES
- **`classify_ja4()` function** decodes JA4 structure into human-readable names:
  - `h2` ALPN → "Browser (TLS 1.3)"
  - `00` ALPN → "Tool/Bot (TLS 1.2)"
- **`fingerprint_labels`** config section maps known fingerprints to specific names (Chrome, Sliver C2, CobaltStrike, etc.)
- **`fingerprint_name` label** added to `ja4_requests_total` Prometheus metric
- Names appear in all proxy log messages and Grafana dashboard panels

### 🔧 BAN ESCALATION FIX
- Lowered `by_ip_ja4_pair` ban threshold from 10→8 (tarpit backpressure capped rate at ~8, preventing ban escalation)
- Lowered `by_ja4` ban threshold from 30→20
- **Pattern-based whitelist**: `whitelist_patterns: ["h2"]` — any JA4 with HTTP/2 ALPN bypasses rate limiting
  - Fixes false positive blocking of browsers when all Docker traffic shares one gateway IP
- **Results**: 100% legitimate allowed, 99.6% malicious blocked, Grafana shows Allowed/Tarpitted/Banned

### 📊 DASHBOARD
- Dashboard panels group by `fingerprint_name` instead of raw fingerprint hash
- Added "Traffic by Country" donut chart
- Added "Blocked Requests by Country" table
- Total: 20 panels

### 📄 DOCUMENTATION
- Cleaned up 24 planning/session artifacts from `docs/`
- Removed root-level `GRAFANA_SETUP.md`, `TRAFFIC_GENERATOR_SUMMARY.txt`
- Rewrote `README.md` — focused POC demo guide with accurate architecture, ports, and commands
- Moved `POC_QUICKSTART.md` to `docs/`

## [3.0.0] - 2026-02-17 - ENTERPRISE SECURITY ARCHITECTURE

### 🏗️ ARCHITECTURE
- **Added HAProxy load balancer** — TCP mode frontend on :443 with TLS passthrough (no termination), PROXY protocol v2 for real client IP forwarding. Stats page on :8404.
- **Added tarpit container** — Async Python TCP server that traps blocked connections, trickling 1 byte/sec for 60 seconds to waste attacker resources. Prometheus metrics on :9099.
- **Upgraded backend to HTTPS** — Mock backend now serves on :443 with self-signed TLS cert. End-to-end encryption preserved (proxy never decrypts).
- **Full traffic path**: Client → HAProxy:443 → JA4proxy:8080 → Backend:443 (or Tarpit:8888 if blocked)

### 🔒 SECURITY
- **Wired `src/security/SecurityManager` into proxy** — Multi-strategy rate tracking (BY_IP, BY_JA4, BY_IP_JA4_PAIR) with automatic threat tier escalation (NORMAL → SUSPICIOUS → BLOCK → BAN).
- **Three-layer security pipeline**:
  1. **Blacklist** — Instant TCP RST for known malware JA4 fingerprints (Sliver, CobaltStrike, IcedID, Evilginx, SoftEther)
  2. **Whitelist** — Fast-pass for known browser fingerprints (Chrome, Firefox, Safari) — bypasses rate limiting
  3. **Rate-based detection** — Unknown fingerprints evaluated by connection rate; high-rate connections get TARPIT/BLOCK/BAN actions
- **PROXY protocol v2 parsing** — Reads real client IP from HAProxy binary header (essential since Docker NATs all traffic through gateway IP)
- **Tarpit redirect** — TARPIT action forwards connection to tarpit container instead of dropping
- **Real JA4 fingerprint extraction** — Parses TLS ClientHello directly from raw TCP stream using Scapy, matching FoxIO JA4 spec format
- **Pre-populated security lists** — Redis whitelist (6 browser fingerprints) and blacklist (7 malware fingerprints) loaded on startup

### 🧪 TRAFFIC GENERATOR
- **Complete rewrite** — Makes real TLS connections using `ssl.SSLContext` with distinct cipher/ALPN/TLS version configs per profile
- **3 legitimate profiles**: Chrome (TLS 1.2+), Firefox (TLS 1.2+), Safari (TLS 1.2+) — connect at 0.3-0.5 req/sec
- **5 malicious profiles**: Sliver C2, CobaltStrike Beacon, Python bot, Credential stuffer, Evilginx — connect at 2-50 req/sec
- **Real JA4 fingerprints** — Each profile produces a unique JA4 from its actual TLS ClientHello
- **Verified results**: 100% legitimate traffic allowed, 0% false positives; 60-100% malicious traffic blocked depending on profile

### 📊 DASHBOARD
- **Redesigned Grafana dashboard** with 14 panels:
  - Stat row: Total/Allowed/Blocked per minute, Block Rate %, Active Connections, Tarpitted count
  - Traffic flow: Stacked area chart of allowed vs blocked over time
  - Block rate timeline with color thresholds
  - Per-fingerprint traffic breakdown (allowed and blocked)
  - Security action distribution pie chart (Allowed/Tarpitted/Blocked/Banned/Blacklisted)
  - Top blocked fingerprints table
  - Blocked reasons table
  - TLS version distribution pie chart
  - Request latency percentiles (p50/p95/p99)
  - Security events timeline

### 📝 FILES ADDED
- `ha-config/haproxy.cfg` — HAProxy configuration
- `tarpit/tarpit-server.py` — Tarpit TCP server
- `tarpit/Dockerfile` — Tarpit container
- `ssl/certs/backend.crt` — Backend TLS certificate
- `ssl/private/backend.key` — Backend TLS private key

### 📝 FILES MODIFIED
- `proxy.py` — Major rewrite: security framework integration, PROXY protocol, tarpit redirect, fixed JA4 parsing
- `config/proxy.yml` — New security section with thresholds, strategies, whitelist, blacklist
- `mock-backend.py` — HTTPS support via TLS_CERT/TLS_KEY env vars
- `Dockerfile.mockbackend` — TLS cert packaging
- `docker-compose.poc.yml` — Added haproxy, tarpit services; backend on :443
- `scripts/tls-traffic-generator.py` — Complete rewrite for real TLS connections
- `generate-tls-traffic.sh` — Updated for new architecture
- `monitoring/grafana/dashboards/ja4proxy-overview.json` — Redesigned dashboard

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