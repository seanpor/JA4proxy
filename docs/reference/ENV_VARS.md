# Environment Variables Reference

Complete census of all environment variables consumed by JA4proxy components.

> **Legend:** ⚠️ = security-sensitive, 🔧 = operational, 📝 = informational

---

## Go Proxy (`cmd/ja4pd`, `internal/`)

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `CONFIG_PATH` | `cmd/ja4pd/main.go:59` | `config/proxy.yml` | Path to main configuration file | 🔧 |
| `ENVIRONMENT` | `cmd/ja4pd/main.go:76` | `""` (empty=off) | Deployment environment (enables structured logging when set) | 📝 |
| `ALLOW_UNAUTH_REDIS` | `cmd/ja4pd/main.go:76` | `""` | ⚠️ Bypass Redis auth requirement (any value enables) | ⚠️ |
| `JA4PROXY_TLS_CERT_FILE` | `cmd/ja4pd/main.go:85` | `""` | Path to TLS certificate for monitoring | 🔧 |
| `JA4PROXY_FORENSIC` | `cmd/ja4pd/main.go:664` | `""` (empty=false) | Enable forensic trace logging | 🔧 |
| `JA4PROXY_ALLOW_UNAUTH_REDIS` | `internal/config/loader.go:886` | `""` | ⚠️ Bypass Redis auth validation (any non-"1" = enforced) | ⚠️ |
| `JA4PROXY_ALLOW_UNAUTH_METRICS` | `internal/config/loader.go:1060` | `""` | ⚠️ Bypass metrics auth validation (any non-"1" = enforced) | ⚠️ |
| `NO_COLOR` | `internal/wizard/output.go:22` | presence-based | Disable color output in CLI | 📝 |
| `JA4PROXY_TOKEN` | `internal/cli/auth/auth.go:25` | `""` | Authentication token for Management API | ⚠️ |
| `JA4PROXY_URL` | `internal/cli/auth/auth.go:63` | `""` | Management API base URL | 🔧 |
| `JA4PROXY_OUTPUT` | `internal/cli/engine/root.go:103` | `""` (falls to `"table"`) | CLI output format (table, json, yaml) | 📝 |
| `JA4PROXY_BACKUP_KEY` | `cmd/ja4p/backup.go:148` | `""` | ⚠️ Encryption key for backup data at rest | ⚠️ |

---

## Management API (`management/`)

### Core Authentication

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `ENVIRONMENT` | `management/api/main.py:119` | `""` | Deployment environment | 📝 |
| `MANAGEMENT_JWT_SECRET` | `management/api/auth.py:144` | **required** | ⚠️ Secret key for JWT signing | ⚠️ |
| `MANAGEMENT_ADMIN_USER` | `management/api/auth.py:163` | `"admin"` | Default admin username | ⚠️ |
| `MANAGEMENT_ADMIN_PASSWORD` | `management/api/auth.py:165` | `""` | Default admin password | ⚠️ |
| `MANAGEMENT_ADMIN_PASSWORD_HASH` | `management/api/auth.py:164` | `""` | Bcrypt hash for admin password (alternative to plaintext) | ⚠️ |
| `MANAGEMENT_TEST_MODE` | `management/api/main.py:135` | `""` (off unless `"1"`) | ⚠️ Disable auth checks (test only) | ⚠️ |
| `MANAGEMENT_DISABLE_CSRF` | `management/api/main.py:143` | `""` (off unless `"1"`) | ⚠️ Disable CSRF protection | ⚠️ |
| `MANAGEMENT_CORS_ORIGINS` | `management/api/main.py:187` | `"http://localhost:8090"` | Allowed CORS origins | 🔧 |
| `MANAGEMENT_TRUSTED_PROXY_CIDRS` | `management/api/auth.py:229` | `""` | ⚠️ CIDRs trusted for X-Forwarded-For (IP spoofing risk) | ⚠️ |

### SAML SSO

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `MANAGEMENT_SAML_STRICT` | `management/api/main.py:151` | `"true"` | Enforce strict SAML validation | 🔧 |
| `MANAGEMENT_SAML_IDP_ENTITY_ID` | `management/api/routes/saml.py:76` | `""` | IdP entity ID | 🔧 |
| `MANAGEMENT_SAML_IDP_SSO_URL` | `management/api/routes/saml.py:77` | `""` | IdP SSO URL | 🔧 |
| `MANAGEMENT_SAML_IDP_CERT` | `management/api/routes/saml.py:107` | `""` | IdP certificate (PEM) | ⚠️ |
| `MANAGEMENT_SAML_SP_ENTITY_ID` | `management/api/routes/saml.py:88` | `"http://localhost:8090/auth/sso/metadata"` | SP entity ID | 🔧 |
| `MANAGEMENT_SAML_SP_ACS_URL` | `management/api/routes/saml.py:93` | `"http://localhost:8090/auth/sso/saml/acs"` | SP ACS URL | 🔧 |
| `MANAGEMENT_SAML_ROLE_MAPPING` | `management/api/routes/saml.py:143` | `"{}"` | JSON mapping of SAML groups to roles | 🔧 |
| `MANAGEMENT_SAML_DEFAULT_ROLE` | `management/api/routes/saml.py:144` | `""` | Default role for SAML users | 🔧 |
| `MANAGEMENT_SAML_GROUPS_ATTRIBUTE` | `management/api/routes/saml.py:291` | `"groups"` | SAML attribute containing groups | 🔧 |

### OIDC SSO

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `MANAGEMENT_OIDC_DISCOVERY_URL` | `management/api/routes/oidc.py:103` | **required** for OIDC | OIDC discovery URL | 🔧 |
| `MANAGEMENT_OIDC_CLIENT_ID` | `management/api/routes/oidc.py:104` | **required** for OIDC | OIDC client ID | 🔧 |
| `MANAGEMENT_OIDC_CLIENT_SECRET` | `management/api/routes/oidc.py:451` | `""` | OIDC client secret | ⚠️ |
| `MANAGEMENT_OIDC_REDIRECT_URI` | `management/api/routes/oidc.py:109` | `"http://localhost:8090/auth/sso/oidc/callback"` | OIDC redirect URI | 🔧 |
| `MANAGEMENT_OIDC_SCOPES` | `management/api/routes/oidc.py:116` | `"openid email profile groups"` | OIDC scopes | 🔧 |
| `MANAGEMENT_OIDC_ROLE_MAPPING` | `management/api/routes/oidc.py:131` | `"{}"` | JSON mapping of OIDC claims to roles | 🔧 |
| `MANAGEMENT_OIDC_DEFAULT_ROLE` | `management/api/routes/oidc.py:132` | `""` | Default role for OIDC users | 🔧 |
| `MANAGEMENT_OIDC_GROUPS_CLAIM` | `management/api/routes/oidc.py:479` | `"groups"` | JWT claim containing groups | 🔧 |
| `MANAGEMENT_SSO_TRUST_IDP_MFA` | `management/api/routes/oidc.py:497` | `"false"` | Trust IdP's MFA status | 🔧 |

### MFA

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `MANAGEMENT_MFA_ENCRYPTION_KEY` | `management/api/routes/mfa_totp.py:61` | `""` | ⚠️ Required for TOTP encryption | ⚠️ |
| `MANAGEMENT_WEBAUTHN_RP_ID` | `management/api/routes/webauthn.py:60` | `"localhost"` | WebAuthn relying party ID | 🔧 |
| `MANAGEMENT_WEBAUTHN_ORIGIN` | `management/api/routes/webauthn.py:64` | `"http://localhost:8090"` | WebAuthn origin URL | 🔧 |

### Redis Connection

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `REDIS_URL` | `management/api/redis_client.py:61` | `""` (falls to component vars) | Redis connection URL | ⚠️ |
| `REDIS_HOST` | `management/api/redis_client.py:65` | `"localhost"` | Redis host | 🔧 |
| `REDIS_PORT` | `management/api/redis_client.py:66` | `"6379"` | Redis port | 🔧 |
| `REDIS_DB` | `management/api/redis_client.py:67` | `"0"` | Redis database number | 🔧 |
| `REDIS_PASSWORD` | `management/api/redis_client.py:68` | `""` | ⚠️ Redis password | ⚠️ |

### External Services

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `HAPROXY_TLS_CERT_PATH` | `management/api/routes/tls_health.py:120` | `"/etc/haproxy/certs/server.pem"` | Path to HAProxy TLS cert | 🔧 |
| `PROMETHEUS_URL` | `management/api/routes/partials.py:688` | `"http://prometheus:9090"` | Prometheus API URL | 🔧 |
| `GEOIP_DB_PATH` | `management/api/routes/health.py:73` | `"/opt/geoip/GeoLite2-City.mmdb"` | Path to GeoIP database | 🔧 |

---

## Analytics (`src/analytics/`)

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `REDIS_URL` | `src/analytics/main.py:58` | `""` | Redis connection URL | ⚠️ |
| `REDIS_HOST` | `src/analytics/config.py:92` | `"localhost"` | Redis host | 🔧 |
| `REDIS_PORT` | `src/analytics/config.py:94` | `6379` | Redis port | 🔧 |
| `REDIS_PASSWORD` | `src/analytics/config.py:96` | `""` | ⚠️ Redis password | ⚠️ |
| `JA4PROXY_PROXY_YML` | `src/analytics/config.py:35` | `"config/proxy.yml"` | Path to proxy config | 🔧 |
| `JA4PROXY_MGMT_BASE_URL` | `src/analytics/config.py:62` | `"http://management:8090"` | Management API base URL | 🔧 |
| `JA4PROXY_FP_CORPUS_PATH` | `src/analytics/ti_feeds/ja4_safety.py:40` | corpus path | Path to JA4 fingerprint corpus | 🔧 |

---

## Tarpit Service (`src/tarpit/`)

| Variable | Source | Default | Description | Security |
|----------|--------|---------|-------------|----------|
| `TARPIT_PORT` | `src/tarpit/tarpit-server.py:39` | `8888` | Tarpit listen port | 🔧 |
| `TARPIT_DURATION` | `src/tarpit/tarpit-server.py:40` | `60` | Connection hold duration (seconds) | 🔧 |
| `TARPIT_METRICS_PORT` | `src/tarpit/tarpit-server.py:41` | `9099` | Metrics expose port | 🔧 |
| `TARPIT_MAX_CONNECTIONS` | `src/tarpit/tarpit-server.py:42` | `1000` | Max concurrent connections | 🔧 |

---

## Docker Compose Variables

### Build Args (proxy)

| Variable | Default | Description |
|----------|---------|-------------|
| `VERSION` | `"unknown"` | Build version string |
| `GIT_COMMIT` | `"unknown"` | Git commit SHA |
| `BUILD_DATE` | `"unknown"` | Build timestamp |

### Runtime (proxy)

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_BIND_IP` | `127.0.0.1` | Agent bind address |
| `JA4PROXY_TRACE` | `"false"` | Enable trace logging |
| `JA4PROXY_FORENSIC` | `"false"` | Enable forensic mode |
| `AGENT_CPU_SET` | `"0-15"` | CPU affinity mask |
| `REDIS_UNIX_SOCKET_PATH` | `/var/run/redis/redis.sock` | Redis Unix socket (production) |

### Host Port Mappings

| Variable | Default | Service |
|----------|---------|---------|
| `HOST_PORT_INGRESS` | `443` | HAProxy ingress |
| `HOST_PORT_STATS` | `8404` | HAProxy stats |
| `HOST_PORT_DIRECT` | `8081` | Proxy direct |
| `HOST_PORT_METRICS` | `9090` | Proxy metrics |
| `HOST_PORT_ANALYTICS` | `8080` | Analytics |
| `HOST_PORT_MANAGEMENT` | `8090` | Management API |
| `HOST_PORT_PROMETHEUS` | `9091` | Prometheus |
| `HOST_PORT_ALERTMANAGER` | `9093` | Alertmanager |
| `HOST_PORT_GRAFANA` | `3000` | Grafana |

---

## Environment Variable Expansion

The proxy configuration file (`config/proxy.yml`) supports `${VAR}` and `${VAR:-default}` syntax for environment variable interpolation at load time. This means any environment variable can be injected via the config file, even if not explicitly read by Go code.

**Security note:** Sensitive values (API keys, passwords) should use `${VAR:-}` syntax in `proxy.yml` and be set via environment variables or Docker secrets — never hardcoded in the config file.

---

## Adding New Environment Variables

When adding a new environment variable:

1. Add it to the appropriate table above
2. Mark security-sensitive variables with ⚠️
3. If it's a production gate (auth bypass, etc.), add a warning in the description
4. Update `template.env` / `.env.example` if it's user-facing
5. Add validation in the loader if it has security implications
