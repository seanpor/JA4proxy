# Changelog

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 10: OpenAPI 3.1 Spec — 2026-04-07

### Added
- `docs/api/openapi.yaml` — static OpenAPI 3.1 spec, 51 routes, generated from the live FastAPI app; canonical format for downstream tooling (Terraform provider Phase 83, SDK generation, compliance evidence)
- `docs/api/openapi.json` — JSON copy of the same spec; replaces the stale Phase 13 placeholder
- `management/scripts/export_openapi.py` — repeatable export script (`MANAGEMENT_TEST_MODE=1 python3 management/scripts/export_openapi.py`)
- `make openapi-spec` — Makefile target that invokes the export script
- All Phase 79 routes present in spec: auth, TOTP MFA, WebAuthn, SAML 2.0, OIDC SSO, bearer tokens, audit, RBAC management endpoints

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 9: OIDC SSO — 2026-04-07

### Added
- `GET /auth/sso/oidc/login` — start OIDC authorization code + PKCE S256 flow; fetches discovery doc, generates state + code_verifier, stores in Redis (5-min TTL single-use)
- `GET /auth/sso/oidc/callback` — receive authorization code, exchange for tokens (PKCE), extract claims from ID token, map groups to role, issue JWT cookie
- `management/api/routes/oidc.py` — full OIDC SSO route handlers
- PKCE S256: `code_verifier = secrets.token_urlsafe(64)`, challenge = `base64url(sha256(verifier))` — no implicit flow
- Group-to-role mapping via `MANAGEMENT_OIDC_ROLE_MAPPING` JSON env var; fallback `MANAGEMENT_OIDC_DEFAULT_ROLE`; deny by default
- Redis key: `mgmt:oidc:state:{state}` (JSON: code_verifier + redirect, 5-min TTL, single-use CSRF protection)
- `authlib>=1.3.0` added to `management/requirements.txt`

### Security
- State is single-use: consumed (deleted) immediately on first use regardless of whether subsequent token exchange succeeds
- ID token signature not verified (base64-decode only) — tracked as Phase 100 Gap 1; safe for dev/CI
- PKCE always required — no authorization_code grant without verifier

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 8: SAML 2.0 SSO — 2026-04-07

### Added
- `GET /auth/sso/saml/login` — redirect browser to SAML IdP SSO URL; generates single-use nonce as RelayState for CSRF protection
- `POST /auth/sso/saml/acs` — Assertion Consumer Service: validates nonce, processes SAML response, maps groups to role, issues JWT cookie
- `GET /auth/sso/metadata` — serve SAML SP metadata XML to IdP administrators (`sp_validation_only=True`)
- `management/api/routes/saml.py` — SAML 2.0 route handlers using `python3-saml`
- Group-to-role mapping via `MANAGEMENT_SAML_ROLE_MAPPING` JSON env var; fallback `MANAGEMENT_SAML_DEFAULT_ROLE`
- Redis key: `mgmt:saml:nonce:{nonce}` (String, 5-min TTL, single-use CSRF protection)
- `python3-saml>=1.16.0` added to `management/requirements.txt`
- `_create_access_token` now accepts `role` parameter (default `"admin"` for backward compat); `get_current_user` reads role from JWT payload with `"admin"` fallback for old tokens

### Security
- Nonces are single-use: deleted immediately before processing SAML response to prevent relay attacks
- SAML strict mode (`MANAGEMENT_SAML_STRICT=true`) enabled by default; disabling only for dev/test

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 7: WebAuthn/FIDO2 — 2026-04-07

### Added
- `POST /auth/mfa/webauthn/register/begin` — generate registration challenge; excludes already-enrolled credentials
- `POST /auth/mfa/webauthn/register/complete` — verify attestation response; store credential hash and public key
- `POST /auth/mfa/webauthn/auth/begin` — generate authentication challenge using enrolled credential IDs
- `POST /auth/mfa/webauthn/auth/complete` — verify assertion; check ownership; update sign_count; mark session MFA-verified
- `management/api/routes/webauthn.py` — WebAuthn route handlers using `py-webauthn`
- New Redis keys: `mgmt:webauthn:challenge:{user_id}` (JSON, 5-min TTL), `mgmt:webauthn:credential:{id}` (Hash: user_id, public_key, sign_count, created_at), `mgmt:webauthn:user:{user_id}:credentials` (SET of credential IDs)
- `webauthn>=2.0.0` added to `management/requirements.txt`

### Security
- Challenges are single-use: consumed (deleted) immediately in `_load_challenge` on any code path — prevents replay within the 5-min TTL window
- Credential ownership validated before assertion verification (403 on mismatch)
- `sign_count` updated after each successful assertion to detect cloned keys

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 6: TOTP MFA — 2026-04-07

### Added
- `GET /auth/mfa/totp/setup` — TOTP enrollment: generates base32 secret, Fernet-encrypts it at rest, returns base64 PNG QR code + 8 plaintext backup codes (shown once)
- `POST /auth/mfa/totp/verify` — validates a 6-digit TOTP code (±30s window) or a single-use backup code; marks session as MFA-verified (`mgmt:mfa:session:*`)
- `management/api/routes/mfa_totp.py` — TOTP setup and verify route handlers
- `mfa_session_key(jwt_token)` in `auth.py` — shared session key derivation (SHA-256 of JWT)
- `require_mfa_verified` FastAPI dependency in `auth.py` — gates cookie-JWT sessions on MFA completion; bearer-token callers are exempt
- New Redis keys: `mgmt:totp:{user_id}` (Fernet-encrypted secret), `mgmt:totp:backup:{user_id}` (LIST of bcrypt hashes, consumed on use), `mgmt:mfa:session:{sha256_of_jwt}` (8h TTL)
- `pyotp>=2.9.0`, `qrcode[pil]>=7.4.2`, `cryptography>=42.0.0` added to `management/requirements.txt`

### Changed
- `PUT /api/v1/dial` now enforces `require_mfa_verified`: cookie-JWT admin users with TOTP enrolled must complete verification before changing the dial; bearer-token admins are unaffected

### Security
- TOTP secret never stored in plaintext — Fernet-encrypted at rest; decryption requires `MANAGEMENT_MFA_ENCRYPTION_KEY` env var
- Backup codes bcrypt-hashed; each is single-use (hash removed from Redis after consumption)
- 401 responses for failed backup code attempts do not reveal the number of remaining codes

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 5: Audit Trail Enhancements — 2026-04-07

### Added
- Enhanced audit log schema: every `management:audit_log` entry now contains `timestamp`, `actor_id`, `actor_ip`, `action_type`, `resource_type`, `resource_id`, `before_value`, `after_value`, `session_id`, `role` — full attribution per operation
- `management/api/audit_utils.py` — shared `write_audit()` coroutine used by all route modules (eliminates duplicated `_write_audit` helpers in bans, dial, config_ops)
- `GET /api/v1/audit?format=jsonl` — NDJSON export, one JSON object per line (`application/x-ndjson`)
- `GET /api/v1/audit?format=csv` — CSV export with required header row (`text/csv`); nested values serialised as JSON strings in cells
- `GET /api/v1/audit?action=<value>` — filter by `action_type` field (exact match)
- `GET /api/v1/audit?actor=<value>` — filter by `actor_id` field (substring match)
- `GET /api/v1/audit?since=<iso8601>` — filter by `timestamp >=` value (lexicographic; ISO 8601 sorts correctly)
- Audit writes added to `POST /api/v1/allowlist|blocklist|watchlist` (action `{list}.created`, `before_value=null`, `after_value={entry, managed_by}`)
- Audit writes added to `DELETE /api/v1/allowlist|blocklist|watchlist/{id}` (action `{list}.deleted`, `before_value=<record>`, `after_value=null`)

### Changed
- `POST /api/v1/bans/{ip}`: audit entry now uses `action_type="ban.created"`, `resource_id=ip`, `after_value={ip, ttl, reason}` instead of old `action`/`user`/`detail` fields
- `DELETE /api/v1/bans/{ip}`: audit entry now uses `action_type="ban.deleted"`, `before_value={ip}` instead of old schema
- `PUT /api/v1/dial`: audit entry now uses `action_type="dial.changed"`, `before_value={value: N}`, `after_value={value: N}` instead of old schema
- `POST /api/v1/config/reload`: audit entry now uses `action_type="config.reload"` instead of old schema
- Removed duplicated `_write_audit`, `_AUDIT_KEY` definitions from `bans.py`, `dial.py`, `config_ops.py` — all now delegate to `audit_utils.write_audit`

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 4: New Observability & Infrastructure Endpoints — 2026-04-07

### Added
- `GET /api/v1/connections` — queries `ja4proxy:events` stream; filterable by `ip`, `ja4`, `action`, `since`, `limit` (Analyst+)
- `GET /api/v1/fingerprints/{ja4}` — aggregate stats (total, unique IPs, action breakdown, last seen); returns 404 on unknown fingerprint (Analyst+)
- `GET /api/v1/fingerprints/{ja4}/history` — chronological event list for a fingerprint (Analyst+)
- `GET /api/v1/nodes` — live proxy node list from `mgmt:node:*` heartbeat Hashes (Auditor+)
- `POST /api/v1/nodes/{host}/reload` — publishes reload signal to `proxy:reload` Redis pub/sub channel (Admin)
- `POST /api/v1/webhooks`, `GET /api/v1/webhooks` — webhook subscription CRUD; secret bcrypt-hashed at rest, never returned via API (Operator write, Auditor read)
- `GET /api/v1/webhooks/{id}`, `PUT /api/v1/webhooks/{id}`, `DELETE /api/v1/webhooks/{id}` — inspect, update, and remove individual webhook subscriptions
- `GET /api/v1/metrics/summary` — JSON snapshot: dial value, active ban count, events stream length (Auditor+)
- `GET /api/v1/health/deep` — deep health check with Redis connectivity test; returns 503 on Redis failure (Auditor+)
- `GET /api/v1/ready` — public readiness probe; no authentication required
- New Redis keys: `webhook:{id}` Hash, `webhook:idx` SET, `proxy:reload` pub/sub channel

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 3: Resource Model (UUID + managed_by) — 2026-04-07

### Added
- New canonical list endpoints: `POST/GET /api/v1/allowlist`, `GET/DELETE /api/v1/allowlist/{id}` (and equivalent routes for blocklist, watchlist)
- Full resource envelope on every list entry: `id` (UUID4), `entry`, `list_type`, `managed_by`, `note`, `created_at`, `created_by`, `expires_at`
- Dual-write pattern: Redis Hash (management record) + proxy SET (hot path) written atomically via pipeline
- `?managed_by=terraform` filter on all `GET` list endpoints
- Expired entries (`expires_at` in the past) excluded from `GET` results
- Migration runs at startup: existing `ja4:whitelist`, `ja4:blacklist`, `static:allowlist` SET members promoted to full Hash records with `managed_by="legacy"`; idempotent via `allowlist:migrated` / `blocklist:migrated` / `ip_allowlist:migrated` flags
- `ManagedBy`, `ResourceCreate`, `ResourceResponse`, `ResourceListResponse` Pydantic models in `management/api/models.py`
- New `ja4:watchlist` Redis SET introduced for watchlist proxy lookups

### Changed
- Old `/api/v1/lists/...` routes unchanged (backward compatibility preserved)

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 2: RBAC Role Enforcement — 2026-04-07

### Added
- `require_role(minimum_role)` dependency factory in `management/api/auth.py`; role hierarchy `auditor=0 < analyst=1 < operator=2 < admin=3` via `_ROLE_ORDER` dict
- All management API endpoints now enforce minimum role via `Depends(require_role(...))`:
  - `GET /api/v1/dial`, `GET /api/v1/bans`, `GET /api/v1/lists/...`, `GET /api/v1/audit` → Auditor+
  - `GET /api/v1/events` → Analyst+
  - `POST /api/v1/bans/{ip}`, `DELETE /api/v1/bans/{ip}`, `POST /api/v1/lists/.../{entry}`, `DELETE /api/v1/lists/.../{entry}` → Operator+
  - `PUT /api/v1/dial`, `POST /api/v1/config/reload`, all `/api/v1/tokens/*` → Admin
  - `GET /api/v1/health` → Public (no auth required, unchanged)
- 403 responses include RFC 7807-style `detail` field: `"Role 'X' insufficient; 'Y' or higher required."`
- Cookie JWT sessions receive `Role.admin` unconditionally for backward compatibility

### Changed
- No new Redis keys introduced; role enforcement is in-process only

## [Phase 79] — Management API v2, RBAC & Enterprise Identity — Cluster 1: Bearer Token Infrastructure — 2026-04-07

### Added
- `POST /api/v1/tokens`, `GET /api/v1/tokens`, `DELETE /api/v1/tokens` endpoints for API token lifecycle management (Admin role only)
- `GET /api/v1/tokens/{id}`, `DELETE /api/v1/tokens/{id}` for individual token inspection and revocation
- `POST /api/v1/tokens/{id}/rotate` for token rotation with a 60-second grace period (old token remains valid during overlap)
- Bearer token authentication middleware: `Authorization: Bearer <token>` accepted on all protected endpoints alongside existing cookie JWT
- `Role` enum (`auditor`, `analyst`, `operator`, `admin`) in `management/api/models.py`
- `TokenCreate`, `TokenResponse`, `TokenCreateResponse`, `TokenListResponse`, `TokenRotateResponse` Pydantic models
- `get_bearer_user()` dependency in `management/api/auth.py` for bearer-token extraction and bcrypt verification
- `get_current_user()` now returns `Tuple[str, Role]` (identity and role); bearer token checked first, cookie JWT as fallback
- Tokens stored as bcrypt hashes in Redis (`mgmt:token:{id}` Hash); raw token shown only once at creation
- `mgmt:token:idx` SET tracks all active token IDs; used by middleware for enumeration during hash-check lookup
- `last_used_at` field updated in Redis on every successful bearer authentication
- `bcrypt>=4.1.0` added to `management/requirements.txt`
- CORS middleware updated to allow `PATCH` method

## [Phase 92] — 2026-04-06

### Added
- `lint-pylint`: pylint `--errors-only` for Python semantic bugs (undefined names, unreachable code, attribute errors)
- `lint-semgrep`: semgrep `--config=auto` cross-language pattern analysis (Python, Go, YAML, shell)
- `lint-checkov`: checkov IaC security scan (Dockerfiles, Compose, Ansible, Helm)
- `lint-haproxy`: `haproxy -c` semantic config validation for `config/haproxy.cfg` and `ha-config/haproxy.cfg`
- `lint-helm`: `helm lint` Helm chart structural and template validation
- `lint-ansible`: ansible-lint for `deploy/ansible/` playbooks and roles
- `lint-markdown`: markdownlint-cli2 Markdown structure checks (heading hierarchy, list consistency, code fences)
- `lint-spelling`: codespell typo detection across docs and code
- `lint-toml`: Python tomllib parse validation for `pyproject.toml` and `.gitleaks.toml`
- `lint-makefiles`: checkmake for Makefile anti-patterns and missing `.PHONY`
- `lint-go-mod`: `go mod verify` module checksum integrity check
- Aggregate targets: `lint-python`, `lint-go`, `lint-sast`, `lint-infra`, `lint-observability`, `lint-supply-chain`, `lint-docs-all`, `lint-all`
- `gosec` and `bodyclose` linters added to `.golangci.yaml` (enabled in `lint-go-full`)

### Fixed
- `docker/docker-compose.scale.yml` was missing from `lint-docker` compose validation

## [Phase 91] — GDPR Live Data Erasure & Operational Script Gap Remediation

### Added
- `scripts/gdpr_delete.py`: audit logging to `management:gdpr_erasure_log` after every invocation (including dry-run)
- `scripts/gdpr_delete.py`: `--report` flag for machine-readable JSON output
- `scripts/gdpr_delete.py`: IP canonicalisation inside `purge_ip()` for correct IPv6 handling
- `tests/unit/test_gdpr_delete.py`: 10 unit tests using fakeredis (TDD)
- `docs/runbooks/gdpr_erasure.md`: operator runbook for GDPR subject erasure
- `tests/integration/phase-87/check_cadvisor_metrics.sh`: alert rule and Grafana dashboard checks
- `tests/integration/phase-87/check_haproxy_exporter.sh`: HAProxy alert rule and traffic metric checks

### Fixed
- `scripts/gdpr_delete.py`: HLL keys were incorrectly listed in deletion patterns — now correctly excluded and reported
- Phase 87 `make test-phase-87-integration` was broken since code was merged (scripts never created) — retrospectively implemented and extended

## [Phase 89] — 2026-04-06

### Added
- `docker/README.md`: Single source of truth for all Docker Compose file purposes and usage scenarios
- Dockerfile location metadata labels on `src/analytics/Dockerfile` and `tarpit/Dockerfile`
- `tests/unit/test_docker_consistency.py`: Pure-Python TDD tests enforcing Dockerfile and compose file hygiene rules
- `tests/integration/test_dockerfile_coverage.py`: Structural relationship tests for Dockerfiles and compose files

### Changed
- Python base images: `python:3.11-slim` → `python:3.14.0-slim` in `docker/Dockerfile.admin` and `docker/Dockerfile.management`
- Python test images: `python:3.14-slim` → `python:3.14.0-slim` in all `tests/docker/` Dockerfiles
- Go toolchain: `golang:1.23-alpine` → `golang:1.25-alpine` in `tests/docker/Dockerfile.test-runner` builder stage
- Network naming: `dmz_net/data_net/origin_net/mgmt_net` → `ja4proxy-dmz/ja4proxy-data/ja4proxy-origin/ja4proxy-mgmt` with explicit `name:` fields in `docker/docker-compose.poc.yml`
- Volume naming: `redis_data/reports_data` → `redis-data/reports-data` in poc; `redis_data/prometheus_data/grafana_data/loki_data` → hyphen form in prod; `ja4proxy_network` → `ja4proxy-network` in scale overlay
- Monitoring overlay external network names updated to match new POC explicit names (`ja4proxy-dmz`, `ja4proxy-data`, `ja4proxy-mgmt`)
- `restart: unless-stopped` added to `proxy`, `redis`, `backend`, `tarpit`, `analytics`, `admin-api`, `trafficgen` in `docker/docker-compose.poc.yml`
- `docker/Dockerfile.admin` and `docker/Dockerfile.management` added to `HADOLINT_DOCKERFILES` in `Makefile`

### Fixed
- Removed `network: host` from all build blocks in `docker/docker-compose.poc.yml` (7 services) and `docker/docker-compose.prod.yml` (3 services) — security fix
- `REDIS_PASSWORD` in `docker/docker-compose.monitoring.yml` redis-exporter now uses `:?` required form (was `:-changeme`)
- Phase 89c: `docker/docker-compose.test.yml` stub already superseded by Phase 90 which moved the canonical 159-line test environment to `docker/`

## [90.0.0] - 2026-04-06 - Root Directory Cleanup & Docker Compose Consolidation

### Changed
- Moved all root-level docker-compose files into `docker/`: `docker-compose.poc.yml`, `docker-compose.python-legacy.yml`, `docker-compose.scale.yml`, `docker-compose.test.yml`
- Updated build contexts in moved files from `context: .` to `context: ..` to preserve correct repo-root references
- Replaced 7-line `docker/docker-compose.test.yml` stub with the full Go test environment compose file
- Moved `benchmark_parallel_signals.py` and `benchmark_phase26.py` from root to `performance/`
- Updated all references in Makefile (30+ occurrences), scripts, and docs to use new `docker/` paths
- Added `REDIS_PASSWORD=lint-placeholder` to `make lint-docker` compose config validation

### Removed
- Untracked artefact files from root: `docker-compose.poc.yml.backup`, `*.log`, `*.pid`, `ja4proxy_plan.zip`
- Unused `package.json`, `package-lock.json`, `node_modules/` from root (`sql.js` was unused)

## [57.0.0] - 2026-04-06 - Cloud Backup & Restore Hardening

### Added
- Phase 57a: 9-byte `JA4B` format header with version and flags bitmask; backward-compatible with all legacy artifacts (`src/backup/format.py`)
- Phase 57a: `StorageAdapter` ABC with `LocalStorageAdapter`; pluggable cloud storage backend (`src/backup/storage_adapter.py`)
- Phase 57b: `S3StorageAdapter` using `boto3 + asyncio.to_thread()`; fail-open on upload failure (`src/backup/cloud/s3_adapter.py`)
- Phase 57c: `GCSStorageAdapter` using `google-cloud-storage + asyncio.to_thread()`; optional dependency (`src/backup/cloud/gcs_adapter.py`)
- Phase 57e: DSAR redactor now deep-scans JSON values for IP addresses (not just key names); `DSARComplianceError` pre-upload compliance check
- Phase 57f: Post-restore key count verification; `restore_with_fallback()` for DR with multiple artifacts; `backup:restored_from` audit trail key
- `scripts/ja4proxy_admin.py`: `backup cloud upload/list/download`, `backup dsar-redact`, and `backup restore --fallback` subcommands
- `docs/decisions/ADR-023.md`: Cloud vs. local backup strategy — why hybrid (local fast path + cloud durable store)
- `docs/decisions/ADR-025.md`: Format versioning — why 9-byte header, backward compat approach, flag bitmask design
- `docs/runbooks/cloud_backup_operations.md`: Operator guide covering S3/GCS setup, daily operations, disaster recovery, DSAR compliance, cost optimisation, and troubleshooting

### Fixed
- `abuseipdb:score:*` removed from backup `include_patterns` in `KeyPolicy` (was silently excluded by the never-backup guard anyway; policy contradiction resolved)
- `attribution:profile:*` and `attribution:ips:*` added to `include_patterns` (attacker fingerprint data now survives Redis failure)

### Changed
- Backup manifests now include `format_version: 1`, `format_flags`, `dsar_scanned`, and `sequence_number` fields

### Deferred
- Phase 57d (dirty tracking and incremental backups): cut after architecture review; insufficient evidence of a production backup-size problem; deferred to Phase 58

---

## [87.0.0] - 2026-04-06 — Phase 87: Container & Host Infrastructure Observability

### Added
- **`docker/docker-compose.monitoring.yml`** — `cadvisor` service (`v0.47.2`, privileged, blkio metrics dropped) and `haproxy-exporter` service (`v0.15.0`) for per-container and load-balancer metrics.
- **`monitoring/prometheus/prometheus.yml`** — `cadvisor` and `haproxy` scrape jobs with cardinality-reducing `metric_relabel_configs` (drops `container_blkio_device.*`, `container_tasks_state.*`, and empty-name host cgroup).
- **`monitoring/grafana/dashboards/ja4proxy-infrastructure.json`** — New "Infrastructure & Attack" dashboard: fleet status strip (11 stat panels, one per container, no scroll); host resource stats (CPU%, memory%, normalised load, disk%, FD%, entropy); network/TCP stack panels (bytes/s, packet-size SYN flood view, socket states, NIC drops); HAProxy section (sessions, queue depth, session limit%, backend health); container drill-down via `$container` template variable; attack detection section (connection rate vs 1h baseline with 200/600 conn/s threshold lines, TIME_WAIT spike, distributed scan indicator).
- **`monitoring/prometheus/alerts.yml`** — 5 new alert groups appended: `ja4proxy_infrastructure` (12 rules), `ja4proxy_container` (4 rules), `ja4proxy_haproxy` (4 rules), `ja4proxy_capacity` (3 rules), `ja4proxy_attack_detection` (7 rules). Every rule has `runbook_url` and `alert_type` label for Alertmanager routing.
- **`monitoring/prometheus/recording_rules.yml`** — `ja4proxy_infra_aggregations` group with 6 pre-computed rules: `ja4proxy:cpu_utilization:pct`, `ja4proxy:load_normalized`, `ja4proxy:filefd_utilization:pct`, `ja4proxy:container_mem_pct`, `ja4proxy:container_cpu_throttle_ratio`, `ja4proxy:network_avg_pkt_size_bytes`.
- **`monitoring/alertmanager/alertmanager.yml`** — Host-saturation inhibition rule: NodeCritical(CPU|Memory) suppresses per-container `alert_type: infrastructure` alerts with same root cause.
- **`docs/runbooks/infrastructure.md`** — 30-section runbook covering every new alert: immediate checks, common causes, resolution steps, escalation criteria.
- **`tests/unit/test_infra_alerts.py`** + **`tests/unit/test_infra_dashboard.py`** — 28 tests; all pass.

### Fixed
- **`monitoring/prometheus/recording_rules.yml`** — Stale metric names `ja4_requests_total`, `ja4_blocked_requests_total` (and related) replaced with correct `ja4proxy_connections_total` variants throughout existing groups.
- **`docker/docker-compose.monitoring.yml`** — HAProxy exporter scrape URI corrected to path-parameter form with auth credentials.
- **`monitoring/grafana/dashboards/ja4proxy-infrastructure.json`** — 600 conn/s threshold moved to `fieldConfig.defaults.thresholds` so Grafana renders the threshold line correctly.

## [46.1.0] - 2026-04-06 — Phase 46 (extended): Coverage Push to 99%

### Changed
- Overall test coverage driven from 82% to **99%** (11,570 statements, 172 missed, 3,557 tests passing).
- All security-critical modules now at ≥99%: `pipeline.py`, `rate_tracker.py`, `abuseipdb.py`, `rdap_enrichment.py`, `blocklists.py`, `beaconing_detector.py`, `dns_enrichment.py`, `ti_provider.py`, `integrity_monitor.py`.
- All backup modules at 100%: `worker.py`, `restorer.py`, `scheduler.py`, `encryption.py`, `format.py`, `policy.py`.
- All TAP modules at ≥99%: `capture.py`, `tap_pipeline.py`, `http_server.py`, `ja4.py`, `ja4t.py`, `ja4x.py`, `ja4ssh.py`, `ja4l.py`.

### Added (tests only)
- `TestRestorerCoverageGaps` — lock contention, encrypted backup no-key, decryption failure paths in restorer.py.
- `TestRetentionCoverageGaps` — nonexistent dir, empty dir, invalid JSON manifest, OSError-on-unlink suppression in worker.py.
- `TestBackupCLICoverageGaps` — unexpected exceptions in restore/list/validate commands; main() entry point.
- `TestRDAPCoverageGaps2` — Redis pipeline exception injection, audit log path, expansion CIDR extraction edge cases.
- `_ConcreteTI` + `retry_with_backoff` tests — abstract method body coverage and retry logic for TI providers.
- `TestHttpServerCoverageGaps` — sensor IP history delegation, Redis exception handling in fingerprint endpoints.
- `TestServerLifecycle` — fixed real port-8090 binding bug; now mocks `AppRunner`/`TCPSite`.
- `TestMTLSCoverageGaps2` — disabled handler fast-path; `has_valid_client_cert` shortcut.
- `TestJA4HCoverageGaps` — decode exception in HTTP method parser.
- `tests/unit/security/test_write_buffer.py` — new file; full `WriteBuffer` coverage.
- `tests/unit/test_logging_config.py` — new file; `logging_config.py` coverage.

### Fixed
- `TestServerLifecycle` was binding real TCP port 8090; caused `OSError: [Errno 98]` in CI if port in use.
- Wrong method names in RDAP coverage tests (`_maybe_enqueue` → `_enqueue_lookup`, `_compute_expansion_cidr` → `_extract_netblock`).
- Async pipeline mock used `AsyncMock()` directly instead of proper context manager; exception injection was silently skipped.

## [35.0.0] - 2026-04-05 — Phase 35: Advanced APT - Supply Chain Integrity & eBPF/XDP Blocking

### Added
- **`src/security/integrity_monitor.py`** — `IntegrityMonitor` class with three capabilities:
  - `verify_config_signature()` — Ed25519 startup verification of `config/proxy.yml`; exits 1 on tamper if `verify_on_startup: true` (default: false — fail open on first deploy).
  - `start_background_monitor()` — async task that re-hashes `proxy.py` and `src/` every 60 s; emits `ja4proxy_integrity_violation_total` Prometheus counter and logs ERROR on mismatch. Skips `__pycache__`/`.pyc` to avoid false positives from normal Python operation. Removes deleted files from baseline after first alert (prevents per-cycle alert flooding).
  - `append_audit_log()` — append-only JSON-line log with SHA-256 hash chain (`prev_hash` field); detects in-line tampering.
- **`scripts/config-signer.py`** — CLI with `genkey` / `sign` / `verify` subcommands; Ed25519 keypair at `config/keys/integrity.{key,pub}` (0600/0644). Private key created atomically via `O_CREAT|O_EXCL` to eliminate TOCTOU window.
- **`ebpf/ja4block.c`** — XDP program: `BPF_MAP_TYPE_HASH` for blocked IPv4 IPs, `BPF_MAP_TYPE_PERCPU_ARRAY` for drop counters; returns `XDP_DROP` for blocked source IPs, `XDP_PASS` otherwise.
- **`ebpf/Makefile`** — `clang -O2 -target bpf` build target.
- **`scripts/redis-to-ebpf.py`** — sidecar polling `ban:*` from Redis every 5 s; syncs via `bpftool map update`; graceful fallback on `FileNotFoundError`/`PermissionError`/`CalledProcessError` (logs WARNING, continues without eBPF — proxy startup never blocked); IPv6 skips logged at DEBUG.
- **`monitoring/alertmanager/rules/ebpf_attack.yml`** — `KernelLevelVolumetricAttack` alert: fires when eBPF drop rate > 10 k/s AND proxy CPU < 5% (kernel absorbing DDoS burst while proxy is idle).
- **`config/proxy.yml`** — `integrity:` section with all keys documented: `verify_on_startup`, `pubkey_path`, `audit_log_path`, `monitor_interval_s`, `monitor_paths`, `shutdown_on_violation`.
- `ja4proxy_integrity_skip_total{reason}` counter — tracks when signature verification is bypassed (e.g. `cryptography` library absent).

### Security
- Private key written with `O_CREAT|O_EXCL|0o600` — no TOCTOU window where world-readable.
- All `IntegrityMonitor` and sync-sidecar errors fail open (log + return) — proxy startup never blocked by integrity subsystem unless `verify_on_startup: true` and sig is invalid.
- eBPF: IPs validated through `socket.inet_pton` before subprocess calls — no command injection from Redis-sourced data.

### Tests
- 61 unit tests across `test_integrity_monitor.py`, `test_config_signer.py`, `test_ebpf_sync.py`.
- Integration tests in `tests/integration/test_integrity_integration.py` covering byte-by-byte corruption, real-filesystem background monitor, and full 5-entry hash-chain verification.

## [78.0.0] - 2026-04-04 — Enterprise Scale, Hardening & Governance (Phases 76, 77, 78)

### Added
- **Phase 76: Enterprise RHEL Production Deployment Strategy** — Best practices for deploying JA4proxy inline on RHEL 8/9 using Podman and Systemd Quadlets.
- **Phase 77: Enterprise Security Stack & SIEM Integration** — Integration patterns for Wazuh, CrowdSec, Splunk, QRadar, and a universal Vector-based translator.
- **Phase 78: Enterprise Scale, Hardening & Governance** — Roadmap for global multi-node scalability, Fail-Open policies, PII masking for GDPR, and FIPS 140-2 compliance.

## [75.0.1] - 2026-04-05 — Fix: agent-env.sh IP collision and volume conflicts

### Fixed
- **`scripts/agent-env.sh` — IP collision under concurrent or repeated use**: custom agents (`claude0`, `claude6`, etc.) now acquire an exclusive `flock` on `/tmp/ja4proxy-agent-env.lock` before scanning for a free IP, preventing two simultaneous `make agent-up` calls from racing to pick the same `127.0.0.x` address. The scan also queries `ss -tlnp` for host-bound loopback IPs, catching stacks whose `.env.*` files were deleted but containers are still running.
- **`docker-compose.poc.yml` — writable bind-mount conflicts**: `./logs:/app/logs` (proxy) and `./reports:/app/reports` (test) were shared host directories, causing all agents to write to the same paths. Both are now named volumes (`logs_data`, `reports_data`) which Docker automatically prefixes with `COMPOSE_PROJECT_NAME` (e.g. `ja4_claude0_logs_data`), giving each agent fully isolated storage.

## [75.0.0] - 2026-04-04 — Docker Multi-Agent Isolation (Phases 71, 72, 73, 74, 75)

### Added
- **Phase 71: Docker Isolation - Foundations & Registry** — Agent identity source of truth; automated environment generator.
- **Phase 72: Docker Isolation - Logical Network Zones** — Three-tier production mirroring (DMZ, APP, ORIGIN) with strict network isolation.
- **Phase 73: Docker Isolation - Host-Level Hardening** — Two-port policy; loopback IP binding; CPU pinning; non-root user.
- **Phase 74: Docker Isolation - Shared Assets & Tooling** — GeoIP sharing (RO); admin script support for --agent flag.
- **Phase 75: Docker Isolation - Security Audit & Validation** — automated isolation audit via `scripts/check-isolation.sh`.
- `scripts/agent-env.sh` — generates `.env.<agent>` with unique loopback IP, CPU set, and secrets.
- `docker-compose.poc.yml` — refactored for dmz_net, data_net, origin_net, and mgmt_net isolation zones.
- `scripts/ja4-admin.sh` — `--agent <name>` flag targets specific agent's containers and endpoints.
- `docs/architecture/ISOLATION_MODEL.md` — updated with quickstart, manual workflow, and verification section.

## [68.0.0] - 2026-04-04 — Phase 68 & 69: Python 3.14 Hot Path Optimizations & Free-Threading

### Changed
- `proxy.py`: replaced `ProcessPoolExecutor` (Phase 28a) with `ThreadPoolExecutor`; safe for free-threaded Python (Phase 69).
- `proxy.py`: added `_install_event_loop()` for uvloop support (Phase 68).

## [66.0.0] - 2026-04-04 — Phase 66, 67, 70: Python 3.14 Compatibility & Base Image Upgrade

### Added
- `scripts/check-python314-compat.py` — PyPI wheel checker for Python 3.14 compatibility (Phase 66).
- All Dockerfiles upgraded to `python:3.14.0-slim` (Phase 67).
- Analytics container upgraded to Python 3.14 with subinterpreter experiment (Phase 70).

### Fixed
- `src/security/tls_enforcer.py`: restore `score=40` default for deprecated TLS bypass-disabled signal (Phase 65).

## [59.0.0] - 2026-04-04 — TI Feed Reliability & Resilience (Phase 59)

### Added
- **Phase 59: TI Feed Reliability & Resilience** — Full circuit breaker and health monitoring system for all five Threat Intelligence providers.
- `src/security/feed_health.py` — Extended `FeedHealthMonitor` with ring buffer and circuit-breaker logic.
- `src/security/ti_provider.py` — `retry_with_backoff()` async helper for stable re-connection.
- `docs/runbooks/ti_feed_health.md` — 617-line operator runbook for security analysts and SREs.
## [Strategic Review] - 2026-04-01 — Roadmap Refactoring & Quality Epic

### Changed
- **Phase 60 Expansion**: As part of a comprehensive strategic quality review, the monolithic Phase 60 ("Technical Quality & Performance") has been broken down into four focused, actionable phases to ensure better governance and execution:
    - **Phase 61**: Technical Quality Improvements (Code, Architecture, Reliability)
    - **Phase 62**: Security Hardening (Pentesting, Threat Modeling, Compliance)
    - **Phase 63**: Observability and Monitoring (Technical & Executive Dashboards)
    - **Phase 64**: Operational Excellence (Process, Documentation, CI/CD)
- **Roadmap Renumbering**: Systematically renumbered all proposed phases (51-64) to resolve naming conflicts and ensure a logical, chronological implementation flow.

## [58.0.0] - 2026-04-01 — Phase 58: Advanced Traffic Intelligence - Phase 3: Feed Optimization & Reliability

### Added
- **Confidence-Based Weighting**: Implemented `ConfidenceManager` to track the historical accuracy of threat intelligence feeds and adjust signal weights dynamically.
- **Dynamic Accuracy Tracking**: Added Bayesian-style tracking of true positives vs. false positives per feed in Redis.
- **Manual Weight Overrides**: Added capability for administrators to manually set or clear confidence weights for specific feeds.
- **Integration**: Confidence weights are now applied to signals from MISP, ThreatFox, and VirusTotal providers.

## [54.0.0] - 2026-03-31 — Phase 54: Advanced Traffic Intelligence - Phase 5: Behavioral Attribution

### Added
- **Sequential Probing Detection**: Implemented logic to detect threat actor fingerprints that systematically probe multiple unique SNIs/hostnames.
- **Coordinated Burst Detection**: Added millisecond-accurate burst detection to identify multiple IPs hitting the same target simultaneously.
- **Fingerprint Drift Alerting**: Implemented real-time tracking and alerting for previously unseen JA4 fingerprints appearing in the environment.
- **Advanced Attribution Integration**: Integrated behavioral signals with Attacker Fingerprints (JA4+JA4X+JA4T) for high-fidelity threat tracking.

## [53.0.0] - 2026-03-31 — Phase 53: Advanced Traffic Intelligence - Phase 2: Secondary Feeds

### Added
- **MISP Integration**: Added `MISPProvider` for real-time reputation lookups against Malware Information Sharing Platform instances.
- **ThreatFox Integration**: Added `ThreatFoxProvider` to identify IPs associated with malware indicators (IOCs) from Abuse.ch.
- **VirusTotal Integration**: Added `VirusTotalProvider` utilizing the v3 API for comprehensive multi-engine reputation analysis.
- **Quota Management**: Implemented persistent quota tracking in Redis for commercial/limited TI feeds.

## [46.0.0] - 2026-03-31 — Phase 46: Coverage Improvement

### Changed
- **Test Coverage**: Achieved 82% overall project code coverage, meeting the enterprise robustness target.
- **Improved Testing**: Significantly expanded unit test coverage for `ProxyServer` edge cases, `TIProvider` framework, and all security modules.

## [45.0.0] - 2026-03-31 — Phase 45: Adversarial Test Expansion

### Added
- **SQL Injection Tests**: Added comprehensive adversarial tests for detecting and blocking common SQLi patterns.
- **XSS Tests**: Added adversarial coverage for Cross-Site Scripting (XSS) attack vectors.
- **Path Traversal Tests**: Implemented tests for detecting and preventing directory traversal attempts.
- **Command Injection Tests**: Added coverage for OS command injection patterns.

## [44.0.0] - 2026-03-31 — Phase 44: Test Audit and Documentation

### Added
- **Test Integrity Audit**: Completed a comprehensive audit of the entire test suite, ensuring all tests use genuine assertions and verify actual behavior.
- **Adversarial Test Suite**: Added 28 new adversarial test cases covering complex attack patterns and bypass attempts.
- **Test Documentation**: Created `docs/TESTING_STRATEGY.md` and `docs/TEST_ORGANIZATION.md` with clear guidelines for different test tiers.

## [43.0.0] - 2026-03-31 — Phase 43: Blue/Green Deployment & Rollback Tooling

### Added
- **Blue/Green Orchestration**: Developed `scripts/blue-green-deploy.sh` to manage zero-downtime rollouts by running parallel stacks (`ja4proxy-blue` and `ja4proxy-green`).
- **Health-Aware Swapping**: Integrated deployment script with the Phase 41 Health API to ensure new stacks are fully functional before shifting traffic.
- **Atomic Traffic-Shifting**: Implemented rapid backend switching in HAProxy using the Phase 42 hot-reload mechanism.
- **Instant Rollback**: Added one-command rollback capability to instantly restore traffic to the previous stable stack in case of issues.

### Changed
- **Stack Isolation**: Updated `docker-compose.prod.yml` to support multiple parallel instances by removing fixed container names and optimizing port bindings.

## [42.0.0] - 2026-03-31 — Phase 42: Zero-Downtime Data Upgrades (GeoIP & Config)

### Added
- **Atomic Hot-Reload**: Implemented an asynchronous reload mechanism for `proxy.yml` and GeoIP databases, ensuring zero dropped connections during updates.
- **GeoIP Live Refresh**: Added `GeoIPLookup.reload()` to atomically swap the underlying IP2Location database file handle.
- **Atomic File Utilities**: Created `src/utils/atomic_swap.py` providing `atomic_write` and `atomic_symlink_swap` for safe data deployment.
- **Enhanced Validation**: Added dry-run validation for configuration reloads; rejected updates keep the previous stable configuration active.

### Changed
- **Async Config Parsing**: Refactored `ConfigLoader.reload()` to use `run_in_executor`, preventing the event loop from blocking during large YAML parsing.

## [41.0.0] - 2026-03-31 — Phase 41: Robust Health Check API & Anti-Flap Logic

### Added
- **Deep Health API**: Implemented a dedicated `HealthMonitor` and `HealthServer` (aiohttp) serving `/health`, `/ready`, and `/metrics` on port 9090.
- **Dependency Tracking**: Health checks now validate Redis connectivity, GeoIP database presence, and monitor average pipeline latency.
- **Anti-Flap Hysteresis**: Implemented rise/fall thresholds (3 successes to become healthy, 2 failures to become unhealthy) to prevent load balancer flapping during transient blips.
- **Readiness Grace Period**: Implemented a 10-second startup grace period where the `/ready` endpoint returns 200 OK to allow for component initialization.

### Changed
- **HAProxy Integration**: Updated `config/haproxy.cfg` to use the new deep `/health` endpoint with JSON status verification.
- **Container Health**: Updated `Dockerfile` `HEALTHCHECK` to use `/health` instead of the simple `/metrics` endpoint.

## [40.0.0] - 2026-03-31 — Phase 40: Backup System Enhancements - Phase 2: Security & Compliance

### Added
- **Authenticated Encryption**: Implemented AES-256-GCM authenticated encryption for backup artifacts to ensure confidentiality and prevent tamper-then-restore attacks.
- **Distributed Locking**: Added Redis-based locking (`backup:operation_lock`) to prevent concurrent backup/restore operations from corrupting state in multi-worker environments.
- **DSAR Redaction Utility**: Added `ja4proxy-admin backup redact --ip <IP>` tool for GDPR compliance, allowing removal of specific subject data from backup archives.
- **Admin CLI Enhancements**: Updated `ja4proxy-admin` with a dedicated `backup` command group for creation, restoration, and redaction of encrypted artifacts.

## [33.0.0] - 2026-03-30 — Phase 33: Advanced Traffic Intelligence - Phase 6: Documentation Diagrams

### Added
- **Mermaid Visualizations**: Enhanced key documentation (Capacity Planning, Security Checklist) with new Mermaid diagrams for better architectural clarity.
- **Documentation Audit**: Completed comprehensive audit of all project documentation to identify and convert legacy ASCII diagrams.

### Changed
- **Diagram Standardization**: Standardized all documentation diagrams to Mermaid format for consistent rendering across GitHub, GitLab, and other platforms.

## [32.0.0] - 2026-03-31 — Phase 32: Advanced Traffic Intelligence - Phase 4: Attacker Attribution

### Added
- **Attacker Fingerprinting**: Implemented `AttributionManager` to compute stable, cross-IP fingerprints by hashing JA4 (TLS), JA4X (Cert), and JA4T (TCP).
- **Cross-IP Correlation**: Added logic to link multiple source IPs to a single threat actor fingerprint in Redis, enabling tracking of distributed botnets.
- **Threat Actor Profiles**: Implemented `AttackerProfile` in Redis to store category (malicious, suspicious), first/last seen timestamps, and associated IP sets.
- **Automated Promotion**: Profiles seen from multiple unique IPs (default: 3) are automatically promoted to "suspicious" and tagged as `multi_ip_actor`.
- **Escalation Signals**: Integrated attribution signals into the pipeline, allowing for immediate risk score escalation when a known malicious profile is matched.

## [31.0.0] - 2026-03-31 — Phase 31: Advanced Traffic Intelligence - Phase 3: Geographical Intelligence

### Added
- **GeoIP Integration**: Integrated IP2Location LITE database for mapping IP addresses to source countries.
- **Country-Based Blocking**: Implemented static and dynamic country-based blocking rules (whitelist/blacklist) in the proxy pipeline.
- **Geographical Metrics**: Added Prometheus metrics for connection tracking and blocking events by country code.
- **GeoIP Maintenance**: Created `scripts/update-geoip.sh` for automated monthly database updates and age verification.

## [23.0.0] - 2026-03-31 — Phase 23: Advanced Traffic Intelligence - Phase 1: Primary Feeds

### Added
- **GreyNoise Integration**: Added `GreyNoiseProvider` utilizing the GreyNoise Community API to identify background noise, scanners, and known benign (RIOT) traffic.
- **AlienVault OTX Integration**: Added `AlienVaultOTXProvider` utilizing the Open Threat Exchange API to identify IPs associated with known threat pulses and indicators.
- **Modular TI Framework**: Implemented a `TIProvider` abstract base class and a parallel background lookup pipeline to ensure threat intelligence never blocks the proxy hot path.
- **Three-Tier Caching**: Implemented a shared cache hierarchy (In-process LRU → Redis → API) with Bloom filter deduplication to minimize external API calls and respect rate limits.
- **TI Metrics**: Added Prometheus metrics for GreyNoise and AlienVault lookup success rates, cache hit ratios, and queue depths.

## [22.0.0] - 2026-03-29 — Phase 22: Backup System Enhancements - Phase 1: Core Features

### Added
- **Backup Scheduler**: Implemented `BackupScheduler` (asyncio task executor) to wire `backup.schedule` config (cron or interval) to automated backup creation.
- **Redis Pipelining**: Added `redis.pipeline()` batching to the backup loop (batches of 1000) for significantly improved performance and reduced round trips.
- **Restore Validation**: Implemented `RestoreError` threshold logic; restores now fail explicitly if more than 5% of keys fail to restore.
- **Enhanced Observability**: Added Prometheus metrics for backup duration, size, success/failure counts, and keys processed.

## [15.0.0] - 2026-03-31 — Phase 15: Go Rewrite (Feature Parity)

### Added
- **JA4X Go Implementation**: Ported the X.509 certificate fingerprinting (JA4X) from Python to Go with full parity.
- **Go Pipeline Integration**: Integrated JA4X extraction, whitelist bypass, and blacklist scoring into the Go proxy pipeline.
- **Lua Script Embedding**: Refactored `internal/redis` to use `//go:embed` for Lua scripts, eliminating runtime file dependencies and simplifying binary distribution.

### Changed
- **Status**: Updated Phase 15 from PARTIAL to COMPLETE after achieving full feature parity with the Python implementation.

## [36.0.0] - 2026-03-31 — Phase 36: Go Test Quality & Parity Gaps

### Added
- **JA4X Real Certificate Tests**: Added test with real X.509 certificate verifying format and hex validity.
- **Cross-Language JA4X Parity**: Added test comparing Go JA4X output against Python reference implementation.
- **JA4X Implementation Fixes**: Fixed Go implementation to match Python format (sorted OID attributes, SAN formatting).
- **JA4X Benchmarks**: Added benchmarks for real certificate, empty input, and invalid DER parsing.

### Fixed
- **JA4 Fixture Parity Test**: Fixed `TestJA4_FixturesParity` to read from `known_ja4.json` instead of hardcoded empty map.
- **JA4X Implementation Fixes**: Fixed Go implementation to match Python format (sorted OID attributes, SAN formatting).

## [39.0.0] - 2026-03-28 — Phase 39: Documentation Audit & Synchronization

### Changed
- **Documentation Audit**: Completed a comprehensive audit of all phase documentation to ensure accuracy and clear status indicators.
- **Roadmap Sync**: Synchronized the manifest, TODO list, and project status to prevent documentation drift.

## [38.0.0] - 2026-03-28 — Phase 38: ISP Blocking Operations

### Added
- **Operational Procedures**: Established formal procedures for identifying,Implementating, and monitoring blocks against malicious ISPs and organizations.

## [37.0.0] - 2026-03-28 — Phase 37: Lint & Static Analysis Cleanup

### Fixed
- **Code Quality**: Resolved remaining mypy, ruff, and bandit warnings across the codebase.
- **CI Gates**: Strictly enforced linting and static analysis gates in the CI pipeline.

## [30.0.0] - 2026-03-28 — Phase 30: Python Throughput Hardening - Phase 4: Write Optimization & Benchmarking

### Added
- **Deferred Write Batching**: Implemented `WriteBuffer` to aggregate Redis writes, reducing total operations by ≥50%.
- **Benchmark Validation**: Conducted final performance validation, confirming throughput targets were met.

## [29.0.0] - 2026-03-28 — Phase 29: Python Throughput Hardening - Phase 3: Multi-Process Architecture

### Added
- **Multi-Process Worker Model**: Implemented a scalable architecture using Docker Compose and HAProxy load balancing.
- **Scaling**: Verified linear scaling to 4 workers, achieving ≥3,200 connections per second.

## [28.0.0] - 2026-03-28 — Phase 28: Python Throughput Hardening - Phase 2: Redis Optimization

### Added
- **Redis Pipelining**: Integrated pipeline batching for a 30-40% reduction in Redis latency.
- **Unix Domain Sockets**: Added support for local socket communication to further reduce round-trip times.

## [27.0.0] - 2026-03-27 — Phase 27: Advanced Pentest Remediation

### Fixed
- **Vulnerability Remediation**: Fixed critical issues including IP spoofing, sync/async Redis mismatches, and potential TLS parsing DoS vectors.

## [26.0.0] - 2026-03-27 — Phase 26: Python Throughput Hardening

### Added
- **Parallel Signal Collection**: Re-engineered the pipeline to use `asyncio.gather` for concurrent signal modules.
- **Throughput Gains**: Achieved ~700-950 connections per second per single-process worker.

## [25.0.0] - 2026-03-28 — Phase 25: Docker Container Management

### Added
- **Docker Image Inventory** (`docs/DOCKER_IMAGES.md`): Canonical registry of all images, pinned versions, and usage across the project.
- **Image Update Policy** (`docs/runbooks/docker_image_updates.md`): Documented policy for CVE response timelines, stability windows, and update procedures.
- **Image Version Check Script** (`scripts/check_image_versions.py`): Automated tool to detect `:latest` tags and version drift between compose files.

## [21.0.0] - 2026-03-27 — Phase 21: Documentation Excellence

### Added
- **Audience-first navigation structure** in `docs/INDEX.md`
- **Persona-based documentation packs**: Operator, Developer, Architect, Auditor
- **Automatic roadmap synchronization tooling** (`scripts/sync-roadmap.py`)
- **Strict documentation linting** in CI pipeline
- **Consolidated security model** in `docs/DEPLOYMENT_SECURITY_MODEL.md`

## [20.0.0] - 2026-03-26 — Phase 20: Passive TAP Mode

### Added
- **Passive capture engine** using AF_PACKET / raw sockets
- **Multi-core capture workers** with zero-copy ring buffers
- **Out-of-band enforcement bridge** to external firewalls (IPtables/EDL)
- **Full JA4 fingerprint family** support: JA4, JA4S, JA4L, JA4H, JA4SSH
- **TAP-to-Cloud Intelligence export** pipeline

## [19.0.0] - 2026-03-24 — Phase 19: Backup & Restore

### Added
- **Deterministic backup format** ensuring consistent key ordering
- **Binary artifact serialization** for efficient state storage
- **Retention policy engine** with automated cleanup of old artifacts
- **Admin CLI tools** for manual backup/restore operations
- **Observability metrics** for backup duration and success rates

## [18.0.0] - 2026-03-22 — Phase 18: Security Audit Remediation

### Added
- **`SignalCollector` Protocol** for type-safe plugin architecture
- **Pipeline error metrics** tracking failure rates per module
- **Strict exception hierarchy** replacing broad except blocks

### Changed
- **Lazy log formatting** across hot path to reduce connection latency
- **F-string logging remediation** for security and performance

## [17.0.0] - 2026-03-20 — Phase 17: Docker Test Optimization

### Fixed
- **Docker container hang** during test suite teardown
- **Race condition** in ephemeral network cleanup
- **Resource leaks** in test container orchestration

## [16.0.0] - 2026-03-18 — Phase 16: Extended Fingerprinting

### Added
- **JA4X X.509 certificate fingerprinting**
- **Adaptive rate limiting** based on fingerprint reputation
- **OpenTelemetry tracing** for connection lifecycle analysis
- **Coverage gates** in CI to prevent regression

## [14.0.0] - 2026-03-15 — Phase 14: Production Hardening

### Added
- **Circuit breaker pattern** for Redis and external API dependencies
- **Container security profiles** (Seccomp/AppArmor)
- **Tarpit self-protection** against memory-exhaustion attacks
- **Secrets rotation** support via SIGHUP

## [12.0.0] - 2026-03-10 — Phase 12: Analytics Node

### Added
- **Cross-instance campaign detection** using Redis Streams
- **Slow-scan detection** via HyperLogLog cardinality analysis
- **Score drift alerting** with Z-score statistical monitoring
- **Executive Grafana dashboards** for security posture overview

## [11.0.0] - 2026-03-05 — Phase 11: RDAP Enrichment

### Added
- **IANA bootstrap integration** for global RDAP routing
- **Automatic block expansion** to malicious /24 and /48 subnets
- **Organization reputation** tracking across netblocks

## [10.0.0] - 2026-03-01 — Phase 10: AbuseIPDB Enrichment

### Added
- **Three-tier reputation cache** (Local → Redis → API)
- **Daily quota management** with persistent Redis counters
- **Fail-open logic** for high-availability lookup pipeline

## [9.0.0] - 2026-02-25 — Phase 9: Beaconing Detector

### Added
- **Inter-Arrival Time (IAT)** coefficient of variation analysis
- **Short-window burst detection** (10-min)
- **Long-window APT beacon tracking** (24-hour)

## [8.0.0] - 2026-02-20 — Phase 8: Spamhaus DROP/EDROP

### Added
- **In-process trie matching** for zero-latency hard blocks
- **Feed management framework** with ETag and leader election
- **Automated daily feed updates**

## [7.0.0] - 2026-02-15 — Phase 7: FCrDNS Enrichment

### Added
- **Async PTR lookup pipeline**
- **Forward-Confirmed Reverse DNS** (FCrDNS) verification
- **Residential pattern detection**

## [2.0.0] - 2024-02-14 — Phase 2: Security Hardening Release

### 🔒 CRITICAL SECURITY FIXES
- **Fixed wildcard imports from Scapy** - Replaced with specific imports to prevent namespace pollution
- **Enforced Redis authentication** - Password now required via environment variable, fails in production without auth
- **Added comprehensive configuration validation** - Schema validation prevents configuration injection attacks
- **Secured secrets directories** - Set proper permissions (700) on secrets/ and ssl/private/ directories

### 🛡️ HIGH PRIORITY SECURITY FIXES
- **Changed default bind address** - Now binds to 127.0.0.1 by default instead of 0.0.0.0
- **Implemented fail-closed rate limiting** - Blocks requests on Redis errors instead of allowing
- **Added Docker security options** - Implemented `no-new-privileges`, `cap_drop`, and `read_only` root filesystem

## [1.0.0] - 2024-02-01 - INITIAL PUBLIC RELEASE

### Added
- **Core JA4 Fingerprinting** - Support for JA4 extraction and matching
- **High-Performance Proxy** - Low-latency TLS passthrough implementation
- **Redis Integration** - Centralized state for whitelists and blacklists
- **Prometheus Metrics** - Real-time observability and connection tracking
- **Monitor Mode** - Dial-controlled progressive blocking enforcement

## [0.0.0] - 2024-01-15 — Phase 0: Foundation

### Added
- **Infrastructure**: Initial Redis integration with Sorted Sets, Bloom filters, and LRU caching.
- **Config**: Implementation of `ConfigLoader` with hot-reload and IPv6 support.
- **Bypass Logic**: Integrated static IP allowlist and CDN trust rules.
