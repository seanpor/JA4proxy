# Changelog

## [62] - 2026-04-09 - Go Fuzzing, Adversarial & Chaos Test Parity

### Added
- `cmd/proxy/fuzz_test.go` — three Go-native fuzz targets (`FuzzClientHello`, `FuzzReadProxyProtocol`, `FuzzReadProxyProtocolV2`) seeded from `tests/adversarial/corpus/*.bin`. Each target ran 10 s × 16 workers panic-free in smoke testing (~915k execs for ClientHello).
- `internal/tls/parser_test.go` — `TestParseClientHello_AdversarialCorpus` table-driven test driving all 13 corpus fixtures with a 100 ms watchdog per fixture. None panic, none hang.
- `internal/tls/ja4_fp_corpus_test.go` + `internal/tls/testdata/ja4_fp_golden.txt` — JA4 fingerprint regression test that locks in the Go-computed JA4 for every fixture in `tests/fixtures/clienthello/`. Regenerate with `go test -run TestJA4_FPCorpus_NoRegression ./internal/tls/ -args -update`.
- `internal/security/pipeline_chaos_test.go` — three fault-injection scenarios (`TestPipeline_RedisOutage_FailsOpen`, `TestPipeline_PartialOutage_AllowBypassesStillWork`, `TestPipeline_DialFlip_NoStaleDecisions`). All assert the asymmetry doctrine from CLAUDE.md.
- `internal/security/property_test.go` — four `pgregory.net/rapid` property tests: `ScoreInRange`, `ScoreMonotonic`, `DecisionIdempotent`, `DialZeroNeverBlocks`. 100 cases each, all pass.
- `cmd/proxy/bench_test.go` — `BenchmarkPipeline_Allow` (~469 ns/op, 8 allocs) and `BenchmarkPipeline_Score` (~1908 ns/op, 19 allocs) on i9-9900K.
- `scripts/generate_validation_report.py` — pre-enterprise validation report generator. Counts Go test surface, surfaces Phase 200-203 commits, runs govulncheck/pip-audit + 1 s fuzz smoke per target. Output: `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md`.
- New Makefile targets (appended at bottom, no existing targets edited): `test-go-fuzz-smoke`, `test-go-property`, `test-go-chaos-unit`, `bench-go-pipeline`, `validation-report`. The `test-go-chaos` name is already used by an unrelated Python-driven target, so the unit-test variant is suffixed `-unit`.
- `pgregory.net/rapid v1.2.0` added to `go.mod` for property-based testing.

### Notes
- Phase 200's `ReadProxyProtocolV2` does not exist yet. `FuzzReadProxyProtocolV2` is wired to the current `ReadProxyProtocol` entry point with v2-shaped binary seeds; when Phase 200 lands, the target should be repointed at the v2 reader directly.
- Python `tests/security_regression/`, `tests/fuzz/` (atheris), and Phase 27 break-glass docs are intentionally NOT carried over — the Python proxy is experimental and those findings are owned by Phases 200-203 on the Go side.

## [Unreleased] - Phase 61 — CI test pipeline + repo hardening

### Added
- **`.github/workflows/ci.yml`** — three test jobs (`test-go`, `test-python`, `lint`) plus five security jobs (`secrets-scan` via TruffleHog, `sast` via Semgrep, `dependency-audit-python` via pip-audit, `dependency-audit-go` via govulncheck, `dependency-review` for HIGH severity + GPL/AGPL/SSPL deny). Triggered on every PR, every push to `main`, and weekly on Mondays at 06:00 UTC. Top-level `permissions: contents: read`; jobs that need more (e.g. SARIF upload) override locally.
- **`.github/dependabot.yml`** — weekly updates for `github-actions`, `pip`, and `gomod` with grouped action bumps and a per-ecosystem PR cap of 5.
- **`scripts/branch_protection.sh`** — one-shot bootstrap script (operator-run) that PUTs the required-status-check rules to GitHub. AI-agent project, so `required_pull_request_reviews=null` — the gate is CI, not human review.
- **`docs/security/CVE_EXCEPTIONS.md`** — exception template, 90-day max expiry, HIGH/CRITICAL 7-day SLA.
- **`tests/test_workflow_pinning.py`** — verification test asserting every `uses:` line is a 40-char SHA, every workflow declares a top-level `permissions:` block, the branch-protection script is executable, and `dependabot.yml` parses and covers all three ecosystems.
- **`Makefile`** — new `ci-local` target so contributors can reproduce the CI test commands locally before pushing.

### Changed
- **`.github/workflows/ja4proxy-policy.yml`** — `actions/checkout@v4` and `actions/setup-python@v5` replaced with their 40-character commit SHAs (matching the canonical pattern in `release-cli.yml`); added top-level `permissions: contents: read`. No logic changes.

## [Unreleased] - Phase 84 second critical review fixes

### Fixed
- **C1 (CRITICAL)** `dsar_erase` ban-preservation TOCTOU — reason and TTL now fetched via a single pipeline; absent bans no longer produce ghost `skipped` entries (`management/api/routes/compliance.py`)
- **C2 (CRITICAL)** Monthly/stream fallback misfired on quiet windows — now falls back only when every month in the requested range is missing an aggregate, not when `total == 0`
- **C3 (CRITICAL)** ISO timestamp comparison was lexicographic, silently dropping events with a different TZ format than the window builders used — added `_parse_ts` / `_ts_in_window` helpers applied to every stream/audit filter in `compliance.py` and `pack_builder.py`
- **H2 (HIGH)** Logo validation was theatre (no size cap, silent errors, hardcoded `image/png` MIME) — replaced with `_validate_logo()`: 1.4MB base64 cap, magic-byte sniff (PNG/JPEG/GIF/SVG), correct MIME, WARN logs on rejection
- **H4 (HIGH)** `/signal-categories` endpoint constructed a bare default classifier and lied about configured overrides — added module-level `_get_classifier()` loading `reporting.signal_categories` from `proxy.yml`
- **H5 (HIGH)** Non-numeric monthly aggregate fields crashed the whole `/compliance/report` call — per-field try/except with WARN log
- **M3 (MEDIUM)** Token inventory denylist → allowlist (`_TOKEN_SAFE_FIELDS`) so future phases adding token fields cannot silently leak them into the evidence pack
- **M5 (MEDIUM)** `ReportData.block_rate_pct` now clamps to `[0, 100]` — prevents rendering "173.4%" when aggregate and stream sources disagree
- **M6 (MEDIUM)** HTML escape in `_render_simple_pdf` titles and artefact row content (defence in depth)
- **L3 (LOW)** DSAR erase audit record now preserves full `skipped` list, not just its length — auditors can prove *which* key was skipped and *why*
- **L4 (LOW)** Module-level classifier cache avoids rebuilding the default mapping on every request

### Changed
- **Python proxy clearly marked EXPERIMENTAL** — loud startup banner in `proxy.py` (bypass with `JA4PROXY_PYTHON_EXPERIMENTAL_ACK=1`), prominent warnings in `CLAUDE.md`, `README.md`, and `src/security/__init__.py`. The production proxy is the Go binary (`bin/proxy`, Phase 15+); the Python implementation exists only as a prototyping surface for new signal modules.

### Added
- 9 new tests in `management/tests/test_compliance_routes.py` covering C1, C3, H2, H4, H5, L3 (**test count: 112 Python + 36 Go = 148**, was 139)
- `docs/phases/PHASE_101.md` — Phase 101 plan tracking the 9 deferred review items (H1 double-XRANGE, H3 CIDR watchlist match, M1 Redis version check, M2 metric rename, M4 audit log pagination, M7 DSAR partial failures, L1 Jinja2 env cache, L2 JSONL invariant doc, L5 DSAR retention text from config)

## [84] - 2026-04-08 - Compliance Reporting & Evidence Pack

### Added
- **Python compliance package** (`management/compliance/`):
  - `classifier.py` — `SignalClassifier` maps fired RiskSignal names to attack categories; configurable weights; tie-breaking by alphabetical category name
  - `purge.py` — `GDPRPurge` enforces retention policy across Stream events, beaconing SortedSets, return-visitor hashes, and monthly aggregates; fail-open with per-category error capture
  - `pack_builder.py` — `PciDssPackBuilder` generates 8-artefact evidence ZIP (block log, allowlist, blocklist, audit log, config changes, RBAC snapshot, risk thresholds, SHA-256-signed deployment confirmation)
  - `report_renderer.py` — `ReportRenderer` renders executive HTML/PDF reports via Jinja2 with full auto-escaping; PDF requires WeasyPrint; falls back to HTML gracefully
- **6 new Management API compliance routes** (`management/api/routes/compliance.py`):
  - `POST /api/v1/compliance/pci-dss-pack` (Auditor+) — ZIP evidence pack
  - `POST /api/v1/compliance/report` (Auditor+) — HTML or PDF executive report
  - `GET /api/v1/compliance/dsar/{ip}` (Auditor+) — GDPR subject access request export
  - `DELETE /api/v1/compliance/dsar/{ip}` (Admin) — GDPR right-to-erasure with audit trail
  - `POST /api/v1/compliance/purge-expired` (Admin) — GDPR retention enforcement
  - `GET /api/v1/compliance/signal-categories` (Auditor+) — active classifier mapping
- **Go compliance package** (`internal/compliance/`):
  - `classifier.go` — cross-language parity with Python `SignalClassifier`; identical tie-breaking and weight resolution
  - `pagination.go` — `PageIterator` for streaming all connection events across pages; `CollectAll` convenience helper; `DecodePageToken` for cursor inspection
- **Go CLI compliance commands** (`internal/cli/commands/compliance.go`):
  - `ja4proxy-cli compliance dsar export <ip>` — DSAR export
  - `ja4proxy-cli compliance dsar erase <ip>` — GDPR erasure (requires `--ticket`)
  - `ja4proxy-cli compliance purge-expired` — retention purge
  - `ja4proxy-cli compliance pci-dss-pack` — download evidence ZIP
  - `ja4proxy-cli compliance connections-export` — paginated JSONL export
  - `ja4proxy-cli compliance signal-categories` — list classifier mapping
  - `ja4proxy-cli report generate` — HTML/PDF executive report
- **HTTP client** (`internal/cli/client/client.go`): added `PostBinaryResponse()` for ZIP/PDF binary downloads
- **`GET /api/v1/connections`** enhanced: `?until=`, `?page_token=` parameters; `_MAX_LIMIT` raised 500→10,000; response adds `has_more`, `next_page_token`, `total_in_window`; `truncated` kept for backwards compatibility
- **Config** (`config/proxy.yml`): `gdpr:` and `reporting:` sections with retention days and configurable signal categories
- **Docs**: `docs/compliance/soc2-control-narrative.md`, `docs/compliance/iso27001-annex-a-mapping.md`, `docs/REDIS_SCHEMA.md` Phase 84 keys
- **Ops**: `deploy/prometheus/alerts/compliance.yml` (purge overdue, stream unbounded, token expiry); `deploy/ansible/playbooks/monthly-report.yml`
- **Makefile**: `test-phase-84`, `test-phase-84-go`, `test-phase-84-python`, `test-phase-84-classifier-parity` targets

### Test coverage
- 27 Go compliance tests (classifier + pagination) — all pass
- 9 Go CLI compliance command tests — all pass
- 103 Python compliance tests across 6 test files — all pass
- Cross-language parity vectors: 18 identical input→output assertions in both Go and Python

---

## [85] - 2026-04-08 - Threat Intelligence Ingestion

### Added
- `src/analytics/ti_feeds/` package — outbound-symmetric inbound TI feed runner that consumes external indicators and writes them through the Phase 79 Management API rather than directly into Redis
  - `base.py` — `FeedClient` ABC, `FeedConfig`, `FeedPollResult` dataclasses
  - `runner.py` — `FeedRunner` scheduler with leader election (`ti_feed:leader_lock`, 30 s TTL), per-feed circuit breaker integration, differential cleanup pass after every successful poll
  - `state.py` — `FeedState` Redis sidecar index for the six `ti_feed:*` keys (per-feed `blocklist_uuids`, `ban_ips`, `active_stix_ids`, `poll_state`, `runtime_enabled`)
  - `circuit_breaker.py` — per-feed CLOSED/HALF-OPEN/OPEN state machine, distinct from the Phase 14e/Phase 59 hot-path TI breaker (batch-poll semantics, opens after N consecutive failed polls not single calls)
  - `mgmt_client.py` — async aiohttp client for `POST /api/v1/bans/{ip:path}` and `POST /api/v1/blocklist`; bearer auth via `JA4PROXY_FEED_CLIENT_TOKEN`; honours the Phase 79 Operator-role rate limit (50 req/s pacing, 50-indicator batches)
  - `taxii.py` — hand-rolled async TAXII 2.1 client (no `taxii2-client` dep — see ADR-024); polls `{root}/collections/{id}/objects/?added_after={ts}`, parses STIX bundles, routes IP and JA4 indicators
  - `recorded_future.py` — Recorded Future connector (TAXII front door + `X-RFToken` header)
  - `crowdstrike.py` — CrowdStrike Falcon Intel OAuth2 client (`/oauth2/token` + `/intel/combined/indicators/v1` cursor pagination)
  - `rest_generic.py` — JSONPath-driven generic REST client (uses `jsonpath-ng`)
  - `seed_file.py` — startup loader for `config/known_bad_fingerprints.yml`, routed through the Management API the same way as any feed
  - `contribution.py` — disabled-by-default community contribution client; hard-gated payload whitelist enforces the GDPR field set (no raw IPs, no SNI, no audit log fields)
  - `stix_ja4.py` — `x-ja4-fingerprint` SCO parse / validation helpers; JA4 regex shared with `monitoring/metrics_registry.md`
  - `metrics.py` — eight Prometheus counters/gauges/histograms registered once to avoid duplicate-timeseries errors
- `management/api/routes/threat_intel.py` — five new routes:
  - `GET  /api/v1/threat-intel/feeds` (Auditor)
  - `GET  /api/v1/threat-intel/feeds/{feed_id}` (Auditor)
  - `POST /api/v1/threat-intel/feeds/{feed_id}/enable`  (Operator)
  - `POST /api/v1/threat-intel/feeds/{feed_id}/disable` (Operator)
  - `POST /api/v1/threat-intel/feeds/{feed_id}/poll`    (Operator)
- `management/api/models.py` — `ManagedBy.feed = "feed"` enum extension and `TIFeedStatus` / `TIFeedListResponse` Pydantic models
- `management/api/main.py` — `include_router(threat_intel.router)`
- `config/known_bad_fingerprints.yml` — 14 vetted JA4 fingerprints from public security research (Cobalt Strike, Sliver, Mythic, Metasploit, etc.) loaded at startup when `threat_intel.seed_file.enabled: true`
- `config/proxy.yml` — new `threat_intel:` block (feeds list, circuit_breaker tunables, seed_file, feed_contribution stub)
- `monitoring/alertmanager/rules/ti_feed.yml` — `TIFeedCircuitOpen`, `TIFeedStale` (>2 h), `TIFeedMgmtApiErrors` (>0.1/s)
- `monitoring/metrics_registry.md` — Phase 85 section documenting all eight metrics
- `docs/decisions/ADR-024.md` — hand-rolled STIX/TAXII chosen over `stix2`+`taxii2-client`; rationale: sync-only TAXII client, transitive dep footprint, fully-async fits the analytics container event loop
- `docs/REDIS_SCHEMA.md` — Phase 85 section for the six `ti_feed:*` keys
- `requirements.txt` — `jsonpath-ng==1.6.1`

### Security
- **C1 SSRF guard**: `validate_feed_url()` rejects non-https feed URLs and any host inside loopback / RFC1918 / link-local / CGNAT / ULA / multicast / reserved ranges. Enforced at config-parse time so a bad URL is refused before any aiohttp client is built.
- **C2 credential redaction**: `runner._rebuild_clients` no longer logs the raw config dict (only the feed id). `routes/threat_intel.py` strips `last_error` to its category prefix at the API boundary so Auditors never see upstream 401/403 bodies that may echo back bearer tokens.
- **C4 feed_id validation**: feed_id must match `^[a-z0-9][a-z0-9_-]{0,63}$` and may not collide with reserved names (`leader_lock`). Closes a Redis-key-namespace pivot and a Prometheus-cardinality inflation vector.
- **C5 ban-target IP allowlist**: `is_bannable_ip()` rejects loopback / RFC1918 / link-local / multicast / reserved targets. Enforced inside `ManagementClient.post_ban` so every feed client (TAXII, RF, CS, REST, contribution) inherits the guard. A compromised upstream feed can no longer ban operator infrastructure.
- **C8 differential-cleanup correctness**: replaced the operator-precedence bug `if handle and handle.count(".") >= 1 or ":" in (handle or "")` with an authoritative-set lookup against `ti_feed:{feed_id}:ban_ips` and `ti_feed:{feed_id}:blocklist_uuids`. Empty handles no longer trigger `delete_blocklist("")`.
- **C7 leader-lock fail-closed**: `FeedState.try_acquire_leader` now returns `False` on Redis errors instead of `True`. The previous fail-open behaviour caused every analytics replica to act as leader during a Redis outage, doubling polls and racing differential cleanup.
- **C7 cleanup atomicity**: per-indicator cleanup now runs through `FeedState.clear_handle`, which executes `hdel(active_stix_ids)` + `srem(ban_ips|blocklist_uuids)` inside a single Redis `MULTI/EXEC` transaction. The mgmt API delete still happens first; combined with idempotent 404 handling, the overall flow is at-least-once and converges.
- **C3 CrowdStrike repr redaction**: `CrowdStrikeFalconClient.__repr__` now emits `<redacted>` placeholders for `client_id`/`client_secret` and a `<set>`/`<unset>` token state instead of falling through to the default `self.config` repr that printed both credentials in plaintext.
- **C6 IPv4-mapped / 6to4 / Teredo canonicalisation**: `is_bannable_ip` now unwraps `ipv4_mapped`, `sixtofour`, and `teredo` IPv6 forms before classifying them, closing a bypass where a feed could ban operator loopback by sending `::ffff:127.0.0.1` (or the equivalent 6to4 / Teredo wrapper of an RFC1918 address).
- Fixed dead-code `JA4_REGEX` character-class bug (`[d|q]` → `[dq]`) so the exported regex stops accepting literal `|` in JA4 strings.

### Notes
- `ManagedBy` enum gained one new member (`feed`); existing `terraform`/`operator`/`api`/`analytics`/`legacy`/`migration` values are unchanged. Phase 79 resource model tests pass unchanged (35/35).
- Phase 23 `src/security/ti_provider.py` (hot-path TI scorer) and Phase 46 `src/security/misp.py` are intentionally untouched. Phase 85 introduces a new abstraction under `src/analytics/ti_feeds/` rather than overloading either of them — different responsibilities, different lifetimes, different failure modes.
- Phase 20 TAP TAXII *publisher* (`src/tap/export/taxii_server.py`) and the new Phase 85 *consumer* round-trip cleanly: both speak `pattern_type: "stix"` over the new `x-ja4-fingerprint` SCO.
- The `feed` provenance value alone does not identify *which* feed; the runner maintains the `ti_feed:{feed_id}:*` Redis sidecar index for that, and every feed-created resource carries `note=feed:{feed_id}:{stix_id}` (blocklist) or `reason=feed:{feed_id}` (ban).
- Recorded Future and CrowdStrike connectors are implemented per the PHASE_85.md spec but **API contracts are not yet vendor-verified** — both clients carry a `# TODO: verify against vendor portal before production use` comment. Both ship `enabled: false` by default.
- The community contribution client is disabled by default and the hosted endpoint at `https://feed.ja4proxy.io/` does not yet exist. The hard GDPR field-whitelist gate is enforced at serialisation, not at the HTTP boundary.

## [83] - 2026-04-07 - ja4proxy-cli Go Binary

### Added
- `ja4proxy-cli` compiled Go binary (`cmd/ja4proxy-cli/main.go`) with 9 top-level command groups: `ip`, `allowlist`, `blocklist`, `dial`, `config`, `health`, `fingerprint`, `policy`, `simulation`
- HTTP client (`internal/cli/client/client.go`): 30s timeout, Bearer auth, descriptive errors including HTTP status codes
- Auth resolver (`internal/cli/auth/auth.go`): flag → `JA4PROXY_TOKEN`/`JA4PROXY_URL` env var → config file (correct precedence)
- CLI config file (`internal/cli/config/config.go`): reads `~/.config/ja4proxy/cli.yaml` for default URL/token/output
- Output formatters (`internal/cli/output/output.go`): ASCII table (tablewriter), JSON (indented), CSV with reflect-based header extraction
- IP commands (`internal/cli/commands/ip.go`): `RunIPBan`, `RunIPRelease`, `RunWatchlistAdd`, `RunWatchlistRemove` (lookup-then-delete), `RunIPLookup` — verified against Phase 79 API (`POST /api/v1/bans/{ip}`, IP in path)
- Allowlist/Blocklist commands: `RunAllowlistAdd/Remove/List`, `RunBlocklistAdd/Remove/List` with lookup-then-delete for remove
- Dial commands (`internal/cli/commands/dial.go`): `RunDialGet`, `RunDialSet` with `PendingApprovalError` (exit 2) on HTTP 202; client-side 0–100 range guard
- Config reload (`internal/cli/commands/config.go`): `RunConfigReload` — iterates all nodes or targets specific node
- Health (`internal/cli/commands/health.go`): `RunHealth` aggregating `/api/v1/nodes` + `/api/v1/health/deep`
- Fingerprint history (`internal/cli/commands/fingerprint.go`): `RunFingerprintHistory`
- Policy validator (`internal/cli/commands/policy.go`): `ValidatePolicy` re-implements all 8 rules natively in Go (YAML parse, top-level keys, dial range 0–100, expires TTL, dial increase >20, CIDR via `net/netip`, JA4 regex, duplicate detection); parity with `scripts/ja4proxy-policy.py`
- Simulation stubs (`internal/cli/commands/simulation.go`): return `ErrSimulationNotAvailable` pending Phase 100-M
- All mutating commands require `--confirm`; missing flag exits 1 with clear message
- Global flags: `--url`, `--token`, `--output` (table|json|csv)
- New Go deps: `github.com/spf13/cobra`, `github.com/olekukonko/tablewriter`
- ADR-083a: Goreleaser selected for multi-arch release + GPG signing + SLSA provenance
- ADR-083b: native Go re-implementation of policy validator (air-gapped compatible)
- `docs/developer/RELEASE_PROCESS.md`: GPG key setup, Goreleaser usage, user verification steps

### Fixed
- Auth resolution order bug: config file was winning over env var; corrected to flag > env > config > keychain
- Parity test GOROOT detection: tests were silently skipping due to wrong Go toolchain path; now detect `/snap/bin/go` with `/snap/go/current` GOROOT explicitly

### Tests
- 76 Go unit tests across `internal/cli/` packages (auth, client, commands, output)
- 14 Python parity tests in `tests/integration/test_cli_parity.py` — compile Go binary, compare exit codes against Python script for 5 policy YAML cases plus `--confirm` enforcement
- `make test-phase-83`: build + vet + Go unit tests + Python parity tests

### Notes
- Keychain (99designs/keyring) integration deferred → Phase 100-O
- `confirm_mutating: false` config flag not yet honoured → Phase 100-P
- Simulation commands (`simulation run/status/report`) are stubs → Phase 100-M

## [Unreleased] - Phase 100 - Phase 79 SSO/MFA Gap Closure

### Added
- OIDC JWKS signature verification: `_fetch_jwks()` with double-checked `asyncio.Lock` caching (1-hour TTL), `authlib.jose` RS256 decode + claim validation; `MANAGEMENT_TEST_MODE=1` bypass for unit tests (`management/api/routes/oidc.py`)
- SSO audit log events: `write_audit()` called on every successful SAML and OIDC login with `action_type="sso.login"`, `resource_type="session"`, and `{"provider": "saml"|"oidc"}` in `after_value`
- WebAuthn credential management endpoints: `GET /auth/mfa/webauthn/credentials` lists enrolled credentials with `created_at`; `DELETE /auth/mfa/webauthn/credentials/{id}` removes credential hash and SET entry with ownership check (returns 204/403/404)
- SSO-delegated MFA trust: `MANAGEMENT_SSO_TRUST_IDP_MFA=true` env var enables automatic MFA session stamp when SAML response includes `TimeSyncToken` or `MobileTwoFactorContract` authn context, or OIDC `amr` claim includes `mfa`, `otp`, `hwk`, or `swk`
- `pytest.mark.integration` markers registered in `pyproject.toml` for SAML and OIDC live-IdP placeholder tests
- `management/api/proxy_config.py`: `get_sso_role_mapping()` reads `sso.role_mapping` from `config/proxy.yml` with 60-second in-process cache; env-var `MANAGEMENT_SAML_ROLE_MAPPING` / `MANAGEMENT_OIDC_ROLE_MAPPING` take priority over config-file entries
- `pyyaml>=6.0.0` added to `management/requirements.txt`

### Tests
- `management/tests/test_proxy_config.py`: 7 tests — valid YAML, missing file, no sso section, cache hit/miss, malformed YAML, empty file
- `management/tests/test_saml.py` Sections 9–11: audit write, MFA trust session key, proxy.yml role-mapping merge, env-override
- `management/tests/test_oidc.py` Sections 9–11: audit write, MFA trust (amr claim), JWKS signature verification with real RSA key pair, cache call-count test
- `management/tests/test_webauthn.py` Section 6: list empty/populated credentials, delete success/not-found/wrong-owner (6 tests)

### Notes
- MANAGEMENT_TEST_MODE=1 bypass in `_extract_claims` mirrors the bcrypt bypass in `auth.py` — allows all existing OIDC tests with unsigned fake tokens to keep passing
- JWKS cache uses double-checked locking to prevent thundering-herd on cold start
- Gap 7 (OpenAPI 3.1 spec generation) was completed in Phase 79 C10; not repeated here

## [Unreleased] - Phase 82 - Policy-as-Code, Shadow Mode & Governance

### Added
- Policy governance module (`src/governance/`): Cerberus-based YAML schema (`policy_schema.py`), 7-step offline validator (`policy_validator.py`) with typed exceptions (`PolicySyntaxError`, `PolicySchemaError`, `PolicyTTLError`, `PolicyDuplicateError`, `PolicyValidationError`), and async aiohttp applier (`policy_applier.py`) with idempotent apply and drift detection
- CLI stopgap script (`scripts/ja4proxy-policy.py`): `validate` (offline, exit 0/1), `apply` (exit 0/1/2 for success/error/pending-approval), `diff` (exit 0/1); interface matches Phase 83 `ja4proxy-cli` so CI templates need no changes when Phase 83 ships
- CI/CD templates: GitHub Actions (`.github/workflows/ja4proxy-policy.yml`), GitLab CI (`.gitlab-ci/ja4proxy-policy.yml`), Jenkins (`Jenkinsfile.ja4proxy-policy`), Ansible (`deploy/ansible/playbooks/apply-policy.yml`)
- Shadow mode storage ADR (`docs/decisions/ADR-082.md`): Option A (Redis + LZ4) for ≤ 50M connections/month; Option B (ClickHouse) for larger deployments
- Policy YAML schema documentation (`docs/policy/schema.md`): full field reference, validation rules, apply behaviour, and approval flow for operators
- Management API mock server (`tests/mocks/management_api_mock.py`): real aiohttp HTTP server on random port with configurable allowlist/blocklist state, 202 dial-pending mode, and `PATCH /api/v1/config` route for bypass toggle tests
- `DiffResult` dataclass in `policy_applier.py`: `diff_policy()` returns `DiffResult(drift=[...])` rather than a bare list, allowing caller code to distinguish "empty drift" from "call failed"
- `docs/REDIS_SCHEMA.md`: 4 new key patterns (`decisions:pending:{id}`, `decisions:history`, `sim:conn:{hour_epoch}:{conn_id}`, `sim:job:{sim_id}`)

### Fixed
- `_get_list` in `policy_applier.py` now raises `RuntimeError` on non-200 responses — previously a 401 was silently treated as an empty list, making bad-token apply runs appear successful
- `_apply_ips()` and `_apply_fingerprints()` called unconditionally so stale `managed_by=policy` entries are removed from the live API when the policy list is emptied
- `diff` CLI sub-command crashed 100% of the time — treated `DiffResult` object as a list; fixed to access `.drift`
- `--env` flag in documentation examples replaced with `--url $JA4PROXY_URL` (flag did not exist in the CLI parser)
- Mock server now has `PATCH /api/v1/config` route; `bypass_toggles` apply path is tested (`test_apply_bypass_toggles`)

### Tests
- `tests/unit/test_policy_validator.py`: 11 tests covering all validator error paths and boundary conditions (dial increase boundary at 20, CIDR validation, JA4 format, duplicate detection)
- `tests/integration/test_policy_apply.py`: 9 tests covering idempotency, new entry creation, stale entry removal, operator drift protection, dial change, 202 pending-approval flow, diff detection, and bypass toggle apply
- `make test-phase-82` target added

### Notes
- Phase 82 §10.1 offline acceptance criteria: all met. 20/20 tests pass.
- Phase 82 §10.2 platform-dependent criteria deferred to Phase 100 item 100-N (blocked on Phase 79 and analytics pre-conditions)
- Phase 79 coordination (7 missing API endpoints/values): tracked in Phase 100 item 100-L
- Analytics pre-conditions for shadow mode (`signal_retention.py`, `simulation_runner.py`): tracked in Phase 100 item 100-M

## [Unreleased] - Phase 81 - SOAR, Webhooks & Enterprise Operations Platforms

### Added
- XSOAR integration package (`integrations/xsoar/JA4proxy/`): 8 commands covering ban, release, connection history, fingerprint detail, watchlist, allowlist, health, and dial — all tested against mock server
- Splunk SOAR app (`integrations/splunk-soar/ja4proxy/`): 8 actions mirroring XSOAR commands, tested against the same mock server (`tests/mocks/soar_mock.py`)
- ServiceNow SecOps handler (`integrations/servicenow/ja4proxy_snow_handler.py`): `ecs_to_sir()` maps ECS event dicts to SIR table payloads; `create_sir_incident()` POSTs to ServiceNow; resolution close-loop releases ban and adds 24h allowlist entry via Integration Hub Spoke
- xMatters two-way response integration: Event Plan with 5 routing conditions; 5 mobile response options including `False Positive — Release` (calls `DELETE /api/v1/bans/{ip}`) and `Extend Ban` (calls `PATCH /api/v1/bans/{ip}`)
- Interlink Software Service Watch integration: Vector sidecar config (`config/integrations/vector-interlink.yaml`) converting ECS JSON to CEF-over-TLS-syslog; Ansible device registration task; CEF severity mapped to integer 0-10 from `event.risk_score`
- Interlink correlation rule examples (`docs/integration/interlink_correlation_rules.md`): campaign detection (N bans from same ASN in T minutes), health degradation (OK→DEGRADED → P2 + auto-ITSM), high-rate source (R events/min → severity escalation)
- PagerDuty and OpsGenie `runbook_url` annotations added to all Alertmanager rules in `monitoring/alertmanager/rules/`
- Token rotation script (`scripts/rotate_soar_token.sh`): calls `POST /api/v1/tokens/{id}/rotate` and logs the rotation event; operator must then copy the new token into the SOAR platform asset configuration (manual step — token is intentionally not printed to stdout to avoid log exposure); schedule on 90-day cron
- `tests/integration/test_soar_connectors.py`: all 8 XSOAR commands and 8 Splunk SOAR actions tested for correct HTTP method, path, headers, and body against mock server
- `tests/unit/test_servicenow_handler.py`: 5 tests covering severity mapping (risk_score 90 → "1", 70 → "2"), signal formatting, success path, and 4xx error propagation

### Notes
- All SOAR integrations use Operator-scoped API tokens; no Admin tokens in any integration config or test fixture
- Platform end-to-end validation (XSOAR tenant, Splunk SOAR sandbox, ServiceNow SIR, xMatters Event Plan, Interlink Service Watch) tracked in Phase 100 item 100-E — these cannot be completed without platform access
- ServiceNow Spoke Store submission and xMatters shared library publication are business-track items; they do not block phase completion
- `PATCH /api/v1/bans/{ip}` and `POST /api/v1/tokens/{id}/rotate` dependency on Phase 79 verified; if absent, raised as Phase 100 items 100-J and 100-K

### Known Limitations
- xMatters Flow Designer export as shared library deferred to Phase 100 when xMatters tenant access is available
- Interlink Service Watch live device registration and CEF syslog end-to-end testing deferred to Phase 100 (requires Service Watch instance)

## [0.80.0] - 2026-04-07 - ECS Structured Logging & SIEM Integration Pack

### Added
- ECS 8.x formatter for Go proxy (`internal/logging/ecs_formatter.go`): outputs dotted-key ECS JSON via `logrus`; `Mode: "ecs"` produces ECS 8.x fields; `Mode: "legacy"` retains pre-Phase 80 format
- ECS 8.x formatter for Python analytics (`src/utils/logging_config.py`): `JSONFormatter(format="ecs")` emits `@timestamp`, `source.ip`, `event.action`, `ja4proxy.*`, and all standard ECS fields; `dual_output=True` emits legacy + ECS lines for migration windows
- Webhook dispatcher (`internal/webhook/delivery.go`): HMAC-SHA256 signed delivery to configurable HTTP endpoints; exponential backoff retry; Redis Stream DLQ (`webhooks:dlq`) after retry exhaustion; `X-JA4Proxy-Signature` header; event-type filtering per endpoint
- Vector config templates in `config/integrations/`: `vector-splunk-hec.yaml`, `vector-sentinel.yaml`, `vector-qradar-leef.yaml`, `vector-elastic.yaml`
- Splunk TA (CIM-compliant, 5 correlation searches covering ban storms, campaign detection, dial changes, TLS downgrade, and score drift)
- Microsoft Sentinel content pack (5 KQL analytic rules, 2 Logic App playbooks for automated IP enrichment and dial adjustment)
- IBM QRadar DSM for LEEF-formatted JA4proxy events
- Elastic integration pack with ingest pipeline and index template
- `config/integrations/ecs-schema.json`: JSON Schema (draft-07) validating the five mandatory ECS fields; used in CI via `make validate-ecs-schema`
- `config/integrations/ecs-sample-event.json`: minimal valid ECS `blocked` connection event for schema CI validation
- `docs/api/ecs_extension.md`: canonical ECS field reference for SOC analysts — mandatory fields table, full `ja4proxy.*` extension field table, event type examples, webhook payload and signature verification (Python and bash), schema validation instructions

### Changed
- `logging.format` config key added to `config/proxy.yml` (default: `legacy`); valid values: `legacy`, `ecs`
- Connection log now emits full ECS field set when `logging.format: ecs` is configured — `@timestamp`, `event.action`, `event.outcome`, `event.severity`, `event.risk_score`, `source.ip`, `tls.version`, `tls.cipher`, `threat.indicator.*` (ban events), all `ja4proxy.*` fields
- `setup_logging()` in `src/utils/logging_config.py` accepts `format=` parameter (`"legacy"` or `"ecs"`) in addition to the existing `level=` and `json_format=` parameters

### Notes
- `logging.format: legacy` is the default; no changes required on upgrade for operators not adopting ECS
- Existing Grafana dashboards consume Prometheus metrics; they are not affected by the log format setting
- Phase 79 API-dependent features (Splunk alert action webhook, Sentinel automated playbooks) are verified once Phase 79 merges; all other deliverables are standalone

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

## [Phase 92] — 2026-04-07

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
- TDD test suite: `tests/phase-92/test_lint_hierarchy.py` (114 tests covering target existence, composition, PHONY declarations, help discoverability)
- `scripts/lint_toml.py`: standalone TOML validation script (extracted from inline heredoc)

### Fixed
- `docker/docker-compose.scale.yml` was missing from `lint-docker` compose validation
- `lint-toml`: heredoc in recipe body broke `make help` (GNU make parse error at line 1151); extracted to `scripts/lint_toml.py`

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
