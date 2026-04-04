# Changelog

## [68.0.0] - 2026-04-04 - Python 3.14 Hot Path Optimizations & Thread Safety

### Changed

- `proxy.py`: verified `_GREASE_VALUES` is a module-level `frozenset`; bound to
  local `_grease` variable inside `generate_ja4()` list comprehensions to avoid
  repeated global lookup (JIT-friendly monomorphic call site).
- `proxy.py`: replaced `ProcessPoolExecutor` (Phase 28a) with
  `ThreadPoolExecutor(thread_name_prefix="tls-parser")` for zero-IPC TLS parsing
  fallback; safe for free-threaded Python (GIL disabled).
- `proxy.py`: added `_install_event_loop()` helper that installs uvloop event loop
  policy when available, with graceful `ImportError` fallback to asyncio default.
- `requirements.txt`: added `uvloop>=0.21.0` conditional dependency
  (Linux + Python >= 3.14 only).
- `config/proxy.yml`: added `runtime:` section with `event_loop` and
  `tls_parser_workers` config keys.
- `src/security/risk_scorer.py`: audited — inner scoring loop already uses
  `dict.get()` with no `try/except`; no change required.
- `src/cache/local_cache.py`: audited — no `asyncio.Lock` found; no lock migration
  required (asyncio-only access pattern).
- `src/config/loader.py`: audited — no `asyncio.Lock` found; no lock migration
  required (config dict replaced atomically).

### Added

- `docs/security/THREAD_SAFETY_AUDIT.md`: full audit of all mutable shared state on
  the hot path with per-object thread-safety assessment and recommendations for full
  free-threading readiness.
- `reports/benchmark/python314-stage2.md`: benchmark notes and reproduction
  instructions (live benchmark requires Python 3.14 Docker image from Phase 67).

## [66.0.0] - 2026-04-04 - Python 3.14 Compatibility Assessment

### Added
- `scripts/check-python314-compat.py` — PyPI wheel checker for Python 3.14 compatibility.
  Parses requirements.txt, requirements-test.txt, requirements-analytics.txt; queries PyPI
  JSON API; checks for cp314/py3 wheels; outputs markdown table. Stdlib-only; runs on
  Python 3.10+. Exit 0 if all packages compatible; exit 1 if any C-extension lacks a wheel.
- `docs/reports/python314-compat.md` — compatibility report for all 33 dependencies.
  Result: 7 packages have cp314 wheels, 25 are pure-Python, 1 (pytricia) is sdist-only
  (warn, not fail). No upgrade blockers found.
- `docs/reports/benchmark/python311-baseline.md` — hot-path performance baseline on
  Python 3.10.12 before Dockerfile upgrade. Key numbers: RiskScorer p99=21.2µs,
  ActionDecider p99=1.54µs, full scoring path p99=11.4µs, all well within limits.

### Changed
- All non-analytics Dockerfiles upgraded: `python:3.11.11-slim` → `python:3.14.0-slim`
  (`docker/Dockerfile`, `docker/Dockerfile.test`, `docker/Dockerfile.mockbackend`,
  `docker/Dockerfile.trafficgen`, `tarpit/Dockerfile`) — Phase 67.
- Test Dockerfiles upgraded: `python:3.11-slim` → `python:3.14-slim`
  (`tests/docker/Dockerfile.test-runner`, `tests/docker/Dockerfile.python-proxy`,
  `tests/docker/Dockerfile.tls-backend`, `tests/docker/Dockerfile.recorder`) — Phase 67.
- `src/analytics/Dockerfile`: `python:3.11.11-slim` → `python:3.14.0-slim` — Phase 70.
- `pyproject.toml`: ruff `target-version` changed from `py311` to `py314` — Phase 67.
- `src/tls/interpreter_pool.py` (new): subinterpreter pool with ThreadPoolExecutor
  fallback for TLS parsing workers. Uses Python 3.14 `interpreters` module (each worker
  gets its own GIL) when available; falls back to ThreadPoolExecutor silently — Phase 70.

### Fixed
- `src/security/tls_enforcer.py`: restore `score=40` default for deprecated TLS
  bypass-disabled signal (Phase 65 regression where score was hardcoded to 10,
  below the `flag` threshold of 20, making the signal functionally useless).
- `tests/unit/test_graceful_shutdown.py`: make `test_connections_drain_before_timeout`
  deterministic under pytest-xdist by using asyncio.sleep hook pattern instead of
  wall-clock timing.

## [Unreleased] - 2026-04-04 — TI Feed Reliability & Resilience (Phase 59)

### Added

- **Phase 59: TI Feed Reliability & Resilience** — Full circuit breaker and health
  monitoring system for all five Threat Intelligence providers.

  - `src/security/feed_health.py` — Extended `FeedHealthMonitor` with 100-entry
    `CircuitBreaker._history` ring buffer, `register_probe`/`start_probing`/`stop_probing`
    background health-check lifecycle, and `set_alert_callback` for circuit-open events.
    New Prometheus gauge `ja4proxy_ti_feed_probe_interval_seconds{feed}`.
  - `src/security/ti_provider.py` — `retry_with_backoff()` async helper with
    exponential backoff (base×2^attempt, capped at `max_delay`), standard log format.
  - Circuit breaker wired into `GreyNoiseProvider`, `AlienVaultOTXProvider`,
    `VirusTotalProvider`, `ThreatFoxProvider` (MISP was already wired). VirusTotal
    403 responses bypass the circuit breaker (quota ≠ outage).
  - `proxy.py` — `FeedHealthMonitor` instantiated at startup; passed as
    `health_monitor=` to all 5 providers; per-feed probes registered for enabled
    feeds; `start_probing()`/`stop_probing()` called in the server lifecycle.
  - `config/proxy.yml` — Added `misp:`, `threatfox:`, `virustotal:` config sections;
    new `threat_intelligence:` block with `circuit_breaker_failure_threshold`,
    `circuit_breaker_recovery_probe_interval`, `health_probe_interval_seconds`.
  - `docs/REDIS_SCHEMA.md` — Added Phase 58 section documenting `ja4proxy:confidence:state`.
  - `docs/runbooks/ti_feed_health.md` — 617-line operator runbook covering Security
    Analyst, DevOps/SRE, Administrator, and Data Scientist audiences; includes
    Alertmanager YAML, Mermaid circuit-breaker diagram, full Prometheus metric table.

### Tests

  - 97 new tests: 33 unit (provider wiring), 15 unit (FeedHealthMonitor extensions),
    4 unit (proxy wiring), 28 chaos (all 5 providers + multi-provider degradation).
  - All pre-existing tests pass (6 pre-existing failures are unrelated: 4 backup
    Redis-connectivity, 2 tarpit timing).

## [Unreleased] - 2026-04-03 — Docker Multi-Agent Isolation (Phases 71–75)

### Added

- **Phase 71–75: Docker Multi-Agent Isolation** — Full implementation of isolated per-agent
  environments on a shared host, enabling Gemini, Claude, Ollama, and Mistral to run
  concurrent independent JA4proxy stacks without interference.

  - `scripts/agent-env.sh` — generates `.env.<agent>` with unique loopback IP
    (`127.0.0.10–13`), CPU set, random secrets, and all compose variables. Overwrite-guarded.
  - `docker-compose.poc.yml` — refactored from 2 flat networks to 4 security zones:
    `dmz_net` (HAProxy↔Proxy), `data_net` (Proxy↔Redis, `internal: true`),
    `origin_net` (Proxy↔Backend/Tarpit, `internal: true`), `mgmt_net` (Proxy↔Analytics).
    Redis, backend, and tarpit ports removed from host. All ports bound to `${AGENT_BIND_IP}`.
    CPU pinning (`cpuset`), non-root users (`1000:1000`), 300 MB log rotation, and shared
    read-only GeoIP volume added to all services.
  - `scripts/ja4-admin.sh` — `--agent <name>` flag targets specific agent's Redis container
    and metrics endpoint. Auto-detects from `.current-agent` when flag is omitted.
  - `Makefile` — `make agent-up NAME=<agent>`, `make agent-down`, `make agent-status`.
    `agent-up` writes `.current-agent` so subsequent commands default to the active agent.
  - `scripts/check-isolation.sh` — automated isolation audit: host port surface,
    Docker socket access, network zone boundaries (including internet egress tests),
    IPC namespace independence, and cross-agent reach verification.
  - `docs/architecture/ISOLATION_MODEL.md` — updated with quickstart workflow, manual
    workflow, agent resolution priority table, and verification section.

### Security: Metrics Endpoint DoS & Startup Crash Remediation

### Security

- **CVE-class: Metrics endpoint denial-of-service** — `src/security/health.py` and
  `src/analytics/main.py` both served `/metrics` via `web.Response(content_type=CONTENT_TYPE_LATEST)`.
  The prometheus-client `CONTENT_TYPE_LATEST` constant includes `charset=utf-8`, which aiohttp
  rejects at the Response constructor level with `ValueError: charset must not be in content_type
  argument`. Every scrape request to either metrics endpoint raised an unhandled exception, causing
  the handler to return HTTP 500 and preventing Prometheus from collecting telemetry. An attacker
  aware of this could use it to blind monitoring silently while conducting other activity.
  **Fix:** pass the Content-Type as a raw header (`headers={"Content-Type": CONTENT_TYPE_LATEST}`)
  in both locations. Confirmed no other `content_type=` usages in the codebase contain `charset`.

- **Startup crash (non-fatal log corruption)** — `proxy.py` emitted a structured JSON log line at
  startup using `%d` format for the initial dial value, which `DialManager.initialize()` returns as
  a string. Python's logging module suppresses the resulting `TypeError` with a `--- Logging error
  ---` banner rather than crashing the process, but the dial-initialized event was silently lost
  from the audit trail on every cold start.
  **Fix:** changed format specifier to `%s` with an explicit `int()` cast.

### Fixed

- HAProxy crash-loop on POC startup: three config errors introduced by Phase 43 blue/green changes
  (`accept-proxy` bare keyword, duplicate `frontend tls_in` block, missing errorfile) and backend
  servers referencing non-existent `proxy-worker-blue-*` containers. Rewritten for single-worker
  POC topology.
- `start-poc.sh` readiness checks used Docker Compose v1-style container names (`ja4proxy-redis`,
  `ja4proxy-backend`); Compose v2 appends `-1` suffix. Fixed to `ja4proxy-redis-1` /
  `ja4proxy-backend-1`.
- Analytics entrypoint used `nc` for Redis readiness check; `nc` is not installed in the analytics
  image, causing an infinite startup loop. Replaced with `python3 socket.connect_ex`.

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
