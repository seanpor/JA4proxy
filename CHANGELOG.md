# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Interface & Container Architecture Review & Consolidation Planning (Phase 230 & 231)**: Completed a thorough architectural audit of all containers and user-facing interfaces. Documented 11 security and operational findings, proposed a target container inventory (eliminating the duplicate `admin-api` service and switching to a plain Alpine Redis base), and established the 7-phase master implementation plan for the Container & Interface Consolidation programme (Phases 232–238). See `docs/phases/complete/PHASE_230.md` and `docs/phases/complete/PHASE_231.md`.
- **Go Redis restore — selective & GDPR-aware (Phase 315b)**: `ja4p restore` loads
  a 315a artifact back into Redis with the guard-rails that make restore safe. **By
  default it can never re-block a real user**: block-state (`ban:*`, `ban_cidr:*`,
  `ip:blacklist`, `ja4:blacklist`, `config:dial`) is skipped unless `--include-blocks`
  is passed. **It never resurrects a GDPR-erased subject**: before writing any per-IP
  key it consults a tombstone set built from the live `management:gdpr_erasure_log`
  (read **before** any `--force` `FLUSHDB` destroys it) merged with an optional
  `--tombstone-file`, with IPv4/IPv6-canonical subject extraction. Integrity is
  verified before any write (tamper/truncation/wrong-key fail closed); a non-empty
  target needs `--force`; `--dry-run` is side-effect-free; TTLs are re-applied from
  the artifact; a newer-schema artifact is refused (downgrade-block); every restore
  is audited to `management:policy_audit` + `backup:last_restore`/`backup:restored_from`.
  Registers the three `ja4proxy_restore_*` series (+`…_skipped_total{reason}`),
  completing the `backup.rules.yml` alert set 315a started. Reuses 315a's
  `DecryptPayload`/artifact format/lock and the CLI's passphrase+redis plumbing.
  Tested (classification incl. IPv6, block-gating, GDPR skip via file **and** live
  log, dry-run, non-empty/force, tamper, schema-block, audit, metrics; real-Redis
  round-trip + GDPR-not-resurrected behind `-tags integration`). See **ADR-206**.
  Deferred (non-safety): full schema-migrator, `--prefix-map`, post-restore smoke.
- **Go Redis backup engine (Phase 315a)**: the Go production runtime can now
  produce an encrypted, restorable snapshot of its durable Redis security state
  via `ja4p backup` (and `ja4p backup inspect` for offline metadata). It uses
  logical per-key `DUMP`/`PTTL` (every Redis type, TTLs preserved), gzip +
  **AES-256-GCM** with a PBKDF2-SHA256-derived key (random salt + nonce per
  artifact, GCM-authenticated header so tampering/truncation fails closed), an
  atomic `0600` write in a `0700` dir, count/age retention pruning, a
  `backup:operation_lock` (`SET NX EX 600`) against concurrent runs, and paced
  pipelined `SCAN` to spare the Redis thread. A conservative default scope backs
  up security-state prefixes and **excludes** credential/session/MFA keys
  (`mgmt:totp`/`webauthn`/`saml`/`oidc`/`session`) and ephemeral counters. This
  revives the four previously-dead `ja4proxy_backup_*` alerts in
  `backup.rules.yml` by finally emitting their metrics (via the process registry
  and an optional node-exporter textfile); the alert series was renamed
  `…_last_success_timestamp` → `…_last_success_seconds` per OBSERVABILITY_STANDARDS.
  Grounding correction vs the plan: the subcommand lives in the cobra CLI `ja4p`,
  not the `ja4pd` daemon. Restore is the sister phase **315b**. See **ADR-205** and
  `docs/runbooks/backup_restore.md`. Unit-tested (crypto round-trip / wrong-key /
  tamper, scope+exclude, TTL capture, retention, metrics toggle, lock); the
  every-type + IPv6 real-Redis round-trip is a `-tags integration` test (miniredis
  only DUMPs strings).

### Security
- **Third-party image HIGH-CVE remediation — differentiated gating (Phase 314)**:
  A fresh authoritative Trivy scan (2026-06-13) showed only 2 of 9 pinned
  third-party images were bump-fixable; the rest are already on their newest
  stable tag with brand-new upstream Go-stdlib/distro HIGH CVEs we cannot fix
  ourselves. Bumped the two that *do* have a fixed tag — `prom/alertmanager`
  `v0.32.1`→`v0.33.0` and `oliver006/redis_exporter` `v1.84.0`→`v1.86.0` (both
  re-scanned HIGH/CRITICAL-clean) — synced across `Makefile` `TRIVY_IMAGES`,
  the monitoring/prod compose files, the `redis-secure` Ansible default, and
  `docs/DOCKER_IMAGES.md`. Adopted a **differentiated gate**: hard HIGH+CRITICAL
  on Dockerfiles and our own Go toolchain; third-party images stay CRITICAL-gated
  with HIGH **reported and tracked** in a new dated waiver register
  (`docs/security/THIRD_PARTY_CVE_WAIVERS.md`) — never silently ignored — rather
  than a blanket HIGH gate that would flap the required CI gate red on un-fixable
  upstream CVEs. Reconciled the long-drifted `docs/DOCKER_IMAGES.md` third-party
  inventory to the actually-pinned tags. The full HIGH gate-flip (first-party
  base-image rework + upstream rebuilds) is deferred to a follow-up; the Phase 313
  deferred HIGH-gate box stays open, annotated with the decision.

### Added
- **Branch hygiene and stale branch cleanup (Phase 329)**: Introduced automated Git branch hygiene guidelines and a Python script (`scripts/branch_hygiene.py`) to safely audit, classify, and delete stale/merged remote and local branches. Developed unit tests and a permanent developer runbook (`docs/developer/BRANCH_HYGIENE.md`).
- **Go blocklist feed downloader (Phase 309 WP-6)**: the Go proxy now downloads
  Spamhaus DROP/EDROP (and any configured CIDR feed) on a per-feed timer and
  atomically swaps the parsed trie into the live `BlocklistManager`. Previously
  the Go `BlocklistManager` only loaded from a local file that nothing ever
  populated, so Spamhaus hard-blocking was inert. The downloader uses
  `ETag`/`If-None-Match` conditional requests (a `304` counts as a successful
  refresh), a bounded 64 MiB body, a lock-free `atomic.Pointer` trie swap, and a
  warm-restart disk cache (default `/var/lib/ja4proxy/blocklists/<name>.txt`,
  overridable per feed via `path:`). **Fail safe**: any error — transport,
  non-2xx, parse, or a 0-entry body — increments
  `ja4proxy_blocklist_download_errors_total{feed}` and keeps the last-good trie.
  No leader election by design (see **ADR-204**). New per-feed metrics
  `ja4proxy_blocklist_download_errors_total` and
  `ja4proxy_blocklist_last_refresh_success_seconds`.

### Removed
- **Orphaned Python-prototype tests (Phase 309 tidyup)**: deleted 35 test files
  that imported modules removed when the Python prototype was archived
  (`5afeba26`) — they errored on collection and could never run, so `pytest
  tests/` aborted with 27 collection errors. `pytest tests/ --co` now collects
  2034 tests with **0 errors**. Each file either tested a subsystem already
  ported to Go (covered by Go tests) or a feature intentionally removed with the
  prototype (TAP sensor, Python backup, the `GDPRStorage` retention abstraction,
  per-provider TI lookups). Retained `tests/fp_corpus/data/` (reusable FP corpus)
  and `tests/fuzz/README.md`. Full audit + the residual Go coverage gaps worth
  porting (notably **quantitative FP-rate thresholds** per CLAUDE.md, and a dead
  `backup.rules.yml` alert set) are catalogued in
  `docs/reports/python-prototype-test-removal-audit.md`.

### Fixed
- **Resolve security scan vulnerability failures (Phase 330)**: Aligned the production proxy image version tag to `ja4proxy:2.0.0` (matching the Go rewrite release) in `deploy/docker/docker-compose.prod.yml` and the `Makefile` first-party image list. This ensures vulnerability scans run against the clean Go/Alpine-based production image instead of the stale Python-based `ja4proxy:1.0.0` image, and resolves `check-image-versions` warnings about version drift.
- **Four dead security alerts now fire on real signals (Phase 309 WP-6)**: the
  metrics behind `AbuseIPDBQuotaExhausted`, `SpamhausDownloadFailed`,
  `SpamhausListStale`, and `BeaconingDetected` were emitted only by the Python
  prototypes that were deleted after the Go port, so the alerts could never
  fire. Added the missing Go emitters: AbuseIPDB detects HTTP 429 /
  `X-RateLimit-Remaining: 0` and flips `ja4proxy_abuseipdb_quota_exhausted`
  (self-clearing on the next lookup with quota); the beaconing detector records
  each flagged `(IP, JA4)` on the `beacon:suspects` ZSET and publishes its size
  as `ja4proxy_beaconing_suspects`; the new feed downloader emits the two
  blocklist metrics. `SpamhausListStale`'s threshold was raised 2h → ~25h to sit
  above the 12h refresh interval. Also fixed the blocklist line parser, which
  never handled Spamhaus DROP annotations (`1.2.3.0/24 ; SBL123`) — only bare
  CIDRs — and now handles `spamhaus`/`cidr`/`ipset` formats.
- **Phase-309 reconciliation — ADR-003 + findings register**: restored **ADR-003**
  (it had been overwritten with a duplicate of ADR-005; its correct subject is the
  cache-TTL asymmetry — ALLOW ~30min / BLOCK ~30s — rewritten from the decision
  log). Repointed **20** stale `docs/security/findings.yaml` `regression_test`
  paths (16 `cmd/proxy/`→`cmd/ja4pd/` + 4 bare Go paths qualified to their real
  `*_test.go`). 12 findings citing deleted Python-prototype tests remain flagged
  for per-finding Go-coverage repointing.

### Added
- **Single-host bootstrap & wizard (Phase 231b, software core)**: `scripts/setup_wizard.py`
  (interactive, generates `.env` secrets — **never echoed** — at chmod 600) and
  `scripts/bootstrap.sh` (zero-compile installer: OS detect, offline-tarball load,
  firewall gating from `.env`, systemd unit, logrotate, daily backup, `--check`/`--uninstall`).
  Defaults to monitor mode; admin ports stay on loopback (real scheme 8090/9090/9091/3000).
- **Single-host core (Phase 231a)**: `ja4pd` can now **write a PROXY protocol
  header (v1/v2) to the backend** so a TLS-passthrough deployment preserves the
  real client IP/port without decrypting — `write_proxy_protocol` (default
  `false`) + `write_proxy_protocol_version` (`1`|`2`, default `1`) in
  `config/proxy.yml`. FP-safe: indeterminate addresses degrade to `PROXY
  UNKNOWN`/v2 LOCAL rather than dropping a valid client. Also enforces **manual
  bans (`ban:{ip}`)** at the top of the pipeline so they block immediately even
  in monitor mode (`dial: 0`), fail-open on a Redis error.

### Fixed
- **Active-bans metric (Phase 231a)**: `CountKeys` queried the wrong prefix
  (`ja4proxy:ban:*`), so the active-bans gauge always read 0; corrected to the
  canonical `ban:*`.
- **CI resilience — `pip-audit` (Phase 311)**: a transient PyPI/OSV outage no
  longer reddens the required Full Lint gate (which also spammed maintainer
  emails and showed public CI failures). `scripts/pip-audit-resilient.sh` retries
  on a service outage and soft-passes with a CI warning if the vulnerability
  service is unreachable, while a **real vulnerability still fails the build**.
  Wired into `make lint` (`lint-static`) and the standalone dependency-audit job.
- **CI resilience — `pip-audit` dual-service fallback (Phase 312)**: when PyPI is
  unreachable the wrapper now falls back to **OSV.dev** before any soft-pass, so
  the warn-and-proceed path requires *both* services down at once (rare) — while
  staying live (no offline/stale DB). A real vulnerability on either path still
  fails the build.
- **Containerise the lint toolchain (Phase 313)**: every linter now runs in a
  container so CI/local share one toolchain and the gate no longer depends on a
  flaky host `pip install`. The Python linters + project Python scripts (ruff,
  mypy, bandit, pip-audit, the doc/meta/phase checks, the ATT&CK pytest) run in a
  pinned `Dockerfile.tools` image via `$(TOOLS_RUN)`; semgrep and ansible-lint
  run from their official images (neither runs on Python 3.14); hadolint,
  shellcheck, trivy, gitleaks, gosec, promtool, amtool, scorecard and lychee stay
  on their own images. `make lint`/`make scan` call `lint-all`/`scan-all`
  directly (the broken `docker-run-tools` Docker-in-Docker wrapper was removed)
  and `scripts/pipeline_summary.py` prints a one-line verdict without recursing into
  `make`. `lint-go` keeps the host Go toolchain (go.mod needs go 1.26); lychee
  link-check, ansible-lint and scorecard are advisory (their gates are the
  dedicated workflows). Verified with a full local `make lint` (exit 0).

### Added
- **Dev lanes + clean load test (Phase 310)**: each git worktree auto-gets a
  collision-free "lane" — its own published host ports + unique compose project
  and docker network — so multiple checkouts run on one host without clashing.
  `make lane` / `make open SVC=…` / `make loadtest` (good/bad traffic mix,
  default 5% good / 95% bad, watch it in the lane's Grafana). The default lane
  runs without HAProxy (single proxy; `WITH_HAPROXY=1` for the multi-proxy test).
- **Management-UI front-end hardening (Phase 230)**: self-hosted + SHA-pinned
  vendored JS (`SHA256SUMS` + `VENDOR.md` + integrity test), a **pre-built purged
  Tailwind CSS** (replacing the 407 KB browser/runtime "Play" build), a
  Content-Security-Policy, and no external CDN/font fetches; plus `make scan-js`
  (retire.js CVE scan of the vendored JS) wired into CI.

### Changed
- **Documentation source-of-truth audit (Phase 309, in progress)**: every doc
  now carries **Version 2.0.0** + a content **"last reviewed"** date (not the
  build date); author name corrected to **Seán Ó Ríordáin**; the user guide,
  `SCALING_GUIDE`, and `OBSERVABILITY_STANDARDS` rewritten to the Go-native
  architecture; the OBSERVABILITY metric registry regenerated from code; live
  alert rules and the CVD/SLA policy text reconciled; Grafana port docs
  `3001`→`3000`. Supersedes **Phase 221** (PDF refresh) and resolves **Phase 159**
  ("10k Mission" — the ~350 CPS cap was the Docker `docker-proxy` relay;
  host-native sustains ~3,000 CPS).

### Security
- **Code-scanning remediation (Phase 308)**: cleared the 60-alert code-scanning
  backlog (7 CodeQL + 53 Scorecard) left after Phase 302 enabled CodeQL +
  OpenSSF Scorecard. **CodeQL (7)**, each verified against the code: `#77`
  (the local fixture recorder `scripts/capture_server.py` bound `0.0.0.0`) is
  **fixed in code** → `127.0.0.1` (its clients already target loopback) rather
  than dismissed; the two `py/url-redirection` findings were dismissed as
  **false positives** (mitigated by `safe_relative_redirect` at `oidc.py:431` /
  `saml.py:323` — CodeQL can't trace the custom sanitizer); the splunk
  `py/clear-text-logging` was dismissed FP (`api_token` is only used in the
  `Authorization` header, never passed to `_log()`); and the two legacy-TLS
  generators + the Go benchmark's `InsecureSkipVerify`-vs-self-signed-mock were
  dismissed **used-in-tests** (their insecurity is intrinsic to the tool and
  non-production). All per-alert with code-backed justifications in the audit
  trail — **no blanket suppression**. **Scorecard (53)**: these are OpenSSF
  supply-chain *scores*, not vulnerabilities, and aren't meaningfully actionable
  — production Dockerfile base images are already digest-pinned (Phase 229); the
  3 `TokenPermissions` are *required* write (SARIF upload / Dependabot
  auto-merge / metrics auto-commit), already job-scoped with `contents: read` at
  top level; `Vulnerabilities` self-clears now Dependabot is at 0; the rest are
  solo-repo process scores. Removed the `"Upload to code-scanning"` step (and
  the now-unneeded `security-events: write`) from `scorecard.yml` so the noise
  stops drowning real CodeQL findings — Scorecard still runs, still publishes
  the badge (`publish_results`), and still keeps the `results.sarif` artifact;
  only the Security-tab upload is gone (one-step reversible).

### Changed
- **Documentation coherence, setup standardization, and link remediation (Phase 307)**: Established a coherent documentation architecture with clear single sources of truth. Standardized onboarding around the `make init` guided wizard and aligned Go proxy paths (`cmd/ja4pd`, `cmd/ja4p`). Removed obsolete Python proxy references, corrected all broken internal links, and added frontmatter blocks to remote manual testing and evaluation guides to pass `make doc-health`.

### Fixed
- **Test environment stability on `.env` presence**: Fixed test failures caused by `pytest-dotenv` loading the production-mode environment and warning level from `.env` by adding explicit environment overrides at the top of `tests/conftest.py`.

### Performance
- **Go proxy hot-path tuning (Phase 306, from PR #95)**: the bidirectional
  forward loop now reuses 32KB buffers from a `sync.Pool` instead of allocating
  one per connection (removes per-connection GC pressure under load); the Redis
  client pool is pre-warmed (`PoolSize: 100`, `MinIdleConns: 10`) to avoid
  cold-start dial latency; and async risk scoring fans out across a **fixed**
  pool of 32 worker goroutines (was 1) draining a deeper `workChan`
  (10000 → 20000) so accept bursts are absorbed rather than serialised. Also
  fixed the dev/POC/Performance wizard scenarios and the POC health check to use
  the real backend port **8443** (was 443, which is HAProxy's ingress;
  Production, a real HTTPS backend, stays 443), and switched `tarpit-server.py`
  to lazy `%s` logging. These are the legitimate wins from external PR #95,
  re-landed on a clean branch without the regressions it carried (see Security
  and Fixed below).

### Fixed
- **ATT&CK mapping doc + CI gate (Phase 306)**: `docs/ATTACK_MAPPING.md` and its
  CI gate `tests/test_attack_mapping.py` were **both broken on `main`** — the doc
  had been relocated to `docs/` but the test still pointed at
  `docs/for-architects/` (so it failed with `FileNotFoundError`), and the doc
  still listed retired Python-prototype source files (`src/security/*.py`, gone
  since v2.0.0). The retired-prototype rows were removed, the two genuine
  rate-tracker rows repointed to `internal/security/rate_limiter.go`, and the
  test path corrected — the gate now passes for the first time. (External PR #95
  had instead run a blind `*.py → *.go` find-replace that produced
  self-contradictory rows; that approach was discarded in favour of this one.)

### Security
- **Forward-path idle timeout restored (Phase 306)**: PR #95's switch to a
  deadline-free copy in the Go proxy's `forward()` silently removed the per-read
  `SetReadDeadline(read_timeout)` / `SetWriteDeadline(write_timeout)`
  idle-connection reaper. That re-opened a resource-exhaustion vector — a
  slowloris / idle-hold client would pin a goroutine **and** a pooled buffer
  indefinitely, and the operator-configured `read_timeout` / `write_timeout`
  knobs became dead. The reaper is restored **inside** the new pooled-buffer copy
  (the buffer-pool win and the deadlines coexist), guarded by a new Go regression
  test (`TestForward_IdleConnectionIsReaped`) that tears down an idle pair at
  `read_timeout` and would hang/fail if the deadlines are ever removed again. The
  per-connection decision log was kept at **Info** (PR #95 demoted it to Debug)
  to preserve the audit trail.
- **CodeQL code-scanning triage (Phase 305)**: worked through the 14 CodeQL
  Python findings (+1 Go bench) that enabling code scanning (Phase 302)
  surfaced. **Three were genuine, all in the Management-API web layer** and are
  now **fixed with regression tests** (`management/tests/test_codeql_305_regression.py`):
  a **reflected XSS** in `/api/v1/partials/list-table` (the unvalidated `list`
  query param was interpolated raw into HTML — now `html.escape`-d), and
  **error-detail exposure** (`str(exc)` of a Redis failure returned to the
  client) in `/health/deep` and the **unauthenticated** `/ready` (now logged
  server-side, generic reason to the caller). A fourth pair (OIDC/SAML
  `py/url-redirection`) was **hardened rather than dismissed**: the post-login
  redirect target is currently a hardcoded `"/"` (no live bug), but to be
  regression-proof a `safe_relative_redirect` guard now confines both callbacks
  to same-site relative paths (rejects absolute / protocol-relative `//evil` /
  backslash variants) — the textbook "don't dismiss a safe-by-constant FP,
  harden it" case. The two test TLS servers
  (`scripts/mock-backend.py`, `tests/docker/tls_backend.py`) were **hardened**
  with an explicit `TLS 1.2` floor — clearing `py/insecure-protocol`
  *legitimately* rather than by dismissal. The remainder were **verified false
  positives** (`redis_client` logs the *redacted* URL — sanitizer confirmed;
  the OIDC/SAML redirect targets are a hardcoded `"/"`; `auth.py` logs a config
  CIDR, not a secret; the Splunk action never logs its token) or **intentional
  test tooling** (the legacy-TLS *generators* exist to exercise the proxy's
  fingerprint detection; the bind-all capture helper; the bench
  `InsecureSkipVerify` against the self-signed mock) — each dismissed
  per-alert with a code-backed justification in the GitHub audit trail, **no
  blanket rule suppression**. The Go production proxy produced no genuine
  code-scanning bug.
- **Dependency CVE remediation (Phase 304)**: triaged the 118 alerts that
  enabling Dependabot + CodeQL (Phase 302) surfaced — the real, fixable,
  *production* findings are concentrated in the Python Management-API auth stack;
  the **Go production proxy is essentially clean**. The Phase 302 auto-merge had
  already landed `authlib 1.4.0→1.6.12` and `python-multipart 0.0.12→0.0.32`
  (minor/patch). This phase did the three Dependabot correctly held back:
  `cryptography 45.0.0→46.0.5` (a **major** bump — `management/requirements.txt`
  and the root `requirements.txt` floor), `python-jose 3.3.0→3.4.0` (critical
  algorithm-confusion CVE; a `python-jose`→PyJWT migration is flagged as a
  follow-up since jose is effectively unmaintained), and the indirect
  `google.golang.org/grpc 1.76.0→1.79.3` in `deploy/terraform-provider/go.mod`
  (deploy tooling, via `go get` + `go mod tidy`). The management suite passes
  (614) against the upgraded stack. Noise documented, **not** bulk-suppressed:
  the bench-tool `go/disabled-certificate-check` (already `#nosec`, hits the
  self-signed mock) and the OpenSSF Scorecard advisories that appear as
  code-scanning "high" are benign; the 9 CodeQL Python findings are left as a
  case-by-case follow-up.
- **Repository security aids enabled + automated (Phase 302)**: turned on Dependabot **alerts** + **security updates** and **private vulnerability reporting**. To keep these low-effort under branch protection, added a SHA-pinned `dependabot-automerge.yml` that auto-merges Dependabot **patch/minor** PRs once the 10 required checks pass (majors stay manual), and throttled `dependabot.yml` weekly → monthly. Two UI-only toggles documented for the operator (CodeQL "Default setup"; secret-scanning validity checks).
- **Production compose port-exposure hardening (Phase 303)**: `docker-compose.prod.yml` published several "internal only" services on `0.0.0.0` (proxy 8080/9090 as random host ports, analytics, tarpit, loki, prometheus) — only Grafana + HAProxy-stats were correctly loopback-bound. Removed the host `ports:` for purely-internal services (reached over the docker network by service name — verified `prometheus.yml` scrapes by DNS, not host ports) and bound the Prometheus UI to `${AGENT_BIND_IP:-127.0.0.1}`. Only `haproxy 443/80` remain public.

### Fixed
- **`make clean` resilient to an incomplete `.env`**: it aborted with `MANAGEMENT_JWT_SECRET is required` in a fresh worktree because `docker compose down` still evaluates the compose `${VAR:?}` interpolations. Added a `CLEAN_DUMMY_ENV` prefix (values irrelevant for `down`) and made `--env-file` conditional on the file existing.

### Fixed
- **Env template completeness (Phase 301)**: added `HAPROXY_STATS_USER`/`HAPROXY_STATS_PASSWORD` (compose-`required`, previously absent) to `template.env` with generation guidance, so `cp template.env .env` boots the full stack incl. monitoring. Deleted the orphan `.env.example` (unreferenced, shipped weak `changeme` defaults). Added an optional commented threat-intel block. (Audit: Phase 300.)
- **Housekeeping**: fixed the `manifest.yaml` `action_plan` path for Phase 160 (`docs/phases/` → `docs/phases/complete/PHASE_160.md`) — `make lint-phases` is now fully clean (0 violations); repaired literal-`\n` corruption in `scripts/perf-matrix.sh` (the whole script was one line); resolved committed merge-conflict markers left in `PHASE_201/202/203.md` (kept the canonical HEAD content).

### Changed
- **Pinned linter container images (Phase 225 part 2, COMPLETE)**: the lint/scan tools already ran in containers, but several used floating tags. Pinned to the exact in-use versions for reproducibility (zero behaviour change): `hadolint/hadolint:v2.14.0`, `koalaman/shellcheck:v0.11.0`, `zricethezav/gitleaks:v8.30.1`, `lycheeverse/lychee:0.24.2`, and the `lint-types`/`lint-quality` image `python:3.14-slim → python:3.14.0-slim` (`amtool`/`promtool` were already pinned). `codespell`/`markdownlint` were dropped from `make doctor`'s tool list — they are not used by any target.

### Added
- **Remote manual-testing (Phase 220, salvaged from PR #82)**: `scripts/test-bot.py` — a stdlib-only TLS test bot that drives connections through a (remote) proxy and reports ALLOWED/BLOCKED + JA4 per profile — plus `make remote-bot HOST=… [PORT=…]` and `docs/runbooks/REMOTE_TESTING.md`.

### Security
- **Remote testing reuses the existing `AGENT_BIND_IP` model, not a `0.0.0.0` override**: PR #82 proposed a `docker-compose.remote.yml` binding *every* port (incl. Management UI and Grafana) to `0.0.0.0`. That was dropped — the `poc`/`monitoring` compose files already bind every service to `AGENT_BIND_IP` (default `127.0.0.1`) and `start-poc.sh` validates it via `check_bind_address.py` (refuses public/`0.0.0.0`). Remote access = set `AGENT_BIND_IP` to the server's private LAN IP, `make start`, `make remote-bot`.

### Security
- **Docs link-check is now a blocking, required gate**: the lychee docs link-check is added to `main`'s required status checks (broken links block the PR instead of merely emailing). To make a required check safe, its workflow (`docs-link-check.yml`) now runs on **every** PR (the previous `paths:` filter would have left non-docs PRs blocked forever waiting for an unreported check). `test_workflow_pinning.py` now also verifies any external required check exists and is unfiltered.

### Added
- **`make scan-summary` (Phase 228, COMPLETE)**: `scripts/scan_summary.py` (stdlib-only, unit-tested) turns the scan blur into compact tables — a per-image Trivy CVE rollup (CRIT/HIGH/MED, reusing the Phase 227 cache) **and** a gosec HIGH/MED/LOW rollup (from the pinned `security-scan` image). Both are reporting-only with gate-consistent verdicts — `make scan` stays the authoritative gate. (A `misconfig` mode is included for manual use but not auto-run, since a whole-dir scan is broader than the gated file list; a `make lint` rollup was deliberately descoped as `make lint` already prints a clear per-target status.)

### Changed
- **Accurate `make doctor` (Phase 225)**: `doctor` now separates **required** host tools (docker, Go 1.26+, python3 — hard-fail if missing) from **informational** notes, and no longer emits scary "Warning: … some targets will fail" for the local Python 3.10-vs-3.14 gap or for absent host copies of `hadolint`/`trivy`/`gitleaks`/`codespell`/`markdownlint`/`amtool` (those run authoritatively in CI; trivy runs in a pinned container via `make scan`). Full tool containerization is the remaining half of Phase 225.

### Performance
- **Trivy DB caching (Phase 227)**: `make scan` now mounts a shared `TRIVY_CACHE` dir into every trivy container, so the vulnerability DB is downloaded once per run instead of once per image (~13× → 1×); a SHA-pinned `actions/cache` step persists it across CI runs.

### Security
- **Branch protection hardened & made correct**: `main` requires a PR passing **all nine** gating CI checks (was only 4) with `enforce_admins=true` and auto-merge; `scripts/branch_protection.sh` was rewritten to the current job names (it had stale `Go tests`/`Python tests` contexts) and the missing require-PR rule; the `KNOWN_ACTION_SHAS` allowlist was completed (ci.yml + scorecard.yml pins); and `tests/test_workflow_pinning.py` is now run by `make test` so pin/context drift can't silently return.

### Security
- **Perl CVEs eliminated, not ignored (Phase 229)**: analytics & tarpit moved from `python:3.14-slim` (Debian, ships perl-base with no-fix CVEs CVE-2026-42496/-42497/-8376) to a digest-pinned `python:3.14.0-alpine` base. All three time-windowed `.trivyignore` perl exceptions are removed — the scan is green with **zero** active exceptions.

### Changed
- **Base-image consolidation (Phase 229)**: the `security-scan` image was aligned from a drifted, unpinned `golang:1.25.10-alpine` to the single pinned `golang:1.26.4-alpine@sha256:…` used by every other Go image. `test_docker_consistency` now accepts a patch-pinned `python:3.14.0-{slim,alpine}` base.

### Added
- **Makefile integrity guard (Phase 224)**: `make lint-meta` now parses the Makefile and fails if any `make help*`-advertised target is missing, any prerequisite or `$(MAKE)` sub-call is unresolved, `.PHONY` lists a phantom, or a light umbrella (`lint`/`scan`/`test`) pulls in a heavy benchmark. Runs in `make test` via `tests/unit/test_makefile_integrity.py`.
- **Pre-push CI gate (Phase 224)**: shared `.githooks/pre-push` (install with `make install-hooks`) runs `make ci-verify` so Makefile/CI breakage is caught before push, not on GitHub Actions.
- **`bench-all` / `verify-all` (Phase 224)**: one-command heavy-benchmark trigger and a full release gate; `make lint scan test` is documented as the full gate minus heavy benchmarks.
- **`make scan-exceptions` (Phase 226)**: lists `.trivyignore` exceptions with days-to-expiry and justification; fails on expired or undated entries. Documented in `docs/runbooks/security_scan_exceptions.md`.

### Security
- **Honest, green security scan (Phase 226)**: the `make scan` gates were de-suppressed (`scan-container` was a no-op; `scan-images`/`scan-first-party` reported CRITICALs but never failed). Real image CVEs are now patched at build time via `apt-get`/`apk upgrade` (e.g. openssl CVE-2026-31789); grafana bumped 13.0.1→13.0.2 to clear bundled-pgx CVE-2026-33816; mockbackend runs non-root. The 23-CVE blanket `.trivyignore` was replaced with 3 justified, **14-day time-windowed** exceptions for genuinely no-fix perl CVEs (retired by Phase 229).

### Fixed
- **CI green end-to-end (Phase 226)**: fixed a hardcoded `GOROOT=/snap/go/current` that broke `make test`/`make lint` in CI; de-hardcoded a `JA4proxy2` dev path in two integration tests; added `pip-audit` to the CI lint job; created the mock-backend cert + `.env` in the scan job.
- **Makefile newline corruption (Phase 224)**: a prior "deduplicate" pass had written literal `\n` into 21 lines, silently commenting out the `scan`, `scan-all`, `scan-container`, `scan-local`, `check-updates-container`, and `check-updates-local` targets — so `make scan` did nothing while reporting success. All restored.
- **Broken `make lint` (Phase 224)**: created the missing `doc-health`, `lint-semgrep`, `lint-ansible`, `lint-docs`, `link-check`, `lint-phases` targets; `make lint` now resolves end to end.
- **Bare `python` in recipes (Phase 224)**: 9 recipes called `python` (absent on python3-only hosts); switched to `$(PYTHON)`.

## [2.0.0] - 2026-06-04

### Added
- **High-Performance Go Core**: Complete rewrite of the proxy logic in Go, achieving sub-microsecond latency.
- **Advanced CLI (ja4p)**: New operational subcommands:
    - `ja4p config validate`: Validates proxy configuration and security feeds.
    - `ja4p test ip`: Simulates pipeline decisions for specific IP addresses.
- **Zero-Copy Parsing**: Optimized TLS ClientHello and SNI extraction using zero-copy memory patterns.
- **Mesh Drift Detection**: Asynchronous decision auditing across proxy instances via Redis.
- **MITRE ATT&CK Mapping**: Formal mapping of JA4proxy signals to adversary techniques in `docs/OPERATIONS_MAPPING.md`.
- **OpenSSF Scorecard**: Integrated automated security auditing (Achieved 10/10 score).
- **SLSA Level 3**: Build provenance and supply chain hardening.
- **Prometheus Instrumentation**: Per-signal latency histograms for deep observability.
- **Maturity Badges**: Codecov, Go Reference, and Release status badges.

### Changed
- **Production Standard**: Go implementation is now the primary production runtime.
- **Repository Pruning**: Removed 150,000+ lines of legacy Python code and obsolete documentation.
- **Documentation Consolidation**: Centralized operational procedures into `docs/OPERATIONS_GUIDE.md`.
- **Helm Chart v2**: Relocated and upgraded Helm charts for Kubernetes-native scaling.

### Removed
- **Legacy Python Proxy**: Python proxy prototype archived to `legacy-v1` branch.
- **Obsolete Docs**: Hundreds of historical research and dev-heavy documents pruned for clarity.

## [1.x.x] - Historical
- Legacy Python prototype implementation (see `legacy-v1` branch for details).
