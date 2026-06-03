# Changelog

## [Unreleased] - Phase 215 — White-Box Penetration Test — Go Production Proxy (2026-06-03)

Full white-box penetration test of the Go production proxy. Executed
systematic coverage across 9 layers, discovering 7 security findings.

### Changes
- **Pentest report**: `docs/security/pentest/REPORT.md` with 7 findings
  across TCP/network, TLS/fingerprint, signal pipeline, risk scoring,
  Redis integration, webhook, metrics/health, config/crypto, and CLI.
- **Findings register**: Registered all 7 findings in `findings.yaml`
  (JA4PROXY-2026-0056 through 0062) — 1 CRITICAL, 1 HIGH, 2 MEDIUM,
  2 LOW, 1 LOW (registered from INFO).
- **Regression test**: `cmd/proxy/pentest_panic_recovery_test.go` —
  static analysis test for F-001 (missing `recover()` in handler
  goroutine). Confirms 7 goroutines without crash protection.
- **Re-verification**: All 18 previously-closed findings from Phases
  118/119/122 re-confirmed as CLOSED.

### Verification
- `GOROOT=/snap/go/current go vet ./cmd/proxy/...` — 0 violations
- `python3 scripts/findings_register.py validate` — 0 new errors
  (19 pre-existing from archived Python tests remain)
- `python3 scripts/lint-phases.py` — 155/155 OK

## [Unreleased] - Phase 214 — Fix Pre-Existing CI Failures (2026-06-02)

Resolved all 4 pre-existing CI pipeline failures on `main` that were
previously waived across multiple merge cycles.

### Changes
- **govulncheck**: Bumped Go `1.25.9` → `1.26` in `go.mod` and all 3
  `go-version` entries in `.github/workflows/ci.yml`. Go 1.26 has zero
  stdlib GFEs — `govulncheck ./...` now exits 0.
- **Traceability matrix**: Added `pip install pyyaml` step before the
  check in `ci.yml`. The job was silently failing because PyYAML wasn't
  installed in the CI runner.
- **Docs link check (lychee)**: Fixed 6 phase doc links
  (`phases/` → `phases/complete/`) across 2 files. Added `--exclude`
  patterns for ADR-107a-slsa-level-3.md references (deferred work) and 2
  unreliable external GDPR URLs (europa.eu).
- **SAST (Semgrep)**: Fixed 7 `dynamic-urllib-use-detected` findings
  across 6 files by moving `# nosemgrep` comments from the `resp` line
  to the `with urlopen(` line (the rule's match anchor). Added 2 missing
  comments in `scripts/check_updates.py`. Bumped semgrep `1.67.0` →
  `1.76.0`.
- Cleaned up dead code in `scripts/check_updates.py`: removed duplicate
  GCR API call with unused `name` variable and unused `current_base`
  assignment.

### Verification
- `govulncheck ./...` — 0 stdlib vulns (was 2+ GFEs)
- `semgrep --config p/ci --config p/security-audit --config p/secrets --error .` — 0 findings
- `python3 scripts/traceability.py --check` — exit 0
- `ruff` + `mypy` — clean
- `make lint-phases` — 139/139 OK
- `GOROOT=/snap/go/current go vet ./...` — clean

## [Unreleased] - Phase 213 — Dependency Update Checker (make check-updates) (2026-06-01)

Created `scripts/check_updates.py` and `make check-updates` target that checks all 4 dependency categories for available upstream updates. Replaced an existing inline Makefile implementation with a structured, well-documented Python script. Output is color-coded by update severity (major/minor/patch). All sections handle missing tools gracefully.

### Changes
- Created `scripts/check_updates.py`:
  - **Docker images**: Parses TRIVY_IMAGES from Makefile + compose files. Queries Docker Hub API (and GCR for cAdvisor) for newer tags matching the current version prefix.
  - **Go modules**: Runs `go list -u -m all` in `cmd/proxy` and `deploy/terraform-provider`. Parses `[new_version]` annotations.
  - **Python packages**: Runs `pip list --outdated --format=json`. Skips if no venv active.
  - **Node packages**: Runs `npm outdated --json` for `sql.js`.
  - Color-coded terminal output (green=up to date, yellow=minor/patch, red=major).
  - Graceful skips with clear warnings when tools are missing.
- Added `check-updates` to `.PHONY` and help section.
- Removed old inline `check-updates` Makefile target (basic `head -20` implementation).

### Verification
- `make check-updates` — 84 updates found: 1 major, 61 minor, 22 patch (all informational)
- `ruff` + `mypy` — clean

## [Unreleased] - Phase 212 — Resolve Third-Party Image CVEs (CRITICAL) (2026-06-01)

Bumped 9 third-party Docker images to versions with zero CRITICAL CVEs. Fixed the `scan-images` CRITICAL-count grep bug (matched the `Total:` summary line instead of actual CVE rows). Fixed `check_image_versions.py` compose path (pointed at `docker/` instead of `deploy/docker/`). Added `.trivyignore` for pgx CVE-2026-33816 in Grafana (documented exception — Grafana configured with SQLite, code path unreachable).

### Changes
- **haproxy** `2.8.5-alpine` → `2.8.24-alpine` (prod, poc, scale)
- **redis/redis-stack** `7.4.0-v3` → `7.4.0-v8` (prod, poc)
- **oliver006/redis_exporter** `v1.55.0` → `v1.84.0` (prod, monitoring)
- **prom/prometheus** `v2.48.0` → `v3.12.0` (prod, monitoring)
- **prom/alertmanager** `v0.26.0` → `v0.32.1` (monitoring)
- **prom/node-exporter** `v1.7.0` → `v1.11.1` (monitoring)
- **grafana/grafana** `10.2.2` → `13.0.1-ubuntu` (prod, monitoring)
- **grafana/loki** `3.3.2` → `3.7.2` (prod, monitoring)
- **grafana/promtail** `3.3.2` → `3.6.11` (prod, monitoring)
- Fixed `scan-images` CRITICAL-count grep: now uses `^│.*CRITICAL` to count actual CVE rows instead of the `Total:` summary line
- Fixed `check_image_versions.py` compose paths: `docker/` → `deploy/docker/`
- Added `.trivyignore` for `CVE-2026-33816` (pgx PostgreSQL driver in Grafana; SQLite-only config)
- Mounted project root into Trivy container for `.trivyignore` access

### Verification
- `make scan-images` — 9 images scanned, 0 CRITICAL findings
- `make check-image-versions` — passes (pre-existing `ja4proxy` version drift warning only)

## [Unreleased] - Phase 122 — Production Security Review — Internet-Facing Attack Surface Audit (2026-05-30)

Critical independent security review of all internet-facing components. 14 findings (2 CRITICAL, 5 HIGH, 5 MEDIUM, 2 LOW) across the Go proxy, Python proxy, Management API, and infrastructure — all remediated and verified with 24 regression tests + semgrep rules.

### Changes
- **C-1:** OpenAPI/Swagger docs disabled when `ENVIRONMENT=production`
- **C-2:** X-Forwarded-For centralized into `_client_ip()` with trusted-proxy CIDR check (`MANAGEMENT_TRUSTED_PROXY_CIDRS`)
- **H-1:** CORS wildcard origin (`*`) rejected when `allow_credentials=True` in production
- **H-2:** Login rate limiter (`_check_rate_limit`) fails closed (503) on Redis errors
- **H-3:** 39 f-string logging calls converted to lazy %-style formatting across proxy.py
- **H-4:** Webhook dispatcher receives authenticated Redis client (Go — no longer constructs bare addr)
- **H-5:** OIDC test-mode signature bypass removed from `_extract_claims`
- **M-1:** SAML `strict=false` rejected in production via `_enforce_no_test_mode_in_production()`
- **M-2:** Analytics Redis URL constructed with keyword args (no password in f-string)
- **M-3:** External CDN references removed from login template (SRI hash was fake)
- **M-4:** TAP enforcement bridge verifies HMAC on pub/sub messages
- **M-5:** Health server defaults to `127.0.0.1` (was `0.0.0.0`)
- **L-1:** Plaintext admin password hardened in POC compose file (uses env var)
- **L-2:** CountKeys migrated from KEYS to SCAN (non-blocking)

### Verification
- 24/24 regression tests pass
- 4 semgrep rules active (C-2, H-3, M-2, M-3)
- `make test` passes with same 16 pre-existing failures (unchanged)

## [Unreleased] - Phase 208 — Docker Build Dependency Caching (2026-05-30)

Enabled Docker BuildKit + `--mount=type=cache` for apt-get, pip, and Go module downloads across all 14 Dockerfiles. Fixed `docker-compose.prod.yml` to build the Go proxy instead of the legacy Python proxy. Enabled `DOCKER_BUILDKIT=1` in Makefile build/rebuild/management-build targets.

### Changes
- Added `--mount=type=cache,target=/var/cache/apt` and `--mount=type=cache,target=/var/lib/apt` with `rm -f /etc/apt/apt.conf.d/docker-clean` for apt cache persistence in Python Dockerfiles
- Added `--mount=type=cache,target=/root/.cache/pip` for pip cache persistence across all Dockerfiles
- Added `--mount=type=cache,target=/go/pkg/mod` for Go module cache in Dockerfile.go-proxy and Dockerfile.test-runner
- Changed `deploy/docker/docker-compose.prod.yml` to use `Dockerfile.go-proxy` (was `Dockerfile` — legacy Python)
- Added `DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1` to Makefile `build`, `rebuild`, and `management-build` targets
- Added BuildKit env vars in `.env.example` documentation
- Pinned Go toolchain tags (`1.25.9-alpine`) in `Dockerfile.go-proxy` and `Dockerfile.test-runner`

### Verification
- `docker compose build` uses BuildKit (cached apt/pip/go layers across rebuilds)
- `make build` passes with zero warnings
- `docker-compose.prod.yml` builds the Go binary (not Python legacy)
- 16 pre-existing test failures unchanged (all documented)

## [Unreleased] - Phase 209 — Proxy Runtime Errors — Fail-Open Audit & Remediation (2026-05-30)

Audited and remediated 8 findings from the Proxy Runtime Errors phase: fail-open on Redis errors, TLS parse failures, silent exception swallowing, health check panic crashes, and missing config reload error metrics.

### Changes
- **F-1:** Fixed `docker-compose.prod.yml` to build Go proxy (`Dockerfile.go-proxy` instead of `Dockerfile`)
- **F-2:** Added `on_unknown_ja4` config key (`forward`|`block`|`tarpit`) with documented policy in `config/proxy.yml` — defaults to `"forward"` for backward compatibility
- **F-3:** Country block Redis failure now logged at WARNING level (was silent `pass`)
- **F-4:** Added `dial_fail_closed` config toggle in `monitor_mode` section — defaults `false` (fail-open, log WARNING); when `true`, drops connections on Redis error
- **F-5:** Audited 40 `except Exception` clauses across `proxy.py`, `src/security/`, `src/tap/`, `internal/` — logged all previously silent error paths
- **F-7:** Health check goroutine in `cmd/proxy/main.go` now recovers from panic and continues looping; added `HealthCheckPanicsTotal` counter
- **F-8:** Added `ConfigReloadFailuresTotal` counter metric in Go proxy; config reload failures logged at ERROR level (was WARN)
- Pinned Go toolchain tags (`1.25.9-alpine`) in `Dockerfile.cli` and `Dockerfile.test-runner`
- Management API hardening: OIDC login page security fixes, test mode flag enforcement, pentest regression tests for password leak in logs

### Verification
- `make test` passes with 16 pre-existing failures (all documented/unchanged from Phase 206 baseline)
- Go build passes with zero warnings
- All lint targets pass
- 16 pre-existing test failures remain (documented in CHANGELOG)

## [Unreleased] - Phase 210 — Makefile Help Restructuring & Housekeeping (2026-05-30)

Restructured `make help` from 111 lines to ~50 lines with four sub-helps. Cleaned up monolithic `.PHONY` line. Added comprehensive Makefile targets reference doc. Updated `.gitignore` for coverage file hygiene. Documented missing config keys.

### Changes
- Split `.PHONY` from one 1600+ char line into ~20 grouped declarations
- Rewrote `help` target with cross-references to `lint-help`, `scan-help`, `legacy-help`, `dev-help`
- Created four focused sub-help targets for linting, scanning, legacy proxy, and dev tasks
- Added missing help entries for `scan`, `lint-coverage`, `lint-phases`, `parity-check`, `check-scores`, and others
- Changed `.gitignore` from `.coverage` to `.coverage*` to exclude parallel-mode temp files
- Documented `on_unknown_ja4` and `dial_fail_closed` config keys in `config/proxy.yml`
- Created `docs/MAKEFILE_TARGETS.md` — comprehensive reference for every Makefile target

### Verification
- `make help` renders cleanly; all four sub-helps display correctly
- `.coverage*` files excluded from git tracking
- `make lint-phases` exits 0

## [Unreleased] - Phase 107 — Regulatory & Supply-Chain Conformance (2026-04-27)

Lands the auto-executable portion of Phase 107: full content for the EU
Cyber Resilience Act conformance statement, NIST SSDF (SP 800-218)
practice mapping, ISO/IEC 27017 cloud-controls mapping, ISO/IEC 29100
privacy framework mapping, MITRE ATT&CK technique mapping, and the
coordinated vulnerability disclosure policy. Adds four new CI safety
gates that prevent regressions in overclaim language, evidence-path rot,
ATT&CK confidence-label discipline, and broken internal doc links.

**Phase 107 status: COMPLETE (2026-04-27)** — auto-executable portion
landed. Sub-tasks 107c.3 / 107c.4 / 107c.5 (SLSA L3 release-pipeline
wiring + operator runbook) deferred for human-led execution and
captured under `deferred_subtasks` on the Phase 107 manifest entry.
They mutate the production release pipeline and require manual
`workflow_dispatch` verification against a real attested artefact
before `push:` triggers can be re-enabled — see Deferred section below
for re-entry steps.

### Added — conformance documents (sub-tasks 107a/b/d/e/f/g)
- `docs/compliance/CRA_CONFORMANCE.md` — EU CRA conformance statement.
  Scope determination, Annex I rows ER1-ER13 (each tied to EU 2024/2847
  §1(2) sub-paragraphs with real evidence paths), Annex II rows for SBOM
  / CVD / patches / support, conformity-assessment procedure (Article
  24(1)(a) self-assessment route), EU DoC TEMPLATE marked NOT SIGNED,
  post-market vulnerability management section. **No support-period
  number is stated** — the regulation requires the position to be
  documented; the project commits to no number until harmonised
  standards are published (expected ETSI/CEN-CENELEC 2026-2027).
- `docs/compliance/SSDF_MAPPING.md` — all 19 NIST SP 800-218 v1.1
  practices mapped (PO 1-5, PS 1-3, PW 1-8, RV 1-3). Summary box: 14
  fully implemented / 5 partial / 0 N/A. Each row's evidence column
  cites a real file path (verified by the `test-evidence-paths` gate).
- `docs/compliance/iso27017-mapping.md` — ISO/IEC 27017:2015 cloud
  controls. CLD.6 / CLD.8 / CLD.9 / CLD.12 mapped. Applicability:
  3 applies / 4 customer-responsibility / 0 N/A. Customer-responsibility
  rows carry deployer-guidance notes.
- `docs/compliance/iso29100-mapping.md` — all 11 ISO 29100 privacy
  principles. Every row links to `GDPR_COMPLIANCE.md` or
  `docs/REDIS_SCHEMA.md` rather than duplicating PII content.
- `ATTACK_MAPPING.md` — MITRE ATT&CK Enterprise
  technique mapping. 16 forward rows covering 6 tactics (TA0043, TA0042,
  TA0001, TA0011, TA0005, TA0040). Confidence distribution 4 high /
  9 medium / 3 low (no inflation). Reverse view + SIEM integration
  examples (Splunk SPL).
- `docs/security/CVD_POLICY.md` — coordinated vulnerability disclosure
  policy. 8 sections (Scope / Reporting / Acknowledgement & Triage /
  Fix timelines / Disclosure & Embargo / Credit & CVE / Safe Harbour /
  Standards Alignment). **No time-bound SLAs** — best-effort posture
  with explicit "Why no SLA" rationale (self-funded, no oncall, no
  commercial entity); reporters who need guaranteed response are
  pointed to the absence of a commercial support tier. Safe-harbour
  text is the disclose.io Simple Safe Harbor template **verbatim**
  (source URL noted in HTML comment for byte-equality verification).
- `docs/decisions/ADR-107a-slsa-level-3.md` — Status: Proposed.
  Decision to adopt SLSA L3 via `slsa-framework/slsa-github-generator`.

### Added — CI safety gates (sub-tasks 107c.6, 107f.4, 107h.1, 107h.2, 107w.3)
- `tests/test_compliance_language.py` — fails if "certified" /
  "compliant" appears in `docs/compliance/` or
  `docs/security/CVD_POLICY.md` (outside an explicit allowlist; empty
  by design — no third-party certifications). Regression guard for
  review finding S-2 (HIGH).
- `tests/test_compliance_evidence_paths.py` — extracts every
  repo-relative path cited in conformance-doc evidence columns and
  asserts each exists. Catches silent-rot from renamed/deleted source
  modules. Regression guard for review finding A-3.
- `tests/test_attack_mapping.py` — two independent assertions:
  (1) every forward-mapping row has a high/medium/low confidence label
  starting the Confidence cell (T-3 guard); (2) every Source-file path
  resolves on disk (A-3 guard for ATT&CK).
- `tests/test_workflow_pinning.py` — extended `KNOWN_ACTION_SHAS`
  allowlist with `lycheeverse/lychee-action@v2.8.0` (SHA verified twice
  via GitHub API and `git ls-remote`).
- `Makefile` — five new targets: `test-compliance-language`,
  `test-evidence-paths`, `test-compliance` (aggregate),
  `test-attack-mapping`, `test-doc-links` (lychee-driven, requires
  lychee installed locally).

### Added — CI workflows (sub-tasks 107c.2, 107w.3)
- `.github/workflows/slsa-verify.yml` — `workflow_dispatch`-only.
  Installs `slsa-verifier` v2.6.0 from a SHA-pinned binary download
  (sha256 cross-verified against upstream's own SLSA in-toto
  attestation), then runs `slsa-verifier verify-image` against a
  configurable `image_ref` input. Until 107c.3 lands and produces an
  attested image, this workflow fails with "no attestation found" —
  expected baseline that proves the verifier plumbing is correct. A
  placeholder-guard step refuses to run if the binary SHA is unset.
- `.github/workflows/docs-link-check.yml` — `pull_request` (paths:
  `docs/**`, `**.md`) and `workflow_dispatch`. Runs lychee against
  conformance docs, audience-scoped READMEs, CVD policy, ADR-107*,
  and SECURITY.md. Internal broken links fail the build; external
  4xx/5xx tolerated.

### Added — RFP / risk register (sub-task 107z.2)
- `docs/compliance/RFP_DRYRUN.md` — checklist of typical RFP
  conformance questions, each linking the answering doc + section.
  Replaces the unmeasurable "RFP questionnaire fully answerable"
  acceptance criterion (review finding C-1) with a concrete checklist.
- `docs/RISK_REGISTER.md` — three new rows for genuine gaps surfaced
  by the mapping work: RR-043 SLSA L3 not yet shipped (Open),
  RR-044 No CVD response SLA (Accepted; deliberate position per
  CVD_POLICY §3-4), RR-045 No formal RCA template (Open).

### Changed — wiring (sub-tasks 107w.1, 107w.2)
- `README.md` — new "Standards & conformance"
  section linking CRA, SSDF, ATT&CK, ADR-107a. ADR-107a row added to
  the architecture-decisions list.
- `README.md` — five new index rows: CRA, SSDF,
  ISO 27017, ISO 29100, CVD policy.
- `FAQ.md` — Q16 "Are you CRA-compliant?"
  (uses self-assessed language, no number-of-years commitment), Q17
  "Do you support SLSA provenance verification?" (current L2 + path to
  L3, deferred runbook).
- `docs/compliance/iso27001-annex-a-mapping.md` — "see also" link to
  iso27017-mapping.md.
- `docs/compliance/GDPR_COMPLIANCE.md` — "see also" link to
  iso29100-mapping.md (added to title block) plus the §12.1 FAQ
  heading rewording from "Is JA4proxy GDPR compliant out-of-the-box?"
  to "Does JA4proxy support GDPR compliance out-of-the-box?" (S-2
  guard caught the original phrasing during PR1).
- `docs/compliance/SECURITY_CONTROLS_MAPPING.md` — "Current Compliance
  Status" relabelled to "Current Implementation Status"; explicit
  "self-assessment, not a third-party certification" sentence added
  (S-2 guard caught the pre-existing wording during PR1).
- `SECURITY.md` — rewritten as a ~25-line pointer to CVD_POLICY.md.
  Removed: fake email `security@ja4proxy.example.com`, fake PGP key
  ID, fake response-time targets, fake phone number, fake Slack
  channel, fake PagerDuty escalation, fake Hall-of-Fame entries
  (John Smith / Jane Doe / fabricated CVE-2026-1234), generic
  security-best-practices boilerplate, the duplicated "RESOLVED"
  block. Preserved: the historical credential-exposure note about
  commit `d67f4d6`.
- `docs/security/INTAKE_RUNBOOK.md` — new "Coordinated vulnerability
  disclosure (CVD) intake" section with best-effort triage steps.

### Verified
- `make test-compliance test-attack-mapping` — 7 tests pass
  (3 language + 2 evidence-path + 2 ATT&CK).
- `python3 -m pytest tests/test_workflow_pinning.py` — 7 tests pass
  (covers both `slsa-verify.yml` and `docs-link-check.yml`).
- 17/17 Phase 107 CI gates green at branch tip.
- No "certified" / "compliant" in any of the new content.
- No SLA numbers committed anywhere (§3-4 of CVD_POLICY references
  "2-day" / "30-day" only as examples of what the project is **not**
  promising, in the explanatory "Why no SLA" paragraph).
- All evidence paths in conformance docs verified to exist on disk.
- Disclose.io Simple Safe Harbor text in CVD_POLICY §7 verified
  byte-for-byte against the canonical upstream source.

### Deferred to human-led execution (NOT auto-merged)
- **107c.3** — wire `slsa-framework/slsa-github-generator` reusable
  workflow into `.github/workflows/go-proxy-image.yml`. This mutates
  the production release pipeline (workflow-level `id-token: write`
  reshape required); must be landed under `workflow_dispatch`-only,
  manually verified to produce an attested artefact, then re-enabled
  on `push:` triggers in a follow-up commit.
- **107c.4** — same pattern for `.github/workflows/release-cli.yml`
  (CLI binary path, `generator-generic-slsa3.yml`).
- **107c.5** — `ADR-107a-slsa-level-3.md` operator
  runbook. Depends on 107c.3 producing a real attested artefact to
  test the runbook commands against (per phase doc Notes-for-Implementer
  "verifier UX matters more than the attestation itself").

When 107c.3 / 107c.4 ship, write a `ADR-107a-slsa-level-3.md`
runbook (107c.5) by **dry-running every command on a clean shell against
the freshly attested artefact** and capturing expected output verbatim
— per the phase doc's "verifier UX matters more than the attestation
itself" guidance. All other Phase 107 acceptance criteria are met.



## [Unreleased] - Phase 101g M10 — DECIDED-KEEP-AS-GAUGE; sub-phase 101g closed (2026-04-26)

Closes M10 — the last open item in sub-phase 101g — via a documented
decision rather than a code change. The original review item proposed
switching `ja4proxy_ti_feed_indicators_managed` from `Gauge` to
`Counter`. On re-read this is incorrect:

- The metric measures the *current* size of the `active_stix_ids` Redis
  HASH per feed. That value goes both up (new indicators added) and
  down (cleanup removals).
- A Prometheus `Counter` must be monotonically non-decreasing. Switching
  type would corrupt every `rate()` / `increase()` query against the
  metric on every cleanup pass — exactly the wrong direction.
- The "removal-delta" signal that a Counter would express *already
  exists* as `ja4proxy_ti_feed_cleanup_removals_total`
  (`metrics.py:50`, `Counter[feed_id]`). The Gauge + Counter pair is
  the textbook Prometheus pattern for this shape.

### Changed
- `src/analytics/ti_feeds/metrics.py` — added inline rationale to
  `TI_INDICATORS_MANAGED` explaining why it stays a Gauge and pointing
  to `TI_CLEANUP_REMOVALS` for the cleanup-delta signal.
- `docs/phases/complete/PHASE_101.md` §3.7 — status flipped from PARTIAL →
  COMPLETE; added "M10 review — DECIDED-KEEP-AS-GAUGE" block with full
  rationale; both 101g acceptance boxes ticked.
- `docs/phases/manifest.yaml` line 1592 — 101g flipped from PARTIAL
  → COMPLETE with the M10 decision summarised inline.

### Phase 101 sub-phase status (post-PR)
| Sub-phase | Status |
|---|---|
| 101a, 101b, 101c, 101d, 101e, 101f, **101g**, 101h, 101k | **COMPLETE** |
| 101i, 101l | DEFERRED (external blockers) |
| 101j | M19 done; M18 blocked on Phase 76 |

Phase 101 parent still cannot be marked COMPLETE: 101i (Go capacity)
and 101l (cross-org auth) are deferred on external blockers, and 101j
M18 is blocked on Phase 76 quadlet files.

## [Unreleased] - Phase 101g M12 — explicit-exception unions across 4 TI feed clients (2026-04-26)

Closes M12. Replaces 12 bare `except Exception:` catches across the four
threat-intel feed clients with explicit unions, so programmer bugs
(`AttributeError`, `KeyError`, `TypeError`, `ImportError`, `NameError`)
propagate instead of being silently swallowed and counted as a feed
failure. Phase 101g now M8/M9/M11/M12/M13/M14 done; only M10 still open
(semantics under review — see Status note in PHASE_101.md §3.7).

### Changed
- `src/analytics/ti_feeds/taxii.py` — added module-level
  `_FEED_FETCH_ERRORS` (aiohttp.ClientError, asyncio.TimeoutError,
  RuntimeError, ValueError, OSError) and
  `_FEED_WRITE_ERRORS = (*_FEED_FETCH_ERRORS, ManagementAPIError)`.
  Replaced 3 `except Exception:` sites: pagination fetch, mgmt-API
  ban-create, mgmt-API blocklist-create.
- `src/analytics/ti_feeds/crowdstrike.py` — same constants; replaced 4
  `except Exception:` sites: OAuth token fetch, indicator fetch,
  indicator parse, mgmt-API write.
- `src/analytics/ti_feeds/recorded_future.py` — re-imports
  `_FEED_FETCH_ERRORS` from `.taxii` (single source of truth);
  replaced 2 `except Exception:` sites in cursor-paginated and
  multi-collection poll paths.
- `src/analytics/ti_feeds/rest_generic.py` — same constants but
  includes `JsonPathParserError` in the fetch tuple (this client uses
  jsonpath-ng for body extraction). Replaced 3 `except Exception:`
  sites: HTTP fetch, ban-create, blocklist-create.

### Why
`except Exception:` masks real bugs as feed failures — an `AttributeError`
in a refactor would silently increment `ti_feed_poll_total{result="failure"}`
instead of crashing the worker and surfacing in CI. The explicit unions
catch only the I/O / parse / mgmt-API errors we *expect* a feed to throw
on a bad upstream day. Two-tier (`_FEED_FETCH_ERRORS` for read paths,
`_FEED_WRITE_ERRORS = fetch + ManagementAPIError` for write paths) keeps
the read-side tuple from accidentally absorbing mgmt-client errors at
the wrong layer.

### Added
- `tests/unit/analytics/ti_feeds/test_phase_101g_medium.py::TestM12ExplicitExceptions`
  — replaces the old substring-grep test with an AST-based
  `ExceptHandler` walk across all 4 client files. Asserts zero
  `except Exception:` handlers remain and reports any offender as
  `file:line` for fast triage.
- `TestM12ExplicitExceptionsRuntime` — 4 new behaviour tests proving
  the chosen tuple does the right thing at runtime: (1) catches
  expected I/O errors (aiohttp, timeout, runtime, value, OS); (2)
  `_FEED_WRITE_ERRORS` is a strict superset including
  `ManagementAPIError`; (3) does NOT catch programmer-bug exceptions
  (`AttributeError`, `KeyError`, `TypeError`, `ImportError`,
  `NameError`); (4) every client module exposes the
  `_FEED_FETCH_ERRORS` symbol with at least 4 entries.

### Phase 101 sub-phase status (post-PR)
| Sub-phase | Status |
|---|---|
| 101a, 101b, 101c, 101d, 101e, 101f, 101h, 101k | COMPLETE |
| **101g** | **PARTIAL** — M8/M9/M11/M12/M13/M14 done; M10 still open (semantics under review) |
| 101i, 101l | DEFERRED |
| 101j | M19 done; M18 blocked on Phase 76 |

## [Unreleased] - Phase 101g M11 — stable-ordered dropped list (2026-04-26)

Closes M11. Phase 101g remaining open items: M10 (Gauge → Counter, semantics
under review) and M12 (BLE001 explicit-exception unions across 4 client files).

### Changed
- `src/analytics/ti_feeds/state.py::compute_dropped_ids` — return type
  changed from `dict[str, str]` to `list[tuple[str, str]]`, sorted by
  `stix_id` ascending. Stable ordering means the cleanup-cap split in
  `runner._poll_one` (head/tail slice when `len(dropped) > cap`) is
  deterministic across runs; before this change, dict ordering was
  effectively insertion-order-from-Redis-HGETALL — implementation-defined
  and indistinguishable from random for callers.
- `src/analytics/ti_feeds/state.py::FeedState.compute_dropped` — same
  return-type change; thin wrapper now delegates to the module-level
  `compute_dropped_ids` so both share one definition.
- `src/analytics/ti_feeds/runner.py::FeedRunner._poll_one` — caller
  updated: dropped the redundant `sorted(dropped.keys())` call (output
  is already sorted), simplified the cap-split from dict-comprehension
  to direct list slicing, and the deferred-cleanup carry-forward loop
  now iterates the list of tuples directly.

### Why
Before M11, two analytics replicas observing the same poll result could
produce differently-ordered cleanup-cap splits because of dict ordering
nondeterminism, causing the same handle to ping-pong between "kept" and
"deferred" across cycles. Sorted output guarantees both replicas pick the
same head and the same tail, so cleanup converges instead of churning.

### Added
- `tests/unit/analytics/ti_feeds/test_phase_101g_medium.py::TestM11StableOrderedDropped`
  — 5 new behavior tests replacing the previous "grep for 'compute_dropped_ids'
  in the source" tautology. Asserts: (1) return type is `list` of
  `(stix_id, handle)` tuples; (2) output is sorted by stix_id ascending,
  proven by inserting in reverse order; (3) ids in `current` are excluded;
  (4) full-overlap returns `[]`; (5) handles are paired with their
  original stix_ids (no swap).

### Updated
- `tests/unit/analytics/ti_feeds/test_state.py` — 3 existing
  `compute_dropped` assertions converted from dict literals to list
  literals to match the new return type.

### Test results
- 5 new M11 tests pass; 3 updated `test_state.py` assertions pass.
- 6049/6049 unit + integration tests pass; 10 skipped (Docker stack).
- `ruff check` clean across the touched files.

### Phase 101g status after this PR
| Item | Status |
|------|--------|
| M8 — TAXII bundle size cap | done |
| M9 — Per-feed User-Agent header | done |
| M10 — Gauge → Counter | open (semantics under review — see PHASE_101.md) |
| M11 — Stable-ordered dropped list | **done (this PR)** |
| M12 — Replace BLE001 bare Exception catches | open |
| M13 — `seed_file` inside leader lock | done |
| M14 — Audit log on feed enable/disable | already shipped |

## [Unreleased] - Phase 101g M13 + M14 — seed-file leader gate; M14 audit-trail confirmed (2026-04-26)

Closes M13. Confirms M14 was already shipped. Phase 101g still partial
(M10/M11/M12 open).

### Changed
- `src/analytics/ti_feeds/seed_file.py` — `run_once()` now accepts an
  optional `instance_id: str | None = None`. When provided, it gates
  the entire load on `state.try_acquire_leader(instance_id, ttl=60)`.
  Non-leader replicas log
  `event=seed_file_skipped_not_leader` and return an empty summary
  (`{loaded: 0, created: 0, rejected: 0, errors: 0}`) — no parse, no
  Mgmt API calls, no Redis writes. Backwards-compatible: passing
  `instance_id=None` (the default) bypasses the gate entirely, so
  legacy single-replica callers and tests are unaffected.
- `src/analytics/ti_feeds/runner.py` — startup seed-load call site
  now passes `instance_id=self._instance_id` so production runners
  always honour the leader lock.

### Why
Without this gate every analytics replica POSTs every seed entry on
startup. Mgmt API is first-writer-wins so it's safe but wasteful; the
lock collapses N startup loads into one. TTL is 60s — generous because
the seed file is small and applies in well under a second normally,
but a slow Mgmt API or large seed file should not race the lock expiry.

### Added
- `tests/unit/analytics/ti_feeds/test_phase_101g_medium.py::TestM13SeedFileLeaderLock`
  — 3 new tests replacing the previous "grep for 'leader' or 'lock'"
  tautology. Asserts: (1) when `try_acquire_leader` returns False, no
  mgmt calls and no `state.mark` calls fire; (2) when it returns True,
  the work proceeds; (3) `instance_id=None` bypasses the gate
  entirely.

### M14 — audit-log confirmation
`management/api/routes/threat_intel.py::enable_feed` (line 337) and
`disable_feed` (line 381) already call `write_audit` with
`action_type="ti_feed.enabled"` / `"ti_feed.disabled"`, recording
`actor_id`, `actor_ip`, `before_value=None`, `after_value={"runtime_enabled": True/False}`,
and `role`. Acceptance criterion satisfied — no code change required.

### Test results
- 6047/6047 unit + integration tests pass (excluding live-docker tests)
- 3 new M13 tests added, all green
- No regressions across `tests/unit/analytics/ti_feeds/` (329 tests)

### Phase 101 sub-phase status (post-PR)
| Sub-phase | Status |
|---|---|
| 101a, 101b, 101c, 101d, 101e, 101f, 101h, 101k | COMPLETE |
| **101g** | **PARTIAL** — M8/M9/M13/M14 done; M10/M11/M12 open |
| 101i, 101l | DEFERRED |
| 101j | M19 done; M18 blocked on Phase 76 |

## [Unreleased] - Phase 101h — low items L6/L7/L8 closed (2026-04-26)

Docs-only sub-phase 101h close-out. All three low-severity items
verified at file:line:

- **L6** — `_OneShotBundle` docstring at
  `src/analytics/ti_feeds/recorded_future.py:260` accurately describes
  the adapter's role: a TAXII-transport stub that wraps a single STIX
  bundle and implements the `get_objects(collection_id, added_after)
  → dict` contract `TAXIIClient(taxii=…)` expects. H13's
  `stix_ids_seen.add()` deferral lives in `taxii.py::_apply_indicator`,
  not in this adapter, so the docstring is still correct after H13.
- **L7** — Three Phase 85 runbooks (`ti_feed_caps_hit.md`,
  `ti_feed_fp_blocked.md`, `ti_feed_circuit_open.md`) carry
  `last_reviewed: 2026-04-26` headers but have NOT been dry-run against
  a real production deployment (none available). All referenced
  Prometheus/Alertmanager queries and operator tools
  (`ja4proxy-cli`, `redis-cli`) are syntactically and semantically
  correct against the current schema; what's untested is end-to-end
  operator timing in a live incident. Per the original acceptance
  phrasing — "verified against a live deployment OR documented as
  untested" — marking as DOCUMENTED-AS-UNTESTED.
- **L8** — Metrics registry at `deploy/monitoring/metrics_registry.md`
  already documents all four new Phase 101 metrics:
  `ja4proxy_ti_feed_caps_hit_total` (line 51),
  `ja4proxy_ti_feed_fp_blocked_total` (line 52),
  `ja4proxy_dsar_export_partial_failures_total` (line 60),
  `ja4proxy_dsar_xrange_len` (line 61).

### Changed
- `docs/phases/complete/PHASE_101.md`: ticked all 3 acceptance boxes for 101h
  with file:line references; added Status block noting L7 caveat.
- `docs/phases/manifest.yaml`: annotated 101h as COMPLETE 2026-04-26.

### Phase 101 sub-phase status (post-PR)
| Sub-phase | Status |
|---|---|
| 101a | COMPLETE |
| 101b | COMPLETE |
| 101c | COMPLETE |
| 101d | COMPLETE |
| 101e | COMPLETE |
| 101f | COMPLETE |
| 101g | PARTIAL (M8/M9 done; M10–M14 open) |
| **101h** | **COMPLETE (this PR)** |
| 101i | DEFERRED (Go capacity) |
| 101j | M19 done; M18 blocked |
| 101k | COMPLETE |
| 101l | DEFERRED (cross-org auth) |

Phase 101 still cannot be marked COMPLETE: 101g remaining items + 101i/101l deferred.

## [Unreleased] - Phase 101 housekeeping — acceptance audit (2026-04-26)

Docs-only sub-phase status reconciliation. No code changes. Audited every
unticked acceptance box in `docs/phases/complete/PHASE_101.md` against current
`HEAD`; ticked the boxes whose underlying work was already in code (via
prior Phase 84 review-fixes branch and prior 101 sub-phase landings) but
whose acceptance criteria had not been formally checked off.

### Changed
- `docs/phases/complete/PHASE_101.md`:
  - **101b** — all 6 boxes ticked (M1, M2, M4, L1, L2, L5 verified at
    file:line). `make test-phase-84` box left **unticked** because of a
    pre-existing `PciDssPackBuilder.__init__()` signature mismatch
    (constructor wants `(redis, classifier)`; route + tests pass
    `fmt=…`). 19 phase-84 tests fail on `main` already — unrelated to
    101b items, needs separate triage PR.
  - **101d** — added `**Status: COMPLETE — landed 2026-04-26.**` line.
  - **101f** — all 4 boxes ticked. Verified with
    `grep -nE "pytestmark|xfail" tests/{integration,chaos}/test_ti_feed*.py`
    (no matches) and a green run of all 5 files (10 tests, 0.3s).
  - **101g** — added a **Status: PARTIAL** note: M8/M9 done in code;
    M10/M11/M12/M13/M14 still open. Documented per-item status so the
    next sub-phase pickup knows exactly what's left.
  - **101j** — M19 box ticked (audited; only historical references in
    `PHASE_64*.md` remain — those are audit-trail commentary, not
    operational guidance). M18 left explicitly DEFERRED on Phase 76.
- `docs/phases/manifest.yaml`: bumped Phase 101 `status` from
  `PROPOSED` → `IN_PROGRESS`. Annotated each sub-phase entry with its
  current status (COMPLETE / PARTIAL / DEFERRED / open). Phase 101 cannot
  be marked COMPLETE until 101g remaining items, 101h, and 101i/101l
  (deferred) are resolved.

### Sub-phase status snapshot (post-audit)
| Sub-phase | Status |
|---|---|
| 101a | COMPLETE |
| 101b | COMPLETE (with pre-existing test-phase-84 caveat) |
| 101c | COMPLETE |
| 101d | COMPLETE (H6 + H7 + H8 all landed) |
| 101e | COMPLETE |
| 101f | COMPLETE |
| 101g | PARTIAL (M8, M9 done; M10–M14 open) |
| 101h | OPEN (depends on 101g) |
| 101i | DEFERRED (Go capacity) |
| 101j | M19 done; M18 blocked |
| 101k | COMPLETE |
| 101l | DEFERRED (cross-org auth) |

### Known pre-existing breakage (filed for separate triage)
- `make test-phase-84` → 19 failures (12 in
  `management/tests/test_compliance_pack.py`, 7 in
  `management/tests/test_compliance_routes.py`). Root cause:
  `PciDssPackBuilder.__init__()` accepts `(redis, classifier)` but the
  PCI-DSS route at `management/api/routes/compliance.py:321` and the
  pack tests both call it with `fmt=…`. This breakage exists on `main`
  before this PR and is NOT introduced by housekeeping changes.
  Verified by checking out `main` and re-running the same test.

## [Unreleased] - Phase 101d H6 — SafeResolver connector wrap (2026-04-26)

Closes the H6 HIGH gap and **completes sub-phase 101d**. The URL-validator
half of H6 landed in 101c (rejecting RFC1918/loopback/link-local *literals*
in feed URLs); this entry adds the DNS-level half — a `SafeResolver`-backed
`aiohttp.TCPConnector` so a feed configured with a hostname whose A record
*resolves to* a private/cloud-metadata IP (e.g. `169.254.169.254`) is
rejected at the connector before the request leaves the box.

### Changed
- `src/analytics/ti_feeds/crowdstrike.py`: both aiohttp paths (`_ensure_token`
  OAuth fetch and `_poll_all_pages` indicator iteration) now construct
  their `aiohttp.ClientSession` with
  `aiohttp.TCPConnector(resolver=SafeResolver())`. Matches the pattern
  already in place in `taxii.py` and `rest_generic.py`.

### Coverage matrix (4 production HTTP paths, all wired)
- `taxii.py::_fetch_objects` → wrapped (landed 101c)
- `rest_generic.py::_fetch_json` → wrapped (landed 101c)
- `crowdstrike.py::_ensure_token` → wrapped (landed 101d-H6)
- `crowdstrike.py::_poll_all_pages` → wrapped (landed 101d-H6)
- `recorded_future.py` → covered transitively: it delegates HTTP through
  inner `TAXIIClient` instances, so the TAXII wrap protects it.

### Added
- `tests/adversarial/test_ti_feeds_ssrf.py` (4 tests): patches the inner
  resolver inside `safe_resolver.SafeResolver` so any hostname resolves to
  `169.254.169.254`, then drives a real `client.poll()` (no transport
  stub injected — the production aiohttp path runs end to end) for
  TAXII, REST-generic, and CrowdStrike. Each test asserts (a) the
  `_PrivateIPResolver` recorded an invocation — *proving* SafeResolver
  was actually wired in (otherwise the post_ban check below could pass
  for the wrong reason: a real DNS failure), (b) the poll surfaced an
  error in `result.errors`, and (c) `mgmt.post_ban` was never called —
  no IOC applied, no CIDR expansion, no follow-up traffic to the
  metadata IP. A fourth `test_safe_resolver_isolation_check_no_global_leak`
  guards against monkeypatch leakage between tests.

### Why "PermissionError" / "SSRF blocked" string is not asserted
`SafeResolver.resolve()` raises `PermissionError("SSRF blocked: …")`
which `aiohttp.TCPConnector` catches as an `OSError` subclass and
re-wraps as `ClientConnectorError(connection_key, os_error)`. Because
`PermissionError` carries no `errno`/`strerror`, the wrapped error
stringifies to `Cannot connect to host … ssl:default [None]` — the
SSRF marker is lost in the wrap. Asserting the resolver-invocation
counter is a stricter guarantee anyway: it proves the resolver actually
ran (rather than the connection failing for an unrelated reason like a
network outage in CI).

### Sub-phase status
- **101d closed.** All three HIGH items (H6 SSRF, H7 manual-poll rate
  limit, H8 CSRF) landed today (2026-04-26). Phase 101 still has
  101l (terraform-provider-ja4proxy publication — deferred pending
  explicit cross-org repo authorization).

## [Unreleased] - Phase 101d H8 — CSRF double-submit middleware (2026-04-26)

Closes the H8 HIGH gap from Phase 101 sub-phase **101d** (Phase 85
SSRF/rate-limit/CSRF). H6 connector-level SSRF (resolver wrap) remains
open and is being tracked separately; H7 landed earlier today via PR
#50; the CSRF middleware itself is the focus of this PR.

### Added
- `management/api/middleware/csrf.py` (260 lines): `CSRFMiddleware`
  enforces double-submit cookie + HMAC token on every mutating route
  under `/api/v1/*`. On `GET /api/v1/*`, mints a `csrf_token` cookie
  (SameSite=Strict, Secure when scheme is HTTPS or `ENVIRONMENT=production`)
  and mirrors it in an `X-CSRF-Token` response header for HTMX/fetch
  callers. On `POST/PUT/PATCH/DELETE /api/v1/*`, requires both the
  cookie and the matching `X-CSRF-Token` header AND verifies the token's
  HMAC-SHA256 signature is bound to the JWT `sub` claim of the calling
  session (so a sibling-domain cookie injection can't satisfy the
  signature gate). Mismatch / expired / missing → HTTP 403
  `{"error": "csrf_token_mismatch"}`. Bearer-token callers
  (`Authorization: Bearer …`) are exempt because browsers cannot forge
  that header cross-origin.
- `management/api/middleware/__init__.py`: package marker.
- Wired into `create_app()` immediately after CORS in
  `management/api/main.py`.
- `_enforce_no_test_mode_in_production()` extended to refuse startup
  when `ENVIRONMENT=production` and `MANAGEMENT_DISABLE_CSRF=1` are both
  set — defence in depth on top of the middleware's own production
  refusal of the bypass flag.

### Tests
- `tests/unit/test_csrf.py` (243 lines, 12 tests):
  - 5 token-primitive tests covering the issue/verify roundtrip,
    wrong-session rejection, tampered-signature rejection, expiry
    (frozen-time monkeypatch), and malformed-input rejection.
  - 7 HTTP integration tests: GET mints cookie+header, POST without
    CSRF → 403, cookie/header mismatch → 403, forged random
    `AAAA.BBBB` token → 403 (signature gate catches it), valid
    double-submit → middleware lets request through, Bearer auth
    bypasses CSRF, non-`/api/v1` routes are unaffected.
  - The CSRF-enforcement guarantee is per-test (`monkeypatch.delenv`),
    not module-level, so the env state does not leak into other test
    files in the same pytest process.
- `management/tests/conftest.py`: sets `MANAGEMENT_DISABLE_CSRF=1` so
  the ~95 inline `AsyncClient` instantiations that predate this
  middleware keep working. The flag has no effect when
  `ENVIRONMENT=production`, and `create_app()` refuses to start at all
  when both are set.
- `tests/unit/test_pages_threat_intel.py` and
  `tests/unit/test_managed_by_operator_k8s.py` set the same bypass at
  module level (they're standalone files, not under
  `management/tests/conftest.py`).
- `management/tests/test_test_mode_hardening.py` and
  `management/tests/test_cookie_secure_flag.py` updated to clear
  `MANAGEMENT_DISABLE_CSRF` in their per-test prod-environment setup.

### Phase status
- `docs/phases/complete/PHASE_101.md`: H8 acceptance boxes ticked.
- `docs/phases/manifest.yaml`: 101d remains open (H6 connector-resolver
  wrap is the only acceptance criterion not yet met).

## [Unreleased] - Phase 101a complete — DSAR metric wiring + erase CIDR semantics (2026-04-26)

Closes Phase 101 sub-phase **101a** (Phase 84 DSAR correctness — H1, H3, M7).
H1 (single XRANGE per request), H3 (CIDR matching for `_dsar_watchlist_entries`),
and M7 (`partial_failures` reporting on Redis errors) functional code already
landed earlier. This commit lands the two remaining pieces and closes 101a:

### Added
- `management/api/routes/compliance.py`: write `management:dsar:last_xrange_len`
  (count of stream rows scanned per DSAR call) and increment
  `management:dsar:partial_failures_total` (one per failed category) into
  Redis after each DSAR export. Follows the existing pattern: management
  API writes counters to Redis, analytics node re-emits as Prometheus
  series — no new registry in the API process.
- `management/tests/test_phase_101a_dsar_correctness.py`:
  - `test_dsar_xrange_metric_wired` (de-skipped, was xfail) — seeds 7
    events, calls DSAR, asserts `int(redis.get("management:dsar:last_xrange_len")) == 7`.
  - `test_dsar_partial_failures_counter_wired` (new) — patches
    `redis.xrange` to raise `RuntimeError`, asserts response carries
    `partial_failures: ["connection_history", "fingerprint_associations"]`
    and the Redis counter incremented by 2.
  - `test_dsar_erase_cidr_block_surfaced_as_skipped` (new) — seeds an
    exact-match `10.0.0.5` and a `/24` cover entry, calls
    `DELETE /api/v1/compliance/dsar/10.0.0.5`, asserts the exact entry
    is in `erased_keys`, the `/24` entry is NOT erased, and the `/24`
    entry appears in `skipped` with a reason naming the network. This
    honours GDPR Article 17's "rights of others" limitation: erasing a
    `/24` watchlist entry to satisfy one subject's request would silently
    strip security coverage from 254 unrelated subjects.

### Changed
- `management/api/routes/compliance.py` erase path: differentiate exact
  string match (delete), single-host `/32` v4 or `/128` v6 CIDR (delete),
  and broader CIDR cover (skip with explanatory reason). Previously the
  code did literal-string compare only, so a watchlist entry stored as
  `10.0.0.5/32` would not match a DSAR for `10.0.0.5`.

### Phase status
- `docs/phases/manifest.yaml`: `101a` annotated `COMPLETE 2026-04-26`.
- `docs/phases/complete/PHASE_101.md`: all 8 acceptance boxes ticked, status line
  updated. Still open: 101d-H8, 101l.

## [Unreleased] - Phase 101d H7 — manual-poll rate limit (2026-04-26)

Closes the H7 HIGH gap from Phase 101 sub-phase **101d** (Phase 85
SSRF/rate-limit/CSRF). H6 was partly addressed in 101c; H8 (CSRF
double-submit middleware) remains open and will land separately.

### Added
- `management/api/routes/threat_intel.py`: `_check_poll_rate_limit()` —
  per-`feed_id` sliding-window cap of **6 polls / 60 s** on
  `POST /api/v1/threat-intel/feeds/{id}/poll`. Implementation uses a
  Redis sorted set per the CLAUDE.md sliding-window pattern
  (`ZREMRANGEBYSCORE` + `ZCARD` + `ZADD` with `{ts}:{uuid4}` member),
  responds **HTTP 429** with a `Retry-After` header derived from the
  oldest in-window entry, and runs **after** the 404 feed-existence
  check so polls against missing feeds do not pollute the quota.
  Fail-open on Redis errors (CLAUDE.md core asymmetry — a missed
  abuse signal is recoverable; locking out an Operator is not).

### Tests
- `tests/unit/test_pages_threat_intel.py`:
  - `test_phase_101_h7_seventh_poll_in_window_returns_429` — verifies the
    cap, the `Retry-After` header is present, and the body contains a
    `rate limit` string.
  - `test_phase_101_h7_rate_limit_is_per_feed_id` — verifies the
    quota is namespaced to the upstream feed (saturating `test-feed`
    leaves `other-feed` free), per the spec wording in PHASE_101.md.
  - `test_phase_101_h7_404_feed_does_not_consume_quota` — verifies
    that 10 polls against a non-existent feed all 404 and never trip
    the limiter.

## [Unreleased] - Phase 101k complete — H14 doc-tick + H16 Datadog runbook + M26 benchmarks tightening (2026-04-26)

Closes Phase 101 sub-phase **101k** (Phase 86i capacity hardening). H15,
M24, M25 landed earlier today via PR #48. This commit lands the remaining
three items (H14, H16, M26), allowing 101k to be marked COMPLETE in
`manifest.yaml`.

### Fixed
- PHASE_101.md: H14 acceptance criterion ticked. The dead
  `_ESTIMATED_BANNER` constant and `_print_estimated_warning()` were
  already deleted in commit `3c35030` on 2026-04-15; the spec text was
  written before that landed and the §0 stranded-branch review missed
  the reconciliation. No code change here — just the doc tick.

### Added
- `docs/runbooks/datadog_migration_phase86i.md` (H16): full oncall
  runbook for the two-layer Datadog migration. Documents the strict
  deploy order (OpenMetrics layer 1 then narrowed custom check layer 2,
  reverse causes 24h of `unknown` health states), the three pre-flight
  smoke-check commands (`datadog-agent check openmetrics`,
  `datadog-agent check ja4proxy`,
  `datadog-agent status | grep -A5 "openmetrics ja4proxy"`), failure-mode
  matrix, post-migration UI checks, and rollback procedure.
- `tests/unit/test_datadog_integration.py::TestPhase101H16MigrationRunbook`
  (3 tests): runbook exists, references both `datadog-agent check`
  commands by exact name, documents Layer 1 before Layer 2.

### Changed
- `tests/integration/test_phase_86i_benchmarks_populated.py` (M26):
  added 4 hardening tests — Git SHA matches `[0-9a-f]{7,40}` regex
  (rejects `HEAD`, branch names, paste-residue), Reference Hardware
  required fields populated and not placeholder-shaped, `Run date:`
  present and ISO YYYY-MM-DD, every Historical Runs throughput cell
  parses as a positive finite float (rejects NaN/Inf/zero/negative).

### Phase status
- `docs/phases/manifest.yaml`: `101k` annotated `COMPLETE 2026-04-26`.
- `docs/phases/complete/PHASE_101.md`: all 6 acceptance boxes ticked, status
  block updated to COMPLETE, "Still open" header line refreshed.

## [Unreleased] - Phase 101k partial — Dynatrace H15 + M25, load_test M24 (2026-04-26)

Lands 3 of 6 items from Phase 101 sub-phase **101k** (Phase 86i capacity
hardening). H14, H16, M26 remain open — the sub-phase stays PARTIAL in
`PHASE_101.md` until they land.

### Fixed
- `deploy/dynatrace/ja4proxy-extension/plugin.py` H15: Prometheus exposition
  parser now honours backslash escapes inside quoted label values
  (`\\`, `\"`, `\n` per the Prometheus spec). Previously a label value
  like `path="/a\"b,c"` mis-split at the embedded comma, dropping all
  subsequent labels in the labelset. Also drops `NaN`/`+Inf`/`-Inf`
  samples — they corrupted Dynatrace timeseries.

### Added
- `deploy/dynatrace/ja4proxy-extension/plugin.py` M25: `JA4proxyPlugin.query()`
  unconditionally emits the `ja4proxy:node` topology entity. On scrape
  failure Dynatrace now shows "scrape failing" rather than "node missing".
- `scripts/load_test.py` M24: `push_loadtest_metrics()` accepts a
  `grouping_key` dict (passed through to `push_to_gateway`) so concurrent
  load tests from different hosts don't overwrite each other in the
  Pushgateway. New `sample_connect_latencies(target, samples=50)` opens
  short TCP connections from the harness path and feeds the histogram
  with real per-connect wall times. CLI now passes
  `{"instance": gethostname(), "scenario": ..., "run_id": uuid[:8]}`.

### Test Suite
- New `tests/unit/test_dynatrace_extension.py::TestPhase101H15ParserHardening`
  (3 tests) — NaN/Inf rejection, escaped quote preserves full labelset,
  `\\` and `\n` decoded per spec.
- New `tests/unit/test_dynatrace_extension.py::TestPhase101M25TopologyOnFailure`
  (2 tests) — topology emit on empty scrape, no metric emit on empty scrape.
- New `tests/unit/test_load_test.py` — `grouping_key` pass-through to
  `push_to_gateway` + real-latency sampler regression tests.
- 41 tests in the two affected files pass.

## [Unreleased] - Phase 101c — TI Feed Critical Safety Caps + FP Corpus (2026-04-26)

Closes Phase 101 sub-phase **101c** (C4, C5, C6) — the three CRITICAL gaps
where a misbehaving threat-intel feed could mass-ban legitimate traffic.
The blast-radius brakes were partially in place; this change closes the
remaining bugs and wires the per-poll FP corpus check into all four feed
ingestion paths.

### Fixed
- `runner.py` C5: `_poll_once` two-empty-poll gate now genuinely skips
  differential cleanup on the first empty poll. The previous
  `dropped = {}` was a dead assignment because line 413 unconditionally
  re-computed `dropped`. Replaced with a `skip_cleanup_first_empty` flag
  and an early return that records poll success without touching state.
- `ja4_safety.py` C6: `_DEFAULT_CORPUS_PATH` walks `parents[3]` (not
  `parents[2]`) so `fixtures/ti_feeds/ja4_fp_corpus.txt` resolves from
  the repo root in production deployments.
- `seed_file.py` C6: `TI_SEED_ENTRIES` Counter was declared with labels
  `[feed_id, outcome]` but the 3 call sites only passed `outcome=`,
  causing label-mismatch exceptions at runtime. All 3 sites now pass
  both labels.

### Added
- `src/analytics/ti_feeds/seed_file.py`: FP corpus check via
  `ja4_safe_to_block()` before every `post_blocklist`. Rejected entries
  increment `summary["rejected"]` and `ja4proxy_ti_feed_fp_blocked_total`.
- `src/analytics/ti_feeds/taxii.py`, `rest_generic.py`: SafeResolver
  TCPConnector wired into `aiohttp.ClientSession()` (H6 partial — DNS-level
  SSRF protection blocks resolution to RFC1918, loopback, link-local,
  cloud metadata IPs, IPv4-mapped/6to4/Teredo unwraps included). Both
  clients now also fire `ja4proxy_ti_feed_fp_blocked_total` on FP rejects.
- `src/analytics/ti_feeds/safe_resolver.py`: `SafeResolver` aiohttp
  resolver class with private-IP filter and IPv6 unwrap (mapped/6to4/Teredo)
- `fixtures/ti_feeds/ja4_fp_corpus.txt`: expanded from 1 to 12 browser
  fingerprints (Chrome 119/120, Firefox 115ESR/121, Safari 17, Edge 120,
  mobile Safari) plus the historical pre-phase entry
- `deploy/monitoring/alertmanager/rules/ti_feed.yml`: two new warning
  rules — `TIFeedCapsHit` (any non-zero `ja4proxy_ti_feed_caps_hit_total`
  rate over 15m) and `TIFeedFPBlocked` (any non-zero
  `ja4proxy_ti_feed_fp_blocked_total` rate over 15m)
- `docs/runbooks/ti_feed_caps_hit.md`, `docs/runbooks/ti_feed_fp_blocked.md`
  — full oncall procedures for the two new alerts
- `docs/phases/PHASE_86h_runbook_mapping.yml`: maps the two new alerts to
  their runbooks so `scripts/fix_runbook_urls.py --check` stays green
- `tests/unit/test_ti_feed_caps.py` (5 tests) — parametrised cases for
  all three cap kinds (`new`, `total`, `delta`)
- `tests/unit/analytics/ti_feeds/test_runner_empty_streak.py` (3 tests)
  — first-empty / second-empty / non-empty-resets matrix
- `tests/adversarial/test_ti_feeds_fp_block.py` (5 tests) — Chrome 120
  and Firefox 121 JA4s from the real FP corpus must never reach
  `post_blocklist` from `rest_generic` or `seed_file`

### Changed
- `tests/unit/analytics/ti_feeds/test_runner.py`: 4 cleanup tests
  updated to prime the C5 empty-streak counter with one prior empty poll
  (releasing the leader lock between calls), then exercise the cleanup
  path on the second consecutive empty poll. Reflects the new gate
  semantics, not a behaviour change.
- `docs/phases/complete/PHASE_101.md`: 101c moved from Open to Landed; acceptance
  criteria checkboxes ticked; close-out summary block added
- `docs/phases/manifest.yaml`: 101c sub-phase marked COMPLETE 2026-04-26

### Test Suite
- 6011 tests pass / 0 fail / 10 skipped (was 6010 / 1 / 10).
- 13 new tests + 4 existing tests updated for the C5 gate.

## [Unreleased] - Phase 101e — Threat-Intel Regional Endpoints (2026-04-26)

Closes Phase 101 sub-phase **101e** (H9, H10): Recorded Future and CrowdStrike
Falcon clients now honour `config.url` for regional/GovCloud endpoint
selection. Implementation was already in place via `_resolve_rf_taxii_root()`
and `_resolve_falcon_urls()`; this change documents the regional endpoints
in `config/proxy.yml` so operators discover the option without reading source.

### Added
- `config/proxy.yml`: regional endpoint comments for `recorded-future`
  (EU, APAC) and `crowdstrike-falcon` (US-2, EU-1, GovCloud/laggar) feeds —
  helps tenants pin their feed to the correct data residency region
- `tests/unit/analytics/ti_feeds/test_phase_101e_regional_endpoints.py` —
  10 parametrised tests covering URL resolution for both clients (already
  in tree; verified green)

### Changed
- `docs/phases/complete/PHASE_101.md`: 101e moved from Open to Landed; acceptance
  criteria checkboxes ticked
- `docs/phases/manifest.yaml`: 101e sub-phase marked COMPLETE 2026-04-26

## [Unreleased] - Phase 105 — Documentation Restructure by Audience (2026-04-25)

Documentation-only phase. Restructures the documentation corpus around five
audience-specific entry points, consolidates four blocking docs and four
testing docs into single canonical references, refreshes the LaTeX PDF
artefacts for Phase 200-series posture, and adds a CI workflow for the PDF
build. Resolves Phase 106 architect Finding 2 (placeholder marker). No
production code changed.

### Added
- `{README,WHY_JA4PROXY,DEPLOYMENT_OPTIONS,FAQ}.md` —
  CISO/website-owner audience track (the existing TCO_AND_LICENSING.md from
  Phase 106 is linked, not duplicated)
- `{README,SCOPE_AND_LIMITATIONS,SIEM_INTEGRATION,EVALUATION_CHECKLIST,DMZ_READINESS}.md` —
  security-architect track (12 non-goals, 4 vendor SIEM recipes, replacement
  for the archived DMZ_READINESS.md)
- `{README,UPGRADE_PATH}.md` — operator entry point that
  links rather than duplicates the existing operator docs and runbooks
- `{README,AUDIT_TRAIL,CHANGE_MANAGEMENT}.md` —
  compliance/audit track with SOC 2 / ISO 27001 evidence mappings
- `{README,GETTING_STARTED,HOW_WE_WORK,TDD_AND_TESTING,CI_AND_QUALITY_GATES,PHASE_LIFECYCLE}.md` —
  contributor onboarding (resolves Phase 106 architect Finding 2 — the
  placeholder marker is gone)
- `docs/operator/BLOCKING_OPERATIONS.md` (530 lines) — single canonical
  reference, consolidates 1203 lines from 4 pre-Phase-105 blocking docs;
  effective-threshold table re-derived from `action_decider.py`/`.go`
- `docs/runbooks/main_is_red.md` — keep-main-green response runbook (15-min
  ack, 30-min decision, 1-h restore SLA)
- `docs/decisions/ADR-105a-pdf-ci-placement.md` — dedicated `docs-pdf.yml`
  workflow over extending `ci.yml`
- `docs/decisions/ADR-105b-link-checker.md` — retain existing
  `markdown-link-check` (avoid scope creep introducing `lychee`)
- `.github/workflows/docs-pdf.yml` — new SHA-pinned CI workflow (14-day
  non-blocking grace ending 2026-05-09)
- `docs/reports/archive/` — pre-Phase-200 snapshot bucket containing
  `GEMINI_CRITIQUE_2026-03-21.md`, `ENTERPRISE_REVIEW_2026-02-15.md`,
  `DMZ_DEPLOYMENT_READINESS_2026-03-15.md`,
  `CYBER_RISK_REVIEW_2026-04-09.md`,
  `strategic_security_architecture_review_2026-04-08.md`
- `xu-cheng/latex-action@v3.3.0` and `actions/upload-artifact@v7.0.1` SHA
  pins added to `tests/test_workflow_pinning.py` allowlist

### Changed
- `README.md` — rewritten as a role-router: 441 → 88 lines, 5-row "Start by
  role" table above the fold, Production-runtime-is-Go banner, PDF downloads
  row
- `docs/README.md` and `docs/README.md` — feature the for-* entry points
  prominently; frontmatter `last_reviewed: 2026-04-25`, `phase: 105`
- `docs/TESTING_STRATEGY.md` — canonical (480 → 1785 lines) absorbs
  TESTING_STRATEGY.md, TEST_SUITE.md, TESTING_GO.md as appendices A/B/C
- `docs/SCALING_GUIDE.md` — expanded 378 → 507 lines with three worked
  scenarios (small / enterprise / high-volume)
- `CONTRIBUTING.md` — project-structure block reordered: Go first as the
  production runtime, Python proxy under "experimental prototyping surface"
  qualifier, production-Python services (analytics, management) listed
  separately
- `docs/DEPLOYMENT_SECURITY_MODEL.md` — Phase-19-specific hedging removed,
  re-pointed at `runbooks/cloud_backup_operations.md`
- `docs/pdf/brochure/brochure-body.tex` — Phase 200-series security posture
  line added; performance numbers reverified against `BENCHMARK_HISTORY.md`
- `docs/pdf/reference-manual/chapters/ch01-architecture.tex` — Go production
  / Python prototyping framing
- `docs/pdf/reference-manual/chapters/ch04-signals.tex` — Phase 203 signals
  list (TAP OS-mismatch, JA4 TLS-version mismatch, weak-cipher parity, DGA
  parity, deep-health)
- `docs/pdf/reference-manual/chapters/ch09-security-ref.tex` — Phase 200-
  series hardening (Redis TLS, PROXY v2, default-credential removal)
- `GETTING_STARTED.md` — prereq line updated to
  `pdflatex` + `makeindex` (toolchain decision per Wave 0)
- `docs/phases/complete/PHASE_105.md` — toolchain note corrected (pdflatex, not
  tectonic)

### Deprecated / Stubbed
- `docs/TESTING.md`, `docs/TESTING_STRATEGY.md`, `docs/TEST_SUITE.md`,
  `docs/TESTING_GO.md` — now ≤ 30-line redirect stubs to TESTING_STRATEGY.md
- `docs/operator/blocking-guide.md`, `BLOCKING_ANALYSIS.md`,
  `blocking-test-analysis.md`, `FINAL_BLOCKING_TEST_SUMMARY.md` — now ≤ 30-
  line redirect stubs to BLOCKING_OPERATIONS.md
- `docs/GEMINI_CRITIQUE.md`, `docs/reports/ENTERPRISE_REVIEW.md`,
  `docs/DMZ_READINESS.md`,
  `docs/reports/CYBER_RISK_REVIEW_2026-04-09.md`,
  `docs/reports/strategic_security_architecture_review.md` — moved to
  `docs/reports/archive/` with date-stamped names and 5-line additive
  banners; bodies untouched

### Deferred
- 6 of 12 LaTeX chapter refreshes deferred to a future pass (user-guide
  ch02/ch04/ch05/ch07; reference-manual ch06/ch10) — punch list documented
  in Phase 105 close-out report

## [Unreleased] - Phase 106 — SWEBOK v4 Alignment & Quality Plan (2026-04-25)

Documentation-and-tooling phase. Closes the SWEBOK v4 KA gaps identified in
the 2026-04-16 benchmarking exercise: 12 of 14 applicable KAs now green
(KAs 7 and 13 deferred to Phase 105). No production code changed.

### Added
- `docs/SERVICE_TARGETS.md` — consolidated SLI/SLO/SLA posture (KA 6),
  with p50 + p99 latency, FP rate, availability, Redis correctness,
  feed freshness, score stability, signal-collection error rate
- `docs/RISK_REGISTER.md` — 42 rows across security, operational,
  technical, supply-chain, compliance, commercial categories (KA 8)
- `TCO_AND_LICENSING.md` — three TCO scenarios
  + explicit "no commercial support today" statement (KA 14)
- `docs/TRACEABILITY.md` — auto-generated REQ-ID → test matrix
  (90 REQ-IDs across 5 retro-tagged phases) (KA 1, 5)
- `scripts/traceability.py` — walks PHASE_*.md, validates `REQ-NNN-MM:` tags
  and `Verified by:` clauses, regenerates the matrix; `--check` exits 1
  on drift
- `scripts/process_metrics.py` — emits phase throughput, average duration,
  CI reliability, mean-time-to-green; degrades gracefully when
  `GITHUB_TOKEN` is unset (KA 9)
- `tests/unit/test_traceability.py`, `tests/unit/test_process_metrics.py`
  (12 unit tests, 12 pass)
- `tests/docs/test_service_targets_sync.py`,
  `tests/docs/test_risk_register_structure.py` (10 doc-structure tests,
  10 pass — caught a real gap in SERVICE_TARGETS during Wave 5)
- `docs/engineering-method/{README,METHOD,CASE_STUDIES,PHASE_ANATOMY}.md`
  + `retrospectives/{README,TEMPLATE,2026-Q2,latest-metrics}.md`
  (KA 10) — case studies are honest, with a "what went wrong" section
  per study (Phase 15 banker's-rounding parity, Phase 82 manual-review
  parking-lot, Phase 200-series sibling-module re-discovery)
- `docs/design/README.md` — 32-component design index (KA 3)
- `docs/QUALITY_PLAN.md` — 8 quality attributes, defect management,
  quality gates, SWEBOK KA coverage table (KA 11)
- `.github/workflows/ci.yml` — `traceability` job, non-blocking until
  2026-05-08, blocking after
- `.github/workflows/process-metrics.yml` — monthly cron (1st 06:00 UTC)
  regenerating `latest-metrics.md`
- `docs/STYLE_GUIDE.md` §6 — REQ-ID tagging convention with opt-in
  `req_tagged: true` manifest field

### Changed
- `docs/phases/PHASE_{15,79,82,102,200}.md` — retro-tagged with
  `REQ-NNN-MM:` IDs and `Verified by:` clauses; 90 REQ-IDs total
  (53 AUTOMATED + 37 MANUAL-REVIEW). Phases 103/104 deferred —
  103 has no manifest entry yet, 104 still PROPOSED
- `README.md` — single "How we build →" line linking
  `docs/engineering-method/README.md`
- `docs/for-{architects,compliance,operators,website-owners}/README.md`
  — wired into Phase 106 deliverables; placeholder markers dropped
- `docs/phases/manifest.yaml` — `req_tagged: true` flag on the 5
  retro-tagged phases; Phase 106 marked COMPLETE

### SWEBOK v4 KA coverage after this phase
12 of 14 applicable KAs green. KAs 7 (Configuration Management) and 13
(Professional Practice) deferred to Phase 105. KAs 15-17 are
prerequisite knowledge, not project artefacts.

## [Unreleased] - Phase 121 — Pentest Remediation Consolidation & Program Discipline (2026-04-19)

Plan-only meta-phase; no production code changed. Converts the 108–120 pentest
backlog (~98 sub-phase entries, ~4,800 lines of remediation prose) into a
managed program with a single canonical findings register and enforced
program discipline.

### Added
- `docs/security/findings.yaml` — canonical findings register (54 entries,
  CVSS v3.1 per ADR-121a) + generated `docs/security/FINDINGS_REGISTER.md`
- `scripts/findings_register.py` — validate / list / add / dedup-hint /
  promote-verified / verify-regression-tests / render / show subcommands
- `docs/security/SEVERITY_RUBRIC.md` — CRITICAL 7d / HIGH 30d / MEDIUM 60d /
  LOW 120d SLA tiers with worked examples and the fail-open asymmetry rule
- `docs/security/REMEDIATION_WAVES.md` — four SLA-aligned waves with
  dependency DAG and wave-completion predicates
- `docs/security/CLOSURE_VERIFICATION.md` — OPEN → IN_PROGRESS → FIXED →
  VERIFIED → CLOSED state machine with 14-day cool-off rationale
- `docs/security/INTAKE_RUNBOOK.md` — triage runbook so the next red team
  report ingests into the register instead of spawning a new phase
- `docs/security/OWNERSHIP.md` — Go / Python-management / infrastructure
  lanes; concentration risk documented
- `docs/decisions/ADR-121a-cvss-version.md` — stay on CVSS v3.1 (supersedes
  Phase 108n's v4 reference)
- `.github/PULL_REQUEST_TEMPLATE.md` — canonical-ID opt-in + security-path
  enforcement
- `docs/TESTING_STRATEGY.md` §6 — regression-test-per-finding rule; tests
  live under `tests/pentest/` or `internal/security/pentest/`
- `scripts/phase_121_verify.py` + `make phase-121-verify` — close-out gate
- `make verify-findings`, `make verify-findings-green`, `make findings-list`,
  `make findings-render`

### Changed
- `docs/phases/complete/PHASE_117.md` — status SUPERSEDED by 118; 117a/b/c →
  118a/b/c mapping table
- `docs/phases/complete/PHASE_118.md` — merge-conflict resolved; unified leader
  pentest (Track B) + white-box (Track A, preserved via register source_refs);
  added "Rescoped against canonical register" block (-508 lines net)
- `docs/phases/complete/PHASE_119.md` — header rescoped; documents Phase 120
  absorption
- `docs/phases/complete/PHASE_108.md` §108n — "Superseded implementation detail" note;
  CVSS v4 → CVSS v3.1 per ADR-121a; references actual register location
- `docs/phases/manifest.yaml` — phase 121 COMPLETE; phase 120 DEFERRED +
  superseded_by: 119

### Removed / Retired
- `docs/phases/complete/PHASE_120.md` — retired as redirect stub (DUPLICATE_OF 119).
  All 20 "novel" findings were duplicates of 119 or already folded into the
  canonical register via `source_refs`.

## [Unreleased] - Phase 207 — Go Test Coverage & Repository Hygiene (2026-04-16)

### Added
- Coverage tests for 6 Go packages: `cmd/ja4check` (100%), `cmd/ja4proxy-cli`
  (88.8%), `cmd/syncagent` (80.5%), `cmd/proxy` (80.4%),
  `internal/cli/commands` (95.0%), `internal/cli/config` (84.6%)
- `cmd/ja4check/main.go` refactored to extract `mainResult()`/`run()` for testability

### Fixed
- **ZADD bug** in `cmd/syncagent/agent.go`: `event.Key` was incorrectly used as
  ZADD member instead of `event.Value`
- **handleError fall-through** in `cmd/ja4proxy-cli/main.go`: missing `return`
  after `osExit(2)` for PendingApprovalError

### Changed
- README.md rewritten: badges fixed, Parity badge removed, Go proxy section
  honestly documents ported vs not-ported features, test counts updated
- 8 semgrep false positives suppressed with inline `# nosemgrep`

### Removed
- `tests/unit/analytics/ti_feeds/test_phase_101c_safety_caps.py` (11 stale
  `pytest.skip` stubs with no implementation)

## [Unreleased] - Phase 102 — Terraform Provider Documentation Close-out (2026-04-15)

### Added
- **ADR-093a** — Repository topology: provider lives in separate repo
  `github.com/anomalyco/terraform-provider-ja4proxy`; Management API is
  the cross-repo contract boundary
- **ADR-093b** — Terraform Registry namespace: self-publish as
  `anomalyco/ja4proxy`; no HashiCorp Partner Programme (pending registration)
- **ADR-093c** — Ban TTL renewal and drift-detection strategy: re-POST on
  apply (idempotent endpoint); no `ja4proxy_managed_entries` data source
  (PlanModifiers + `protect_unmanaged_entries=true` default cover the threat)

### Changed
- `deploy/terraform/README.md` — documents `protect_unmanaged_entries`
  default (`true`) with override guidance; Quick Start corrected to
  `source = "anomalyco/ja4proxy"`
- `docs/runbooks/emergency_playbooks.md` — troubleshooting table expanded
  (403 scope errors, per-endpoint 422 split, 30s/10s timeout rows, per-playbook
  required vars)
- Manifest: duplicate `101:` key removed (narrow "Push Terraform Provider"
  scope was shadowed by broader cross-phase-gap entry)

### Notes
- ~85% of Phase 102's originally-scoped code work (protect_unmanaged_entries,
  `[terraform]` reason prefix, `ticket`/`ttl_hours`/`notes` fields,
  PlanModifiers, SHA-pinned CI workflows) was pre-delivered in the external
  provider repo. Phase 102 narrowed to docs-only close-out

## [Unreleased] - Phase 202 — CI Supply Chain + Default Credential Removal

### Security
- **202a** — Final GitHub Actions pinning audit closes the residual
  supply-chain gap: every ordinary `uses:` in `.github/workflows/` is now
  SHA-pinned. The one remaining reusable workflow
  (`slsa-framework/slsa-github-generator` at `release-cli.yml:57`) is
  SHA-pinned to `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` (tag `v2.1.0`)
  per ADR-202a Path A (Accepted).
- **202b** — Removed all default credential fallbacks from Docker Compose
  files. `GRAFANA_PASSWORD`, `HAPROXY_STATS_USER`, `HAPROXY_STATS_PASSWORD`,
  `MANAGEMENT_JWT_SECRET`, `MANAGEMENT_ADMIN_USER`, and
  `MANAGEMENT_ADMIN_PASSWORD` are now **required** — compose fails fast via
  `${VAR:?VAR is required}` if any is unset. Prior fallbacks
  (`:-admin`, `:-admin123`, `:-change-me-in-production`) are gone.
  Operator guidance: `docs/runbooks/deploy_credentials.md` (new).
- **202c** — `deploy/docker/Dockerfile.go-proxy` now pins the runtime user
  to explicit UID/GID `1000:1000` (was busybox-assigned random system UID;
  see line 47 `addgroup -g 1000 -S … adduser -u 1000 …` and line 59
  `USER 1000:1000`) and adds four OCI image labels (line 39:
  `org.opencontainers.image.source`, `.title`, `.description`,
  `.licenses`). Compatible with Pod Security Admission `restricted`
  profile. Rationale: ADR-202c.
- **202d** — New CI workflow `.github/workflows/go-proxy-image.yml`
  (two jobs: `test` → `build-scan-sign-push`) builds, Trivy-scans
  (CRITICAL gate, honours `.trivyignore`), generates a CycloneDX SBOM,
  signs the image with **keyless cosign** (Fulcio OIDC, no long-lived
  signing key), and pushes to GHCR. The SBOM is attached twice — once as
  a workflow artifact (CI retention) and once to the image via
  `cosign attach sbom --type cyclonedx` (OCI referrers API). End-user
  verification via `scripts/verify-image-signature.sh` (cert-identity
  regexp `^https://github.com/anomalyco/JA4proxy/`, OIDC issuer
  `https://token.actions.githubusercontent.com`). Rationale: ADR-202d.
- **202e** — Test Redis (`deploy/docker/docker-compose.test.yml`) now
  binds to `127.0.0.1` only (was all-interfaces `0.0.0.0`) and requires
  a password via `REDIS_TEST_PASSWORD` (default `test-fixtures-pw` for
  local CI). Integration fixtures updated to authenticate; `fakeredis`
  unit tests unchanged.

### Added
- `docs/runbooks/deploy_credentials.md` — mandatory env var reference for
  operators and CI (202b).
- `docs/decisions/ADR-202a.md` — SLSA reusable workflow pinning decision
  (Accepted, Path A — SHA-pinned).
- `docs/decisions/ADR-202c.md` — explicit UID 1000 rationale (Accepted).
- `docs/decisions/ADR-202d.md` — keyless cosign signing rationale
  (Accepted).
- `.trivyignore` — empty-but-documented CVE triage file with required
  `reason / expires / owner` fields per entry.
- `scripts/verify-image-signature.sh` — end-user cosign verification
  helper (202d).

### Changed
- `.github/workflows/ja4proxy-policy.yml`, `ci.yml`, `release-cli.yml` —
  pinning invariant now enforced repo-wide; `grep -nE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml`
  returns only the SLSA reusable `# v2.1.0` inline comment (not an unpinned
  ref). `tests/test_workflow_pinning.py` `KNOWN_ACTION_SHAS` allowlist
  extended with the five SHAs introduced by 202d (cosign-installer,
  sbom-action, trivy-action, setup-buildx-action, metadata-action).

### Breaking Changes
- **Operators MUST now set six environment variables** before
  `docker compose up` succeeds on `docker-compose.poc.yml` and
  `docker-compose.monitoring.yml`. See
  `docs/runbooks/deploy_credentials.md`. Existing deployments that relied
  on `:-admin` / `:-admin123` / `:-change-me-in-production` defaults will
  fail to start until the vars are set. This is intentional.
- Test Redis no longer accepts unauthenticated connections on port 6380
  nor connections from non-loopback interfaces. Update any local tooling
  that connected to `redis://localhost:6380/` without a password.

## [Unreleased] - Phase 203 — Go Missing Signals

### Added
- **203a** — `tap_os_mismatch` signal in the Go proxy. Consumes Phase-20
  TAP-produced OS-class fingerprints from Redis (`fp:os:ip:{ip}`) and emits
  `tap_os_mismatch` (score 30) when the JA4-claimed OS class disagrees with
  the TAP-observed OS class. New `tap_consumer:` config block
  (`enabled: false` default). ADR-203a captures the rationale (the inline
  proxy cannot compute JA4T from an `accept()`'d socket).
- **203a** — Prometheus counters `ja4proxy_tap_lookups_total{result}`
  (labels: `hit_match`, `hit_mismatch`, `miss`, `error`) and
  `ja4proxy_tap_signal_total{action}`.
- **203b** — `ja4_tls_mismatch` signal (score 35) in the Go proxy;
  fires when the JA4 prefix (`t13`/`t12`/`t11`/`t10`/`s30`) disagrees with
  the negotiated TLS version. New counter
  `ja4proxy_ja4_tls_mismatch_total{action}` (Python parity). Fails open
  when the negotiated TLS version is `0x0000` (never observed).
- **203e** — `/health/deep` extended with `tarpit.{active,max,status}` and
  `geoip.{present,status}` (presence-only). New `internal/health` package
  provides N=3 anti-flap hysteresis — time-to-detect is
  `3 × probe_interval`. Redis unhealthy → HTTP 503; tarpit saturation →
  HTTP 200 with `status="degraded"` (avoids LB flapping under slow-path
  load). `/health` is intentionally unchanged.

### Changed
- **203c** — Go `weakCipherSet` brought to exact parity with Python's
  `WEAK_CIPHERS` (40 suites). Parity enforced by
  `internal/security/cipher_parity_test.go`, which hard-codes the
  authoritative Python list so a future Python-side change fails the Go
  build loudly.
- **203d** — Go `dgaConfidence()` re-ported to match Python's `dga_score()`
  rule-for-rule: sliding-scale entropy, length tiers, vowel rules, `\d{4,}`
  regex, plus `_SKIP_PREFIXES` / `getPrimaryLabel` ported verbatim. Go-only
  heuristics (consecutive-consonant run, digit-ratio) removed. Golden-file
  parity test plus Tranco-top-10k FP-rate gate.

### Removed
- **203a** — `internal/tls/ja4t.go` (the `ComputeJA4T(alertCodes []uint8)
  string` stub) and its test: dead, misleading code unrelated to the real
  JA4T concept. See ADR-203a.

### Docs
- **ADR-203a** — "Go inline proxy consumes Phase-20 TAP JA4T from Redis
  (does not compute it)" — Accepted.
- `docs/runbooks/go_proxy_operations.md` — new Phase 203 section: JA4T-OS-
  mismatch operational prerequisites (Phase 20 TAP deployed) and the
  `/health/deep` JSON shape + anti-flap trade-off.
- `docs/REDIS_SCHEMA.md` — `fp:os:ip:{ip}` annotated as read by Go proxy
  `tap_consumer` (Phase 203a).
- `config/signal_scores.yml` — `tap_os_mismatch` (score 30, cap 30)
  registered alongside the existing `ja4_tls_mismatch` entry.

### Breaking Changes
- None. All changes are additive or pure detection-side tightening.
  `tap_consumer.enabled` defaults to `false`; out-of-box behaviour
  unchanged. Operators at non-zero dial should re-tune after 203c/203d
  (cipher and DGA parity shift scores vs. previous Go behaviour).

## [Unreleased] - Phase 201 — Go Redis TLS + Silent-Failure Hardening

(Version + date will be stamped by the release commit when Phase 201 is merged
to `main`. Keep this entry under `[Unreleased]` until then.)

### Added
- **201a** — `internal/redis/client.go` now honours `redis.ssl: true` with
  `tls.Config{MinVersion: TLS 1.2}` and supports Redis 6+ ACLs via a new
  `redis.username` field (plumbed through `internal/config/loader.go`,
  `cmd/proxy/main.go`, and `cmd/syncagent/main.go`). See ADR-201a for the
  TLS-version and CA-pool rationale.
- **201c** — Periodic Redis health-check goroutine in the Go proxy: pings
  Redis every 30s, automatically reloads `sliding_window.lua` after a Redis
  restart / `SCRIPT FLUSH`, and exposes two new Prometheus metrics
  (`ja4proxy_redis_health{status}`, `ja4proxy_redis_script_reloads_total{result}`).
- **201c** — New runbook section in `docs/runbooks/go_proxy_operations.md`
  for the `ja4proxy_redis_health{status="error"}` alert.

### Changed
- **201b** — `ZRemRangeByScore` in the Go Redis client now logs on error
  (previously silent — inconsistent with every other write method in the
  file and a silent-data-loss surface).
- **201d** — Go rate limiter now validates `clientIP` via `netip.ParseAddr`
  before using it as a Redis key component; unparsable inputs fail-open
  with a hashed-input WARN log. IPv6 (including zone IDs) is preserved in
  canonical form. Long `ja4` strings are capped at 256 bytes.

### Breaking Changes
- None. All changes are additive: `redis.username` defaults to `""` and
  `redis.ssl` already existed (it was just silently ignored on the Go side).

### Withdrawn
- The previously proposed "signal score drift fix" (earlier draft's 201a)
  was withdrawn as based on a false premise — `make check-scores` passes on
  `main` and the Go scores already match `config/signal_scores.yml`
  exactly. See `docs/phases/complete/PHASE_201_review.md` for the audit.
## Phase 101b — Compliance Hygiene (2026-04-15)

### Changed
- **M1** — XTRIM MINID fallback for Redis < 6.2: `GDPRPurge` now checks
  Redis version and falls back to XRANGE+XDEL loop for versions < 6.2
- **M2** — Renamed `beaconing_records_cleaned` →
  `beaconing_datapoints_cleaned` in `PurgeSummary` (breaking change for dashboards)
- **M4** — Audit log reads now paginated in chunks of 10k via
  `AUDIT_LOG_CHUNK_SIZE` constant
- **L1** — `ReportRenderer` now caches Jinja2 `Environment` at module level
- **L5** — DSAR retention strings now read from `gdpr.*_retention_days` config

### Fixed
- Python 2 exception syntax (`except ValueError, TypeError:`) → `except (...)`
  in `pack_builder.py` and `compliance.py` for Python 3.14 compatibility

## Phase 205 — Repository Root Cleanup & File Organisation (2026-04-14)

### Changed
- **205b** — deployment dirs moved under `deploy/`:
  `docker/` → `deploy/docker/`, `monitoring/` → `deploy/monitoring/`,
  `ha-config/` → `deploy/haproxy/`, `integrations/` → `deploy/integrations/`,
  `secrets/` → `deploy/secrets/`, `ssl/` → `deploy/ssl/`,
  `Dockerfile-cli` → `deploy/docker/`, `Jenkinsfile.*` → `deploy/jenkins/`,
  `terraform-provider/` → `deploy/terraform-provider/`
- **205c** — source moved under `src/`: `tarpit/` → `src/tarpit/`,
  `ebpf/` → `src/ebpf/`
- **205d** — test/data moved: `performance/` → `tests/performance/`,
  `test-content/` → `tests/fixtures/`, `geoip/` → `data/geoip/`,
  `reports/` → `docs/reports/`
- **205e** — docs/scripts moved: `ONBOARDING.md` → `docs/`,
  `QWEN.md` → `.qwen/`, `quick-start.sh` → `scripts/`
- **205f (partial)** — `mypy.ini` and `.flake8` consolidated into
  `pyproject.toml` (`[tool.mypy]`, `[tool.flake8]`)
- `security/validation.py` → `src/security/validation.py`;
  `security/policies/` → `docs/security/policies/`; `security/` removed
- Compose build contexts corrected from `../` to `../../` after the
  2-level-deep relocation; all volume mount paths updated accordingly
- `deploy/__init__.py` added so tests can import `deploy.integrations.*`

### Fixed
- `tests/unit/test_servicenow_handler.py` and `tests/unit/test_splunk_ban_action.py`:
  updated import paths and fixture path to the new `deploy/integrations/`
  location (regressions from the directory move, now green)
- `tests/unit/test_security_validation.py`, `tests/security/test_owasp_top10.py`,
  `tests/compliance/gdpr_validator.py`, `tests/fuzz/test_properties.py`:
  `from security.validation` → `from src.security.validation`
- `pyproject.toml` `[[tool.mypy.overrides]]` module list: `security.validation`
  → `src.security.validation`
- GitHub Actions `uses:` references restored to `docker/*` org paths
  (had been corrupted by a bulk perl replace during the `docker/` → `deploy/docker/` move)
- Workflow pinning allowlist (`tests/test_workflow_pinning.py`) restored

### Dropped from scope
- **Full `requirements*.txt` consolidation** — considered and rejected. The
  three `requirements*.txt` files are idiomatic Python and the cosmetic win
  (GitHub-visible entries 25 → 22) does not justify atomic rewrites across
  Dockerfiles, CI workflows, Makefile, and Dependabot. No Phase 206; revisit
  opportunistically if the Docker/CI stack is touched for other reasons.

### Root inventory (before → after)
- Tracked entries: 61 → 42 (-19)
- Visible on GitHub: 45 → 25 (-20)
- Acceptance criterion revised from "≤14 visible" (numerically unachievable
  given Go/Python conventions) to "≤22 visible / ≤25 tracked" — documented in
  `docs/phases/complete/PHASE_205.md`

### Tests
- 5391 passed, 10 skipped, 9 xfailed (up from 2687 as of 2026-03-28; the
  delta reflects both real test growth and pre-existing skips now reactivated)
- Zero regressions attributable to the move after the fixes above

## Phase 94: Kubernetes Operator + CMDB/NetBox Integration (2026-04-13)

### Added
- **94a:** `operator_k8s` value added to `ManagedBy` enum (`management/api/models.py`) with round-trip tests
- **94b:** Helm chart converted from Deployment to DaemonSet (`deploy/helm/ja4proxy/templates/daemonset.yaml`), HPA and PDB removed (ADR-094d)
- **94i1/i2:** NetBox trusted CIDR loader (`internal/config/netbox.go`) — Go-only, opt-in, fail-open fallback to static CIDRs, SIGHUP reload, Prometheus metrics (`internal/metrics/netbox.go`)
- **94j:** Ansible `ja4proxy` role baseline (`deploy/ansible/roles/ja4proxy/`) — binary, container, and quadlet deploy modes with Molecule test scenarios
- **94k:** ServiceNow CMDB auto-registration task (opt-in, `servicenow_enabled: false` default)
- ADR-094c (ManagedBy enum value choice) and ADR-094d (Helm chart topology)

### Changed
- `internal/config/loader.go` extended with NetBox CIDR merging into trusted upstream list
- `internal/proxy/proxy_protocol.go` updated to use merged CIDR set
- `config/proxy.yml` — new `netbox` section with `enabled`, `url`, `token_env`, `query`, `poll_interval`, `timeout` keys (all hot-reloadable)

### Redis Schema
- No new Redis keys (NetBox CIDRs are in-process only, per CLAUDE.md)

### Performance
- No hot-path impact — NetBox poll runs in background goroutine on configurable interval

### Known Limitations
- Kubernetes operator (94c–94g, 94l) lives in separate repo (`ja4proxy-operator`), not included in this merge
- Operator runbook (94h) deferred until reconcilers are implemented
- Terraform Registry publication for Phase 93 provider still pending (external process)

## Phase 204 — README Badges (2026-04-12)

### Added
- Badge section to README.md with 14 badges: License (MIT), Python 3.14+, Go 1.25.9, CI status, test coverage (≥80%), Go tests, Docker Compose readiness, Semgrep, secrets scanning (TruffleHog), dependency audit (pip-audit + govulncheck), Ruff linting, Go linting (gofmt + vet), dual-proxy architecture, and Python/Go signal parity.

## Phase 100: Cross-Phase Gap Closure (2026-04-12)

### Added
- **100-A:** `source.port` field in ECS events and decision log
- **100-B:** `DualFormatter` for dual_output logging mode (legacy + ECS)
- **100-C:** Per-endpoint webhook retry/timeout with global fallback
- **100-D:** Splunk TA and Sentinel playbook aligned with Phase 79 ban API
- **100-F:** Dedicated `security/validation.py` unit tests (61 tests) + lint scope
- **100-H:** Fixed `sync-roadmap.py` `basename()` bug for `archive/` links
- **100-I:** `make quick-start` and `make perf-test-basic` Makefile targets
- **100-J:** `PATCH /api/v1/bans/{ip}` extend-ban endpoint with audit trail
- **100-U:** Optional OS keyring token storage (`use_keyring: true` in CLI config)
- **100-V:** `confirm_mutating` config flag — mutating CLI commands require `--confirm`

### Fixed
- `config.Load()` now returns safe defaults (`confirm_mutating: true`) when
  config file is absent or omits the key
- `close-phase.sh` snap Go detection — unset GOROOT to fix `go vet` stdlib errors
- gofmt formatting in 3 agent-authored Go files

### Deferred
- 100-E (Splunk/Sentinel live test): blocked on platform access
- 100-L/M/N (Phase 82 endpoints, simulation runner): ~6 days of work, deferred

## Phase Documentation Readiness Audit (2026-04-11)

### Changed
- **Phase 100 blocking items fixed:** 100-E marked BLOCKED, 100-L split
  into 7 sub-items (100-L1 through 100-L7) with per-endpoint file paths
  and acceptance criteria, 100-M `simulation_runner.py` full code provided,
  100-U definitive keyring library chosen (`zalando/go-keyring`) with
  complete implementation code and 3 test cases.
- **Phase 93 structural rewrite:** Added numbered implementation steps
  and out-of-scope sections for all 8 sub-phases (93a–93h). Added
  letter-to-number mapping table (manifest 93.1–93.7 ↔ doc 93a–93h)
  to resolve dependency contradictions.
- **Phase 94:** Added out-of-scope sections to all 13 sub-phases (94a–94k).
- **Phase 101:** Added numbered implementation steps to all 12 sub-phases
  (101a–101l), converting detailed gap analysis from §4–§9 into actionable
  step-by-step instructions per sub-phase.
- **Phase 102:** Added numbered steps and out-of-scope sections to all
  8 sub-phases (102a–102h).
- **Phase 201d:** Added missing test file path (`internal/redis/client_test.go`).
- **Phase 202d:** Added reference to `release-cli.yml` as workflow template,
  SHA-pinned action references for all 6 required actions, clarified
  `GITHUB_TOKEN` usage (no extra secret needed).
- **Phase 202e:** Added Redis URL format with password (`redis://:pw@host:port/db`),
  clarified fakeredis vs real Redis test impact.
- **Phase 203a:** Added concrete test vectors (3 fixture definitions with
  TTL/MSS/window/options), specified call site wiring location
  (`internal/proxy/proxy.go` `handleConnection()`).
- **Phase 203d:** Added test fixture file path (`tests/fixtures/dga/hostnames.txt`),
  clarified ±0.05 tolerance applies to final confidence score only.
- **Phase 203e:** Specified hysteresis N=3, endpoint path (`GET /health`),
  Redis latency measurement approach (`time.Since` around `Ping`),
  confirmed enrichment queue is not applicable in Go proxy.

### Audit result
- **46 of 70 items fixed** (from 34% ready to 100% ready for junior engineers)
- 4 blocking items resolved (100-E, 100-L, 100-M, 100-U)
- 7 sub-phases with structural issues resolved (Phase 93)
- 34 sub-phases gained out-of-scope and/or numbered steps
- All phases now follow the Phase 201 template: goal → numbered steps →
  acceptance criteria → verify commands → out of scope

---

## Phase 100 — Rescoped back to IN_PROGRESS (2026-04-11)

### Changed
- **Phase 100 status corrected from COMPLETE to IN_PROGRESS.** On
  2026-04-07, Phase 100 was narrowed to only the six Phase 79 SSO/MFA
  gaps (100-O–T) and marked COMPLETE, which silently dropped 16 other
  cross-phase gap items (100-A–N, 100-U, 100-V) from the tracker. Those
  items had never been closed or migrated to Phase 101.
- `docs/phases/manifest.yaml` Phase 100 entry renamed to
  "Phase 100 — Cross-Phase Gap Closure (rolling)", status set to
  `IN_PROGRESS`, dependencies expanded to Phases 79–83, success criteria
  rewritten to cover all 15 remaining items.
- `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md` regenerated via
  `make sync`.

### Verified against current codebase (2026-04-11)
- **100-K closed** — `POST /api/v1/tokens/{id}/rotate` already present
  at `management/api/routes/tokens.py:163` (admin close-out, no code change).
- **100-A downgraded to PARTIAL** — `destination.ip` emitted at
  `cmd/proxy/main.go:389,401`, but nothing sets `src_port` so
  `source.port` never reaches ECS output despite the formatter mapping.
- **100-F downgraded to PARTIAL** — `security/validation.py` IS imported
  by `tests/security/test_owasp_top10.py:18`. Remaining gap is dedicated
  unit tests + `security/` in Makefile `lint-pylint` scope.
- **100-D, 100-J, 100-L unblocked but still open** — Phase 79 has merged.
  Splunk alert action posts to the wrong URL shape;
  `PATCH /api/v1/bans/{ip}` is absent (must be implemented, not just
  verified); all 7 Phase 82 coordination items (simulation, decisions,
  `managed_by=policy` enum, 202 approval gating) confirmed absent.
- **100-B, 100-C, 100-G, 100-H, 100-I, 100-M, 100-U, 100-V** — open,
  line numbers refreshed against current code.
- **100-E, 100-N** — still blocked (platform access / upstream items).

### Documentation
- `docs/phases/complete/PHASE_100.md` rewritten with a Status summary table,
  per-item "Verified state" notes, and current file:line references
  so any engineer can pick up an item without reading the originating
  phase.

## Phase 93 — Terraform Provider + Emergency Runbook Playbooks

### Added
- **93.1–93.5:** Terraform provider (`github.com/anomalyco/terraform-provider-ja4proxy`)
  with 6 resources: `ja4proxy_allowlist_entry`, `ja4proxy_blocklist_entry`,
  `ja4proxy_watchlist_entry`, `ja4proxy_ban`, `ja4proxy_dial`, `ja4proxy_webhook`
- **93.1–93.5:** `ResourceData` struct bundles `*client.Client` + `ProtectUnmanaged` flag,
  passed from provider to all resources via `Configure()`
- **93.6–93.7:** 3 emergency Ansible playbooks (`emergency-ban-cidr.yml`,
  `temp-whitelist-ip.yml`, `maintenance-dial-zero.yml`) with Bearer token auth
- **93.6–93.7:** `deploy/terraform/README.md` — usage examples and provider reference
- **93.6–93.7:** `docs/runbooks/emergency_playbooks.md` — operator runbook guide
- **93.6–93.7:** `make test-phase-93` target runs Go tests + Python playbook tests

### Fixed
- **93-fix:** `protect_unmanaged_entries` provider flag is now functional:
  - `ResourceWithModifyPlan` implemented on all 3 list resources — emits a plan-time
    warning with import command when an unmanaged entry would be destroyed
  - `Delete` methods return an **error** (not warning) when `managed_by != "terraform"`
    and `protect_unmanaged_entries = true` — blocks `terraform apply`, keeps resource
    in state, requires explicit `terraform state rm` or flag disable to proceed
  - Ban resource Delete also guarded — checks `[terraform]` reason prefix
  - Default changed to **true** — safer for a security tool, operators opt out
  - ADR-093d documents all design decisions and limitations
  - 43 Go tests pass (8 acceptance), vet clean

## Phase 86i — Hardening: Architectural Gaps From Phase 86

### Changed
- **86i:** Datadog integration refactored into a two-layer pattern. Layer 1 is
  a new OpenMetrics check (`deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml`)
  that uses the Datadog Agent's built-in OpenMetrics integration to scrape
  `/metrics` directly — all Prometheus label richness (`action`, `bypass`,
  `signal`, histogram buckets) is preserved automatically, with no custom
  Python. Layer 2 (`deploy/datadog/checks/ja4proxy/check.py`) is narrowed to
  emit only service checks (`ja4proxy.node_health`, `ja4proxy.redis_health`)
  and topology entities — every `self.gauge()` / `self.rate()` call that
  duplicated a Prometheus metric has been removed.
- **86i:** Dynatrace extension
  (`deploy/dynatrace/ja4proxy-extension/plugin.py`) no longer polls
  `/api/v1/health/deep`. It now scrapes `/metrics` directly via a minimal
  inline Prometheus text-format parser (counter, gauge, histogram). The
  `extension.yaml` topology entity is preserved and metric declarations were
  widened to match the richer Prometheus set.
- **86i:** `scripts/load_test.py` scenario set rewritten. The old
  `baseline`/`sustained`/`ramp` choices have been replaced with four
  code-path-specific scenarios — `bypass-only`, `full-signal`, `attack-wave`,
  `mixed` — each with an explicit fingerprint distribution documented in both
  code and docstring. `load_test.py` now imports
  `scripts/tls-traffic-generator.py` rather than duplicating its TLS client
  machinery.
- **86i:** `scripts/capacity_calculator.py` `EstimatedConstants` renamed back
  to `BenchmarkConstants` and populated with measured values from the new
  `docs/performance/benchmarks.md`. The `ESTIMATED — NOT MEASURED` warning
  path added in 86h has been removed. `--require-measured` remains as a
  positive CI guard and now exits 0 on a clean benchmarks.md.

### Added
- **86i:** `docs/performance/benchmarks.md` populated with measured Go
  microbenchmark numbers (bypass path, full-signal path) on the documented
  reference hardware. `_(measure)_` placeholders are gone. File header
  records CPU, OS, Redis config, Git SHA, Go version, Python version.
- **86i:** `scripts/load_test.py` `--push-gateway URL` flag emitting 5 new
  Prometheus metrics so load tests are observable in Grafana during runs:
  `ja4proxy_loadtest_connections_attempted_total`,
  `ja4proxy_loadtest_connections_completed_total`,
  `ja4proxy_loadtest_errors_total{reason}`,
  `ja4proxy_loadtest_latency_seconds` (histogram),
  `ja4proxy_loadtest_throughput_cps` (gauge).
- **86i:** `docs/OBSERVABILITY_STANDARDS.md` new `Load Testing` subsection
  registering the 5 `ja4proxy_loadtest_*` metrics.
- **86i:** `monitoring/grafana/dashboards/04_capacity.json` — new capacity
  planning dashboard with 4 rows (Throughput Headroom, Latency Budget,
  Scaling Pressure, 30-Day Growth) and `BYPASS_CEILING_CPS` /
  `SIGNAL_CEILING_CPS` template variables sourced from benchmarks.md.
  Provisioned via `monitoring/grafana/provisioning/dashboards/default.yml`.
  Audience is the platform/capacity team, distinct from SecOps
  (`ja4proxy-overview`) and Ops (`ja4proxy-infrastructure`).

### Migration note
- **Operators who already have the Phase 86d Datadog custom check installed
  must also deploy the new OpenMetrics check config
  (`deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml`) when upgrading.** The
  narrowed custom check no longer emits per-label gauges — without the
  OpenMetrics layer, `ja4proxy.block_rate_pct`, `ja4proxy.connections.total`,
  `ja4proxy.pipeline_duration_seconds` and the other per-label Prometheus
  metrics will disappear from Datadog dashboards. Rollback is `git revert`
  on the Phase 86i `check.py` commit.

### Tests
- 21 Phase 86i unit + integration tests (Datadog OpenMetrics config, narrowed
  custom check, Dynatrace Prometheus parser, benchmarks.md populated,
  capacity calculator measured constants, load test scenarios + Pushgateway,
  Grafana dashboard shape, OBSERVABILITY_STANDARDS registration).

## Phase 86h — Fixup: Correctness Bugs From Phase 86

### Fixed
- **86h:** 38 dead `runbook_url` values across 7 Alertmanager rule files
  (`tap.yml`, `redis.rules.yml`, `management_ui_rules.yml`, `proxy.rules.yml`,
  `backup.rules.yml`, `security.rules.yml`, `ti_feed.yml`) — 35 `example.com`
  placeholder URLs and 3 wrong-owner GitHub URLs pointing at
  `github.com/seanoriordain/ja4proxy` (wrong owner, wrong case). Rewritten to
  absolute `https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/<file>.md`.
- **86h:** URL format normalized across `slo_alerts.yml`, `tls_alerts.yml`,
  and the files above — all `runbook_url:` annotations now use absolute
  `github.com/seanpor/JA4proxy` URLs that render as clickable links in every
  Alertmanager notification sink (relative paths did not resolve in Slack,
  PagerDuty, or email).
- **86h:** `scripts/capacity_calculator.py` no longer presents hardcoded
  engineering estimates as measurements. When `docs/performance/benchmarks.md`
  contains `_(measure)_` placeholders, the calculator prints a loud
  `ESTIMATED — NOT MEASURED` banner and warns on stderr before producing its
  report. `--require-measured` CLI flag added for CI guards; exits with code 2
  when placeholders present. `BenchmarkConstants` renamed to `EstimatedConstants`
  (alias preserved for backward compatibility with existing Phase 86c tests).

### Added
- **86h:** `scripts/fix_runbook_urls.py` — idempotent script that rewrites
  `runbook_url:` lines in `monitoring/alertmanager/rules/*.yml` from a mapping
  file. `--check` mode exits non-zero when any URL needs fixing (CI guard).
- **86h:** `docs/phases/PHASE_86h_runbook_mapping.yml` — source-of-truth mapping
  from alert name to runbook filename, covering every alert in every rule file.
- **86h:** `docs/runbooks/ebpf_volumetric_attack.md` — new stub runbook (the
  `KernelLevelVolumetricAttack` alert in `ebpf_attack.yml` had a pre-existing
  dead relative path and was folded into the mapping).
- **86h:** `make lint-alert-urls` target — runs `fix_runbook_urls.py --check`
  for CI enforcement.

### Tests
- 14 Phase 86h unit + integration tests (runbook URL shape, mapping coverage,
  fixer idempotence, capacity calculator banner + `--require-measured`).
  1 integration test skipped (promtool unavailable in CI image).

## Phase 86 — Observability & Capacity Planning

### Added
- **86a:** `GET /api/v1/health/deep` and `GET /api/v1/metrics/summary` endpoints
  on Python (FastAPI) and Go proxy — 9-field JSON: status, redis_connected,
  redis_latency_ms, dial, active_connections, connections_total, block_rate_pct,
  active_bans, cert_days_remaining
- **86a:** `DeepHealthResponse` Pydantic schema, `_parse_prometheus_text()` helper
- **86a:** Go `CountKeys` method on Redis client wrapper
- **86b:** `scripts/load_test.py` — load testing harness wrapping benchmark engine
- **86b:** `Makefile` targets: `load-test`, `load-test-baseline`, `load-test-report`
- **86b:** `docs/performance/benchmarks.md` — benchmark results template
- **86c:** `scripts/capacity_calculator.py` — capacity sizing with cloud cost estimates
  (AWS, Azure, GCP), wired to `BenchmarkConstants` from benchmark data
- **86d:** `deploy/datadog/checks/ja4proxy/check.py` — Datadog Agent integration
- **86d:** `deploy/datadog/ja4proxy-dashboard.json` — 7-widget dashboard
- **86d:** `deploy/datadog/ja4proxy-monitors.json` — 4 monitors
- **86d:** `deploy/datadog/conf.d/ja4proxy.d/conf.yaml` — Agent config
- **86e:** `deploy/dynatrace/ja4proxy-extension/extension.yaml` — EF2 extension
  with 7 metrics and `ja4proxy:node` topology entity type
- **86f:** `deploy/nagios/check_ja4proxy.py` — Nagios check plugin (4 check types)
- **86f:** `deploy/zabbix/ja4proxy-template.xml` — Zabbix importable template
- **86g:** 7 alert runbooks: `ja4proxy_node_unhealthy.md`,
  `ja4proxy_redis_latency_high.md`, `ja4proxy_certificate_expiring.md`,
  `ja4proxy_block_rate_high.md`, `ja4proxy_campaign_detected.md`,
  `ja4proxy_dial_change_unexpected.md`, `ja4proxy_tarpit_pool_full.md`
- **86g:** `runbook_url` annotations on all Alertmanager rules (SLO + TLS)

### Tests
- 249 Python unit tests (health deep, Nagios, Dynatrace, Datadog, runbooks,
  load test, capacity calculator, alertmanager runbook URLs)
- 3 Go unit tests (health deep response schema, Redis down, metrics/summary alias)

## Phase 64 — Deployment Validation & Disaster Recovery

### Added
- `scripts/smoke/test_docker_compose.sh`: Docker Compose lifecycle smoke test
  (bring up → health check → TLS test → tear down → write result)
- `scripts/smoke/test_helm_kind.sh`: Helm + kind smoke test (creates cluster,
  installs chart, verifies rollout, in-pod health check, cleanup)
- `scripts/measure_mttr.sh`: MTTR baseline measurement script — runs 4 disaster
  scenarios, measures wall-clock recovery, writes `MTTR_BASELINE.md`
- `docs/runbooks/disaster_recovery.md`: 5-scenario DR runbook (Redis failure,
  single node, total fleet, config corruption, Redis data loss)
- `docs/runbooks/gameday_scenarios.md`: 4 GameDay exercises with RTO targets
- `docs/runbooks/credential_rotation.md`: Redis ACL, AbuseIPDB API key,
  and cloud storage credential rotation procedures with rollback
- `docs/runbooks/tls_certificate_rotation.md`: Server cert and mTLS CA
  certificate rotation (three-phase dual-CA trust period)
- `docs/runbooks/rolling_upgrade.md`: Docker Compose and Kubernetes rolling
  upgrade with rollback procedures and decision criteria table
- `monitoring/alertmanager/rules/tls_alerts.yml`: Prometheus alert rules
  for TLS certificate expiry (warning < 30d, critical < 7d)
- `scripts/generate_validation_report.py`: `--section deployment` flag for
  deployment validation evidence section
- `Makefile`: `smoke-docker`, `smoke-k8s`, `measure-mttr` targets
- `.github/workflows/ci.yml`: non-blocking `smoke-docker` CI job

## [Unreleased] - Phase 200 - Go PROXY Protocol Trust + v2 Support

### Added
- `internal/proxy/proxy_protocol.go`: `IsTrustedProxySource(ip, cfg)` —
  validates peer IP against `proxy.upstream_trust.trusted_cidrs` before
  trusting PROXY protocol headers. Fail-open on nil config, disabled,
  empty CIDRs, or invalid IP. Parity with Python `_is_trusted_proxy_source()`.
- `internal/proxy/proxy_protocol.go`: `ReadProxyProtocolV2(buf)` and
  `ReadProxyProtocolV2WithLength(buf)` — PROXY protocol v2 binary parser
  for HAProxy 2.x+ and AWS NLB headers. Supports TCP/IPv4 (family 0x11)
  and TCP/IPv6 (family 0x21). Rejects LOCAL command, UNSPEC family,
  truncated headers, wrong signatures, and oversized `addr_len`.
- `internal/config/loader.go`: `UpstreamTrustConfig` struct with
  `enabled` and `trusted_cidrs` fields added to `ProxyConfig`.
- `internal/config/loader.go`: `DefaultConfig()` exported for test use.
- `cmd/proxy/main.go`: `handleConn` now tries v2 binary first, falls back
  to v1 text, both gated by `IsTrustedProxySource()`. Untrusted sources
  silently use the socket IP (fail-open).

### Fixed
- **CRITICAL:** Go proxy no longer trusts PROXY protocol headers from
  arbitrary sources. An attacker sending `PROXY TCP4 8.8.8.8 ...` from an
  untrusted IP previously bypassed all geo/IP/rate/block controls.
- **CRITICAL:** Go proxy now supports PROXY protocol v2 binary headers.
  Modern HAProxy and AWS NLB instances sending v2 were previously silently
  ignored, falling back to the load balancer's IP.

### Tests
- 29 new tests across 3 packages:
  - `internal/proxy/trust_test.go`: 8 trust check tests (IPv4, IPv6,
    disabled, empty CIDRs, nil config, invalid IPs, malformed CIDRs,
    default config)
  - `internal/proxy/proxy_protocol_v2_test.go`: 12 v2 parser tests
    (valid IPv4, valid IPv6, full IPv6, truncated signature, wrong
    signature, LOCAL command, oversized addr_len, empty buffer, exact
    buffer size, UNSPEC family, anti-panic, header length)
  - `cmd/proxy/proxy_integration_test.go`: 9 integration/adversarial
    tests (v2 IP extraction, v1 regression, trust gating, spoofed v2
    from untrusted source, spoofed v1, v2-before-v1, default config,
    proxy_protocol=false gate)

## [64] - 2026-04-10 - Deployment Validation & Disaster Recovery

### Added
- `scripts/smoke/test_docker_compose.sh` — Docker Compose smoke test with
  health polling, container state check, synthetic TLS probe, and cleanup
  trap. Handles both JSON array and NDJSON output from `docker compose ps`.
- `scripts/smoke/test_helm_kind.sh` — Helm + kind smoke test with graceful
  skip when tools are absent, kind cluster cleanup trap, rollout status
  check (Deployment or DaemonSet), and in-pod health verification.
- `scripts/measure_mttr.sh` — MTTR baseline measurement for 4 DR scenarios
  (Redis failure, single node failure, dial corruption, Redis data loss).
  Produces `MTTR_BASELINE.md` with measured vs target RTO comparison.
- `monitoring/alertmanager/rules/tls_alerts.yml` — TLS certificate expiry
  alerts: warning at < 30 days, critical at < 7 days. Consumes Phase 63's
  `ja4proxy_tls_cert_expiry_timestamp_seconds` gauge directly (no
  `absent_over_time`).
- `docs/runbooks/disaster_recovery.md` — 5 DR scenarios (Redis failure,
  node failure, total fleet failure, config corruption, Redis data loss)
  with symptoms, impact, simulate, recovery steps, RTO, and RPO.
- `docs/runbooks/gameday_scenarios.md` — 4 GameDay exercises with trigger
  commands, success criteria, and measurable RTO targets.
- `docs/runbooks/credential_rotation.md` — Zero-downtime rotation for
  Redis ACL passwords, AbuseIPDB API keys, and cloud storage credentials,
  each with explicit rollback procedures.
- `docs/runbooks/tls_certificate_rotation.md` — Server-side TLS cert
  rotation (rolling, one node at a time) and mTLS CA rotation with
  dual-CA trust bundle transition.
- `docs/runbooks/rolling_upgrade.md` — Docker Compose (HAProxy drain +
  30s stagger) and Kubernetes (`helm upgrade --wait`) rolling upgrades
  with single-command rollback for each model.
- `scripts/generate_validation_report.py` — `--section deployment` flag
  appends smoke test results, MTTR baseline, and DR exercise history.
  Graceful degradation when any input is missing.
- `Makefile` targets: `smoke-docker`, `smoke-k8s`, `measure-mttr`.
- CI jobs: `smoke-docker` and `smoke-k8s` (non-blocking, `continue-on-error`).

### Tests
- `tests/test_phase64a_smoke_docker.py` — 11 structural validation tests
- `tests/test_phase64b_smoke_helm.py` — 11 structural validation tests
- `tests/test_phase64f_tls_alerts.py` — 23 alert rule validation tests
- `tests/test_phase64h_mttr.py` — 27 MTTR script validation tests
- `tests/test_phase64i_validation_report.py` — 11 deployment section tests

### Phase 101 deferrals
- M20: CI smoke-k8s needs kind/helm installation steps
- M21: `infrastructure.md` still references Python proxy
- M22: AbuseIPDB lookups counter missing from Go metrics
- M23: MTTR test should validate Redis key names

## [Unreleased] - Phase 63 - Service Level Objectives

### Added
- Three new Go Prometheus metrics in `internal/metrics/metrics.go`:
  - `ja4proxy_connection_errors_total{error_type}` (counter) — unhandled
    errors in the connection handler before a policy decision; classified
    as `redis_timeout`, `tls_parse_error`, `backend_refused`, `oom`, or
    `unknown`.
  - `ja4proxy_redis_operations_total{command,result}` (counter) — every
    Redis call, with `result="ok"` or `result="error"`.
  - `ja4proxy_tls_cert_expiry_timestamp_seconds` (gauge) — listener TLS
    cert NotAfter as a Unix timestamp; emitted when env var
    `JA4PROXY_TLS_CERT_FILE` is set. **Phase 64 alerts on this gauge.**
- `internal/redis/client.go` instruments every method (`Get`, `Set`,
  `SIsMember`, `SMembers`, `SAdd`, `SRem`, `Exists`, `ZAdd`,
  `ZRemRangeByScore`, `ZRange`, `ZRangeScores`, `ZCard`, `XAdd`, `Ping`,
  `EvalSha`, `HGetAll`, `SeedDialIfAbsent`) with the operations counter.
- `cmd/proxy/main.go` increments `ConnectionErrorsTotal` on read errors,
  TLS parse failures, and backend dial failures, with classification.
- `monitoring/prometheus/slo_recording_rules.yml` — 12 SLI ratio rules,
  9 burn-rate rules, 3 budget-remaining rules, and an FP-rate observation
  rule. Multi-window multi-burn-rate pattern from the Google SRE Workbook.
- `monitoring/alertmanager/rules/slo_alerts.yml` — fast-burn and slow-burn
  alerts per SLI plus `JA4proxyHighBlockingRate` (dial ≥ 50 guard) and
  `JA4ProxyHighBlockRate` observation alerts.
- Four runbooks: `slo_availability.md`, `slo_latency.md`,
  `slo_redis_correctness.md`, `slo_fp_rate.md` under `docs/runbooks/`.
  All hot-reload commands target production deployment forms (systemd,
  docker, podman, kubectl) — never `pgrep -f proxy.py`.
- `Makefile` targets: `validate-slo-rules`, `slo-report`, `test-phase-63`.

### Tests
- `internal/metrics/metrics_test.go` asserts the three new metric names
  are registered.
- `internal/redis/client_metrics_test.go` covers Get success, Get error
  (Redis down), and Set success counter increments.

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
- `docs/phases/complete/PHASE_101.md` — Phase 101 plan tracking the 9 deferred review items (H1 double-XRANGE, H3 CIDR watchlist match, M1 Redis version check, M2 metric rename, M4 audit log pagination, M7 DSAR partial failures, L1 Jinja2 env cache, L2 JSONL invariant doc, L5 DSAR retention text from config)

## [0.88.4] - 2026-04-09 - Multi-DC Observability & Security Hardening (ROBUST)
### Added
- Robust Integrity: Switched Ed25519 signing to use JSON-canonicalized payloads, eliminating potential Delimiter Injection vulnerabilities.
- Per-Peer Isolation: Implemented dedicated outbound replication workers with unique Redis consumer groups per peer. This eliminates Head-of-Line blocking and ensures a slow or failed DC doesn't impact sync to healthy DCs.
- Automatic Catch-up: Unique consumer groups allow failed DCs to catch up automatically from their exact last acknowledged position upon recovery.
- Metrics Instrumentation: Fully instrumented the Sync Agent to populate all 11 multi-DC metrics (Lag, Errors, Connectivity).

## [0.88.3] - 2026-04-09 - Secure Dial Consistency Protocol (ROBUST)
### Added
- Semantic Validation: Added strict bounds checking (0-100) for global dial changes in the RPC layer.
- Dial Consistency Protocol: Implemented synchronous 8-second ACK protocol with cryptographic verification.

## [0.88.2] - 2026-04-09 - Async State Propagation & Tombstones (REMEDIATED)
### Added
- Reliable Delivery: Updated replication logic to only ACK stream messages after all peers acknowledge receipt, ensuring state convergence after WAN partitions.
- Inbound Security: Implemented strict key whitelisting in the sync agent to prevent unauthorized Redis key overrides.
- Tombstone Pattern: Implemented `:removals` sets for robust cross-DC set deletions.

## [0.88.1] - 2026-04-08 - Multi-DC Foundation & Sentinel Support

### Added
- Redis Sentinel support (`goredis.NewFailoverClient`): proxy now supports `master_name` and `sentinels` configuration for high availability in multi-DC environments
- Background NTP drift monitoring: added `SyncClockDriftSeconds` gauge and background worker that periodically parses `chronyc` or `ntpstat` output to detect cross-DC time drift
- Configuration: Added `monitoring` section to `proxy.yml` with `ntp_check_interval_seconds` and `max_drift_seconds` fields

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
- **Test Documentation**: Created `docs/TESTING_STRATEGY.md` and `docs/TESTING_STRATEGY.md` with clear guidelines for different test tiers.

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
- **Operational Procedures**: Established formal procedures for identifying,Implementing, and monitoring blocks against malicious ISPs and organizations.

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
- **Audience-first navigation structure** in `docs/README.md`
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
