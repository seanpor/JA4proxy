# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`make scan-summary` (Phase 228)**: `scripts/scan_summary.py` (stdlib-only) runs Trivy in JSON mode per image and prints a compact one-row-per-image CRIT/HIGH/MED table with a verdict + rollup, so the scan result is readable at a glance instead of a wall of tables. Reporting-only — `make scan` stays the authoritative gate — and unit-tested. (gosec/`make lint` rollups are the remaining half of Phase 228.)

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
