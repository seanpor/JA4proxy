<!--
title: Scripts
audience: reference
last_reviewed: 2026-03-27
phase: 21
-->

# Scripts Reference

All scripts live in `scripts/`. Each has a usage header — run with `--help` or
read the top of the file for full options.

<!-- BEGIN GENERATED: scripts -->

_129 scripts. Generated from each script's header comment by `make sync` — do not edit this table by hand._

| Script | Called by | What it does |
|--------|-----------|--------------|
| `agent-env.sh` | `make agent-up` | scripts/agent-env.sh — Generate isolated .env file for a named agent |
| `assemble-changelog.py` | `make changelog-assemble` | Assemble CHANGELOG news fragments into CHANGELOG.md. |
| `basic_perf_test.sh` | `make perf-test-basic` | Basic performance test script |
| `bench-hostnative.sh` | `make bench-hostnative` | end-to-end throughput benchmark with the engine running |
| `bench-tls-backend.py` | — | Minimal asyncio TLS echo backend for benchmark use. |
| `benchmark.py` | — | JA4proxy Performance Benchmark |
| `benchmark_comparison.py` | — | JA4proxy Comprehensive Benchmark: Go Proxy vs Python Proxy. |
| `blue-green-deploy.sh` | — | Phase 43 — Blue/Green Deployment Tooling |
| `bootstrap.sh` | — | JA4proxy single-host bootstrapper (phase-231b / phase-332). |
| `branch_hygiene.py` | — | Automates Git branch hygiene analysis and stale branch cleanup. |
| `branch_protection.sh` | — | scripts/branch_protection.sh — bootstrap GitHub branch protection for main. |
| `capacity_calculator.py` | — | Phase 86c / 86i — Capacity sizing calculator for JA4proxy. |
| `capture_clienthello.py` | — | Capture TLS ClientHello bytes from connections for JA4 parity testing. |
| `capture_server.py` | — | Persistent TLS ClientHello capture server. |
| `check-action-shas.py` | — | Verify SHA-pinned GitHub Actions use commit SHAs, not annotated tag SHAs. |
| `check-isolation.sh` | — | scripts/check-isolation.sh — Verify multi-agent Docker isolation |
| `check-python314-compat.py` | — | check-python314-compat.py — PyPI wheel compatibility checker for Python 3.14. |
| `check-signal-scores.py` | `make check-scores` | Signal Score Consistency Linter. |
| `check-status.sh` | — | Quick status check for JA4proxy POC and monitoring stack |
| `check_bare_except.py` | — | Fail if any file contains a bare except: or a bare except Exception: pass. |
| `check_bind_address.py` | — | Pre-flight guard for JA4PROXY-2026-0045 (Phase 226). |
| `check_doc_frontmatter.py` | `make doc-health` | Documentation Frontmatter Validator |
| `check_finding_spec.py` | — | check_finding_spec.py — completeness gate for penetration-testing finding |
| `check_image_versions.py` | `make scan-images` | check_image_versions.py — detect :latest tags and version drift between compose files. |
| `check_logger_format.sh` | — | Fail if any Python file uses f-strings in logger calls. |
| `check_manifest.py` | `make check-manifest` | check_manifest.py — local consistency gate for the manifest-driven roadmap. |
| `check_trivyignore_drift.py` | — | Diff what the deployed images actually carry against what the ignorefile waives. |
| `check_updates.py` | `make check-updates-local` | check_updates.py — Check all project dependencies for available updates. |
| `ci_summary.py` | `make lint` | CI summary utility. |
| `close-phase.sh` | — | mechanical pre-merge gate for phase close-out. |
| `compute_ja4_fixtures.py` | — | Add current dir to path to import local modules |
| `config-signer.py` | — | config-signer.py — Ed25519 signing utility for JA4proxy configuration files. |
| `count_lines.py` | — | Count non-blank lines of code by category across the JA4proxy project. |
| `create_test_mmdb.py` | — | Create a minimal MaxMind test database for ASN classifier testing. |
| `demo-bot.sh` | `make demo-bot` | make ONE deliberately non-browser TLS connection. |
| `demo-check.sh` | `make demo-check` | refuse to start a demo on a stack that is quietly broken. |
| `demo-poc.sh` | — | JA4 Proxy POC Demo Script |
| `demo-scan.py` | — | Generate distributed-scan traffic from many real source IPs. |
| `demo-scan.sh` | — | run demo-scan.py in a container with many source IPs. |
| `dependabot_pr_refresh.py` | — | Decide whether a Dependabot PR needs a stale-CI refresh or cascading rebase (Phase 812, Phase 830). |
| `deploy.sh` | `make deploy-enterprise` | Enterprise deployment script for JA4 Proxy |
| `detect_workers.py` | `make test-calibrate` | Detect optimal parallel worker count for this machine. |
| `docker-entrypoint.sh` | — | phase-800: MUST be /bin/sh, not /bin/bash. |
| `docker-net-diag.sh` | — | Diagnose Docker container networking |
| `ensure-poc-secrets.sh` | `make poc-secrets` | create any missing deploy/secrets/*.txt the PoC |
| `env-sync.sh` | `make env-sync` | Top up an EXISTING .env with any newly-required variables. |
| `export_ci_benchmark_textfile.sh` | — | Phase 805 — host-side puller for the nightly benchmark regression job. |
| `fetch-ja4db.sh` | `make fetch-db` | Fetch known-bad JA4 fingerprints from FoxIO's public database |
| `fetch_tranco_top10k.py` | — | Fetch Tranco top 10,000 domains for false-positive testing. |
| `findings_register.py` | `make verify-findings` | Canonical findings register CLI for JA4proxy. |
| `fix-docker-dns.sh` | — | Fix Docker container networking while keeping "iptables": false and UFW intact. |
| `fix_doc_links.py` | — | Documentation Link Fixer |
| `fix_runbook_urls.py` | `make lint-alert-urls` | Phase 86h - Rewrite dead runbook_url annotations in Alertmanager rule files. |
| `gdpr_delete.py` | — | GDPR Subject Erasure (Right to be Forgotten) — Live Redis Purge |
| `generate-backend-cert.sh` | — | Generate a self-signed TLS cert for the mock backend (deploy/docker/Dockerfile.mockbackend |
| `generate-test-traffic.sh` | — | Generate realistic test traffic for JA4proxy to populate Grafana dashboard |
| `generate-tls-traffic.sh` | — | TLS Traffic Generator - Performance Testing Script for JA4proxy |
| `generate_adversarial_corpus.py` | — | Generate adversarial TLS corpus files for testing. |
| `generate_dependency_graph.py` | — | Dependency Graph Generator |
| `generate_fixtures.sh` | `make capture-fixtures` | Build ja4check |
| `generate_fixtures_browser.py` | — | Generate TLS ClientHello fixtures from real browsers using Playwright. |
| `generate_realistic_domains.py` | — | Generate realistic domain list for Tranco top 10k testing. |
| `generate_residential_ips.py` | — | Generate anonymized residential IP addresses for ASN testing. |
| `generate_synthetic_fixtures.py` | — | Generate synthetic TLS ClientHello fixture files with known JA4 fingerprints. |
| `generate_test_pcap.py` | — | generate_test_pcap.py — Synthetic PCAP corpus generator for TAP mode tests. |
| `generate_validation_report.py` | `make validation-report` | Phase 62 — pre-enterprise validation report generator. |
| `geoip-monitor.sh` | `make geoip-monitor` | Auto-block countries that are actively attacking |
| `ja4-admin.sh` | `make agent-up` | ja4-admin — JA4proxy incident response CLI |
| `ja4proxy_admin.py` | — | ja4proxy-admin — CLI for JA4proxy operational management. |
| `lane-env.sh` | `make lane` | assign this git worktree a collision-free "lane" of host ports |
| `lint-phases.py` | `make lint-phases` | lint-phases.py — Validate phase documentation consistency. |
| `lint_toml.py` | `make lint-toml` | TOML syntax + parse validation. |
| `load_test.py` | `make load-test` | Phase 86b / 86i — Load testing harness for JA4proxy. |
| `measure_mttr.sh` | `make measure-mttr` | Phase 64h — MTTR baseline measurement script. |
| `meta_lint.py` | `make lint-meta` | Meta-lint: verify the Makefile is internally honest. |
| `mock-backend.py` | — | Mock backend server for testing JA4 Proxy |
| `namespace_setup.sh` | — | Namespace isolation helper for JA4proxy (Phase 56b-3) |
| `nightly_benchmark_gate.py` | — | nightly_benchmark_gate.py — Phase 805 nightly performance regression gate. |
| `perf-matrix.sh` | — | — |
| `perf-test.sh` | — | Performance testing script for JA4 Proxy |
| `phase-800-code-health.sh` | — | deterministic gate-runner + reporter (Phase 800). |
| `phase_121_verify.py` | `make verify-manifest-closeout` | Phase 121 close-out gate. |
| `pin_table_autofix.py` | — | Verify and append new GitHub Actions SHA pins (Phase 812, 812-C). |
| `pip-audit-resilient.sh` | `make lint-static` | run pip-audit but don't let a transient outage of a |
| `pipeline_summary.py` | `make test` | scripts/pipeline_summary.py — unified one-line verdict for lint, scan, and test. |
| `poc-status-check.sh` | — | Quick POC readiness check |
| `populate-grafana-demo-data.sh` | — | Populate Grafana with realistic demo data by simulating security events |
| `process_metrics.py` | — | process_metrics.py — emit an engineering-process metrics report. |
| `quick-start.sh` | `make quick-start` | JA4proxy quick-start helper |
| `reconcile_ipset.py` | — | reconcile_ipset.py — iptables/ipset drift reconciliation for TAP enforcement. |
| `redis-acl-setup.sh` | — | scripts/redis-acl-setup.sh — Configure Redis ACL users for least-privilege operation |
| `redis-to-ebpf.py` | — | redis-to-ebpf.py — Sync Redis blacklist/ban entries into a BPF hash map. |
| `refresh_trivyignore_justifications.py` | — | Regenerate the "carried by" line on each .trivyignore entry from scan data. |
| `renew_trivyignore.py` | — | Renew soon-to-expire .trivyignore exceptions (Phase 812, 812-B). |
| `rotate_soar_token.sh` | — | Rotate a JA4proxy Management API SOAR token. |
| `run-all-tests.sh` | — | JA4proxy Comprehensive Test Runner |
| `run-benchmark.sh` | — | Load .env if available |
| `run-local-tests.sh` | — | JA4proxy — local test runner |
| `run-tests.sh` | `make test-docker` | Test runner script for JA4 Proxy POC |
| `scale-proxies.sh` | — | Scale JA4proxy to N proxy instances behind HAProxy |
| `scan_exceptions.py` | `make scan-exceptions` | List Trivy scan exceptions (.trivyignore) with days-to-expiry. |
| `scan_summary.py` | `make scan-summary` | scripts/scan_summary.py — human-readable rollup of the security scans (Phase 228). |
| `set_dial.py` | `make dial` | Set the proxy dial value via pubsub. |
| `setup-redis-security.sh` | — | Setup script for Redis security (TLS + Secrets) |
| `setup_wizard.py` | — | DEPRECATED — superseded by Phase 161 Go-native ``ja4p init`` wizard. |
| `smoke-test.sh` | `make smoke-test` | Quick smoke test to verify POC is working |
| `start-all.sh` | `make start` | Start complete JA4proxy with monitoring |
| `start-monitoring.sh` | `make start-monitoring` | Quick start script for JA4proxy monitoring stack |
| `start-pentest-range.sh` | `make pentest-range` | bring up the JA4proxy penetration-testing range |
| `start-poc.sh` | `make compose-validate` | JA4 Proxy POC Startup Script |
| `status.sh` | `make status` | Unified JA4proxy health status |
| `stop-all.sh` | `make stop` | Stop all JA4proxy stacks (POC + monitoring) |
| `sync-roadmap.py` | `make sync` | Sync Roadmap Script |
| `sync_reference_docs.py` | `make sync` | sync_reference_docs.py — generate the reference lists from the things they |
| `tap_benchmark.py` | — | tap_benchmark.py — TAP mode throughput benchmark. |
| `test-bot.py` | `make remote-bot` | JA4proxy test bot — lightweight manual tester. |
| `test-ja4-blocking.sh` | — | JA4 Fingerprint Blocking Test Script |
| `test-wrapper.sh` | — | Test wrapper script that ensures proper exit with debugging |
| `test_ratio.py` | `make test-ratio` | Test-to-Code Ratio Calculator |
| `tls-traffic-generator.py` | — | TLS Traffic Generator for JA4proxy Performance Testing |
| `traceability.py` | — | traceability.py — generate ``docs/reference/TRACEABILITY.md`` from phase docs. |
| `update-geoip.sh` | `make update-geoip` | Download the latest IP2Location LITE country database |
| `update_readme_stats.py` | — | Map count categories to README labels |
| `validate-single-host.sh` | — | JA4proxy single-host deployment validator (phase-231b real-host E2E). |
| `verify-image-signature.sh` | — | Usage: scripts/verify-image-signature.sh <image-ref> |
| `verify-slsa.sh` | — | scripts/verify-slsa.sh — Verify SLSA Level 3 provenance for JA4proxy artifacts. |
| `verify_revert.sh` | — | machine-check the two-state proof (Phase 814a). |
| `view-metrics.sh` | — | — |
| `workspace_integrity_tool.py` | — | Workspace Integrity Tool (WIT) |

<!-- END GENERATED: scripts -->

---

## Redis / Lua

| Script | What it does |
|--------|-------------|
| `sliding_window.lua` | Atomic sliding-window rate tracker loaded into Redis via `SCRIPT LOAD` / called with `EVALSHA`. Never call inline — always use the cached SHA. See file header for `KEYS`/`ARGV` contract. |

---

## Subdirectories

| Directory | What it contains |
|-----------|-----------------|
| `scripts/docker-troubleshooting/` | One-off Docker networking repair scripts (`../scripts/docker-troubleshooting/fix-docker.sh`, `../scripts/docker-troubleshooting/nuclear-reset-docker.sh`, etc.) — only needed when Docker networking breaks on this host |

---

## Line Counter

```bash
python3 scripts/count_lines.py          # run from repo root
python3 scripts/count_lines.py --root /path/to/repo
```

Counts non-blank lines by category (Python proxy, Go proxy, tests, scripts, infrastructure, docs).
Excludes `.git`, build artefacts, generated output, and binary files.
