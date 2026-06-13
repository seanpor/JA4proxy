# Unified Interface & Container Consolidation Master Plan

## Goal

Provide a single, hardened pane of glass for SecDevOps engineers by unifying all user-facing interfaces and backend operations into the FastAPI + HTMX management console. This phase consolidates redundant container infrastructure, resolves event stream data contract discrepancies between the Go proxy and the Python console, and hardens operational endpoints without introducing security regressions.

---

## Roadmap Overview

This program is divided into eight sub-phases to ensure incremental, testable delivery:

- **PHASE_321: Event Contract Unification** — Align the Go proxy daemon's event emissions with the Python console's stream parsing.
- **PHASE_322: Security Foundations & Admin API Cleanup** — Deprecate the legacy unauthenticated admin API, enforce proper TLS verify/Redis ACL policies, and secure local JS loading.
- **PHASE_323: Observability Foundations & Core Metrics** — Harmonize proxy metrics scrapers and alert rules, avoiding empty panels or dead alert alarms.
- **PHASE_324: Unified Threat Posture Dashboard** — Build the high-level dashboard visualization based on the unified stream schema.
- **PHASE_325: Fingerprint & IP Drill-Down Pages** — Connect drill-down views to real-time Redis structures and MMDB geo-lookups.
- **PHASE_326: Analytics Intelligence & Findings UI** — Expose active detection rules and model outputs in the management layer.
- **PHASE_327: Operational Workflows & Dial Audit Hardening** — Implement secure dial auto-revert, additive audit logging, and trie-based CIDR ban interfaces.
- **PHASE_328: Accessibility Hardening & Infrastructure Docs** — Deploy automated axe-core testing and document final deployment topologies.

---

## Scope

### In scope
- Unifying data structures between `cmd/ja4pd/main.go` and FastAPI handlers.
- Deprecating and deleting legacy unauthenticated code (`src/management/app.py` and `deploy/docker/Dockerfile.admin`).
- Implementing comprehensive integration tests in `management/tests/test_pages.py` and `tests/integration/test_container_config.py` for all new pages and environments.

### Out of scope
- Rewriting the management interface in Go or another framework (FastAPI + Jinja + HTMX is the standard).
- Re-architecting the single-host bootstrap wizard (`setup_wizard.py`), which is owned by `PHASE_231b`.

---

## A — Roadmap Alignment

Verify all sub-phase documents exist, contain no stale references, and are correctly registered in the project manifest.

---

## Acceptance Criteria

- [ ] All sub-phase documents (PHASE_321 through PHASE_328) are present and pass `scripts/lint-phases.py` with exit code 0.
- [ ] The manifest `docs/phases/manifest.yaml` contains complete entries for phases 320 to 328.
- [ ] No regression occurs in existing unit or integration tests during development.

---

## Files to Modify

| File | Change |
|------|--------|
| `docs/phases/manifest.yaml` | Add entries for Phase 320 through 328 |
| `docs/phases/PHASE_320.md` | New file — Program Umbrella Master Plan |
