<!--
title: "JA4proxy Quality Plan"
audience: architects, compliance, developers, maintainers
last_reviewed: 2026-04-24
phase: 106h
-->

# JA4proxy — Quality Plan

This is the project's consolidated quality plan. It exists to give one
landing page for the question "how does JA4proxy assure quality?" — covering
quality attributes and their targets, the defect-management process, the
quality gates that run before merge / release / phase-close, the QA roles in
the multi-agent workflow, and SWEBOK v4 KA coverage.

This document is intentionally short and link-heavy. The authoritative
content lives in the documents linked from each section; if those documents
ever drift from this page, the linked source wins. The value of this page is
that one page exists.

**This is not:**

- A test plan — see [`docs/TESTING_STRATEGY.md`](TESTING_STRATEGY.md).
- A test-organization manual — see [`docs/TEST_ORGANIZATION.md`](TEST_ORGANIZATION.md).
- An observability standard — see [`docs/OBSERVABILITY_STANDARDS.md`](OBSERVABILITY_STANDARDS.md).
- A documentation style guide — see [`docs/DOCUMENTATION_STANDARDS.md`](DOCUMENTATION_STANDARDS.md).
- A risk register — see [`docs/RISK_REGISTER.md`](RISK_REGISTER.md).

---

## 1. Quality attributes and targets

Each row gives the attribute, its measurable target, and where the target is
verified (the authoritative source). Targets are mirrored from
[`docs/SERVICE_TARGETS.md`](SERVICE_TARGETS.md) where applicable; if the two
ever drift, SERVICE_TARGETS wins.

| Attribute | Target | Verified by |
|---|---|---|
| **Performance** | Pipeline latency p99 < 10 ms (per-connection scoring path) | [`docs/runbooks/slo_latency.md`](runbooks/slo_latency.md), [`tests/performance/test_bench_go_proxy.py`](../tests/performance/test_bench_go_proxy.py), [`tests/performance/benchmark_parallel_signals.py`](../tests/performance/benchmark_parallel_signals.py) |
| **Availability** | 99.9% (28-day error budget = ~40 bad minutes) | [`docs/runbooks/slo_availability.md`](runbooks/slo_availability.md), Alertmanager rules `JA4ProxyAvailability{Fast,Slow}Burn` |
| **False-positive rate** | Trigger if blocking rate > 2% at `dial >= 50` (per-incident, no rolling budget — dominant quality attribute) | [`docs/runbooks/slo_fp_rate.md`](runbooks/slo_fp_rate.md), Tranco-top-10k FP corpus tests under `tests/fp_corpus/` |
| **Redis correctness** | 99.5% successful Redis ops / total | [`docs/runbooks/slo_redis_correctness.md`](runbooks/slo_redis_correctness.md) |
| **Security** | No HIGH or CRITICAL findings unmitigated; pentest campaign findings closed per [`docs/security/FINDINGS_REGISTER.md`](security/FINDINGS_REGISTER.md) | [`docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`](security/COMPREHENSIVE_SECURITY_AUDIT.md), [Phase 14 hardening](phases/PHASE_14.md), Phase 118-119 remediation |
| **Maintainability** | Go coverage ≥ 80%, Python coverage ≥ 80%, test-to-code ratio ~1.3× | `Makefile` targets `quality` and `lint-coverage`, [`docs/TESTING_STRATEGY.md`](TESTING_STRATEGY.md), enforced in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| **Portability** | Linux x86_64; Docker image (Go + Python services) builds clean; Helm chart deploys on k8s ≥ 1.27 | [`docs/DOCKER_IMAGES.md`](DOCKER_IMAGES.md), [`tests/integration/test_dockerfile_coverage.py`](../tests/integration/test_dockerfile_coverage.py), CI matrix in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| **Usability** (Management UI) | Authenticated GET on every HTML route returns 200 + landmark; unauth returns < 500 | Per-phase `test_pages*.py` tests (e.g. [`tests/unit/test_pages_threat_intel.py`](../tests/unit/test_pages_threat_intel.py)); pattern documented in [`CLAUDE.md`](../CLAUDE.md) §Testing Standards |

The **core asymmetry** governs every threshold: blocking a real user costs
more than missing a bad bot, so the false-positive-rate row above is treated
as the dominant attribute, not as one of several equal ones. See
[`CLAUDE.md`](../CLAUDE.md) §Core Asymmetry and
[`docs/SERVICE_TARGETS.md`](SERVICE_TARGETS.md) for the full justification.

---

## 2. Defect management

JA4proxy runs as an open-source project on GitHub. Defect management is
lightweight; SLAs apply to security defects only. Process metrics are
tracked quarterly in
[`docs/engineering-method/retrospectives/`](engineering-method/retrospectives/README.md).

**Reporting**

- Functional bugs: GitHub Issues, public.
- Security vulnerabilities: private channel per [`SECURITY.md`](../SECURITY.md)
  (private/confidential issue, or email to `security@ja4proxy.example.com`,
  or PGP-encrypted). Do not file security issues on the public tracker.

**Triage**

- Cadence: best-effort, batched roughly weekly. The project does not commit
  to a triage SLA on functional bugs.
- Triage adds labels (severity, area, audience). The label taxonomy is whatever
  the issue templates and project conventions enforce — when in doubt, copy
  labels from a recently triaged issue rather than inventing.

**Security SLAs** — copied from [`SECURITY.md`](../SECURITY.md):

- Critical: initial response within 24 hours.
- High: initial response within 48 hours.
- Disclosure timeline coordinated with reporter; default 90-day window.

**Fix and verify**

- Every fix lands as a phase under [`docs/phases/`](phases/) (see Phase 118
  series for the recent pentest-driven cadence).
- Each fix is paired with a regression test (`*_regression_test.go` /
  `test_pentest_*.py` convention).
- The closing commit references the finding ID
  (`JA4PROXY-YYYY-NNNN`) and updates
  [`docs/security/FINDINGS_REGISTER.md`](security/FINDINGS_REGISTER.md).

---

## 3. Quality gates

| Gate | When it runs | What must pass | Source |
|---|---|---|---|
| **Pre-merge** | Every PR | Lint (Python ruff/mypy + Go vet/golangci-lint), unit tests, integration tests, Go build, doc-link check, workflow SHA-pin check | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`Makefile`](../Makefile) target `quality` |
| **Pre-release (CLI binary)** | Tag push matching `cli-v*` | Cross-platform binary build, signature, SBOM, container scan | [`.github/workflows/release-cli.yml`](../.github/workflows/release-cli.yml) |
| **Pre-release (Go proxy image)** | Workflow dispatch + tag | Multi-arch image build, vulnerability scan | [`.github/workflows/go-proxy-image.yml`](../.github/workflows/go-proxy-image.yml) |
| **Pre-phase-close** | Manually, before flipping `manifest.yaml` to `COMPLETE` | All acceptance criteria green; full local sweep (`make test`); coverage gate; CHANGELOG entry; `make sync` clean | [`scripts/close-phase.sh`](../scripts/close-phase.sh), [`docs/TESTING_STRATEGY.md`](TESTING_STRATEGY.md) §phase gate, [`CLAUDE.md`](../CLAUDE.md) §How to Run a Phase |
| **Coverage gate** | Pre-merge + pre-phase-close | Go ≥ 80% per package (Phase 207 raised from 50% to 80%); Python ≥ 80% (Phase 104) | `Makefile` target `quality` (calls `lint-coverage`) |
| **Doc gate** | Pre-merge | `make lint-docs`, `make link-check`, `make doc-health`, `make lint-phases` | [`Makefile`](../Makefile), [`docs/DOCUMENTATION_STANDARDS.md`](DOCUMENTATION_STANDARDS.md) |
| **Workflow pin gate** | Pre-merge | All third-party GHA actions are SHA-pinned, not version-pinned | [`tests/test_workflow_pinning.py`](../tests/test_workflow_pinning.py) |

The pre-phase-close gate is the load-bearing one. Phase completion is not
"all PRs merged" — it is "all acceptance criteria are green and verified".
The methodology is in [`docs/TESTING_STRATEGY.md`](TESTING_STRATEGY.md).

---

## 4. Quality-assurance roles

QA in JA4proxy is **distributed across the multi-agent workflow** rather
than concentrated in a separate QA team. Roles are functional, not titles —
the same human or agent often plays several. The narrative of how this works
is in [`docs/engineering-method/README.md`](engineering-method/README.md);
the rules below are the load-bearing summary.

- **Code author** — writes code and unit tests, TDD where the spec allows.
  Owns the phase branch (`phase-XX-description`). Responsible for
  passing the pre-phase-close gate before requesting merge.
- **Reviewer** — peer agent or human, often invoked via `/review-phase`.
  Reviews PRs against the phase's acceptance criteria, not just the diff.
  Six review lenses: security, devops, SRE, architecture, testing, docs (see
  any `PHASE_XX_review.md` for the worked example).
- **Independent cyber architect** — reviews phase-doc *plans* before
  implementation begins. Output lives in `docs/phases/PHASE_XX_review.md`.
  This is the role that catches scope/dependency problems before code is
  written.
- **Maintainer** — signs off on close. Verifies `manifest.yaml`, CHANGELOG,
  and `make sync` artefacts are committed atomically. Holds the merge
  authority: agents do not merge their own branches to `main` (see
  [`CLAUDE.md`](../CLAUDE.md) §Multi-Agent Coordination).
- **Security reviewer** — for phases touching the proxy hot path or
  security-policy code, runs `/security-review` (see [`SECURITY.md`](../SECURITY.md)).
  Pentest campaigns (Phase 118-119) are conducted by an independent red-team
  agent and produce findings filed against
  [`docs/security/FINDINGS_REGISTER.md`](security/FINDINGS_REGISTER.md).

Human review points: every PR before merge; every phase-doc plan before
implementation begins; every security-finding fix.

---

## 5. SWEBOK v4 KA coverage (post-Phase 106)

The SWEBOK v4 (2024) Knowledge Areas serve as the framing checklist for
documentation completeness. Phase 106 closes the externally visible gaps;
KAs 7 and 13 close out in Phase 105 (versioning/release policy and
professional-practice docs respectively). KAs 15-17 (Computing /
Mathematical / Engineering Foundations) are prerequisite knowledge and not
project documentation.

Table copied verbatim from [`docs/phases/PHASE_106.md`](phases/PHASE_106.md)
§"SWEBOK v4 KA Coverage After Phase 106":

| KA | Current | Phase 106 delivers | Post-106 |
|----|---------|--------------------|----------|
| 1. Software Requirements | 🟡 | Traceability matrix (106d) | ✅ |
| 2. Software Architecture | ✅ | — | ✅ |
| 3. Software Design | 🟡 | Component-level design index (106f) | ✅ |
| 4. Software Construction | ✅ | — | ✅ |
| 5. Software Testing | ✅ | Traceability matrix ties requirements→tests (106d) | ✅ |
| 6. Software Engineering Operations | 🟡 | Consolidated SLA/SLO doc (106a) | ✅ |
| 7. Software Configuration Management | 🔴 | Deferred to Phase 105 (versioning/release policy) | 🟡 |
| 8. Software Engineering Management | 🟡 | Risk register (106b) | ✅ |
| 9. Software Engineering Process | ✅ | Retrospective mechanism + process metrics (106e) | ✅ |
| 10. Software Engineering Models and Methods | 🔴 | Formal method statement (106g) | ✅ |
| 11. Software Quality | 🟡 | Quality plan consolidation (106h) | ✅ |
| 12. Software Security | ✅ | — | ✅ |
| 13. Software Engineering Professional Practice | 🔴 | Deferred to Phase 105 (CoC, CLA, AI disclosure) | 🟡 |
| 14. Software Engineering Economics | 🔴 | TCO & commercial model doc (106c) | ✅ |

Target met: **12 of 14 applicable KAs green** after Phase 106. KAs 7 and 13
are tracked in Phase 105.

---

## 6. Cross-references

Operational and engineering documents this plan touches:

- [`docs/SERVICE_TARGETS.md`](SERVICE_TARGETS.md) — SLIs, SLOs, SLA posture, error-budget policy
- [`docs/RISK_REGISTER.md`](RISK_REGISTER.md) — consolidated risk register (Phase 106b)
- [`docs/TRACEABILITY.md`](TRACEABILITY.md) — requirements-to-test matrix (Phase 106d, generated)
- [`docs/TESTING_STRATEGY.md`](TESTING_STRATEGY.md) — full test methodology and phase-completion gate
- [`docs/TEST_ORGANIZATION.md`](TEST_ORGANIZATION.md) — test layout, conftest, fixtures
- [`docs/DOCUMENTATION_STANDARDS.md`](DOCUMENTATION_STANDARDS.md) — CHANGELOG / Redis schema / runbook / ADR formats
- [`docs/OBSERVABILITY_STANDARDS.md`](OBSERVABILITY_STANDARDS.md) — Prometheus naming, JSON log schema, dashboards, alerts, SLIs
- [`docs/STYLE_GUIDE.md`](STYLE_GUIDE.md) — config syntax, log format, doc language, REQ-tagging convention
- [`docs/engineering-method/README.md`](engineering-method/README.md) — formal method statement, case studies, retrospectives
- [`docs/design/README.md`](design/README.md) — component design index (Phase 106f)
- [`docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`](security/COMPREHENSIVE_SECURITY_AUDIT.md) — security audit
- [`docs/security/FINDINGS_REGISTER.md`](security/FINDINGS_REGISTER.md) — pentest findings + remediation status
- [`SECURITY.md`](../SECURITY.md) — security reporting + SLAs
- [`docs/for-architects/README.md`](for-architects/README.md) — architect entry point
- [`docs/for-compliance/README.md`](for-compliance/README.md) — compliance entry point
- [`CLAUDE.md`](../CLAUDE.md) — agent master plan (multi-agent coordination, core asymmetry, cross-cutting requirements)

---

*Last reviewed 2026-04-24 (Phase 106h). Next review: alongside the next
quarterly retrospective.*
