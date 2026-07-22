---
phase: 501
title: "Codebase Bug Hunt — Pass 2 (IEEE 1044 Classification)"
size: XLARGE
created: 2026-06-24
audience: [security, developer]
---

# Codebase Bug Hunt — Pass 2 (IEEE 1044 Classification)

## What is this?

A second pass of the Phase 500 bug hunt, this time organized by **IEEE 1044-2009
(Standard Classification for Software Anomalies)** rather than CWE families.

Phase 500 found 18 bugs organized by *where* they live (Go proxy, Python, infra).
Phase 501 finds bugs organized by *what kind* they are — using IEEE 1044's
taxonomy of activity, type, severity, and cause.

**Why a second pass?** Different classification schemes surface different bugs.
Phase 500's CWE-based approach was strong on input validation and crypto but
weak on design-level flaws, interface mismatches, and lifecycle issues. IEEE 1044
forces you to think about every anomaly from four angles simultaneously.

## IEEE 1044 Classification Schema

Every finding in this phase MUST be classified along all four IEEE 1044 dimensions:

### 1. Activity (where was it found?)

| Code | Activity | Example |
|------|----------|---------|
| `COD` | Code | Bug in source code |
| `DES` | Design | Architectural flaw |
| `TST` | Test | Inadequate or missing test |
| `DOC` | Documentation | Incorrect/missing docs |
| `BUI` | Build/Configuration | CI, Docker, config issue |
| `REQ` | Requirements | Ambiguous or missing requirement |

### 2. Type (what kind of anomaly?)

| Code | Type | Description |
|------|------|-------------|
| `ALG` | Algorithm | Incorrect algorithm or computation |
| `DAT` | Data | Wrong data, missing data, data corruption |
| `IFC` | Interface | API contract violation, type mismatch, parameter error |
| `LOG` | Logic | Wrong conditional, missing branch, inverted logic |
| `PRF` | Performance | Resource waste, inefficiency, unbounded growth |
| `STD` | Standards | Coding standard violation, style inconsistency |
| `SYN` | Syntax | Language syntax error, parse error |
| `TMR` | Timing | Race condition, deadlock, ordering issue |
| `OTH` | Other | Doesn't fit above categories |

### 3. Severity

| Code | Severity | Description |
|------|----------|-------------|
| `FAT` | Fatal | System crash, data loss, security breach |
| `SEV` | Severe | Major functionality broken, significant security risk |
| `MOD` | Moderate | Degraded functionality, moderate security risk |
| `MIN` | Minor | Minor inconvenience, low security risk |
| `COS` | Cosmetic | No functional impact |

### 4. Cause (what introduced it?)

| Code | Cause | Description |
|------|-------|-------------|
| `AMB` | Ambiguous | Requirement or spec was unclear |
| `INC` | Incorrect | Logic or implementation error |
| `MIS` | Missing | Something was omitted |
| `EXT` | Extraneous | Something unnecessary was added |
| `ICP` | Incomplete | Partially implemented |
| `STD` | Standards | Didn't follow coding standards |

## CWE ↔ IEEE 1044 Mapping (from Phase 500)

The first pass findings map to IEEE 1044 as follows. This mapping guides what
**Type** categories are already well-covered and which need attention:

| Finding | CWE | IEEE Activity | IEEE Type | IEEE Severity |
|---------|-----|---------------|-----------|---------------|
| 0063 | CWE-20 | COD | ALG | SEV |
| 0064 | CWE-362 | COD | TMR | MIN |
| 0065 | CWE-532 | COD | LOG | MOD |
| 0066 | CWE-918 | COD | IFC | MIN |
| 0067 | CWE-400 | COD | PRF | SEV |
| 0068 | CWE-362 | COD | TMR | SEV |
| 0069 | CWE-362 | COD | TMR | MOD |
| 0070 | CWE-732 | COD | IFC | MOD |
| 0071 | CWE-732 | COD | IFC | MOD |
| 0072 | CWE-770 | COD | PRF | MIN |
| 0073 | CWE-400 | COD | PRF | MIN |
| 0074 | CWE-532 | COD | LOG | MIN |
| 0075 | CWE-532 | COD | LOG | MIN |
| 0076 | CWE-1188 | BUI | DAT | MOD |
| 0077 | CWE-250 | BUI | DAT | MIN |
| 0078 | CWE-532 | BUI | SYN | MIN |
| 0079 | CWE-214 | BUI | DAT | MIN |
| 0080 | CWE-1188 | DES | MIS | MIN |

### Coverage gaps (Types not yet hit)

- **`ALG`** — Only 1 finding. Look for algorithm correctness issues in
  scoring, risk calculation, beaconing detection, rate limiting.
- **`DES`** — Only 1 finding. Look for architectural/design flaws:
  missing circuit breakers, wrong abstraction boundaries, coupling issues.
- **`TST`** — Zero findings. Look for missing test coverage, weak assertions,
  test-only code paths that don't match production.
- **`DOC`** — Zero findings. Look for documentation that contradicts code,
  missing operator guidance, stale runbooks.
- **`IFC`** — 3 findings but all key-file permission issues. Look for API
  contract mismatches between Go proxy and Python management API, Redis
  schema violations, webhook payload format issues.

## Sub-phases

| Sub-phase | Focus | IEEE Types | Files |
|-----------|-------|------------|-------|
| **501a** | Algorithm correctness | ALG | `internal/security/scorer.go`, `internal/security/decider.go`, `internal/security/beaconing_detector.go`, `internal/security/rate_limiter.go` |
| **501b** | Design & architecture | DES | `internal/security/pipeline.go`, `cmd/ja4pd/main.go`, `internal/redis/client.go` — overall structure, coupling, error handling philosophy |
| **501c** | Interface contracts | IFC | `internal/redis/` (Redis schema), `internal/webhook/` (payload format), `management/api/` (API contract), `internal/config/` (config schema) |
| **501d** | Timing & lifecycle | TMR | `internal/security/pipeline.go` (worker lifecycle), `cmd/ja4pd/main.go` (shutdown, graceful drain), `internal/redis/pubsub.go` (reconnect) |
| **501e** | Test adequacy | TST | Coverage gaps, weak assertions, missing adversarial tests |
| **501f** | Documentation accuracy | DOC | Runbooks, API docs, operator guides vs actual code behavior |
| **501g** | Data integrity | DAT | Config validation, Redis data corruption, backup/restore correctness |

## Finding template (IEEE 1044 format)

```yaml
- id: JA4PROXY-2026-NNNN
  title: "One-line description"
  severity: MODERATE          # FAT/SEV/MOD/MIN/COS
  cwe: CWE-NNN                # Keep CWE for cross-reference
  ieee_1044:
    activity: COD              # COD/DES/TST/DOC/BUI/REQ
    type: ALG                  # ALG/DAT/IFC/LOG/PRF/STD/SYN/TMR/OTH
    severity: MOD              # FAT/SEV/MOD/MIN/COS
    cause: INC                 # AMB/INC/MIS/EXT/ICP/STD
  file: internal/foo.go:123
  title: "Description"
  description: >
    What the bug is and why it matters.
  impact: >
    What an attacker/user could achieve.
  regression_test: internal/foo_test.go:TestXxx
  remediation: >
    What the fix does.
  status: OPEN
  phase: 501a
```

## Execution order

1. **501a** — Algorithm correctness (highest security impact)
2. **501d** — Timing & lifecycle (builds on 500b concurrency work)
3. **501c** — Interface contracts (cross-component issues)
4. **501g** — Data integrity (config, Redis, backup)
5. **501b** — Design & architecture (broader refactoring opportunities)
6. **501e** — Test adequacy (coverage gaps)
7. **501f** — Documentation accuracy (lowest urgency)

All sub-phases are **independent** — work on multiple in parallel.

## Acceptance criteria

- [ ] Every finding has full IEEE 1044 classification (all 4 dimensions)
- [ ] Every confirmed bug has a regression test
- [ ] Every IEEE type category has at least one finding (coverage)
- [ ] Phase 500 findings re-classified under IEEE 1044
- [ ] `make lint` exits 0
- [ ] `make test` passes with zero regressions
- [ ] Expert critical review (security, concurrency, code quality)

## Out of scope

- Re-finding Phase 500 bugs (already tracked)
- Dependency CVEs (separate process)
- Performance benchmarking (separate phase)
- Third-party image issues
