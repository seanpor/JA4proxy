# JA4proxy Findings Register

> **Source of truth:** [`findings.yaml`](findings.yaml). This markdown file is
> a generated human-readable view. Regenerate with
> `python3 scripts/findings_register.py render`.

The findings register is the single canonical list of every security finding
the project has ever acknowledged — whether discovered by an internal pentest
campaign, an external red team, a vendor audit, or a routine code review. A
finding is opened once, fixed once, tested once, and closed once.

## Why this exists

Between April 2026 pentest campaigns and red team assessments, roughly 98
sub-phase entries accumulated across 13 separate phase documents with no
shared IDs and heavy duplication (see `docs/phases/PHASE_121.md` §1 for the
full context). The register collapses that pile into a managed backlog with
canonical IDs, unambiguous severity, SLA tracking, and a regression-test
requirement for closure.

## ID scheme

`JA4PROXY-YYYY-NNNN` where `YYYY` is the calendar year the canonical ID was
allocated (not the year of discovery — a finding discovered in 2024 and
canonicalised in 2026 is a 2026 ID). `NNNN` is a zero-padded monotonic
counter, never reused. IDs are allocated by `scripts/findings_register.py add`;
never assigned by hand.

## Workflow

```
           ┌──────┐ add       ┌─────────────┐ PR opened  ┌───────┐
report ──▶ │ OPEN │ ────────▶ │IN_PROGRESS  │ ─────────▶ │ FIXED │
           └──────┘           └─────────────┘            └───┬───┘
                                                             │ reviewer
                                                             │ verifies
                                                             ▼
                            ┌────────┐  14 days no    ┌──────────┐
                            │ CLOSED │◀───regression──│ VERIFIED │
                            └────────┘                └──────────┘
```

Promotion rules live in `docs/security/CLOSURE_VERIFICATION.md`. The key
enforcement rule is: **a finding cannot reach `CLOSED` without a populated
`regression_test` that exists and is green** (checked by `make verify-findings`).

## Severity and SLA

Severity labels are assigned per `docs/security/SEVERITY_RUBRIC.md`, not
copied from external CVSS scores. Each level carries an SLA measured from the
earliest `discovered` date across the finding's `source_refs`:

| Severity | SLA (fix → verified) |
|----------|----------------------|
| CRITICAL | 7 days fix / 14 days verified |
| HIGH     | 30 days |
| MEDIUM   | 60 days |
| LOW      | 120 days |

`scripts/findings_register.py list --sla-breach` returns all entries past
their `due` date.

## Lanes (owner split)

Findings are assigned to one of three lanes for ownership purposes, even
while a single engineer may hold all three hats:

| Lane | Scope |
|------|-------|
| `go-proxy` | Everything under `cmd/proxy/`, `cmd/syncagent/`, `cmd/ja4check/`, `cmd/ja4proxy-cli/`, `internal/` |
| `python-management` | `management/`, `src/analytics/`, `src/security/`, `src/tap/`, `src/tls/` |
| `infrastructure` | `Dockerfile*`, `docker-compose*.yml`, `deploy/`, `scripts/`, `.github/`, Jenkins, Redis config, HAProxy config |

Full ownership policy in `docs/security/OWNERSHIP.md`.

## Intake

When a new report arrives, follow `docs/security/INTAKE_RUNBOOK.md`. The
short version: run `dedup-hint` against each reported finding, append to an
existing canonical entry via `source_refs` if it's a duplicate, or `add` a
new canonical ID if it's novel.

## Schema

See header comments at the top of [`findings.yaml`](findings.yaml) for the
authoritative schema. Minimum required fields at creation time: `id`,
`title`, `severity`, `severity_rationale`, `source_refs`, `discovered`,
`due`, `status`, `lane`. Other fields populate as the finding moves
through the workflow.

## Migration plan

Markdown + YAML is fine up to ~100 canonical entries. When the register
exceeds 100 entries, migrate to a GitHub Projects board with custom fields
matching this schema and regenerate this markdown from the Projects API.
The migration trigger is documented in `INTAKE_RUNBOOK.md` so it does not
get forgotten.

---

<!-- BEGIN GENERATED: findings_register.py render -->

## Register snapshot (2026-04-19)

**Total:** 0 canonical finding(s).

| Severity | Count | Status | Count |
|----------|-------|--------|-------|
| CRITICAL | 0 | OPEN | 0 |
| HIGH | 0 | IN_PROGRESS | 0 |
| MEDIUM | 0 | FIXED | 0 |
| LOW | 0 | VERIFIED | 0 |
|  |  | CLOSED | 0 |
|  |  | DUPLICATE | 0 |

_No SLA breaches._

<!-- END GENERATED -->
