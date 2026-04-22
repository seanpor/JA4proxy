# JA4proxy Findings Ownership & RACI

> **Sub-phase:** 121g. **Source of truth for the `owner` and `lane` columns in
> `docs/security/findings.yaml`.**

## Concentration risk (acknowledged)

At the time this policy was written (2026-04-19), a single engineer holds
every lane defined below. Splitting ownership by lane now — even while the
same person holds all three hats — means the first hire drops into a clean
structure instead of triggering a rewrite. The concentration itself is a
documented risk:

> While all three lanes roll up to the same engineer, any CRITICAL finding
> that requires simultaneous remediation across lanes cannot be parallelised.
> Executive review is aware. Mitigation is to hire for one lane (recommended:
> `python-management`, the largest surface).

## Lanes

Every canonical finding has exactly one `lane`. The lane determines ownership,
escalation path, and which subject-matter reviewers are Consulted.

| Lane | Scope | Primary surfaces |
|------|-------|------------------|
| **`go-proxy`** | The Go production proxy and its CLI tooling. | `cmd/proxy/`, `cmd/syncagent/`, `cmd/ja4check/`, `cmd/ja4proxy-cli/`, `internal/` (all packages), Go-side Redis client, Go-side TLS parsing, Go PROXY protocol parser. |
| **`python-management`** | Everything Python that runs in production. | `management/` (FastAPI + UI backend), `src/analytics/` (analytics node + threat-intel feeds), `src/security/` (Python signal modules — experimental but still deployed), `src/tap/` (passive capture), `src/tls/`. Includes the Python proxy prototype (`proxy.py`) while it continues to exist, but fixes there do not block unless they also affect the Go proxy. |
| **`infrastructure`** | Build, deploy, and runtime platform outside the two service lanes. | `Dockerfile*`, `docker-compose*.yml`, `deploy/`, `scripts/`, `.github/workflows/`, Jenkins pipeline, HAProxy config, Redis config (including ACL files), Helm charts, systemd units, secret-management tooling. |

### Assigning a lane

- A finding touching both lanes (e.g. a fix requires coordinated changes in
  Go and Python) takes the lane of the **higher-risk surface**. Record the
  dual-lane nature in `notes`.
- A finding in a shared config file (`config/proxy.yml`, `config/*.yml`)
  takes the lane of the **consumer** that the fix primarily hardens.
- Infrastructure lane includes the Redis runtime config but not Redis *data*
  hygiene (unbounded keys, ACL misuse from a service) — those go to the
  consuming service's lane.

## RACI model

For every finding:

| Role | Who | What |
|------|-----|------|
| **R — Responsible** | The engineer whose `owner` appears on the register entry. | Writes the fix, adds the regression test, moves status OPEN → IN_PROGRESS → FIXED. |
| **A — Accountable** | The security lead. Currently `@seanpor` for every lane — documented as concentration risk above. | Approves severity classification, signs off on VERIFIED transition, owns SLA breaches. |
| **C — Consulted** | Subject-matter experts named per lane (see below). | Reviewed during PR; asked for advice on approach. |
| **I — Informed** | Release manager and the author of the originating source report. | Notified when the finding transitions FIXED and again when CLOSED. |

### Consulted list (by lane)

| Lane | Consulted (review-required roles) |
|------|-----------------------------------|
| `go-proxy` | Go release manager, Redis SME if Redis keys touched. |
| `python-management` | FastAPI maintainer, analytics lead if threat-intel touched, GDPR owner if DSAR paths touched. |
| `infrastructure` | Release manager, Docker/CI SME, on-call lead. |

All of these are the same engineer today. The policy is written for the
structure we want, not the structure we have.

## Escalation

| Trigger | Action |
|---------|--------|
| Fix PR open >14 days with no CI progress on a CRITICAL finding | Lane accountable pulls in extra hands from adjacent lanes. |
| SLA breached on a CRITICAL | Page on-call via the `#sec-ops` channel; annotate the register entry `breach_acknowledged: true` within 24h with a one-line reason. |
| SLA breached on a HIGH | Weekly security review. |
| Dispute over severity classification | A different engineer than the one who classified it re-reads the rubric and votes. Tie goes to the higher severity. |
| Dispute over lane assignment | Lane is decided by who will merge the fix PR. |

## Ownership transitions

- `owner` is set at creation by `scripts/findings_register.py add --owner=…`.
- Re-assigning ownership is a plain YAML edit, but must be accompanied by a
  `notes` line like `owner transferred 2026-04-19 from @x to @y (reason)`.
- An unassigned finding (`owner: ""`) for >7 days on a CRITICAL or >30 days
  on a HIGH triggers the escalation above.

## Relationship to other docs

- **`SEVERITY_RUBRIC.md`** defines severity; `OWNERSHIP.md` defines who owns
  each severity.
- **`CLOSURE_VERIFICATION.md`** defines the state machine; `OWNERSHIP.md`
  names who drives which transition.
- **`INTAKE_RUNBOOK.md`** defines how a new report enters the register;
  `OWNERSHIP.md` determines who receives the output of that intake.

## Hiring signal

When the register regularly exceeds an engineer's bandwidth (rule of thumb:
>10 simultaneous OPEN findings in one lane, or any breached CRITICAL for two
consecutive weeks), open a hiring requisition for that lane. Do not rebalance
across lanes without hiring — cross-lane rebalancing hides the concentration
risk rather than addressing it.
