# JA4proxy Finding Closure Verification Protocol

> **Sub-phase:** 121h. Defines the state machine every canonical finding in
> `docs/security/findings.yaml` follows, the evidence required at each
> transition, and the CI enforcement that keeps the protocol honest.

## Why this exists

Before Phase 121, "fixed" meant a PR merged with the word "security" in the
title. There was no consistent expectation that the fix was tested, that the
test was observed red on the vulnerable code, or that a second pair of eyes
re-ran the proof-of-exploit. The result was predictable: the same finding
reappeared in a later audit under a new ID, because the first "fix" had only
partially addressed it — or sometimes not at all.

Closure verification fixes this by making every status transition **cite
evidence** that lives in git or in the register, and by making the final
transition to `CLOSED` automatic (14-day cooling-off) rather than a judgement
call.

## The state machine

```
┌─────┐   PR opened      ┌─────────────┐  merge + test  ┌───────┐
│OPEN │ ────────────────►│IN_PROGRESS  │ ──────────────►│ FIXED │
└─────┘   references id  └─────────────┘  green         └───┬───┘
                                                            │
                                                independent │ reviewer
                                                re-exploits │ / reviews
                                                            ▼
┌────────┐  14d no regression   ┌──────────┐              ┌──────────┐
│ CLOSED │ ◄────────────────────│ VERIFIED │ ◄────────────┤(reviewer)│
└────────┘  promote-verified    └──────────┘              └──────────┘
```

Plus one terminal side-state:

```
 OPEN ─► DUPLICATE   (status set when another canonical ID subsumes this one;
                      supersedes[] must be non-empty)
```

### Transitions in detail

| From → To | Trigger | Required evidence in register | Enforced by |
|----|----|----|----|
| OPEN → IN_PROGRESS | Engineer opens a PR that references the canonical ID | `notes`: PR URL | Reviewer check + PR template (see §PR template) |
| IN_PROGRESS → FIXED | PR merges, regression test added and green | `regression_test` populated; `notes` records the merge SHA | `scripts/findings_register.py validate` rejects missing `regression_test` once status ≥ FIXED |
| FIXED → VERIFIED | An engineer **who did not write the fix** independently re-runs the original proof-of-exploit (or carefully reviews the fix against the original report) and records the result | `verified_by` (GitHub handle), `verified_on` (ISO date) | Not automatable; recorded in register, policed in review |
| VERIFIED → CLOSED | 14 calendar days elapse with no regression report that cites this finding | `closed_commit` (merge SHA); auto-set by `promote-verified` | `scripts/findings_register.py promote-verified` run nightly or on demand |
| OPEN/IN_PROGRESS → DUPLICATE | Triage concludes another ID subsumes this one | `supersedes: [<canonical-id>, ...]` | `validate` rejects DUPLICATE without non-empty `supersedes` |

### Why 14 days from VERIFIED to CLOSED

Half a day of grace is not enough — bugs resurface on the first production
traffic pattern that differs from the pre-prod test harness. Thirty days is
too long and gives the register chronic stale-VERIFIED entries. Fourteen
days covers the common "we only noticed on Monday" feedback cycle and one
full on-call rotation.

The window is configurable via `VERIFIED_TO_CLOSED_DAYS` in
`scripts/findings_register.py` — change it only with a security-lead
sign-off recorded in an ADR.

## Evidence fields

These fields already exist in the register schema and become load-bearing
under this protocol:

- `regression_test` — pytest nodeid or Go test path; **required** once
  status ≥ FIXED. See `docs/developer/TESTING_STRATEGY.md §6` for naming and docstring
  rules. `validate` checks the file exists on disk.
- `closed_commit` — the merge SHA at which the finding was closed. Required
  when `status == CLOSED`.
- `verified_by`, `verified_on` — optional new string fields used by step
  FIXED → VERIFIED. The `promote-verified` command refuses to advance to
  CLOSED unless both are populated on a VERIFIED entry.
- `notes` — free-text, preserves the red-commit reference ("first observed
  on commit abc123 of branch xyz") and any context reviewers need.

## Definition of Done for each transition

### OPEN → IN_PROGRESS

- A canonical ID is cited in the PR title or body.
- The owner in the register is set.
- No code evidence required — this is a bookkeeping move.

### IN_PROGRESS → FIXED

All of:

1. PR merged to `main` (or the phase branch that will merge to main).
2. A regression test exists at the path stored in `regression_test`.
3. The test is **observably green** on the merge commit — proven by
   `make verify-findings-green` passing on that SHA.
4. The test was **observably red** before the fix — proven by either (a)
   committing the test alone before the fix and running it, or (b) noting
   in `notes` the commit/branch at which it failed.
5. If the fix changes Redis keys, log format, or metric names, the relevant
   cross-cutting docs (`REDIS_SCHEMA.md`, `OBSERVABILITY_STANDARDS.md`) are
   updated in the same PR.

### FIXED → VERIFIED

All of:

1. A second engineer (not the PR author) re-runs the proof-of-exploit or
   reviews the diff against the source finding(s) in `source_refs`.
2. They record `verified_by: @handle` and `verified_on: YYYY-MM-DD` in the
   register.
3. If they cannot reproduce the vulnerability on the pre-fix code either,
   they still verify — but add a `notes` entry flagging the low-confidence
   verification, so the 14-day window is scrutinised more carefully.

**Rubber stamping is a protocol violation.** A verifier who did not actually
run or read the fix must not sign off. This rule is social, not automated,
but is auditable: `git log --author=<verifier>` on the fix branch should
show activity around the verification date, or the verifier should be able
to show their re-exploit transcript.

### VERIFIED → CLOSED

All of:

1. Fourteen calendar days have passed since `verified_on`.
2. No regression report filed in that window that cites this canonical ID or
   its `source_refs`.
3. `closed_commit` is set (the merge SHA of the fix PR).
4. `scripts/findings_register.py promote-verified` performs the transition.
   Do not hand-edit `status: CLOSED` into the YAML — the CLI preserves the
   audit trail and sets any missing fields consistently.

## PR template

Every PR that touches security-sensitive code must declare one of:

- **A canonical finding ID** that the PR addresses (`JA4PROXY-YYYY-NNNN`).
- **"No finding"** when the PR is a net-new feature or refactor with no
  security-finding motivator.
- **"Finding TBA"** when the PR is an emergency fix and the finding will be
  back-filled into the register within 48 hours of merge.

See `.github/PULL_REQUEST_TEMPLATE.md` for the canonical form.

### What counts as "security-sensitive"

A PR is security-sensitive if it changes any of:

- `internal/security/**`, `internal/pipeline/**`, `internal/proxyproto/**`,
  `internal/tls/**`, `internal/redis/**` (Go production proxy).
- `src/security/**`, `src/tap/**`, `proxy.py` (Python prototype proxy).
- `src/mgmt/**` (FastAPI management plane).
- `config/proxy.yml` bypass toggles, TLS settings, or rate-limit defaults.
- Any file under `tests/pentest/` or `internal/security/pentest/` (the
  regression test lane).
- `docs/security/**`, `docs/decisions/**`, `docs/phases/PHASE_1[0-2][0-9].md`
  (governance docs that are themselves the controls).

This is the list the CI check (below) consults. Extend it as the codebase
grows; remove from it only with a security-lead sign-off recorded in an ADR.

## CI enforcement (spec)

The intent is a lightweight GitHub Actions job that runs on every PR:

1. **Detect security-sensitive changes.** Pass the merge-base diff against
   the security-sensitive path list above. If no match, exit 0 immediately.
2. **Scan the PR body + title + commit messages for one of:**
   - `JA4PROXY-\d{4}-\d{4}` (canonical ID), or
   - `No finding` (case-insensitive, must appear in PR body), or
   - `Finding TBA` (case-insensitive).
3. If none match, fail with a comment pointing at this runbook.
4. If a canonical ID is cited, call `scripts/findings_register.py show <id>`
   and assert the finding exists and is not already CLOSED.
5. Run `make verify-findings` to assert the register is internally consistent.
6. Run `make verify-findings-green` to assert no existing regression test is
   broken by the diff.

The check must be **advisory** (warning comment) for the first 30 days after
the protocol lands, then switched to **required** on the `main` branch. This
gives contributors time to adjust PR habits before merges start being
blocked.

### Implementation notes

- The detection can be a shell script under `scripts/ci/check_finding_citation.sh`
  driven by `gh pr view --json body,title` or `${{ github.event.pull_request.body }}`.
- "No finding" is an explicit opt-out, not a silent default — we want to
  see someone have to type it for a change that genuinely has no security
  implications.
- "Finding TBA" is the emergency hatch. It **must** be tracked: a follow-up
  check 48 hours later scans merged PRs with "Finding TBA" in their body
  and files a GitHub issue if no canonical ID was subsequently added.

## Failure modes and escalation

| Symptom | Diagnosis | Response |
|--------|----------|---------|
| Finding stuck in IN_PROGRESS past its SLA | Owner blocked or unassigned | Security lead reassigns; escalate to `#sec-ops` if > 7d past SLA |
| Finding stuck in FIXED (never verified) | No second engineer available | Rotate verification onto the oncall queue; verify within 5 business days of FIXED |
| Regression test exists but was never observed red | Protocol violation | Require a demonstration PR that reverts the fix, shows the test fail, then reinstates |
| Finding closed without a regression test (legacy) | Pre-protocol closure | Annotate `notes: "pre-121h closure"`; file a HIGH-priority follow-up to back-fill the test |
| `promote-verified` refuses to advance a VERIFIED finding | Missing `closed_commit`, `verified_by`, or `verified_on` | Populate the missing field; never hand-edit `status: CLOSED` |
| Finding reappears under a new canonical ID after CLOSED | Protocol failure: either verification was superficial or the fix regressed | Reopen the original ID (`CLOSED → OPEN`), link the new report to it via `source_refs`, and write a post-mortem |

## Relationship to other docs

- `SEVERITY_RUBRIC.md` — how `severity` is classified, which sets the SLA
  that `due` enforces.
- `OWNERSHIP.md` — who the `owner` is and who acts as the verifier.
- `INTAKE_RUNBOOK.md` — how findings get to `status: OPEN` in the first
  place.
- `docs/developer/TESTING_STRATEGY.md §6` — what the regression test looks like and
  where it lives.
- `scripts/findings_register.py` — validates every rule above; the source
  of truth for the state machine's implementation.
