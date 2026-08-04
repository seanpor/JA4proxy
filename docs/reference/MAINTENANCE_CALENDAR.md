<!--
title: "Maintenance Calendar"
audience: reference
last_reviewed: 2026-08-04
phase: 814
-->

# JA4proxy — Maintenance Calendar

> **What this is:** every recurring obligation in one place — what runs, when,
> whether a machine or a human does it, and **what silently rots if it is
> skipped**. Written because recurring work that lives only in a cron
> expression is invisible until the day it breaks.
>
> **What this is not:** a service-level commitment. Every cadence here is an
> internal best-effort intention for a self-funded project with no on-call
> rotation. Per [`CVD_POLICY.md`](../security/CVD_POLICY.md) the project makes
> no external commitment on response or fix timelines, and nothing in this
> document creates one.

## How to read this

| Column | Meaning |
|---|---|
| **Who** | 🤖 automated (a workflow runs it) · 🧑 human (someone must act) · 🤖→🧑 automated, but opens something a human must review |
| **If skipped** | The actual failure mode — not "it would be bad", but what breaks and how you find out |

Two audiences, separated below because they rarely overlap: **project
maintenance** (the repository, CI, security posture) and **deployment
operations** (a running JA4proxy install). Skip to the one you own.

---

## Part 1 — Project maintenance

### Continuous — every pull request

| Task | Who | If skipped |
|---|---|---|
| Full lint, full test, meta-validation, security scan (the four required checks) | 🤖 `ci.yml` | `main` is branch-protected; a PR simply cannot merge. This is the backstop everything else assumes |
| `pentest_*` regression corpus (Go) + `tests/adversarial/` (Python) | 🤖 `ci.yml` | A previously-fixed vulnerability regresses undetected |
| Findings-register integrity (`make verify-findings`) | 🤖 `ci.yml` | Register drifts: findings ≥ `FIXED` without a `regression_test`, broken references. **Wire this in if it is not there yet** — an integrity gate nobody runs is not a gate |
| PoC cold-start smoke test (on touched paths) | 🤖 `ci.yml` | Bootstrap bugs reach the nightly run instead of the PR that caused them (the Phase 809/812/813 failure mode) |

### Daily

| Time (UTC) | Task | Who | If skipped |
|---|---|---|---|
| 03:17 | Nightly performance/load benchmark vs baseline | 🤖 `nightly-benchmark.yml` | Hot-path latency/throughput regressions land unnoticed; no signal until someone benchmarks by hand |

### Weekly

| Time (UTC) | Task | Who | If skipped |
|---|---|---|---|
| Mon 06:00 | CVE sweep across all scanned images | 🤖 `ci.yml` scheduled run | Newly published CVEs sit unnoticed in shipped images |
| Wed 05:00 | `.trivyignore` proactive renewal — opens a PR ~5 days before the earliest expiry | 🤖→🧑 `trivyignore-renewal.yml` | Exceptions expire in a cluster and redden `Security Scan` on `main` **and every open PR at once**, for reasons unrelated to those PRs |
| Sat 01:30 | OpenSSF Scorecard | 🤖 `scorecard.yml` | Supply-chain posture score drifts down silently |
| — | Extended fuzz run against the pentest range | 🧑 (proposed) | Deep parser bugs need hours of fuzzing; PR-time smoke runs will not find them |
| — | Attack-surface drift check (`ATTACK_SURFACE.md`) | 🤖 (proposed) | New listeners/routes/workflows appear with nobody noticing they were never security-tested |

### Monthly

| When | Task | Who | If skipped |
|---|---|---|---|
| 1st, 06:00 UTC | Process metrics roll-up | 🤖 `process-metrics.yml` | No trend data on how the project is actually running |
| Monthly | Dependabot bumps: GitHub Actions, pip, gomod, Docker (7-day cooling-off per ecosystem) | 🤖→🧑 `dependabot.yml` | Dependencies age; the gap between "CVE published" and "we ship the fix" grows |
| Monthly | Review open `EXCEPTIONS.md` entries approaching expiry | 🧑 | An accepted risk quietly becomes permanent — the precise way findings disappear |

### Quarterly

| Task | Who | If skipped |
|---|---|---|
| **Pentest delta cycle** — workstreams covering whatever changed that quarter ([`PROGRAMME.md`](../security/pentest/PROGRAMME.md) §15) | 🧑 | Coverage decays exactly as it did between 2026-04-16 and 2026-08-04: new components ship with no adversarial attention at all |
| Re-verify a sample of already-`FIXED` findings (two-state proof, `PROGRAMME.md` §10.4) | 🧑 | "Fixed" stays an assertion; a regressed CRITICAL looks identical to a fixed one |
| Credential rotation — Redis ACL, AbuseIPDB key, cloud storage IAM (90 days, [`credential_rotation.md`](../runbooks/credential_rotation.md)) | 🧑 | Long-lived credentials; a leak from a year ago is still valid |
| Documentation review sweep — `last_reviewed` older than ~2 quarters | 🧑 | Docs drift from code; the Phase 309/340 audits exist because this was skipped |
| Engineering-method retrospective ([`retrospectives/`](../engineering-method/retrospectives/)) | 🧑 | Process problems recur instead of being fixed once |

### Annual

| Task | Who | If skipped |
|---|---|---|
| **Full pentest cycle** — every workstream, full report, KPI baseline | 🧑 | The only thing that answers "what has never been tested?" stops being answered |
| Method retrospective + amendment of [`PROGRAMME.md`](../security/pentest/PROGRAMME.md) §16 | 🧑 | The method stops improving and calcifies around its original blind spots |
| Threat-model refresh ([`threat-model.md`](../security/threat-model.md)) | 🧑 | Tests keep deriving from an out-of-date model of the adversary |
| Review this calendar against reality | 🧑 | It becomes aspirational fiction — the standard fate of maintenance calendars |

### Event-driven — not on a clock

| Trigger | Task |
|---|---|
| New component, new trust boundary, or new external interface | Targeted pentest workstream before it ships |
| CRITICAL found anywhere in a class | Re-run that class's workstream across the codebase (`PROGRAMME.md` §11 Q3) |
| External vulnerability report | [`INTAKE_RUNBOOK.md`](../security/INTAKE_RUNBOOK.md) → the standard three-pass lifecycle |
| Finding affects a **released** artefact | [`CVD_POLICY.md`](../security/CVD_POLICY.md); decide explicitly whether an advisory is published |
| `main` goes red | [`main_is_red.md`](../runbooks/main_is_red.md) |

---

## Part 2 — Deployment operations

For teams **running** JA4proxy. The operator source of truth is
[`OPERATIONS_GUIDE.md`](../operations/OPERATIONS_GUIDE.md); this is the
recurring subset.

| Cadence | Task | Runbook | If skipped |
|---|---|---|---|
| Continuous | Alert response (block-rate spike, node unhealthy, Redis latency, tarpit pool full, dial change) | [`runbooks/`](../runbooks/) | — |
| Weekly | Review dial setting vs observed score distribution | [`OPERATIONS_GUIDE.md`](../operations/OPERATIONS_GUIDE.md) | The dial stays where someone left it during an incident |
| Monthly | GeoIP / ASN database refresh (`make update-geoip`) | [`feed_management.md`](../runbooks/feed_management.md) | Stale database → inaccurate country and ASN lookups → **wrong scoring decisions**, which for this product means false positives |
| Monthly | Threat-intel feed health check | [`feed_management.md`](../runbooks/feed_management.md) | A dead feed fails open and nobody notices the coverage loss |
| Quarterly | Credential rotation (90 days) | [`credential_rotation.md`](../runbooks/credential_rotation.md) | See above |
| Quarterly | **Restore drill** — actually restore a backup, do not just check it exists | [`backup_restore.md`](../runbooks/backup_restore.md) | An untested backup is a hypothesis. Discovering it does not restore during an incident is the worst possible time |
| Quarterly | Game-day exercise | [`gameday_scenarios.md`](../runbooks/gameday_scenarios.md) | Runbooks rot; the first person to test one should not be doing it under pressure |
| Semi-annual | Disaster-recovery rehearsal | [`disaster_recovery.md`](../runbooks/disaster_recovery.md) | DR plan is untested |
| Ongoing | Certificate expiry (alert-driven, not calendar-driven) | [`ja4proxy_certificate_expiring.md`](../runbooks/ja4proxy_certificate_expiring.md) | Expiry outage |
| Per release | Review upgrade notes before upgrading | [`UPGRADE_PATH.md`](../operations/UPGRADE_PATH.md) | Breaking change lands unannounced |

---

## Scheduling notes

Automated jobs are deliberately spread so they do not collide or mask each
other:

```
Mon 06:00  CVE sweep  ─┐
Wed 05:00  .trivyignore renewal  (mid-week: slack before the Monday sweep,
                                  away from the weekend gap)
Sat 01:30  Scorecard              ─┘
Daily 03:17 Benchmark (off-peak, offset from the Monday 06:00 sweep)
1st 06:00  Process metrics
```

When adding a scheduled workflow: pick a slot that does not collide, note it
here, and make sure it **reports its own failure** — a scheduled job that fails
silently is worse than no job, because it manufactures false confidence. The
`notify-scheduled-failure` pattern in `ci.yml` is the model.

## Keeping this honest

A calendar nobody checks is worse than none — it converts unknown risk into
*believed-covered* risk. Two safeguards:

1. **The annual review is on the calendar itself** (above). Any row that has not
   actually happened gets deleted or fixed, not quietly carried forward.
2. **Rows marked "(proposed)" are not yet real.** They are intentions from
   Phase 814's planning, and they stay labelled until the automation exists or
   the human task has been done at least once. Do not read a proposed row as
   coverage.
