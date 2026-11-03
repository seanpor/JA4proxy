<!--
title: Unblock Dependabot Queue & Remediate pyasn1 CVE Baseline Issues
audience: developer
last_reviewed: 2026-11-01
phase: 859
-->

# Unblock Dependabot Queue & Remediate pyasn1 CVE Baseline Issues

> **Size:** SMALL
> **Dependencies:** [855]
> **Branch:** `phase-859-unblock-dependabot-cve-triage`
> **Follow-ups:** [860] (python-dependencies reconciliation, PR #682), [861] (Python 3.15 migration)

---

## Goal

Clear the 4 open CVE-baseline issues (#672–#675) and unblock the 7 open
Dependabot PRs (#676–#682) **with the smallest possible first-party diff**,
letting each Dependabot PR land on its own merits rather than being
consolidated into one large superseding PR.

This document records the plan **and** the outcome: see
[Implementation Results](#implementation-results) and
[Differences from Original Plan](#differences-from-original-plan).

---

## Background (verified 2026-11-01)

| Item | What it is | Why it is blocked / open |
|---|---|---|
| #672–#675 | `[cve-baseline]` CVE-2026-119194..119197 (HIGH), `pyasn1 0.6.4` in `image:ja4proxy-management`; fix 0.6.5 | Unwaived finding raised by `scan-baseline-monitor.yml`. Pinned at `management/requirements.txt:19`; required as a direct dependency of `webauthn==3.0.0` and `pyasn1_modules` under rule JA4PROXY-2026-0044. Cannot be deleted without floating transitive pins. Must be bumped to `0.6.5`. |
| #676 | Go deps (8 updates) | Only failure: lychee **timeout** on `https://ico.org.uk/for-organisations/guide-to-data-protection/` (`docs/compliance/GDPR_COMPLIANCE.md:747`). Every PR is exposed to this flake. |
| #677 / #678 / #680 | `python:3.14.6-alpine3.24 → 3.15.0-alpine3.24` (`/src/tarpit`, `/src/analytics`, `/deploy/docker`) | Out of policy (prod targets 3.14.*). Worse than a build break: the hardening step `rm -rf /usr/local/lib/python3.14/...` (`Dockerfile.management:32`, `Dockerfile.test:48`, `src/analytics/Dockerfile:33`) becomes a **silent no-op** on 3.15, shipping pip/ensurepip/setuptools in runtime images. |
| #679 | `alpine 3.24.2 → 3.24.3` (`/deploy/docker`) | `scripts/sync_reference_docs.py --check` drift (generated base-image table); Dependabot does not run `make sync`. |
| #681 | GitHub Actions (7 updates) | All checks green; `BLOCKED` on required human review (`enforce_admins` on — an agent cannot satisfy it). |
| #682 | python-dependencies (26 updates) | `ResolutionImpossible`: `semgrep>=1.182.1` (requirements.txt:21) pins `jsonschema~=4.25.1` and `mcp==1.29.0`; PR bumps `jsonschema==4.26.0` and `mcp>=2.3.0`; also a protobuf major (5 → 7). **Deferred to Phase 860.** |

---

## Scope

1. **Lychee flake (affects every PR).** Harden `.github/workflows/docs-link-check.yml`
   with `--timeout 30 --max-retries 3`, update the retired ICO URL to its current
   UK GDPR guidance page, and update the workflow header comment to state the
   timeout policy. No domain-wide exclusion.
2. **pyasn1 (#672–#675).** Audit dependencies of `ja4proxy-management`. Confirmed
   `webauthn==3.0.0` strictly requires `pyasn1>=0.6.2` and `pyasn1_modules>=0.4.2`.
   Under repository rule JA4PROXY-2026-0044, dependencies must be pinned exactly.
   Bump `pyasn1==0.6.5` in `management/requirements.txt` to clear the 4 HIGH CVEs.
3. **Dependabot policy (`.github/dependabot.yml`).**
   - Ignore `python` `versions: [">=3.15.0"]` for `/deploy/docker`, `/src/analytics`,
     `/src/tarpit` (3.14.x patch bumps still flow). Dated comment pointing at Phase 861.
   - Ignore the semgrep-coupled pins (`jsonschema >=4.26`, `mcp >=1.30`) following the
     existing `pip-audit` precedent, with a comment pointing at Phase 860.
4. **Register follow-ups** 860 and 861 as `PROPOSED` in the manifest with stub docs.
5. **Changelog fragment** `docs/fragments/phase-859-unblock-dependabot-cve-triage.md`.
6. **Post-merge Dependabot handling** (no first-party code):
   - #676, #681 → `@dependabot rebase`; merge on green (#681 needs human approval).
   - #679 → push a `make sync` commit onto the Dependabot branch (or a tiny superseding PR if that fails).
   - #677 / #678 / #680 → close with a comment citing the ignore rule and Phase 861.
   - #682 → close with a comment pointing at Phase 860.

### Security process note
Third-party image CVEs follow the **waivers + baseline** path
(`security/waivers.yaml`, `security/baseline.json`, `scan-baseline-monitor`), not the
first-party findings register — precedent: CVE-2026-30922 (pyasn1, Phase 800) has no
`findings.yaml` entry. The HIGH-severity **self-review checklist** from AGENTS.md is still
completed in the PR body (propagation sweep + scan evidence).

---

## Implementation Plan

1. Manifest: 859 `IN_PROGRESS`; add 860/861 `PROPOSED` + stub docs. `make lint-phases`.
2. Lychee: timeout/retry args, ICO URL update, header comment.
3. pyasn1: build `ja4proxy-management`, run the reverse-dependency check, then delete or bump.
4. `dependabot.yml`: python ≥3.15 ignores (3 dirs) + semgrep-coupled pip ignores.
5. Fragment; `make sync` (expect no drift); `make preflight` green.
6. PR with `Refs #672 #673 #674 #675` + HIGH self-review checklist; auto-merge.
7. Post-merge: trigger `scan-baseline-monitor` via `workflow_dispatch`; confirm it closes #672–#675.
8. Work the Dependabot PRs per Scope §6.
9. Fill in Results / Differences tables; move doc to `complete/`, manifest `COMPLETE` (close-out PR).

---

## Test Strategy

- **Image scan (the real gate for pyasn1):** rebuild `ja4proxy-management`; `make scan-regression`
  (and trivy on the image) → 0 unwaived HIGH/CRITICAL; `security/baseline.json` unchanged or
  regenerated deliberately.
- **Management test suite** passes in-container (proves deleting the pin breaks nothing at import/runtime).
- **Lychee:** run the link-check workflow on the PR (`workflow_dispatch`) — green.
- **Dependabot config:** `tests/` YAML/semgrep `dependabot-missing-cooldown` checks pass in `make lint`.
- **`make preflight`** (lint + scan + test, incl. `test-race`) green; `make lint-phases` 0 violations;
  `make sync` no drift.
- No decorative version-assertion test is added (it would only fail if the same line were edited;
  the scan is the meaningful regression gate).

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|---|---|
| A1 | `ja4proxy-management` image has 0 unwaived HIGH/CRITICAL | Local `docker build` + Trivy scan & post-merge monitor |
| A2 | #672–#675 closed by the monitor and not reopened | `gh workflow run scan-baseline-monitor.yml -f apply=true` post-merge |
| A3 | Lychee job green on this PR with no domain-wide exclusion | CI run URL |
| A4 | Dependabot ignores in place; 3.14.x patch bumps still allowed | `dependabot.yml` diff review |
| A5 | Per-PR end state recorded for #676–#682 (merged / closed-with-comment / deferred-to-N) | Results table below |
| A6 | `make preflight`, `make lint-phases`, `make sync` (no drift) all green | local + CI |
| A7 | Phases 860 / 861 registered as `PROPOSED` | manifest |

---

## Out of Scope

- Reconciling PR #682's 26 Python bumps (→ Phase 860).
- Migrating any image or the tools image to Python 3.15 (→ Phase 861).
- Automating `make sync` on Dependabot branches (noted as a candidate in Phase 861 / future).
- Any proxy runtime / TLS logic change.

---

## Implementation Results

*Populated during execution.*

| Item | Planned action | Actual action | PR / commit | CI / evidence |
|---|---|---|---|---|
| #672–#675 | delete or bump pyasn1 | | | |
| Lychee flake | timeout/retry + URL update | | | |
| dependabot.yml | py≥3.15 + semgrep-coupled ignores | | | |
| #676 | rebase, merge on green | | | |
| #677 / #678 / #680 | close (policy) | | | |
| #679 | `make sync` commit, merge | | | |
| #681 | rebase, human approve, merge | | | |
| #682 | close → Phase 860 | | | |

---

## Differences from Original Plan

*Populated during execution. Includes changes made after the 2026-11-01 expert review.*

| Planned | Actual | Reason | Follow-up |
|---|---|---|---|
| (draft v1) One consolidated PR superseding all 7 Dependabot PRs, numbered 856 | Small unblocker PR + per-PR handling; renumbered to 859 | Expert review: blast radius / bisectability; 856 was already allocated to telemetry smoke tests | — |
| (draft v1) Bump pyasn1 + version-assertion test | Reverse-dep check → delete or bump; scan is the gate | Review: pin likely orphaned; version test decorative | — |
| (draft v1) Exclude `ico.org.uk` domain from lychee | Timeout/retry + updated URL | Review: domain exclusion hides future rot; link returns fast 403 (accepted) locally | — |
| (draft v1) Reconcile #682 in this phase | Deferred | Root cause is semgrep's pins on jsonschema/mcp + protobuf major | 860 |
