# Phase 102 — Critical Review

**Reviewer:** Claude (Opus 4.6) — Senior Cyber / DevOps / SRE / Architect hat
**Date:** 2026-04-15
**Target:** `docs/phases/complete/PHASE_102.md` (423 lines, 9 gaps G1–G9, 8 sub-phases)
**Prerequisite:** Phase 93 — COMPLETE.
**Go / Python:** Go (external repo `/home/sean/LLM/terraform-provider-ja4proxy`).

---

## 0. Executive Summary — Phase 102 is Stale

**Phase 102 was authored against an in-tree `terraform-provider/` directory
that no longer exists in this repository.** The provider was extracted to
`/home/sean/LLM/terraform-provider-ja4proxy` as part of Phase 93/101 scope.
Most of the gaps Phase 102 enumerates **have already been implemented there**.

Verified against the external repo at 2026-04-15:

| Phase 102 gap | Status in external repo |
|---|---|
| G1 `protect_unmanaged_entries` in provider schema | **DONE** — `internal/provider/provider.go` already has `ProtectUnmanaged types.Bool` field with description |
| G3 `[terraform]` prefix on ban reason | **DONE** — 2 matches in `ban_resource.go` |
| G4 ban `ticket` + `ttl_hours` fields | **DONE** — 14 matches in `ban_resource.go` + tests |
| G5 dial `ticket` + `notes` | **DONE** — 5 matches in `dial_webhook.go` + 3 in tests |
| G7 CI workflows | **DONE** — `.github/workflows/{test,release}.yml` both present |
| G1 webhook `managed_by` | **DONE** — 22 matches in `list_resources.go` + tests |

**What is still open (in the main repo):**

| Gap | Status | Where |
|---|---|---|
| G6 ADR-093a, ADR-093b, ADR-093c | **NOT DONE** — `docs/decisions/` contains only ADR-094c/d | main repo |
| G9 `docs/runbooks/emergency_playbooks.md` audit | **UNVERIFIED** — doc exists from Phase 93 merge; not re-audited against current playbooks | main repo |
| G2 drift detection data source | **UNVERIFIED** — needs external-repo verification; not obvious from file listing | external repo |
| G8 ban TTL 24h near-expiry detection | **UNVERIFIED / probably LOW-defer** — optimisation not required for correctness | external repo |

**File-path divergence:** PHASE_102.md references `internal/resources/ban.go`,
`dial.go`, `webhook.go`, `allowlist_entry.go`, `blocklist_entry.go`,
`watchlist_entry.go`. The external repo has **merged** these into:
`ban_resource.go`, `dial_webhook.go`, `list_resources.go`. Every sub-phase
step that names a file will fail a junior engineer following it literally.

---

## 1. Verdict

**`/run-phase 102` must not be started against the current phase doc.**

The phase needs either:
- **(A) Rewrite** to reflect reality: narrow scope to (G2 re-verify, G6 ADRs,
  G9 runbook audit, G8 deferred), correct file paths, acknowledge that the
  provider repo is external, and re-ground cross-repo coordination.
- **(B) Close as COMPLETE-by-prior-work** (with `lessons_learned:` note)
  after a brief sweep confirms G2 and produces the three ADRs + runbook audit.

I recommend **(B)** — the real remaining work is ~2–4 hours of doc and
external-repo verification, not a MEDIUM-size phase.

---

## 2. Six-Lens Critical Review (Remaining Work Only)

### 2a. Security Review

- **G2 drift detection** is the only security-adjacent gap: without it, an
  operator can silently delete a `managed_by=terraform` entry via the UI and
  Terraform won't warn on next plan. This is a **defence-in-depth** gap, not a
  direct vulnerability. Verify against external repo; if missing, implement.
- No new secrets introduced. Provider token handling already validated in
  Phase 93.
- No new attack surface — the provider is an outbound-only IaC client.

### 2b. DevOps Review

- **Cross-repo coordination risk.** Phase 102 work splits across two git repos
  with no tooling to atomically update both. Any doc in `docs/decisions/`
  referencing external-repo line numbers will rot silently. Rule: keep
  main-repo docs at the level of *decision and contract*, not file lines.
- **Manifest duplicate `101:` key** (noted in PHASE_101_review.md) overlaps
  with 102 success criteria — both reference the provider. Reconcile manifest
  first.
- **Release workflow (G7)** claims DONE, but existence ≠ correctness. Verify
  that `release.yml` uses SHA-pinned actions per Phase 202 supply-chain policy
  (`tests/test_workflow_pinning.py` runs only against main-repo workflows;
  external repo has no equivalent gate — **new risk**).

### 2c. SRE Review

- No runtime/observability footprint from the remaining items (all doc /
  CI / external).
- **G9 playbook runbook audit** affects operator behaviour during incidents
  — worth doing even if low-severity.

### 2d. Architecture Review

- No new module boundaries. No Redis schema changes. No pipeline touch-points.
- Phase 102 was written as if the provider were in-tree; the architectural
  reality (external repo) must be reflected in ADR-093a.

### 2e. Testing Review

- Phase 102's "test strategy" (§3) lists Go tests that live in the external
  repo. Main-repo `make test` cannot run them. The acceptance-criteria line
  "make test-phase-93 passes" is correct only if `make test-phase-93` restricts
  itself to playbook static tests — verify.
- **No new main-repo tests needed** for remaining work beyond linting ADRs.

### 2f. Documentation Review

- **ADR-093a (repo topology):** now has something concrete to document —
  *the provider was extracted* — with the extraction procedure as evidence.
- **ADR-093b (Registry namespace):** decision probably already reflected in
  external repo's `go.mod` module path (`github.com/anomalyco/…`).
- **ADR-093c (TTL renewal):** document the "re-POST on apply is idempotent"
  decision; reference external-repo `ban_resource.go` by symbol name, not
  line number.
- Phase 102 acceptance criteria §3 includes
  "`docs/phases/manifest.yaml`: Phase 93 sub-phases 93.1–93.7 marked
  COMPLETE" — verify; Phase 93 already shows COMPLETE per top-level entry.
- Phase 102 success criteria duplicates Phase 101 H17 (provider repo push).
  Resolve ownership: 101 owns the *push*, 102 owns the *docs*.

---

## 3. Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | Phase doc premises obsolete (provider extracted) | **HIGH** | Architecture/Docs | Rewrite or close-by-prior-work |
| 2 | File paths in sub-phase steps are wrong | HIGH | Docs | Update to `{ban,list,dial_webhook}_resource.go` OR drop the steps entirely |
| 3 | External-repo release.yml may not be SHA-pinned | MEDIUM | DevOps/Security | Verify; if not, raise separate issue against external repo |
| 4 | G2 drift detection status not yet verified | MEDIUM | Security | 30-min sweep of external repo |
| 5 | Duplicate 101/102 ownership of "provider push" | LOW | Docs | Reconcile; 101 owns push, 102 owns ADRs |
| 6 | ADR-093a/b/c still missing in main repo | MEDIUM | Docs | Write them (~1h) |
| 7 | `emergency_playbooks.md` audit not performed | LOW | Docs | Diff against playbook YAML (~30m) |
| 8 | G8 ban TTL 24h auto-refresh | LOW | Feature | Defer — optimisation, not correctness |

No CRITICAL findings.

---

## 4. Recommended Sub-Task Decomposition (Narrowed)

Given the staleness of the phase doc, the honest decomposition is small.

### Group 0 — Pre-flight

#### Sub-task 0.1: Rewrite or narrow Phase 102 doc
**Size:** S (1-1.5h)
**Depends on:** none
**Files:** `docs/phases/complete/PHASE_102.md`
**What to do:**
- Replace §1 "Context" with the actual current state (provider is external).
- Mark G1, G3, G4, G5, G7, and G1-webhook as **closed-by-prior-work** with
  a verification pointer (git SHA in external repo).
- Retain G2 (verify), G6 (ADRs), G8 (defer), G9 (audit) as active work.
- Fix every file path in retained sub-phases (no `ban.go`, no `dial.go`).
- Update §5 implementation order and effort (≈3h, not 6h).
**Done when:**
- [ ] `make lint-phases` exits 0
- [ ] Phase doc reflects external-repo layout

### Group 1 — Verification (parallel-safe)

#### Sub-task 1.1: Verify G2 drift detection status
**Size:** XS (30m)
**Depends on:** 0.1
**Parallel with:** 1.2, 1.3
**Files:** (read-only) `/home/sean/LLM/terraform-provider-ja4proxy/internal/resources/list_resources.go`, `internal/data_sources/` if present
**What to do:**
- Grep for `ja4proxy_managed_entries`, `ModifyPlan`, `protect_unmanaged` usage.
- If drift-detection data source + PlanModifier exists: mark G2 closed-by-prior-work.
- If missing: file an issue in external repo and document as deferred in 102.
**Done when:**
- [ ] G2 status recorded in PHASE_102.md with pointer (external commit SHA or issue URL)

#### Sub-task 1.2: Verify external-repo CI workflows are SHA-pinned
**Size:** XS (15m)
**Depends on:** 0.1
**Parallel with:** 1.1, 1.3
**Files:** (read-only) external `.github/workflows/{test,release}.yml`
**What to do:**
- Inspect both workflows; confirm every `uses:` line is SHA-pinned per Phase 202.
- If not: file issue against external repo; do not treat as a 102 blocker.
**Done when:**
- [ ] Finding recorded in PHASE_102.md §Findings

#### Sub-task 1.3: Audit `docs/runbooks/emergency_playbooks.md` (G9)
**Size:** S (30-45m)
**Depends on:** 0.1
**Parallel with:** 1.1, 1.2
**Files:** `docs/runbooks/emergency_playbooks.md`, `deploy/ansible/playbooks/emergency/*.yml`
**What to do:**
- Read the 3 playbook YAML files; list each `vars:`, `tasks:` of note, abort-on-422 behaviour.
- Compare against runbook; amend runbook to match playbook reality.
- Run `python3 -m pytest tests/integration/test_emergency_playbooks.py -v` — 14 tests must pass.
**Done when:**
- [ ] Runbook lists all 3 playbooks with vars + safety constraints
- [ ] 14 playbook tests pass

### Group 2 — ADRs (parallel-safe, main-repo only)

#### Sub-task 2.1: ADR-093a — Repository topology
**Size:** XS (20m)
**Depends on:** 0.1
**Parallel with:** 2.2, 2.3
**Files:** `docs/decisions/ADR-093a-repository-topology.md` (new)
**What to do:**
- Context: provider was initially in-tree, extracted to
  `github.com/anomalyco/terraform-provider-ja4proxy` for Registry publication.
- Decision: separate repo, independent CI, independent release cadence.
- Consequences: cross-repo coordination cost; document contract boundary
  (Management API is the interface).
**Done when:** [ ] ADR file exists, formatted per project template

#### Sub-task 2.2: ADR-093b — Registry namespace
**Size:** XS (15m)
**Depends on:** 0.1
**Parallel with:** 2.1, 2.3
**Files:** `docs/decisions/ADR-093b-registry-namespace.md` (new)
**What to do:**
- Document chosen namespace (match external repo's `go.mod` module path —
  inspect, don't guess).
- Decision: self-published, no HashiCorp partner programme.
**Done when:** [ ] ADR file exists

#### Sub-task 2.3: ADR-093c — TTL renewal strategy
**Size:** XS (15m)
**Depends on:** 0.1
**Parallel with:** 2.1, 2.2
**Files:** `docs/decisions/ADR-093c-ttl-renewal-strategy.md` (new)
**What to do:**
- Document the "Update re-POSTs the ban, API's idempotent POST resets TTL"
  decision. Reference external-repo `ban_resource.go` by symbol, not line.
- Mark G8 (24h near-expiry auto-refresh) as deferred with rationale
  (user can run `terraform apply -refresh-only`).
**Done when:** [ ] ADR file exists; G8 explicitly deferred

### Group 3 — Close

#### Sub-task 3.1: Update manifest and close
**Size:** XS (15m)
**Depends on:** all above
**Files:** `docs/phases/manifest.yaml`, `CHANGELOG.md`
**What to do:**
- Set 102 status to COMPLETE with `completed: 2026-04-XX` and
  `lessons_learned: 'Phase doc was stale — scope was 85% pre-delivered in external provider repo.'`.
- Also fix the duplicate `101:` manifest key (coordinate with 101 review).
- One CHANGELOG entry summarising the narrow scope.
- `make sync`; `bash scripts/close-phase.sh`.
**Done when:** [ ] close-phase.sh exits 0

---

## 5. Blocking Items Before `/run-phase 102`

1. **User decision required:** rewrite phase doc (Sub-task 0.1) OR close as
   prior-work. Without this, `/run-phase` will spawn agents against a phase
   doc whose file paths don't exist — agents will flail.
2. **External repo authorization:** any writes to
   `/home/sean/LLM/terraform-provider-ja4proxy` must be explicit — PM must
   ask before pushing or committing there.

---

## 6. Totals

- **Sub-tasks (post-rewrite):** 8 (1 pre-flight + 3 verify + 3 ADRs + 1 close)
- **Estimated hours:** ~3h active (not 6h as the phase doc suggests)
- **Parallel-safe groups:** Groups 1 and 2 run concurrently after 0.1
- **Critical path:** 0.1 → (longest of Group 1/2) → 3.1 ≈ 1.5–2h
- **Risk:** the phase as written will actively mislead a junior engineer.
  Do not run `/run-phase 102` until Sub-task 0.1 is complete.

Written to: `docs/phases/complete/PHASE_102_review.md` for `/run-phase 102` to consume.
