# Phase 102 — Phase 93 Finishing Work: ADRs, Runbook Audit, Drift-Detection Decision

> **Status:** PROPOSED
> **Size:** SMALL (≈3 hours of focused work)
> **Dependencies:** Phase 93 (COMPLETE)
> **Parent:** Phase 93 (Terraform Provider + Emergency Runbook Playbooks)

## Why this phase exists

Phase 93 delivered a working Terraform provider. The phase doc originally
listed ~40% of its acceptance criteria as DEFERRED/PARTIAL. Subsequent work
(in the **external provider repo** at `/home/sean/LLM/terraform-provider-ja4proxy`)
closed most of those gaps — `protect_unmanaged_entries`, `[terraform]` reason
prefix, `ticket`/`ttl_hours`/`notes` fields, `PlanModifiers`, 24h-near-expiry
TTL renewal, and SHA-pinned CI workflows are all in place.

What remains is **hygiene**: three ADRs that were promised but never written,
a runbook audit, a README refresh, and one architectural decision to
**document and close**: whether to add a drift-detection data source
(decision: no — `PlanModifiers` + `protect_unmanaged_entries=true` default
are sufficient).

> **Important:** This phase touches **two repositories**:
> - `/home/sean/LLM/JA4proxy` (this repo) — docs, runbook, README, manifest
> - `/home/sean/LLM/terraform-provider-ja4proxy` (external repo) — verification only; no code changes planned in this phase
>
> No code changes land in the external repo during Phase 102. Every task below is doc-only.

## Verified current state (2026-04-15, external repo HEAD `17da9ea`)

| Item originally in Phase 93 backlog | Status | Evidence |
|---|---|---|
| `protect_unmanaged_entries` provider field | **DONE** | `internal/provider/provider.go:31,68,118`. Default is **true** (safer than the originally-proposed false). |
| `[terraform]` reason prefix on ban | **DONE** | `ban_resource.go` |
| Webhook `managed_by` on create | **DONE** | `list_resources.go` |
| Ban `ticket` + `ttl_hours` fields | **DONE** | `ban_resource.go` |
| Dial `ticket` + `notes` fields | **DONE** | `dial_webhook.go` |
| Ban 24h near-expiry auto-renewal | **DONE** | `ban_resource.go:46,64,170` |
| PlanModifiers on list resources | **DONE** | `list_resources.go:61,68,261,268,461,468` |
| CI `test.yml` + `release.yml` | **DONE**, SHA-pinned | `.github/workflows/` |
| `ja4proxy_managed_entries` data source | **NOT PRESENT** | `provider.go:150` — `DataSources()` returns empty slice |
| ADR-093a/b/c in main repo | **MISSING** | `docs/decisions/` contains only 094c/094d |
| `docs/runbooks/emergency_playbooks.md` | **EXISTS but not audited** | created at Phase 93 merge |
| `deploy/terraform/README.md` | **EXISTS** | needs refresh to document `protect_unmanaged_entries` default=true |

**Decision on drift-detection data source (G2 in the prior phase doc):**
Close as **"architectural choice, not a gap"**. Rationale captured in
ADR-093c. The combination of `PlanModifiers` + `protect_unmanaged_entries`
default-true already prevents out-of-band deletions from being silently
reapplied. A data source would be additive, not corrective. Deferring keeps
the provider surface minimal and avoids committing to a contract we don't
need yet.

---

## Sub-phase index

| ID | Title | Size | Repo | Depends on | Parallel |
|---|---|---|---|---|---|
| **102a** | Write ADR-093a: Repository topology | XS (20m) | main | none | 102b, 102c, 102d |
| **102b** | Write ADR-093b: Terraform Registry namespace | XS (15m) | main | none | 102a, 102c, 102d |
| **102c** | Write ADR-093c: TTL renewal + drift-detection decision | XS (20m) | main | none | 102a, 102b, 102d |
| **102d** | Audit `emergency_playbooks.md` against playbook YAML | S (30–45m) | main | none | 102a, 102b, 102c |
| **102e** | Refresh `deploy/terraform/README.md` | XS (20m) | main | 102a, 102b, 102c | — |
| **102f** | Reconcile manifest + close phase | XS (15m) | main | 102a–102e | — |

Total: 6 small tasks, one critical path (102a–d parallel → 102e → 102f).

---

## Sub-task 102a — ADR-093a: Repository topology

**Size:** XS (20 min)
**Files to touch:** `docs/decisions/ADR-093a-repository-topology.md` (new)
**Depends on:** none. **Parallel with:** 102b, 102c, 102d.

**What to do**
1. Copy the structure of an existing ADR (e.g. `docs/decisions/ADR-094c.md`) as a template.
2. Fill in these sections:
   - **Context** — the provider was initially drafted in-tree in Phase 93 but was extracted to `/home/sean/LLM/terraform-provider-ja4proxy` (external GitHub: `github.com/anomalyco/terraform-provider-ja4proxy`) to enable independent versioning and Terraform Registry publication. Module path: `github.com/anomalyco/terraform-provider-ja4proxy` (verified in external `go.mod`).
   - **Decision** — provider lives in a separate repo. Contract boundary between the two repos is the Management API (versioned, tested). Main repo documents decisions; external repo owns implementation.
   - **Consequences** — cross-repo coordination overhead; two CI systems; ADRs in main repo must reference external symbols by name, never by line number.
   - **Status** — Accepted, 2026-04-15.
3. Do **not** reference external-repo line numbers (they rot silently across the repo boundary).

**Done when**
- [ ] File exists and follows the ADR template format
- [ ] `grep -r "ADR-093a" docs/` returns at least the new file (referenced from any index)
- [ ] `make lint-phases` (if it covers ADRs) or `markdownlint docs/decisions/` exits 0

**Watch out for**
- Don't invent facts about Registry submission dates — if you don't know, write "pending" and link ADR-093b.

---

## Sub-task 102b — ADR-093b: Terraform Registry namespace

**Size:** XS (15 min)
**Files to touch:** `docs/decisions/ADR-093b-terraform-registry-namespace.md` (new)
**Depends on:** none. **Parallel with:** 102a, 102c, 102d.

**What to do**
1. Read `/home/sean/LLM/terraform-provider-ja4proxy/go.mod` to confirm the exact module path. Use that path in the ADR rather than guessing.
2. Fill in:
   - **Context** — Terraform Registry requires a namespace. HashiCorp Partner Programme requires legal paperwork; self-publish route does not.
   - **Decision** — self-publish under the org/namespace reflected in the external repo's `go.mod` (verify: `github.com/anomalyco/terraform-provider-ja4proxy`). No HashiCorp partner status pursued at this time.
   - **Consequences** — users add the provider via explicit `source = "anomalyco/ja4proxy"` (or whatever the Registry canonicalises to); no partner badge; release process is goreleaser-driven (see external `.github/workflows/release.yml`).
   - **Status** — Accepted, 2026-04-15.

**Done when**
- [ ] File exists
- [ ] Module path in ADR matches `go.mod` exactly

**Watch out for**
- The GitHub org name and the Registry namespace are not always identical. Document what has actually been registered (or "pending registration" if not yet submitted). Do not invent.

---

## Sub-task 102c — ADR-093c: TTL renewal + drift-detection decision

**Size:** XS (20 min)
**Files to touch:** `docs/decisions/ADR-093c-ttl-renewal-and-drift-detection.md` (new)
**Depends on:** none. **Parallel with:** 102a, 102b, 102d.

**What to do**
1. Document two related decisions in one ADR:
   - **TTL renewal:** `ja4proxy_ban.Update` re-POSTs the ban; the Management API's idempotent POST resets the TTL. The provider additionally auto-renews when the remaining TTL drops below 24 hours (verified in external `internal/resources/ban_resource.go` — symbol-level reference, not line number). No dedicated `/renew` endpoint required.
   - **Drift detection:** no `ja4proxy_managed_entries` data source is shipped. Rationale: `PlanModifiers` on list resources plus `protect_unmanaged_entries` defaulting to **true** already prevent the failure mode the data source would address (out-of-band deletions reapplying silently). A data source is additive and can be introduced in a future phase if an operator need emerges.
2. Include a **Consequences** section listing what operators lose by not having the data source (no plan-time warning for drifted entries *that still exist with a different managed_by*) and the mitigation (Management API's audit log still captures the change).

**Done when**
- [ ] File exists with both decisions clearly separated
- [ ] Rationale for deferring the data source is written down, not implicit

**Watch out for**
- `protect_unmanaged_entries` default was changed from the originally-planned `false` to `true` by the external repo (safer for a security tool). Note this deviation explicitly so future readers don't think it's a bug.

---

## Sub-task 102d — Audit `emergency_playbooks.md` against playbook YAML

**Size:** S (30–45 min)
**Files to touch:** `docs/runbooks/emergency_playbooks.md`
**Depends on:** none. **Parallel with:** 102a, 102b, 102c.

**What to do**
1. Read all three playbooks in `deploy/ansible/playbooks/emergency/*.yml` in full. For each, note:
   - Playbook name + purpose (from the top-level `name:` key)
   - Required variables (anything under `vars:` or referenced via `{{ }}` that isn't defaulted)
   - Optional variables (ServiceNow / Slack integration vars)
   - Safety constraints (abort-on-422, dial ±10 stepping, rollback behaviour)
2. Read `docs/runbooks/emergency_playbooks.md` and diff mentally against what you found.
3. Amend the runbook so it matches the playbooks, preserving existing structure. Update only what is wrong or missing. Do **not** rewrite sections that are accurate.
4. Add a troubleshooting sub-section if one is missing — include at least: auth errors (401/403), API validation failures (422), network timeout, missing Ansible vars.

**Done when**
- [ ] Every playbook in `deploy/ansible/playbooks/emergency/*.yml` has a section in the runbook
- [ ] Every required variable is listed in the runbook's "Prerequisites"
- [ ] `python3 -m pytest tests/integration/test_emergency_playbooks.py -v` passes (14 tests)

**Watch out for**
- The playbooks are the source of truth. If runbook and playbook disagree, update the runbook, not the playbook.
- `test_emergency_playbooks.py` tests the YAML structure, not the runbook. Passing tests do not imply the runbook is correct — human read-through is required.

---

## Sub-task 102e — Refresh `deploy/terraform/README.md`

**Size:** XS (20 min)
**Files to touch:** `deploy/terraform/README.md`
**Depends on:** 102a, 102b, 102c (ADRs should exist so the README can link them).

**What to do**
1. Add a short section titled "Drift protection" documenting:
   - `protect_unmanaged_entries` default is **true** (link to ADR-093c)
   - To override for a specific apply: set `protect_unmanaged_entries = false` at the provider block, or run `terraform state rm <resource>` to acknowledge the orphaning
2. Add a link to ADR-093a (repo topology) in a "See also" section so users know where the provider code lives.
3. If the existing quick-start example does not set `protect_unmanaged_entries`, add a comment in the example showing the default and how to override.
4. Do not rewrite the whole file — this is a targeted addition.

**Done when**
- [ ] `grep -c protect_unmanaged_entries deploy/terraform/README.md` ≥ 2 (section header + example comment)
- [ ] Links to ADR-093a and ADR-093c resolve (relative paths checked with `ls`)

**Watch out for**
- Don't add configuration examples that don't match the external provider's actual schema. If unsure, open `internal/provider/provider.go` in the external repo and copy field names verbatim.

---

## Sub-task 102f — Reconcile manifest + close phase

**Size:** XS (15 min)
**Files to touch:** `docs/phases/manifest.yaml`, `CHANGELOG.md`
**Depends on:** 102a–102e all complete.

**What to do**
1. In `docs/phases/manifest.yaml`:
   - Set Phase 102 to `status: COMPLETE` with `completed: '2026-04-XX'` (today's date).
   - Add a `lessons_learned:` field noting that most of 102's original scope was closed in the external provider repo before 102 started; the phase narrowed to docs-only.
   - Delete the duplicate `101:` key at lines 1124–1138 (superseded by the broader cross-phase-gap entry at line 1435). Coordinate with Phase 101's close-out if 101 is still open.
2. Prepend a CHANGELOG entry: `## [Unreleased] - Phase 102 — Terraform provider documentation close-out`. List the three ADRs, the runbook audit, and the README refresh.
3. Run `make sync` — regenerates `TODO.md` and `PROJECT_STATUS.md`.
4. Run `bash scripts/close-phase.sh`. **Must exit 0.**

**Done when**
- [ ] Only one `101:` key exists in the manifest (`grep -c "^  101:" docs/phases/manifest.yaml` returns 1)
- [ ] `yaml.safe_load` on the manifest succeeds
- [ ] `make sync` exits 0
- [ ] `bash scripts/close-phase.sh` exits 0

**Watch out for**
- Don't delete line 1435's broader `101:` entry — delete line 1124's narrower one. The broader one is the source of truth.
- `close-phase.sh` runs the full test suite. Budget ~3 minutes for it to finish. Don't interrupt.

---

## 3. Acceptance criteria

- [ ] ADR-093a (repo topology) exists in `docs/decisions/`
- [ ] ADR-093b (Registry namespace) exists in `docs/decisions/`
- [ ] ADR-093c (TTL renewal + drift-detection decision) exists in `docs/decisions/`
- [ ] `docs/runbooks/emergency_playbooks.md` matches the three YAML playbooks
- [ ] `deploy/terraform/README.md` documents `protect_unmanaged_entries`
- [ ] `docs/phases/manifest.yaml` has exactly one `101:` key
- [ ] Phase 102 marked `COMPLETE` in manifest with `completed` date
- [ ] `bash scripts/close-phase.sh` exits 0
- [ ] 14 playbook tests in `tests/integration/test_emergency_playbooks.py` still pass

## 4. Explicitly out of scope

- Any code changes in `/home/sean/LLM/terraform-provider-ja4proxy`. If
  verification in 102d or later reveals a genuine external-repo bug, file a
  separate issue; do not fix it inside Phase 102.
- Terraform Registry submission (asynchronous, external process — tracked by ADR-093b).
- `ja4proxy_managed_entries` data source (decision to defer is documented by ADR-093c).
- Ansible playbook changes (playbooks are source of truth; runbook follows them, not vice versa).
- Phase 94 (Kubernetes Operator) — separate phase, separate repo.
- Pushing the external repo to GitHub (that is Phase 101 H17, different phase).

## 5. Implementation order

```
     ┌── 102a ──┐
     ├── 102b ──┤
none ┼── 102c ──┼── 102e ── 102f (close)
     └── 102d ──┘
```

All of 102a–102d are parallel-safe (different files, no shared state). 102e
can start as soon as the three ADRs land. 102f runs last.

**Total effort:** ~3 hours for one engineer working sequentially, or ~1 hour
wall-clock for two engineers working in parallel on the independent tasks.

## 6. Junior-engineer checklist before starting

Before touching any file, confirm:

- [ ] You have read-only access to `/home/sean/LLM/terraform-provider-ja4proxy` (needed for verification in 102a–102c).
- [ ] You understand that **no code changes** go into the external repo in this phase.
- [ ] You know the ADR template — read `docs/decisions/ADR-094c.md` as a worked example.
- [ ] You are on a feature branch off `main`, not on `main` directly.
- [ ] You will commit **per sub-task** (one commit per ADR, one for the runbook, one for README, one for manifest).
