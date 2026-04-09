# Phase 94 — Review & Re-plan (2026-04-09 16:55)

> **Status:** PROPOSAL — does not modify `PHASE_94.md`. Captures the review,
> what is still genuinely needed, and an independent sub-phase split.
> **Author:** Claude (Opus 4.6), commissioned review.

---

## 1. Why this re-plan exists

`PHASE_94.md` bundles three loosely-related deliverables under one phase:

1. A **Kubernetes operator** (separate repo, three CRDs, admission webhook,
   ArgoCD integration).
2. A **NetBox loader** for trusted upstream CIDR ranges.
3. A **ServiceNow CMDB registration** task in an Ansible post-deploy role.

Like PHASE_64.md, parts of the doc were drafted before Go was promoted to
production and have not been updated. The current draft also makes several
assumptions about the state of other components (ja4proxy Ansible role
exists, Helm chart is a DaemonSet, the Management API accepts a new
`managed_by` value) that are **not true today**. A junior team picking
this up unmodified would either (a) do the work in the wrong language, or
(b) be blocked on prerequisites that were silently assumed.

This document records the review, lists what is still needed, removes
the parts that overlap with deprecated paths or other phases, and re-cuts
the work into independent sub-phases.

---

## 2. Findings — what is stale or wrong

| § in PHASE_94.md | Issue | Reality |
|---|---|---|
| §3.2 (allowlist CRD), §10 (Phase 79 coordination) | "Uses `managed_by=operator-k8s`" treated as a coordination request | **`management/api/models.py:238` defines `ManagedBy` as a strict enum:** `terraform`, `operator`, `api`, `analytics`, `legacy`, `migration`. **There is no `operator-k8s` value.** Posting one will be rejected with 422. ADR-094c is therefore not "decide later" — it is a hard prerequisite that must be resolved before any controller code is written. |
| §6 (CMDB Ansible task) | "Add a task to the existing Ansible post-deploy role in `deploy/ansible/roles/ja4proxy/`" | **That role does not exist.** Only `deploy/ansible/roles/redis-secure/` exists. The CMDB task has nowhere to plug in. PHASE_94 silently assumes a baseline that was never built. |
| §1, §4.3 | "DaemonSet topology in Phase 76 §5.3" / "operator-managed DaemonSet" | **The shipped Helm chart at `deploy/helm/ja4proxy/templates/deployment.yaml` is `kind: Deployment`,** not DaemonSet. Phase 76's *paper* recommends DaemonSet, but no DaemonSet artifact exists in-tree. The operator's DaemonSet-safety annotations (`safe-to-evict: false`, `system-node-critical`, etc.) cannot be applied to a Deployment. This is a real, blocking inconsistency between the Helm chart and the operator design. |
| §7 (NetBox loader) | Specifies BOTH `src/config/netbox_loader.py` (Python) AND `internal/config/netbox.go` (Go) | **The Python proxy is deprecated** (CLAUDE.md line 12: "Default to the Go side. Touch the Python side only when the task explicitly involves prototyping…"). Trusted-CIDR loading is a hot-path concern of the production proxy — Go only. The Python file should not exist; building it doubles the test surface and creates a second source of truth that will drift. |
| §1, §4.1 reference Phase 93 | "Prerequisites: Phase 93 (Terraform provider — for shared client library patterns)" | **Phase 93 is still PROPOSED** (per `manifest.yaml`). Meanwhile a Go HTTP client already lives at `internal/cli/client/client.go` (Get/Post/Patch/Delete, ~150 lines, used by `ja4proxy-cli`). The operator can either copy this file into its own repo (small, no risk) or wait for Phase 93. There is no functional dependency on 93 — only a stylistic one. |
| §10 | Lists three coordination items as if they need negotiation with Phase 79 | Two of the three are already supported: `_get_all_entries(...)` in `management/api/routes/canonical_lists.py:211` already accepts a `managed_by_filter`, and `GET /api/v1/config` already returns the live config. The only real Phase 79 ask is the enum extension (above). The other two items can be removed from the coordination table. |
| §6 prose | Implies ServiceNow integration is operationally low-risk and appropriate to bundle with the operator | The two pieces of work share **nothing**: different language (Ansible YAML vs Go controller-runtime), different deployment surface (Ansible-managed RHEL hosts vs Kubernetes), different test infrastructure (Molecule/check-mode vs envtest), different reviewers, different release cadence. They were bundled because they both said "enterprise integration" — that is not a good reason. |
| §5 (ArgoCD integration) | Sets `argocd.argoproj.io/health-check: "true"` annotation on the operator Deployment | That annotation is not a real ArgoCD API. ArgoCD custom health checks are configured via the ConfigMap snippet shown earlier in §5 — the annotation does nothing. Drop it. |
| §11 acceptance criteria | "All 7 operator unit tests (envtest) pass" | The test list in §8 has 7 named cases, but the list is the *minimum*. Acceptance should require coverage of every reconciler path, not a hard count. A junior team will read "all 7 tests" and stop there. |

### Tangentially observed (file in Phase 101 register, not in scope here)

- `src/governance/policy_applier.py` writes `managed_by="policy"` but the
  Pydantic enum at `management/api/models.py:238` does not include
  `policy`. Either the policy applier is bypassing schema validation or
  the API is silently coercing the value. This is a separate bug; flag
  it in Phase 101 and let the policy / Management API owner triage.

### Items already covered elsewhere (drop / cross-link only)

- **Phase 76** — DaemonSet topology recommendation. Phase 76 is paper-only
  (no in-tree artifacts). Already noted in the PHASE_64 re-plan; the same
  observation applies here. Phase 94 cannot rely on Phase 76 having
  shipped a DaemonSet manifest — it has not.
- **Phase 93** — shared Go client library. Not a real blocker (see §2
  above). Cross-link only.

---

## 3. What is still genuinely needed

After cutting the stale and overlapping items, the real deliverables are:

### A. Prerequisites (must land before any operator controller code)

1. `ManagedBy` enum extension in `management/api/models.py` to accept the
   new K8s-operator value (whatever name is chosen — see ADR-094c). Plus
   round-trip tests that the new value is accepted on POST and filterable
   on GET.
2. A decision on Helm chart topology: either (a) convert the Helm chart
   from Deployment to DaemonSet so the operator's safety annotations
   apply, or (b) keep Deployment as the default and add an opt-in
   DaemonSet variant under `deploy/helm/ja4proxy/templates/daemonset.yaml`
   gated by a values flag, with the operator targeting whichever the
   user has installed. Recorded as ADR-094d (new — was missing from the
   original ADR list).

### B. Kubernetes operator (separate repo, `github.com/anomalyco/ja4proxy-operator`)

3. Repo scaffolding (`go.mod`, `controller-runtime` skeleton, `Makefile`,
   GitHub Actions for `make test` and `make docker-build`, copied
   `client.go` from `internal/cli/client/client.go`).
4. `JA4ProxyAllowlist` controller — Create / Read / Delete reconciliation
   against the Management API allowlist endpoints.
5. `JA4ProxyDial` controller — including 202 pending-approval handling,
   K8s `Warning` event emission, and stop-retry semantics on pending.
6. `JA4ProxyConfig` controller — hot-reloadable fields via PATCH; restart-
   required fields trigger pod annotation update only (never a forced
   delete).
7. Admission webhook (separate HTTPS server in the operator pod) +
   cert-manager dependency documentation in the operator's Helm chart
   README.
8. Operator Helm chart with optional ArgoCD custom health check ConfigMap
   gated behind `{{ if .Values.argocd.enabled }}`.
9. `docs/runbooks/kubernetes_operator.md` in the **main** repo covering
   CRD lifecycle, pending-approval resolution, envtest setup, and the
   cert-manager prerequisite. `deploy/k8s/README.md` with a pointer to
   the operator repo and example CRD manifests.

### C. NetBox integration (in-tree, Go-only)

10. `internal/config/netbox.go` — `LoadTrustedCIDRsFromNetBox(ctx, url,
    token, tag)`. Fail-open: returns empty slice on any error.
11. New `trusted_upstream_sources` config block in `config/proxy.yml`
    (opt-in, default off), wired into the Go pipeline's trusted-upstream
    resolution. Merged with `static_cidrs` (union, deduplicated). Reload
    on SIGHUP.
12. Prometheus counter `ja4proxy_netbox_cidrs_loaded{status="ok|error"}`.
13. Go unit tests covering: success (200, N prefixes returned), HTTP 500
    fall-back, timeout fall-back, merge with static CIDRs, dedup. Plus a
    chaos test that simulates NetBox returning malformed JSON and
    confirms the loader returns empty (not panic).

### D. Ansible / ServiceNow CMDB

14. Create `deploy/ansible/roles/ja4proxy/` baseline (defaults, tasks,
    handlers, README) — this currently does not exist.
15. Add `tasks/cmdb_register.yml` with `when: servicenow_enabled | bool`
    guard. Default `servicenow_enabled: false` in
    `defaults/main.yml`.
16. Molecule scenario or `--check`-mode test that proves the role
    converges cleanly with `servicenow_enabled: false` (skip path) and
    with a mock ServiceNow API stub (POST path).

---

## 4. Sub-phase split

Each sub-phase is one branch, one PR, one reviewer. Cross-sub-phase
dependencies are flagged explicitly. Where there is no dependency,
sub-phases can run in parallel.

| ID | Sub-phase | Repo / area | Size | Depends on |
|---|---|---|---|---|
| **94a** | `ManagedBy` enum extension + Phase 79 patch | main repo, `management/api/` | XS | none |
| **94b** | Helm chart topology decision (ADR-094d) + chart change | main repo, `deploy/helm/ja4proxy/` | S | none |
| **94c** | Operator repo scaffolding + admission webhook skeleton | new repo `ja4proxy-operator` | M | 94a |
| **94d** | `JA4ProxyAllowlist` controller | operator repo | M | 94a, 94c |
| **94e** | `JA4ProxyDial` controller (incl. 202 pending-approval) | operator repo | M | 94c |
| **94f** | `JA4ProxyConfig` controller (hot-reload vs restart) | operator repo | M | 94b, 94c |
| **94g** | Operator Helm chart + optional ArgoCD custom health check | operator repo | S | 94c |
| **94h** | `kubernetes_operator.md` runbook + `deploy/k8s/README.md` | main repo | XS | 94d, 94e, 94f at least drafted |
| **94i** | NetBox loader (Go-only, in-tree) + config + tests | main repo, `internal/config/` | M | none |
| **94j** | Ansible `ja4proxy` role baseline (skeleton + Molecule) | main repo, `deploy/ansible/roles/ja4proxy/` | S | none |
| **94k** | ServiceNow CMDB Ansible task | main repo, `deploy/ansible/roles/ja4proxy/tasks/` | XS | 94j |

**Truly independent streams** (can run completely in parallel with no
coordination beyond the sub-phase boundaries above):

- **Stream 1 (operator):** 94a → 94b → 94c → {94d, 94e, 94f} → 94g → 94h
- **Stream 2 (NetBox):** 94i alone
- **Stream 3 (Ansible/CMDB):** 94j → 94k

A team of three could pick up one stream each. The streams share no
files, no test infrastructure, no reviewers, and no release artifacts.

### File ownership matrix

| Sub-phase | Owns (creates) | Touches (appends only) |
|---|---|---|
| 94a | tests for new enum value | `management/api/models.py` (single-line enum extension), `management/api/routes/canonical_lists.py` test fixtures |
| 94b | new ADR `docs/decisions/ADR-094d.md`, `deploy/helm/ja4proxy/templates/daemonset.yaml` (if option (b)) or revised `deployment.yaml` (if option (a)) | `deploy/helm/ja4proxy/values.yaml` |
| 94c | entire `ja4proxy-operator` repo | — |
| 94d, 94e, 94f | controller + tests in operator repo | — |
| 94g | operator Helm chart in operator repo | — |
| 94h | `docs/runbooks/kubernetes_operator.md`, `deploy/k8s/README.md` | — |
| 94i | `internal/config/netbox.go`, `internal/config/netbox_test.go` | `config/proxy.yml` (new keys, `# phase-94i` comments), `internal/metrics/metrics.go` (new counter), wiring in the trusted-upstream resolver |
| 94j | `deploy/ansible/roles/ja4proxy/{defaults,tasks,handlers,meta,README.md}` | — |
| 94k | `deploy/ansible/roles/ja4proxy/tasks/cmdb_register.yml` | `defaults/main.yml` (add `servicenow_enabled: false`) |

### Conventions for every sub-phase

- All work happens on `claude/phase-94<letter>-<description>`.
- Every sub-phase ends by writing `PHASE_94<letter>_notes.md` summarising
  what was done, what was tested, and any new Phase 101 entries.
- Each sub-phase MUST be tested by the author before opening the PR. For
  the operator: `make test` (envtest) green. For NetBox: `go test
  ./internal/config/...` green plus a manual run against a NetBox
  fixture or `httptest.NewServer`. For Ansible: `molecule test` or at
  minimum `ansible-playbook --check`.

---

### Sub-phase 94a — `ManagedBy` enum extension

**Deliverable:** New value in `management/api/models.py` `ManagedBy` enum
to represent the K8s operator. Recommended name: `operator_k8s` (snake
case to match Pydantic convention; serialized as `operator_k8s`). The
exact string is the subject of ADR-094c — the sub-phase must write the
ADR before changing the code.

**What to do:**
1. Write `docs/decisions/ADR-094c.md` choosing the value. The two
   serious options are `operator_k8s` (new) or reuse `operator` with a
   `subsystem` discriminator field on the resource. Recommended:
   `operator_k8s`. Document why.
2. Add the value to the enum.
3. Update any persistence-layer code that round-trips the value (the
   route handlers already pass through whatever is in the enum, but
   verify by reading `canonical_lists.py`).
4. Add tests:
   - POST `/api/v1/allowlist` with `managed_by=operator_k8s` returns
     201.
   - GET `/api/v1/allowlist?managed_by=operator_k8s` returns only the
     entries that were posted with that value.
   - The other enum values still work unchanged (regression).

**Acceptance criteria:**
- [ ] ADR-094c written and merged.
- [ ] `ManagedBy` enum extended.
- [ ] Three new tests added (POST, GET filter, regression).
- [ ] No other phase's tests fail.
- [ ] `PHASE_94a_notes.md` records the chosen value and the policy
      applier mismatch (see Phase 101 entry §6 below).

**Out of scope:** Operator code (94c+), CRD design (PHASE_94 §3 already
covers it).

---

### Sub-phase 94b — Helm chart topology decision

**Deliverable:** ADR-094d documenting the Deployment-vs-DaemonSet choice
for the in-tree Helm chart, plus the chart change to match.

**What to do:**
1. Write `docs/decisions/ADR-094d.md`. The decision is between:
   - **(a) Convert the chart to DaemonSet.** Pros: matches Phase 76's
     paper recommendation; matches the operator's safety annotations;
     one node = one proxy is the documented production topology.
     Cons: breaks any existing user with replicated Deployment usage
     (likely zero; the chart has only just shipped).
   - **(b) Keep Deployment as default, add opt-in DaemonSet variant.**
     Pros: backward-compatible. Cons: doubles the chart surface area;
     forces the operator to detect which is installed.
   - Recommendation: **(a)**, on the grounds that the chart is recent
     and the operator design assumes DaemonSet end-to-end. Backward
     compatibility is not a real constraint at this stage.
2. Implement the chosen option in `deploy/helm/ja4proxy/templates/`.
3. Update `deploy/helm/ja4proxy/values.yaml` to expose the new toggles
   (if option b).
4. Run `helm template` and verify the rendered manifest is valid.
5. If option (a): run `make smoke-k8s` (sub-phase 64b, when it lands)
   to confirm the DaemonSet starts cleanly in `kind`.

**Acceptance criteria:**
- [ ] ADR-094d written.
- [ ] Chart change matches the ADR.
- [ ] `helm template deploy/helm/ja4proxy/` succeeds with default values.
- [ ] `helm lint deploy/helm/ja4proxy/` succeeds.
- [ ] `PHASE_94b_notes.md` records the option chosen and the rationale.

**Out of scope:** Operator repo, NetBox, Ansible.

---

### Sub-phase 94c — Operator repo scaffolding + admission webhook skeleton

**Deliverable:** A new repository `github.com/anomalyco/ja4proxy-operator`
containing:
- `go.mod` with module path `github.com/anomalyco/ja4proxy-operator`.
- `main.go` with a controller-runtime manager (no controllers wired yet —
  those land in 94d/94e/94f).
- `api/v1alpha1/` with the three CRD type stubs (`JA4ProxyConfig`,
  `JA4ProxyAllowlist`, `JA4ProxyDial`) and `+kubebuilder:object` markers.
- `config/crd/` with manifests generated by `controller-gen`.
- `internal/client/client.go` — copy of `internal/cli/client/client.go`
  from the main repo.
- `webhook/ja4proxyconfig_webhook.go` — admission webhook skeleton with
  validation rules for dial 0–100, JA4 fingerprint regex, and future
  `expires` timestamps.
- `Makefile` with `make generate`, `make manifests`, `make test`,
  `make docker-build`.
- `.github/workflows/test.yml` running `make test` on every PR.
- `deploy/helm/ja4proxy-operator/` with bare-minimum chart (operator
  Deployment, ServiceAccount, RBAC). ArgoCD additions land in 94g.
- `README.md` and `docs/cert-manager.md`.

**Acceptance criteria:**
- [ ] Repo created, `go build ./...` succeeds.
- [ ] `make test` runs with envtest (no controllers tested yet — webhook
      tests only).
- [ ] Admission webhook rejects invalid JA4 in unit test.
- [ ] CI green on initial commit.
- [ ] `PHASE_94c_notes.md` records the controller-runtime version, the
      `kubebuilder` version, and the Kubernetes API version targeted.

**Out of scope:** Reconciler logic, Helm ArgoCD integration, runbook.

---

### Sub-phases 94d, 94e, 94f — Three controllers

Each is one controller, one reconciler test suite, one merge. They share
the operator repo but touch disjoint files (`controllers/<name>_controller.go`
and `controllers/<name>_controller_test.go` each).

**94d — `JA4ProxyAllowlist` reconciler**
- Spec list → API state diff → POST missing, DELETE stale.
- Uses `managed_by=operator_k8s` (the value chosen by 94a).
- Tests: add, remove, no-op, API 5xx → status condition `Reconciled=False`.

**94e — `JA4ProxyDial` reconciler**
- Watches the CRD; on change, calls dial-set endpoint.
- Handles 202: sets `status.pendingDecisionId`, emits K8s `Warning` event,
  stops retry loop.
- Tests: 200 happy path, 202 pending path, retry on 5xx, no-op when
  spec matches current.

**94f — `JA4ProxyConfig` reconciler**
- Hot-reloadable fields (`bypassToggles.*`) → PATCH `/api/v1/config`.
- Restart-required fields (`redisUrl`) → annotation update on the
  DaemonSet pod template (triggers rolling restart). Operator MUST NOT
  delete pods directly.
- Tests: hot-reload path (no restart), restart path (annotation set),
  mixed change (both behaviours in one reconcile).

**Acceptance criteria (each):**
- [ ] Controller compiles and reconciler tests pass under envtest.
- [ ] Status conditions written on success and failure paths.
- [ ] No pod deletion in any code path.
- [ ] Notes file records which Phase 79 endpoints were exercised in the
      tests and which were stubbed.

---

### Sub-phase 94g — Operator Helm chart + ArgoCD custom health check

**Deliverable:** Complete the operator's own Helm chart with:
- ValidatingWebhookConfiguration (assumes cert-manager — chart README
  documents the dependency).
- ArgoCD custom health check ConfigMap, gated behind
  `{{ if .Values.argocd.enabled }}`.

Drop the bogus `argocd.argoproj.io/health-check: "true"` annotation from
PHASE_94 §5 — that is not a real ArgoCD API.

**Acceptance criteria:**
- [ ] `helm lint` and `helm template` both succeed.
- [ ] `argocd.enabled=false` produces a chart without the ConfigMap.
- [ ] `argocd.enabled=true` produces the ConfigMap with the Lua health
      check from PHASE_94 §5.
- [ ] cert-manager prerequisite documented in the chart README.

---

### Sub-phase 94h — Documentation

**Deliverable:**
- `docs/runbooks/kubernetes_operator.md` in the **main** repo. Covers
  CRD lifecycle, pending-approval resolution workflow, envtest setup,
  cert-manager prerequisite, how to upgrade the operator, how to roll
  back.
- `deploy/k8s/README.md` in the main repo with a pointer to the operator
  repo and a worked example of each CRD type.

**Acceptance criteria:**
- [ ] Both files exist.
- [ ] Runbook links into existing operational runbooks rather than
      duplicating them (same rule as PHASE_64 §3.6).
- [ ] Example CRD manifests in `deploy/k8s/README.md` use the
      `managed_by` value chosen in 94a.

---

### Sub-phase 94i — NetBox loader (Go-only)

**Deliverable:** `internal/config/netbox.go` plus wiring into the
trusted-upstream config resolver.

**What to do:**
1. Implement `LoadTrustedCIDRsFromNetBox(ctx context.Context, url,
   token, tag string) ([]string, error)`. The function:
   - Issues `GET {url}/api/ipam/prefixes/?tag={tag}&limit=1000` with
     `Authorization: Token {token}` and a 5-second total timeout.
   - On any HTTP non-2xx, returns `[]string{}, nil` and logs a WARN
     (fail-open).
   - On any transport / timeout / decode error, returns `[]string{},
     nil` and logs a WARN.
   - Increments `ja4proxy_netbox_cidrs_loaded{status="ok|error"}`.
2. Add the `trusted_upstream_sources` block to `config/proxy.yml` with
   `# phase-94i` comments and conservative defaults
   (`netbox.enabled: false`).
3. Wire the loader into the Go pipeline's trusted-CIDR resolver. On
   startup and on SIGHUP, merge NetBox results with `static_cidrs`
   (union, deduplicated) and write into the in-process trie.
4. Add tests:
   - 200 with two prefixes → both returned.
   - 500 → empty slice, no error.
   - Timeout (use `httptest.NewServer` with a sleep) → empty slice, no
     error.
   - Malformed JSON → empty slice, no error.
   - Merge with `static_cidrs` → union, no duplicates.

**Acceptance criteria:**
- [ ] All five test cases pass.
- [ ] `ja4proxy_netbox_cidrs_loaded` counter visible at `/metrics`.
- [ ] SIGHUP reload re-runs the loader.
- [ ] **No Python file is added.** This is Go-only.
- [ ] `PHASE_94i_notes.md` records the NetBox API version targeted and
      a sample successful response shape.

**Out of scope:** Operator, Ansible, CMDB. **Explicitly out of scope:**
any Python `netbox_loader.py` from PHASE_94 §7.1 — Python proxy is
deprecated.

---

### Sub-phase 94j — Ansible `ja4proxy` role baseline

**Deliverable:** `deploy/ansible/roles/ja4proxy/` with the standard
Ansible role layout:
```
deploy/ansible/roles/ja4proxy/
  defaults/main.yml
  tasks/main.yml
  handlers/main.yml
  meta/main.yml
  README.md
  molecule/default/   # optional but recommended
```

**What to do:**
1. Define the minimum viable role that installs and starts the Go
   proxy on a RHEL host (image pull, systemd / Quadlet unit drop,
   service start, health check). Cross-link Phase 76 for the strategy
   and Phase 64 for the smoke test.
2. Provide a Molecule scenario that converges the role on a CentOS
   Stream / Rocky 9 container.
3. Document required variables in `defaults/main.yml` with comments.

**Acceptance criteria:**
- [ ] Role exists with the layout above.
- [ ] `molecule converge` succeeds (or `ansible-playbook --check` if
      Molecule is not available in CI).
- [ ] No reference to `proxy.py` or any Python entrypoint anywhere in
      the role — production is Go.
- [ ] `PHASE_94j_notes.md` records what was tested and on which OS.

**Coordination note:** This role becomes the home for the CMDB task in
94k. It is **not** a prerequisite for any operator sub-phase.

---

### Sub-phase 94k — ServiceNow CMDB task

**Deliverable:** `deploy/ansible/roles/ja4proxy/tasks/cmdb_register.yml`
plus a default `servicenow_enabled: false` in
`defaults/main.yml`.

**What to do:** Implement the task body from PHASE_94 §6 verbatim
(it is correct Ansible) under a `when: servicenow_enabled | bool`
guard. Include the task from `tasks/main.yml`.

**Acceptance criteria:**
- [ ] Task file exists.
- [ ] Default is opt-out (`servicenow_enabled: false`).
- [ ] Molecule run with `servicenow_enabled: false` skips the task
      cleanly (zero changed).
- [ ] Molecule run with `servicenow_enabled: true` and a stubbed
      ServiceNow endpoint exercises the POST path.
- [ ] `PHASE_94k_notes.md` records the stubbing approach.

**Depends on 94j.**

---

## 5. Items dropped from scope — file as Phase 101 entries

| Dropped item | Why | Phase 101 entry to file |
|---|---|---|
| Python `src/config/netbox_loader.py` | Python proxy is deprecated; trusted-CIDR resolution is a hot-path concern of the Go proxy | "PHASE_94 §7.1 specified a Python NetBox loader; dropped because the production proxy is Go. If the Python analytics path also needs trusted CIDRs, file a separate phase." |
| `policy` value missing from `ManagedBy` enum (tangential) | `src/governance/policy_applier.py` writes `managed_by="policy"` but `management/api/models.py` does not include it in the enum | "Bug: `policy_applier.py` writes `managed_by='policy'` which is not in the `ManagedBy` enum at `management/api/models.py:238`. Either the API silently coerces, or there is a hidden bypass. Audit and fix." |
| Bogus `argocd.argoproj.io/health-check: "true"` annotation | Not a real ArgoCD API | (Resolved by 94g — no entry needed.) |
| Phase 76 DaemonSet artifacts referenced but absent | Phase 76 was paper-only | Already filed under PHASE_64 re-plan §5 — no duplicate entry needed. |

---

## 6. What this re-plan does NOT change

- The three CRD designs in PHASE_94.md §3 are sound and survive
  unchanged. 94d/94e/94f implement them as written.
- The reconciliation strategy in §4.1 is sound.
- The DaemonSet safety annotations in §4.3 are sound — they apply once
  94b lands a real DaemonSet.
- The test plan in §8 is a good starting point for envtest cases. It
  is not the *complete* set; treat it as the floor.
- Phase 79 (Management API) is COMPLETE and does not need re-opening
  beyond the single-line enum extension in 94a.

---

## 7. Recommended landing order (not required — sub-phases are independent)

If a single agent picks up multiple sub-phases sequentially, the most
useful order is:

1. **94a** (enum extension) — unblocks everything operator-related.
2. **94b** (Helm topology decision) — small ADR + chart change. Resolves
   the Deployment-vs-DaemonSet inconsistency before any controller is
   written.
3. **94c** (operator scaffolding) — repo, webhook skeleton, CI green.
4. **94d / 94e / 94f** — three reconcilers, in any order, by different
   junior devs in parallel.
5. **94g** (operator Helm chart) — once at least one reconciler is
   working end-to-end against envtest.
6. **94h** (docs) — last in the operator stream.
7. **94i** (NetBox) — start any time, completely independent.
8. **94j → 94k** (Ansible role + CMDB task) — start any time,
   completely independent.

A team of three could work the three streams in parallel from day one
with no coordination beyond merge ordering inside each stream.

---

## 8. Open questions for the maintainer

1. **Repo creation:** the operator must live in
   `github.com/anomalyco/ja4proxy-operator`. Does that org already
   exist, and who has permission to create the repo? 94c is blocked on
   the answer. (PHASE_64 had no equivalent question; the operator's
   separate-repo requirement adds it here.)
2. **Helm topology decision:** prefer 94b option (a) — convert to
   DaemonSet — or option (b) — keep Deployment, add opt-in DaemonSet
   variant? Recommendation in §3.B above is (a).
3. **Should this re-plan replace PHASE_94.md wholesale,** or should
   PHASE_94.md remain and gain a "superseded by sub-phases" header
   pointing here? Same question as the PHASE_64 re-plan. This document
   does not pre-empt that choice.
4. **Phase 93 dependency:** is the maintainer happy to drop the "Phase
   93 prerequisite" line in PHASE_94.md given that the operator can
   simply copy `internal/cli/client/client.go`? The original
   prerequisite was stylistic, not functional.
