# Phase 94 — Kubernetes Operator + NetBox + ServiceNow CMDB

> **Status:** PROPOSED — split into 13 independent sub-phases (see §5).
> **Last revised:** 2026-04-11 (compact sub-phase index added for junior engineer handoff;
> design details from 2026-04-09 review preserved in §3–§7).
> **Prerequisites:** Phase 79 (Management API v2) — COMPLETE. Phase 83
> (`ja4proxy-cli`) — COMPLETE.
> **Not a prerequisite (despite the original draft):** Phase 93 (Terraform
> provider). The operator can vendor `internal/cli/client/client.go`
> directly; the original "shared client library" dependency was stylistic,
> not functional.

## Sub-phase quick reference (13 sub-phases, 3 parallel streams)

**Stream 1 — Kubernetes operator** (6 sub-phases, sequential within stream):

| ID | Sub-phase | Repo | Size | Depends on |
|---|---|---|---|---|
| **94a** | `ManagedBy` enum extension + ADR-094c | main repo | XS | none |
| **94b** | Helm chart topology (ADR-094d) | main repo | S | none |
| **94c1** | Operator repo bootstrap | operator repo | S | 94a |
| **94c2** | CRD stubs + admission webhook | operator repo | S | 94c1 |
| **94d** | Allowlist reconciler | operator repo | M | 94a, 94c2 |
| **94e** | Dial reconciler | operator repo | M | 94c2 |
| **94f** | Config reconciler | operator repo | M | 94b, 94c2 |
| **94g** | Operator Helm chart + ArgoCD | operator repo | S | 94c2 |
| **94h** | Operator runbook | main repo | XS | 94d–94f |

**Stream 2 — NetBox loader** (2 sub-phases, Go-only):

| ID | Sub-phase | Repo | Size | Depends on |
|---|---|---|---|---|
| **94i1** | NetBox loader (Go) + tests | main repo `internal/config/` | S | none |
| **94i2** | Config wiring + SIGHUP + metrics | main repo | S | 94i1 |

**Stream 3 — Ansible / CMDB** (2 sub-phases):

| ID | Sub-phase | Repo | Size | Depends on |
|---|---|---|---|---|
| **94j** | Ansible role baseline | main repo `deploy/ansible/` | S | none |
| **94k** | ServiceNow CMDB task | main repo `deploy/ansible/` | XS | 94j |

Three engineers can pick up one stream each on day one with zero coordination.
Detailed sub-phase specifications are in §7 below.

---

## 1. Overview

Phase 94 delivers three loosely-related capabilities for enterprises
running JA4proxy on Kubernetes / OpenShift or under Ansible-managed RHEL
hosts:

1. **Kubernetes operator** — declarative management of JA4proxy
   configuration via Kubernetes CRDs, eliminating out-of-band API calls
   after initial cluster deployment. Lives in a **separate repository**
   (`github.com/anomalyco/ja4proxy-operator`) so it can release
   independently and be published to OperatorHub.
2. **NetBox integration** — read trusted upstream CIDR ranges from
   NetBox so network engineers manage IP space in one place. **Go-only**;
   the deprecated Python proxy is not in scope.
3. **ServiceNow CMDB integration** — automatic asset registration on
   deploy via an Ansible task in the (currently nonexistent) `ja4proxy`
   role.

These three capabilities share **nothing** operationally — different
languages, different deployment surfaces, different test infrastructures,
different reviewers. They are bundled into one phase only because they
are all "enterprise integrations". The sub-phase split in §5 separates
them into three streams that can be worked entirely in parallel.

---

## 2. Production-runtime constraint

CLAUDE.md is unambiguous: the production proxy is the **Go binary**
(`bin/proxy`). The Python proxy is deprecated and retained only for
prototyping. Any Phase 94 component on the proxy hot path is therefore
Go-only:

- The NetBox loader is Go-only (`internal/config/netbox.go`). There is
  no Python equivalent in scope, regardless of what earlier drafts said.
- The Ansible role provisions and starts the **Go** binary. It must
  contain no reference to `proxy.py` or any Python entrypoint.
- The operator targets the Go-binary DaemonSet pods (see §6.3 for the
  Helm chart topology decision).

---

## 3. Findings from the 2026-04-09 review

The original PHASE_94.md was drafted before Go was promoted to
production and contained several assumptions that did not match the
state of the codebase. The 2026-04-09 review found:

| Original assumption | Reality | Resolution in this re-plan |
|---|---|---|
| `managed_by=operator-k8s` is a "coordination ask" with Phase 79 | `management/api/models.py:238` defines `ManagedBy` as a strict Pydantic enum with values `terraform / operator / api / analytics / legacy / migration`. **No `operator-k8s` value.** POSTing it returns 422. | Sub-phase **94a** explicitly extends the enum and adds round-trip tests. ADR-094c chooses the value (recommended: `operator_k8s`). |
| The CMDB Ansible task plugs into "the existing Ansible post-deploy role in `deploy/ansible/roles/ja4proxy/`" | That role does not exist. Only `deploy/ansible/roles/redis-secure/` exists today. | Sub-phase **94j** creates the role baseline; **94k** adds the CMDB task on top. |
| The Helm chart is a DaemonSet (per Phase 76 §5.3) | The shipped chart at `deploy/helm/ja4proxy/templates/deployment.yaml` is `kind: Deployment`. Phase 76 was paper-only — its DaemonSet recommendation produced no in-tree artifact. The operator's safety annotations (`safe-to-evict: false`, `system-node-critical`, `terminationGracePeriodSeconds`) cannot apply to a Deployment. | Sub-phase **94b** writes ADR-094d and changes the chart. Recommended: convert to DaemonSet (the chart is recent; backward compatibility is not a real constraint). |
| NetBox integration ships both `src/config/netbox_loader.py` (Python) AND `internal/config/netbox.go` (Go) | Python proxy is deprecated. | Python file dropped entirely. NetBox loader is Go-only (sub-phases **94i1**/**94i2**). |
| Phase 93 (Terraform provider) is a prerequisite for "shared client library patterns" | A Go HTTP client already lives at `internal/cli/client/client.go` (~150 lines, used by `ja4proxy-cli`). Phase 93 is still PROPOSED. | The operator vendors `client.go` directly. Phase 93 dependency dropped. |
| `argocd.argoproj.io/health-check: "true"` annotation on the operator Deployment | This annotation does not exist in the ArgoCD API. | Dropped. The Lua health check ConfigMap in §6.5 is the only ArgoCD integration. |
| Phase 79 coordination needs three items: enum value, GET filter, GET config response shape | Two of the three already work: `_get_all_entries(redis, list_name, managed_by_filter)` exists at `management/api/routes/canonical_lists.py:211`; `GET /api/v1/config` returns the live config. | Only the enum extension is real. Reduced from three coordination items to one. |

### Tangentially observed (Phase 101 entry, not in scope here)

`src/governance/policy_applier.py` writes `managed_by="policy"` but the
`ManagedBy` enum at `management/api/models.py:238` does not include
`policy`. Either the API silently coerces, or there is a hidden bypass.
This is a separate bug — file under Phase 101 and let the policy /
Management API owner triage.

---

## 4. Three independent streams

The 13 sub-phases below split into three streams that share no files,
no test infrastructure, no reviewers, and no release artifacts:

- **Stream 1 — Kubernetes operator:** 94a → 94b → 94c1 → 94c2 →
  {94d, 94e, 94f} → 94g → 94h
- **Stream 2 — NetBox loader:** 94i1 → 94i2 (in-tree, Go only)
- **Stream 3 — Ansible / CMDB:** 94j → 94k

A team of three could pick up one stream each on day one with no
coordination beyond merge ordering inside each stream.

---

## 5. Sub-phase index

| ID | Sub-phase | Repo / area | Size | Depends on |
|---|---|---|---|---|
| **94a** | `ManagedBy` enum extension + ADR-094c | main repo `management/api/` | XS | none |
| **94b** | Helm chart topology decision (ADR-094d) + chart change | main repo `deploy/helm/ja4proxy/` | S | none |
| **94c1** | Operator repo bootstrap (go.mod, manager, CI) | new repo `ja4proxy-operator` | S | 94a |
| **94c2** | CRD type stubs + admission webhook skeleton | operator repo | S | 94c1 |
| **94d** | `JA4ProxyAllowlist` reconciler | operator repo | M | 94a, 94c2 |
| **94e** | `JA4ProxyDial` reconciler (incl. 202 pending-approval) | operator repo | M | 94c2 |
| **94f** | `JA4ProxyConfig` reconciler (hot-reload vs restart) | operator repo | M | 94b, 94c2 |
| **94g** | Operator Helm chart + optional ArgoCD custom health check | operator repo | S | 94c2 (one reconciler ideally working) |
| **94h** | `kubernetes_operator.md` runbook + `deploy/k8s/README.md` | main repo | XS | 94d, 94e, 94f at least drafted |
| **94i1** | NetBox loader (Go) + unit tests | main repo `internal/config/` | S | none |
| **94i2** | NetBox config wiring + SIGHUP reload + Prometheus counter | main repo (config + pipeline) | S | 94i1 |
| **94j** | Ansible `ja4proxy` role baseline | main repo `deploy/ansible/roles/ja4proxy/` | S | none |
| **94k** | ServiceNow CMDB Ansible task | main repo `deploy/ansible/roles/ja4proxy/tasks/` | XS | 94j |

### Size summary

- **XS** (3): 94a, 94h, 94k
- **S** (7): 94b, 94c1, 94c2, 94g, 94i1, 94i2, 94j
- **M** (3): 94d, 94e, 94f — the three reconcilers, M because each is
  one controller + status conditions + envtest reconciler tests +
  one API failure-mode handler. They are the smallest meaningful unit;
  splitting "reconciler" from "reconciler tests" would ship untested
  code.

### File ownership matrix

| Sub-phase | Owns (creates) | Touches (appends only) |
|---|---|---|
| 94a | `docs/decisions/ADR-094c.md`, new tests in `tests/unit/management/` | `management/api/models.py` (single-line enum extension) |
| 94b | `docs/decisions/ADR-094d.md`, new or revised manifest under `deploy/helm/ja4proxy/templates/` | `deploy/helm/ja4proxy/values.yaml` |
| 94c1 | entire `ja4proxy-operator` repo (`go.mod`, `main.go`, `Makefile`, `.github/workflows/test.yml`, `internal/client/client.go` copied from main) | — |
| 94c2 | `api/v1alpha1/{ja4proxyconfig,ja4proxyallowlist,ja4proxydial}_types.go`, generated `zz_generated.deepcopy.go`, `config/crd/*.yaml`, `webhook/ja4proxyconfig_webhook.go`, webhook unit tests | — |
| 94d, 94e, 94f | `controllers/<name>_controller.go` + `_test.go` in operator repo | — |
| 94g | `deploy/helm/ja4proxy-operator/` in operator repo | — |
| 94h | `docs/runbooks/kubernetes_operator.md`, `deploy/k8s/README.md` | — |
| 94i1 | `internal/config/netbox.go`, `internal/config/netbox_test.go` | — |
| 94i2 | wiring code in trusted-upstream resolver | `config/proxy.yml` (new keys, `# phase-94i2` comments), `internal/metrics/metrics.go` (new counter) |
| 94j | `deploy/ansible/roles/ja4proxy/{defaults,tasks,handlers,meta,molecule,README.md}` | — |
| 94k | `deploy/ansible/roles/ja4proxy/tasks/cmdb_register.yml` | `deploy/ansible/roles/ja4proxy/defaults/main.yml` (add `servicenow_enabled: false`) |

There is no shared-file conflict between any two sub-phases.

### Conventions for every sub-phase

- All work happens on `claude/phase-94<letter>-<description>`.
- Every sub-phase ends by writing `PHASE_94<letter>_notes.md` summarising
  what was done, what was tested, and any new Phase 101 entries.
- Each sub-phase MUST be tested by the author before opening the PR. For
  the operator: `make test` (envtest) green. For NetBox: `go test
  ./internal/config/...` green plus a manual run against
  `httptest.NewServer`. For Ansible: `molecule test` or, if Molecule is
  not available, `ansible-playbook --check` against a local container.

---

## 6. Design (preserved from the original draft)

The CRD designs, reconciliation strategy, admission webhook scope, and
ArgoCD integration shape from the original draft remain sound. They are
reproduced here as the *design* the sub-phases implement.

### 6.1 Custom Resource Definitions

#### `JA4ProxyConfig`

```yaml
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyConfig
metadata:
  name: prod-config
  namespace: security
spec:
  # Fields marked requiresRestart: true cannot be hot-reloaded.
  # The operator annotates the DaemonSet pods to trigger a rolling restart
  # when these fields change.
  redisUrl: "redis://redis.ja4proxy.svc.cluster.local:6379"   # requiresRestart: true
  bypassToggles:
    alpnBrowserBypass: true
    spamhausBypass: true
    tlsVersionBypass: true
    ja4WhitelistBypass: true
    mtlsBypass: true
status:
  conditions:
    - type: Reconciled
      status: "True"
      reason: ConfigApplied
      message: "PATCH /api/v1/config succeeded"
      lastTransitionTime: "2026-04-07T12:00:00Z"
  lastAppliedGeneration: 3
```

Hot-reloadable fields: `bypassToggles.*`. Fields requiring restart:
`redisUrl`. The operator MUST NOT delete or restart pods directly for
hot-reloadable changes (that would cause a traffic gap). For
hot-reloadable fields it issues PATCH `/api/v1/config`. For
restart-required fields it updates a config-hash annotation on the
DaemonSet pod template, which Kubernetes turns into a rolling restart.

#### `JA4ProxyAllowlist`

```yaml
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyAllowlist
metadata:
  name: monitoring-tools
  namespace: security
spec:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "Internal monitoring"
      ticket: "CHG0001100"
    - ja4: "t13d1516h2_112233445566_aabbccddeeff"
      reason: "Partner API client"
      expires: "2027-01-01T00:00:00Z"
status:
  conditions:
    - type: Reconciled
      status: "True"
  entriesManaged: 2
  lastSyncTime: "2026-04-07T12:00:00Z"
```

Reconciliation: diff the spec list against `GET /api/v1/allowlist?managed_by=<value chosen by 94a>`,
POST missing entries, DELETE extra entries. The `managed_by`
discriminator separates operator-managed entries from policy-applied,
terraform-managed, and CLI-applied entries.

#### `JA4ProxyDial`

```yaml
apiVersion: ja4proxy.io/v1alpha1
kind: JA4ProxyDial
metadata:
  name: prod-dial
  namespace: security
spec:
  setting: 70
  ticket: "CHG0001234"
  notes: "Post shadow-mode validation"
  requiresApproval: false   # set true to gate the controller on four-eyes approval
status:
  conditions:
    - type: Reconciled
      status: "True"
  pendingDecisionId: ""     # non-empty when API returned 202
  currentSetting: 70
```

When the dial-set API returns 202, the controller sets
`status.pendingDecisionId`, **stops the retry loop**, and emits a
Kubernetes `Warning` event:

```
Warning  PendingApproval  JA4ProxyDial/prod-dial  dial change requires approval: dec-001
```

This surfaces in `kubectl describe ja4proxydial prod-dial` and in
ArgoCD application health.

### 6.2 Reconciliation loop

- **Trigger:** Kubernetes watches every JA4proxy CRD + a 30-second timer.
- **On change:** the controller calls the Management API to converge
  actual state → spec state.
- **Idempotent:** the controller checks current API state before
  making changes (POST only if absent, DELETE only if stale) — same
  pattern as `policy_applier.py`.
- **Error handling:** on API error, requeue with controller-runtime's
  default exponential backoff. On 5xx, write `Reconciled=False` to
  `status.conditions` with the error detail.
- **Concurrency:** each CRD type has its own controller goroutine; they
  share one Management API client with a connection pool capped at 5
  concurrent requests.

### 6.3 DaemonSet safety

When the in-tree Helm chart is converted to a DaemonSet (sub-phase 94b),
the pod template **must** include:

```yaml
spec:
  template:
    metadata:
      annotations:
        cluster-autoscaler.kubernetes.io/safe-to-evict: "false"
    spec:
      priorityClassName: system-node-critical   # prevent eviction under memory pressure
      terminationGracePeriodSeconds: 30         # allow in-flight connections to drain
```

The chart MUST NOT set `hostNetwork: true` unless the deployment
specifically requires it. If a future deployment does enable it, that
must be documented as a security trade-off in the chart README.

### 6.4 Admission webhook

Validates CRDs **before** the Kubernetes API server accepts them:
- `dial.setting` must be 0–100.
- JA4 fingerprints must match `[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}`.
- `expires` must be a future ISO 8601 timestamp.
- Unknown fields in `bypassToggles` are rejected.

The webhook runs as a separate HTTPS server on port 9443 inside the
operator pod. It requires a TLS certificate.

**cert-manager is a hard dependency** for serving the webhook
certificate. The operator's Helm chart README documents installation
instructions; do not implement a manual rotation workaround. cert-manager
is standard in enterprise Kubernetes clusters.

### 6.5 ArgoCD integration

ArgoCD's default health check for Deployments and DaemonSets only
checks pod readiness. A pod that is `Running` but with Redis
unreachable is not healthy. The operator's Helm chart ships an optional
custom health check via a ConfigMap, gated behind
`{{ if .Values.argocd.enabled }}`:

```yaml
# deploy/helm/ja4proxy-operator/templates/argocd-health-check.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
  labels:
    app.kubernetes.io/part-of: argocd
data:
  resource.customizations.health.ja4proxy.io_JA4ProxyConfig: |
    hs = {}
    if obj.status ~= nil then
      for _, condition in ipairs(obj.status.conditions or {}) do
        if condition.type == "Reconciled" and condition.status == "True" then
          hs.status = "Healthy"
          hs.message = condition.message
          return hs
        end
      end
    end
    hs.status = "Progressing"
    hs.message = "Waiting for reconciliation"
    return hs
```

There is **no** `argocd.argoproj.io/health-check: "true"` annotation on
the operator Deployment. That string is not part of the ArgoCD API; it
appeared in earlier drafts and was wrong.

### 6.6 NetBox integration design

```go
// internal/config/netbox.go (sub-phase 94i1)
// LoadTrustedCIDRsFromNetBox fetches trusted upstream CIDRs from
// NetBox IPAM. Fails open: returns an empty slice (not an error) on
// any HTTP, transport, timeout, or decode failure. The caller merges
// the result with static CIDRs from config/proxy.yml.
func LoadTrustedCIDRsFromNetBox(ctx context.Context, url, token, tag string) ([]string, error)
```

Config wired in by sub-phase 94i2:

```yaml
# config/proxy.yml
trusted_upstream_sources:
  netbox:                          # phase-94i2
    enabled: false                 # opt-in; default off
    url: "https://netbox.corp.internal"
    token: "${NETBOX_API_TOKEN}"
    tag: "ja4proxy-trusted"        # NetBox tag identifying trusted prefixes
    refresh_on_sighup: true        # reload from NetBox on SIGHUP
  static_cidrs:
    - "10.0.0.0/8"                 # always trusted regardless of NetBox
```

**Integration flow:**
1. On startup and on SIGHUP: if `netbox.enabled`, call `LoadTrustedCIDRsFromNetBox`.
2. Merge the result with `static_cidrs` (union, deduplicated).
3. Write the merged list into the in-process pytricia/Go-trie used for
   trusted-upstream matching.
4. On NetBox unreachable: keep the previously-loaded set (or just
   `static_cidrs` on first boot) and emit `WARN netbox_unavailable`.
5. Increment `ja4proxy_netbox_cidrs_loaded{status="ok|error"}`.

**Fail-open invariant:** the proxy never blocks startup waiting for
NetBox.

### 6.7 ServiceNow CMDB integration (Ansible)

Created by sub-phase 94k inside the role baseline from sub-phase 94j:

```yaml
# deploy/ansible/roles/ja4proxy/tasks/cmdb_register.yml
- name: Register JA4proxy node in ServiceNow CMDB
  when: servicenow_enabled | bool
  servicenow.itsm.configuration_item:
    name: "{{ inventory_hostname }}"
    short_description: "JA4proxy TLS Security Proxy"
    asset_tag: "JA4PROXY-{{ inventory_hostname }}"
    install_status: "installed"
    ip_address: "{{ ansible_host }}"
    u_version: "{{ ja4proxy_image_tag }}"
    u_upstream_lb: "{{ upstream_lb_host }}"
    u_downstream_backend: "{{ backend_host }}"
    u_environment: "{{ deploy_environment }}"
    u_last_deployed: "{{ ansible_date_time.iso8601 }}"
    u_config_checksum: "{{ config_checksum.stdout }}"
  delegate_to: localhost
```

Default in `defaults/main.yml`: `servicenow_enabled: false`. CI runs do
not need a ServiceNow instance — the `when:` clause skips the task.

---

## 7. Sub-phase details

### 7.1 Sub-phase 94a — `ManagedBy` enum extension

**Deliverable:** New value in `management/api/models.py` `ManagedBy` enum
to represent the K8s operator. Recommended: `operator_k8s` (snake-case
to match Pydantic convention). The exact string is the subject of
ADR-094c.

**Steps:**
1. Write `docs/decisions/ADR-094c.md` choosing the value. Two serious
   options: (a) add `operator_k8s` to the enum; (b) reuse `operator`
   plus a new `subsystem` discriminator field on the resource.
   Recommended: (a). Document why.
2. Add the value to the enum.
3. Verify route handlers pass the value through unchanged (read
   `management/api/routes/canonical_lists.py`).
4. Add tests:
   - POST `/api/v1/allowlist` with `managed_by=operator_k8s` → 201.
   - GET `/api/v1/allowlist?managed_by=operator_k8s` returns only the
     entries posted with that value.
   - All other enum values still work (regression).

**Acceptance criteria:**
- [ ] ADR-094c written and merged.
- [ ] Enum extended.
- [ ] Three new tests added.
- [ ] No other phase's tests fail.
- [ ] `PHASE_94a_notes.md` records the chosen value AND files the
      `policy_applier.py` enum mismatch as a Phase 101 entry.

**Out of scope:** This sub-phase only changes the enum value. It does not touch operator code, NetBox, Ansible, or any route handlers beyond verifying the filter works.

### 7.2 Sub-phase 94b — Helm chart topology decision

**Deliverable:** ADR-094d documenting the Deployment-vs-DaemonSet choice
plus the chart change to match.

**Steps:**
1. Write `docs/decisions/ADR-094d.md`. Two options:
   - **(a) Convert the chart to DaemonSet.** Pros: matches Phase 76's
     paper recommendation; matches the operator's safety annotations;
     one node = one proxy is the documented production topology.
     Cons: a breaking change for any existing user with replicated
     Deployment usage (likely zero — chart is recent).
   - **(b) Keep Deployment as default, add opt-in DaemonSet variant.**
     Pros: backward compatible. Cons: doubles chart surface area;
     forces the operator to detect which is installed.
   - **Recommendation:** (a). The chart is recent and the operator
     design assumes DaemonSet end-to-end.
2. Implement the chosen option in `deploy/helm/ja4proxy/templates/`.
3. Update `deploy/helm/ja4proxy/values.yaml` (only if option b).
4. `helm template deploy/helm/ja4proxy/` and `helm lint` must succeed.
5. If sub-phase 64b (Helm + kind smoke test) has landed, run
   `make smoke-k8s` to confirm the chart starts cleanly in `kind`.

**Acceptance criteria:**
- [ ] ADR-094d written.
- [ ] Chart change matches the ADR.
- [ ] `helm template` and `helm lint` succeed.
- [ ] `PHASE_94b_notes.md` records the option chosen.

**Out of scope:** This sub-phase covers only the ADR and chart topology change. It does not implement DaemonSet safety annotations, ArgoCD health checks, or operator code.

### 7.3 Sub-phase 94c1 — Operator repo bootstrap

**Deliverable:** A new repository `github.com/anomalyco/ja4proxy-operator`
containing the bare minimum to compile and run a controller-runtime
manager with no controllers wired.

**Steps:**
1. Create the repo (depends on org permissions — see open question §10).
2. `go mod init github.com/anomalyco/ja4proxy-operator`.
3. `main.go` with a controller-runtime manager. No controllers
   registered yet.
4. `internal/client/client.go` — verbatim copy of
   `internal/cli/client/client.go` from the main repo. Vendor the import
   path inward; do not depend on the main repo.
5. `Makefile` with `make generate`, `make manifests`, `make test`,
   `make docker-build`.
6. `.github/workflows/test.yml` running `make test` on every PR.
7. `README.md` and a stub `docs/cert-manager.md`.

**Acceptance criteria:**
- [ ] Repo created, `go build ./...` succeeds.
- [ ] `make test` runs (no tests yet; just confirms the harness works).
- [ ] CI green on initial commit.
- [ ] `PHASE_94c1_notes.md` records controller-runtime version,
      kubebuilder version, and the targeted Kubernetes API version.

**Out of scope:** This sub-phase covers only repo bootstrap. It does not add controllers, CRDs beyond stubs, or admission webhook logic.

### 7.4 Sub-phase 94c2 — CRD type stubs + admission webhook skeleton

**Deliverable:** The three CRD types and a working admission webhook
with unit tests.

**Steps:**
1. `api/v1alpha1/ja4proxyconfig_types.go`,
   `ja4proxyallowlist_types.go`, `ja4proxydial_types.go` with
   `+kubebuilder:object` markers and validation tags.
2. `make generate` produces `zz_generated.deepcopy.go`.
3. `make manifests` produces `config/crd/*.yaml`.
4. `webhook/ja4proxyconfig_webhook.go` validates dial 0–100, JA4
   regex, future `expires` timestamp, no unknown `bypassToggles` keys.
5. Unit tests for the webhook (no envtest needed yet — pure function
   tests are fine for the webhook validators).

**Acceptance criteria:**
- [ ] All three CRD types compile.
- [ ] `config/crd/*.yaml` files generated and committed.
- [ ] Webhook unit tests cover all four validation rules.
- [ ] `PHASE_94c2_notes.md` records the CRD validation tags chosen.

**Out of scope:** This sub-phase covers only CRD type stubs and the webhook skeleton. It does not implement reconciliation loops or actual CRD application against a cluster.

### 7.5 Sub-phases 94d / 94e / 94f — Three reconcilers

Each is one controller, one reconciler test suite, one merge. They
share the operator repo but touch disjoint files
(`controllers/<name>_controller.go` + `_test.go`).

#### 94d — `JA4ProxyAllowlist` reconciler (M)

- Spec list → API state diff → POST missing, DELETE stale.
- Uses the `managed_by` value chosen in 94a.
- Tests: add, remove, no-op, API 5xx → status `Reconciled=False`.

#### 94e — `JA4ProxyDial` reconciler (M)

- Watches the CRD; on change calls the dial-set endpoint.
- Handles 202: sets `status.pendingDecisionId`, emits a Kubernetes
  `Warning` event, **stops the retry loop**.
- Tests: 200 happy path, 202 pending path, 5xx retry, no-op when spec
  matches current.

#### 94f — `JA4ProxyConfig` reconciler (M)

- Hot-reloadable fields (`bypassToggles.*`) → PATCH `/api/v1/config`.
- Restart-required fields (`redisUrl`) → annotation update on the
  DaemonSet pod template (triggers a rolling restart). Operator MUST
  NOT delete pods directly.
- Tests: hot-reload path (no restart), restart path (annotation set),
  mixed change (both behaviours in one reconcile).

**Acceptance criteria (each reconciler):**
- [ ] Reconciler compiles, envtest reconciler tests pass.
- [ ] Status conditions written on success and failure paths.
- [ ] No pod deletion in any code path.
- [ ] Notes file records which Management API endpoints were exercised
      vs stubbed.

**Out of scope (94d):** This sub-phase covers only the allowlist reconciler. It does not touch dial, config, or NetBox code.

**Out of scope (94e):** This sub-phase covers only the dial reconciler. It does not touch allowlist, config, or approval UI.

**Out of scope (94f):** This sub-phase covers only the config reconciler. It does not touch actual pod restart orchestration (that's Kubernetes' job).

### 7.6 Sub-phase 94g — Operator Helm chart + ArgoCD custom health check

**Deliverable:** The operator's own Helm chart at
`deploy/helm/ja4proxy-operator/` in the operator repo.

**Includes:**
- Operator Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding.
- ValidatingWebhookConfiguration (assumes cert-manager — README
  documents the dependency).
- ArgoCD custom health check ConfigMap (§6.5), gated behind
  `{{ if .Values.argocd.enabled }}`.

**Acceptance criteria:**
- [ ] `helm lint` and `helm template` both succeed with default values.
- [ ] `argocd.enabled=false` produces a chart without the ConfigMap.
- [ ] `argocd.enabled=true` produces the ConfigMap with the Lua health
      check.
- [ ] cert-manager prerequisite documented in the chart README.

**Out of scope:** This sub-phase covers only the operator Helm chart. It does not implement ArgoCD live testing or the Lua health check ConfigMap beyond the chart template.

### 7.7 Sub-phase 94h — Documentation

**Deliverable:**
- `docs/runbooks/kubernetes_operator.md` in the **main** repo. Covers
  CRD lifecycle, pending-approval resolution workflow, envtest setup,
  cert-manager prerequisite, upgrade procedure, rollback procedure.
  Links into existing operational runbooks (do not duplicate them —
  same rule as `disaster_recovery.md` in Phase 64c).
- `deploy/k8s/README.md` in the main repo with a pointer to the
  operator repo and one worked example per CRD type, using the
  `managed_by` value chosen in 94a.

**Acceptance criteria:**
- [ ] Both files exist.
- [ ] No duplicated content from existing runbooks.
- [ ] Example CRD manifests parse cleanly with `kubectl --dry-run=client`.

**Out of scope:** This sub-phase covers only documentation. It does not update operator repo docs or touch any code.

### 7.8 Sub-phase 94i1 — NetBox loader (Go)

**Deliverable:** `internal/config/netbox.go` plus unit tests.

**Implementation:**
- `LoadTrustedCIDRsFromNetBox(ctx context.Context, url, token, tag string) ([]string, error)`.
- Issues `GET {url}/api/ipam/prefixes/?tag={tag}&limit=1000` with
  `Authorization: Token {token}` and a 5-second total timeout.
- On any HTTP non-2xx, transport error, timeout, or decode failure:
  return `[]string{}, nil` (fail-open), log WARN.

**Tests** (`internal/config/netbox_test.go` using `httptest.NewServer`):
- 200 with two prefixes → both returned.
- 500 → empty slice, no error.
- Timeout → empty slice, no error.
- Malformed JSON → empty slice, no error.
- Missing `tag` query handled correctly by the server stub.

**Acceptance criteria:**
- [ ] `go test ./internal/config/...` green.
- [ ] All five test cases pass.
- [ ] **No Python file is added.** Go-only.
- [ ] `PHASE_94i1_notes.md` records the NetBox API version targeted
      and a sample successful response shape.

**Out of scope:** This sub-phase covers only the NetBox loader function. It does not wire it into config, SIGHUP, or Prometheus metrics.

### 7.9 Sub-phase 94i2 — NetBox config wiring + SIGHUP + metric

**Deliverable:** Wire 94i1's loader into the trusted-upstream
resolution path so it actually affects proxy behaviour.

**Steps:**
1. Add the `trusted_upstream_sources` block to `config/proxy.yml` with
   `# phase-94i2` comments and conservative defaults
   (`netbox.enabled: false`).
2. In the Go pipeline's trusted-upstream resolver, on startup and on
   SIGHUP: if `netbox.enabled`, call `LoadTrustedCIDRsFromNetBox`,
   merge with `static_cidrs`, write into the in-process trie.
3. Add `ja4proxy_netbox_cidrs_loaded{status="ok|error"}` counter to
   `internal/metrics/metrics.go`.
4. Integration test: spin up `httptest.NewServer` with two prefixes,
   reload config, confirm the trie now contains the merged set and
   the counter incremented.

**Acceptance criteria:**
- [ ] Counter visible at `/metrics`.
- [ ] SIGHUP reload re-runs the loader.
- [ ] Integration test passes.
- [ ] `PHASE_94i2_notes.md` records the integration-test fixture
      used and a sample `/metrics` snippet.

**Out of scope:** This sub-phase covers only config wiring and SIGHUP. It does not change the NetBox loader algorithm or add new NetBox API fields.

### 7.10 Sub-phase 94j — Ansible `ja4proxy` role baseline

**Deliverable:** `deploy/ansible/roles/ja4proxy/` with the standard
role layout:

```
deploy/ansible/roles/ja4proxy/
  defaults/main.yml
  tasks/main.yml
  handlers/main.yml
  meta/main.yml
  README.md
  molecule/default/   # recommended
```

**Steps:**
1. Define the minimum viable role: install/pull the Go proxy image,
   drop a systemd unit (or Quadlet unit if the host has one), start
   the service, run a health check. Cross-link Phase 76 for strategy
   and Phase 64 for the smoke test.
2. Provide a Molecule scenario that converges on Rocky 9 / CentOS
   Stream 9.
3. Document required variables in `defaults/main.yml` with comments.

**Acceptance criteria:**
- [ ] Role exists with the layout above.
- [ ] `molecule converge` succeeds (or `ansible-playbook --check` if
      Molecule is unavailable in CI).
- [ ] **No reference to `proxy.py` or any Python entrypoint** anywhere.
- [ ] `PHASE_94j_notes.md` records the OS tested.

**Out of scope:** This sub-phase covers only the Ansible role baseline. It does not include CMDB registration (that's 94k) or any reference to proxy.py.

### 7.11 Sub-phase 94k — ServiceNow CMDB Ansible task

**Deliverable:** `deploy/ansible/roles/ja4proxy/tasks/cmdb_register.yml`
plus a `servicenow_enabled: false` default in `defaults/main.yml`.

**Steps:**
1. Create the task file with the body from §6.7.
2. Add `servicenow_enabled: false` to `defaults/main.yml`.
3. Include the task from `tasks/main.yml`.
4. Molecule scenario: one converge with `servicenow_enabled: false`
   (zero changed); one converge with `servicenow_enabled: true` and
   a stubbed ServiceNow endpoint that records the POST.

**Acceptance criteria:**
- [ ] Task file exists with the `when:` guard.
- [ ] Default is opt-out.
- [ ] Both Molecule scenarios pass.
- [ ] `PHASE_94k_notes.md` records the stubbing approach.

**Depends on 94j.**

**Out of scope:** This sub-phase covers only the CMDB Ansible task. It does not touch the operator, NetBox, or any other integration.

---

## 8. ADRs required

| ADR | Decision | Owner sub-phase |
|---|---|---|
| ADR-094a | Operator framework (`controller-runtime` directly vs `operator-sdk`) | 94c1 |
| ADR-094b | Admission webhook cert management (cert-manager hard dependency vs self-signed rotation script) | 94c2 |
| ADR-094c | `managed_by` value for the operator | 94a |
| ADR-094d | Helm chart topology (DaemonSet vs Deployment+opt-in DaemonSet) | 94b |

ADR-094c and ADR-094d are blocking — sub-phases 94a and 94b respectively
write them before any code change. ADR-094a and ADR-094b can be written
inside the corresponding sub-phase PRs.

---

## 9. Phase 101 entries to file during this phase

- **`policy_applier.py` / `ManagedBy` enum mismatch.** Filed by 94a.
  `src/governance/policy_applier.py` writes `managed_by="policy"` but
  the Pydantic enum at `management/api/models.py:238` does not include
  `policy`. Audit and fix.
- **(Already filed by Phase 64 re-plan, no duplicate needed):**
  Phase 76 paper-only — no Quadlet artifacts. Phase 94j must define
  systemd / Quadlet units locally rather than referencing a Phase 76
  artifact that does not exist.

---

## 10. Open questions for the maintainer

1. **Operator repo creation.** The operator must live in
   `github.com/anomalyco/ja4proxy-operator`. Does that org exist, and
   who has permission to create the repo? **Sub-phase 94c1 is blocked
   on this.**
2. **Helm topology decision.** Recommendation in §7.2: option (a),
   convert to DaemonSet outright. Confirm or override before 94b
   starts.
3. **Should this phase eventually publish to OperatorHub?** The
   original draft listed OperatorHub publication as a deferred item
   (§12 in the previous version). It is still deferred — confirm that
   is still the right call.

---

## 11. Known gaps / deferred (unchanged from the original draft)

| Item | Notes |
|---|---|
| OperatorHub publication | Business track — submit after internal validation. |
| Multi-namespace support | The operator initially watches a single namespace. Multi-tenant support is a follow-on phase. |
| Audit log for K8s operator changes | The Management API logs all changes; K8s events reference the same decision IDs. No separate audit log needed. |
