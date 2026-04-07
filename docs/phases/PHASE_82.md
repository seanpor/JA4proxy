# Phase 82: Policy-as-Code, Shadow Mode & Governance

> **Prerequisite: Phase 79 (Management API) must be in a state where the API endpoints
> listed in §9 exist and are authenticated. Phase 79 does not need to be fully complete
> (SSO, MFA, etc.) — only the resource API and token auth are required.**

> **Phase 83 note:** `ja4proxy-cli policy` commands are Phase 83 deliverables. Phase 82
> ships a thin Python stopgap script (`scripts/ja4proxy-policy.py`) with the same
> interface. Phase 83 replaces it with the compiled Go binary — existing CI/CD templates
> need no changes.

---

## 1. Overview

IaC-mature enterprises expect security rules to live in version control — reviewed
via pull request, tested in CI, applied automatically on merge. This phase delivers
three interconnected governance capabilities:

1. **Policy-as-code** — all JA4proxy rules expressed as YAML, versioned in git,
   applied via the Management API in CI/CD
2. **Shadow mode simulation** — "what would dial=80 have blocked last week?" — the
   single feature most likely to give a CISO the confidence to raise the dial
3. **Four-eyes approval workflow** — peer review on high-impact changes; ITSM
   integration for regulated environments

Shadow mode is the highest-value feature in this phase. The core asymmetry of
JA4proxy (false positives are expensive) means every customer deploys with dial=0.
Without shadow mode, there is no evidence to justify raising it. Shadow mode is the
mechanism that makes the product actually deliver protection, not just log.

---

## 2. Policy-as-Code

### 2.1 Policy YAML Schema

All mutable JA4proxy rules are representable as a single YAML file checked into
the customer's git repository:

```yaml
# ja4proxy-policy.yaml
# Managed by: git + CI/CD. Manual changes via UI are tracked via managed_by field.

meta:
  version: "1.0"
  environment: prod
  last_updated: "2026-04-04T14:23:01Z"
  last_updated_by: "j.smith@company.com"

dial:
  setting: 70
  changed_by: "m.jones@company.com"
  ticket: "CHG0001234"
  notes: "Raised from 60 after 30-day shadow mode validation"
  shadow_mode_approved: true   # required when increase > 20 points

allowlist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"
      reason: "Internal monitoring tool — Chrome 131 on macOS"
      added_by: "j.smith@company.com"
      ticket: "CHG0001100"
    - ja4: "t13d1516h2_112233445566_aabbccddeeff"
      reason: "Partner API client — known good fingerprint"
      added_by: "m.jones@company.com"
      expires: "2027-01-01T00:00:00Z"
  ips:
    - cidr: "10.0.0.0/8"
      reason: "Internal network — never block"
      added_by: "ops-team"

blocklist:
  fingerprints:
    - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
      reason: "Known Cobalt Strike default profile"
      source: "threat_intel_feed"
      added_by: "auto_feed_ingest"
      ticket: "INC0005432"
    - ja4: "t13d190900_9dc949161b6c_e7d705d9851f"
      reason: "Confirmed scanner — Masscan with TLS"
      added_by: "j.smith@company.com"
      ticket: "INC0005100"
      expires: "2026-07-01T00:00:00Z"

watchlist:
  ips:
    - ip: "198.51.100.0/24"
      reason: "Suspicious /24 — monitoring before ban decision"
      added_by: "j.smith@company.com"
      ticket: "INC0005500"
      expires: "2026-04-11T00:00:00Z"

bypass_toggles:
  alpn_browser_bypass: true
  ja4_whitelist_bypass: true
  mtls_bypass: true
  spamhaus_bypass: true
  tls_version_bypass: true
```

### 2.2 Apply Workflow

Phase 82 ships `scripts/ja4proxy-policy.py` — a Python script making direct API
calls. Phase 83 replaces this with the compiled `ja4proxy-cli` Go binary. The
interface is identical; CI/CD templates do not change.

```
git commit policy change to feature branch
    │
    ▼
CI: python3 scripts/ja4proxy-policy.py validate --file ja4proxy-policy.yaml
    │  (runs entirely offline — no API call required)
    │  Exits non-zero if: invalid YAML, unknown fields, expired TTLs,
    │  dial increase > 20 points without shadow_mode_approved: true
    ▼
PR review (human, or auto-approve for watchlist additions)
    │
    ▼
Merge to main
    │
    ▼
CI: python3 scripts/ja4proxy-policy.py apply \
      --file ja4proxy-policy.yaml --url $JA4PROXY_URL --token $OPERATOR_TOKEN
    │  Calls: PATCH /api/v1/dial, POST /api/v1/allowlist,
    │         POST /api/v1/blocklist, POST /api/v1/config, etc.
    │  Idempotent: entries already present with matching content → no-op
    │  Reports: N added, M removed, P unchanged
    │  Approval gate: if a change requires approval (§4.2), the API returns
    │  202 Accepted with a decision_id. Script reports PENDING and exits 2.
    │  CI job fails until the change is approved via the UI or decisions API.
    ▼
Audit log entry: actor=ci_pipeline, token=deploy-token-prod, changes=[...]
```

#### Dial idempotency behaviour

The policy file is the source of truth. If the policy says `dial: 70` and
production is at `dial: 80`, `policy apply` **will lower the dial**. This is
intentional — the YAML file governs. If `approval_required.dial_decrease: true`,
lowering also creates a pending decision rather than applying directly.

#### `bypass_toggles` and the approval queue

`bypass_toggle_change: true` (default in §4.2) means the management API returns
`202 Accepted` when a bypass toggle is changed via policy apply. The change enters
the pending queue. CI reports `PENDING APPROVAL` and exits non-zero until an Admin
approves via `POST /api/v1/decisions/{id}/approve`. This is not a bypass hole —
policy apply is subject to the same approval rules as the UI.

### 2.3 Drift Detection

A scheduled CI job (every 4 hours) runs:
```bash
python3 scripts/ja4proxy-policy.py diff \
  --file ja4proxy-policy.yaml --url $JA4PROXY_URL --token $OPERATOR_TOKEN
```

This calls `GET /api/v1/allowlist?managed_by=policy` (and equivalent for other
resource types) and compares against the YAML file. Resources applied by policy
carry `managed_by=policy`. Unexpected entries — those added via the UI or direct
API call with `managed_by=operator` — are reported as drift, not automatically
removed. The drift report is posted to a monitoring channel.

**Phase 79 coordination:** `managed_by=policy` is a new value not in Phase 79's
current design (`terraform`, `operator`, `api`, `analytics`). This value must be
added to Phase 79 before Phase 82 implements drift detection. See §9.

### 2.4 CI/CD Templates

Ship ready-to-use CI/CD workflow files:

- `.github/workflows/ja4proxy-policy.yml` — GitHub Actions
- `.gitlab-ci/ja4proxy-policy.yml` — GitLab CI
- `Jenkinsfile.ja4proxy-policy` — Jenkins Pipeline
- `deploy/ansible/playbooks/apply-policy.yml` — Ansible (for AWX/AAP)

All templates use `scripts/ja4proxy-policy.py`. When Phase 83 ships the CLI
binary, replace `python3 scripts/ja4proxy-policy.py` with `ja4proxy-cli policy`
— no other changes required.

---

## 3. Shadow Mode Simulation

Shadow mode answers: "If I had set dial=X last week, what would have been blocked
that was actually allowed?" This is the evidence a CISO needs to raise the dial
confidently.

### 3.1 How It Works

The analytics node stores sufficient per-connection signal data to replay the scoring
decision at a hypothetical dial setting. The simulation runs as a background job and
does not affect live traffic.

```
POST /api/v1/simulation/run
{
  "name": "dial-80-last-30-days",
  "hypothetical_dial": 80,
  "time_range": {
    "from": "2026-03-05T00:00:00Z",
    "to": "2026-04-04T00:00:00Z"
  }
}

→ 202 Accepted
{
  "simulation_id": "sim-20260404-a3f2",
  "status": "running",
  "estimated_completion": "2026-04-04T14:35:00Z"
}
```

**Phase 79 coordination:** `POST /api/v1/simulation/run` and
`GET /api/v1/simulation/{id}/report` are not in Phase 79's current resource
catalogue. They must be added before Phase 82 implements these endpoints. See §9.

### 3.2 Simulation Report

```
GET /api/v1/simulation/{id}/report

→ 200 OK
{
  "simulation_id": "sim-20260404-a3f2",
  "hypothetical_dial": 80,
  "period": "30 days",
  "summary": {
    "total_connections": 14200000,
    "would_have_blocked": 12847,
    "would_have_tarpitted": 3241,
    "blocked_pct": 0.090,
    "estimated_fp_count": 3,
    "estimated_fp_pct": 0.023
  },
  "top_blocked_fingerprints": [
    {"ja4": "t10d170900_...", "count": 4821, "likely_category": "scanner"},
    {"ja4": "t13d190900_...", "count": 2100, "likely_category": "headless_browser"}
  ],
  "fp_candidates": [
    {
      "source_ip": "203.0.113.5",
      "ja4": "t13d1516h2_...",
      "score_at_dial_80": 72,
      "reason": "datacenter_asn + missing_sni",
      "note": "This IP resolves to monitoring.partner.com — likely a legitimate monitor"
    }
  ],
  "recommendation": "Safe to raise dial to 80. 3 potential false positives identified — review fp_candidates before applying."
}
```

### 3.3 Required Data Retention

Shadow mode requires connection-level signal data retained for at least 90 days.
Estimate: ~500 bytes per connection × 14M connections/month = ~7 GB/month.

### 3.3.1 Storage Backend — Decision Gate (Required Before Implementation)

The storage backend for shadow mode signal data must be decided and recorded in an
ADR (`docs/decisions/ADR-082.md`) before any implementation begins. The two options:

| | Option A: Redis (compressed) | Option B: ClickHouse |
|---|---|---|
| **Additional infrastructure** | None (uses existing Redis) | New ClickHouse container/cluster |
| **Estimated size (90 days)** | ~63 GB compressed (~17 GB/month after LZ4 compression) | Same data, columnar — ~8–12 GB |
| **Query performance** | Adequate for ≤ 10M connections/period | Better for > 10M; supports SQL aggregations |
| **Operational complexity** | Low — no new service | High — ClickHouse backup, replication, monitoring |
| **Recommended for** | Single-site, ≤ 50M connections/month | Multi-site or high-volume |

**Decision process:**
1. Estimate the target deployment's connection volume.
2. ≤ 50M connections/month → Option A (Redis). > 50M → Option B (ClickHouse).
3. Record the decision in `docs/decisions/ADR-082.md`.
4. No shadow mode code starts until the ADR is committed.

### 3.4 Analytics Node Pre-Conditions

Shadow mode requires the analytics node (Phase 12, Python) to be extended before
the simulation API can return meaningful results. This work must be scoped and
completed as part of Phase 82:

1. **Signal retention store**: after each connection, write a compact signal snapshot
   to the chosen storage backend. Schema: `{timestamp, source_ip, ja4, score, signals[]}`.
   Key: `sim:conn:{unix_ts_hour}:{conn_id}` (Redis) or equivalent row (ClickHouse).
2. **Retention sweep**: background task deletes records older than 90 days (Redis TTL
   or ClickHouse TTL policy).
3. **Simulation runner**: iterates stored snapshots for the requested time range,
   re-runs `ActionDecider.decide()` at the hypothetical dial, accumulates results.
4. **FP enrichment**: for connections the simulation would have blocked, enrich with
   FCrDNS data (already available from Phase 7) to generate `fp_candidates`.

### 3.5 UI Integration

Shadow mode results are displayed in the Management UI with:
- Summary card on the dial configuration page: "Last simulation at dial=80: 0.09%
  of traffic would be blocked, 3 FP candidates identified."
- Drill-down to FP candidate list with "Add to allowlist" one-click action
- "Apply dial change" button that pre-fills the policy YAML with the new setting
  and the recommended allowlist additions, ready for PR creation

*UI implementation is blocked on Management UI phases (13, 51, 52). The API
endpoints are implemented regardless; UI follows when the UI phases are active.*

---

## 4. Four-Eyes Approval Workflow

Regulated industries (financial services, government) require that security rule
changes are reviewed by a second person before taking effect. This applies
particularly to: dial increases, new CIDR bans, bypass toggle changes, and new
fingerprint blocklist entries.

### 4.1 Built-in Pending Queue

The Management API maintains a pending queue for changes requiring approval. When a
mutating call is made for a change type that has `approval_required: true`, the API
returns `202 Accepted` instead of `200 OK`, and the change is written to
`decisions:pending:{id}` with status `pending_approval`:

1. An Operator proposes a change (e.g., `POST /api/v1/bans` with TTL > 30 days)
2. The API returns `202 Accepted { "decision_id": "dec-abc123", "status": "pending_approval" }`
3. The pending queue is visible to all Operators and Admins in the UI
4. A second Operator or Admin approves via `POST /api/v1/decisions/{id}/approve`
5. Only then does the change take effect (the ban is written to Redis)
6. Audit log records both proposer and approver identities

**Phase 79 coordination:** `POST /api/v1/decisions`, `GET /api/v1/decisions`,
`POST /api/v1/decisions/{id}/approve`, `POST /api/v1/decisions/{id}/reject` are
not in Phase 79's current resource catalogue. See §9.

### 4.2 Which Changes Require Approval

Configurable per environment in `config/proxy.yml`:

```yaml
governance:
  approval_required:
    dial_increase: true          # any upward dial change
    dial_decrease: false         # lowering dial never requires approval
    new_ban: false               # per-IP bans can be immediate (incident response)
    new_cidr_ban: true           # CIDR bans always require approval
    bypass_toggle_change: true   # any bypass enable/disable
    blocklist_addition: false    # fingerprint blocklist additions
    allowlist_addition: false    # allowlist additions
  auto_approve_after_hours: 0   # 0 = never auto-approve; set to N for timeout approval
  # WARNING: setting auto_approve_after_hours > 0 means security configuration
  # changes apply without human review after the timeout. Only enable if 24×7 coverage
  # is impossible and the business accepts this risk. Document in your risk register.
```

### 4.3 ServiceNow Change Record Integration

For environments with formal change management:

```yaml
governance:
  itsm_integration:
    provider: servicenow
    require_change_ticket: true
    ticket_pattern: "^CHG[0-9]{7}$"
    auto_create_change: true      # create CHG record automatically on proposal
    servicenow_url: "https://company.service-now.com"
    servicenow_token: "${SERVICENOW_API_TOKEN}"
```

When `auto_create_change: true`, proposing a change automatically creates a
ServiceNow Standard Change record. The change ticket number is attached to the
pending queue entry and appears in the audit log.

---

## 5. Rule Audit Trail

All rule changes — whether made via the UI, API, policy-as-code apply, or SOAR
platform — are recorded in the append-only audit trail from Phase 79, with:

- `actor_id`: user email, API token ID, or `ci_pipeline`
- `action`: `ban_added`, `ban_released`, `allowlist_entry_added`, `dial_changed`, etc.
- `before_value` and `after_value`: the full resource state before and after
- `itsm_ticket`: if provided
- `approved_by`: if four-eyes workflow was used
- `source`: `ui`, `api`, `policy_apply`, `soar_xsoar`, `soar_servicenow`, etc.

This trail satisfies PCI-DSS 10.x (audit logging of access to cardholder data
environment security controls) and SOC 2 CC7.2 (monitoring of system operations).

---

## 6. File Locations

```
src/governance/
  __init__.py
  policy_schema.py          # Pydantic v2 models for policy YAML
  policy_validator.py       # offline validation logic (TTL, dial, CIDR checks)
  policy_applier.py         # async aiohttp client that applies policy via API

scripts/
  ja4proxy-policy.py        # CLI entry point (stopgap until Phase 83 CLI)

.github/workflows/
  ja4proxy-policy.yml       # GitHub Actions CI/CD template

.gitlab-ci/
  ja4proxy-policy.yml       # GitLab CI template

Jenkinsfile.ja4proxy-policy # Jenkins Pipeline template

deploy/ansible/playbooks/
  apply-policy.yml          # Ansible playbook (AWX/AAP)

docs/policy/
  schema.md                 # Human-readable policy YAML schema documentation

docs/decisions/
  ADR-082.md                # Shadow mode storage backend decision (REQUIRED GATE)

tests/unit/
  test_policy_validator.py  # Offline validator unit tests (no API needed)

tests/integration/
  test_policy_apply.py      # Policy apply/diff integration tests (require API mock)
```

Analytics node additions (in existing files):
```
analytics/
  signal_retention.py       # New: write connection signal snapshots; retention sweep
  simulation_runner.py      # New: replay scoring at hypothetical dial
```

---

## 7. Redis Key Schema

New keys introduced in Phase 82:

| Key pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `decisions:pending:{id}` | Hash | None (explicit delete on approve/reject) | Pending approval queue entry: `{proposed_by, action, resource_type, resource_id, payload, status, created_at, itsm_ticket}` |
| `decisions:history` | Stream (XADD) | None | Append-only log of all approve/reject decisions |
| `sim:conn:{hour_epoch}:{conn_id}` | Hash | 90 days | Connection signal snapshot for shadow mode replay |
| `sim:job:{sim_id}` | Hash | 7 days | Simulation job state: `{status, hypothetical_dial, from_ts, to_ts, result_json}` |

Add these entries to `docs/REDIS_SCHEMA.md` when Phase 82 is implemented.

---

## 8. Test Plan

### 8.1 Unit Tests — Offline (`tests/unit/test_policy_validator.py`)

All tests run without a network connection or running API.

| Test | What it verifies |
|------|-----------------|
| `test_valid_minimal_policy` | Minimal valid YAML passes validation |
| `test_invalid_yaml_syntax` | Malformed YAML raises `PolicySyntaxError` with line number |
| `test_unknown_field_raises` | Extra top-level field fails strict validation |
| `test_expired_ttl_detected` | `expires` value in the past raises `PolicyTTLError` |
| `test_dial_increase_gt_20_without_flag` | dial increase > 20 points without `shadow_mode_approved: true` exits non-zero |
| `test_dial_increase_gt_20_with_flag` | same increase with `shadow_mode_approved: true` passes |
| `test_dial_decrease_no_flag_required` | dial decrease never requires `shadow_mode_approved` |
| `test_invalid_cidr_notation` | `cidr: "not-a-cidr"` raises `PolicySchemaError` |
| `test_invalid_ja4_format` | Fingerprint not matching JA4 pattern raises error |
| `test_duplicate_allowlist_entries` | Two identical JA4 entries raise `PolicyDuplicateError` |
| `test_bypass_toggle_unknown_key` | Unrecognised bypass name raises error |

### 8.2 Integration Tests (`tests/integration/test_policy_apply.py`)

Use a mock Management API server (same pattern as `tests/mocks/soar_mock.py`).

| Test | What it verifies |
|------|-----------------|
| `test_apply_idempotent_allowlist_entry` | Applying same entry twice: second call is a no-op (no duplicate POST) |
| `test_apply_adds_new_blocklist_entry` | Entry in policy but not in API → POST called once |
| `test_apply_removes_entry_not_in_policy` | Entry in API (`managed_by=policy`) but not in YAML → DELETE called |
| `test_apply_operator_drift_not_removed` | Entry with `managed_by=operator` not in YAML → no DELETE (drift only) |
| `test_apply_sets_dial` | `dial.setting: 70` → `PATCH /api/v1/dial` called with `{"value": 70}` |
| `test_apply_pending_on_approval_required` | Mock API returns 202 → script exits with code 2, prints `PENDING APPROVAL: {id}` |
| `test_diff_detects_operator_drift` | Entry in API not in policy YAML → reported as drift in output |
| `test_diff_clean_no_drift` | Policy matches API state → output is `No drift detected` |

### 8.3 Platform-Dependent Tests (deferred to Phase 100)

- Policy apply against live Phase 79 API with real tokens
- Four-eyes approval flow end-to-end via Management UI
- ServiceNow auto-change-record creation
- Shadow mode simulation results via running analytics node

---

## 9. Phase 79 Coordination Requirements

**Before Phase 82 implementation begins, confirm the following are in Phase 79's
scope and will ship in Phase 79:**

| Item | Required for | Status |
|------|-------------|--------|
| `POST /api/v1/simulation/run` added to resource catalogue | Shadow mode | Needs confirmation |
| `GET /api/v1/simulation/{id}/report` added to resource catalogue | Shadow mode | Needs confirmation |
| `GET /api/v1/decisions` — list pending decisions | Four-eyes workflow | Needs confirmation |
| `POST /api/v1/decisions/{id}/approve` | Four-eyes workflow | Needs confirmation |
| `POST /api/v1/decisions/{id}/reject` | Four-eyes workflow | Needs confirmation |
| `managed_by=policy` added as valid value (alongside `terraform`, `operator`, `api`, `analytics`) | Drift detection | Needs confirmation |
| Mutation endpoints return `202 Accepted` with `decision_id` when approval required | Policy apply + approval queue | Needs confirmation |

These items cannot be assumed — they must be explicitly confirmed with whoever is
working Phase 79. If Phase 79 cannot take them, Phase 82 must implement them as
an extension to the management service.

---

## 10. Acceptance Criteria

### 10.1 Offline-Testable (CI must pass these before any platform work)

- [ ] `ADR-082.md` committed to `docs/decisions/` with storage backend decision before any shadow mode code
- [ ] `docs/policy/schema.md` documents the full policy YAML schema
- [ ] `src/governance/policy_schema.py` — Pydantic models for all policy YAML fields
- [ ] `src/governance/policy_validator.py` — all 11 unit tests in §8.1 pass
- [ ] `scripts/ja4proxy-policy.py validate` exits 0 on valid YAML, non-zero on all error types
- [ ] `scripts/ja4proxy-policy.py validate` exits non-zero on dial increase > 20 without `shadow_mode_approved: true`
- [ ] GitHub Actions, GitLab CI, and Jenkins templates ship and use `scripts/ja4proxy-policy.py`
- [ ] All 8 integration tests in §8.2 pass against the mock Management API server
- [ ] `managed_by=policy` usage confirmed with Phase 79 team (see §9)

### 10.2 Platform-Dependent (deferred to Phase 100 item 100-F)

- [ ] `policy apply` is idempotent across all resource types against a live Phase 79 API
- [ ] `policy diff` correctly identifies drift added via the Management UI
- [ ] Shadow mode simulation endpoint returns results within 5 minutes for a 30-day window
- [ ] Simulation report includes FP candidates with FCrDNS enrichment
- [ ] Four-eyes pending queue visible to Operators and Admins in Management UI
- [ ] Approval gate enforced — changes do not apply until approved
- [ ] `approval_required` config respected per change type
- [ ] ServiceNow auto-change-record creation working when configured
- [ ] All rule changes attributed in audit log with source, actor, and approver
- [ ] Audit log exported as JSONL for SOC 2 auditor review

---

## 11. Implementation Notes

Decisions made during Phase 82 planning that are non-obvious:

1. **`ja4proxy-cli` stopgap pattern**: The Phase 82 Python script and Phase 83 Go CLI
   have an identical command interface (`validate`, `apply`, `diff`). CI templates
   swap one for the other by changing one word. This avoids reworking CI templates
   when Phase 83 ships.

2. **Policy apply subject to approval rules**: Policy apply is NOT a governance bypass.
   When the management API returns 202 for a pending change, the apply script exits
   with code 2 ("PENDING APPROVAL"). This makes CI fail until the change is approved
   by a human — aligning policy-as-code and four-eyes governance rather than
   contradicting them.

3. **`managed_by=policy` is a new Phase 79 value**: Policy-applied resources use
   `managed_by=policy`, not `managed_by=terraform`. Terraform-managed resources are
   Phase 83's domain. The drift detection query uses `?managed_by=policy`.
   Operator-added resources (`managed_by=operator`) are reported as drift but never
   auto-removed — removing them requires an explicit policy file change.

4. **Dial is the source of truth from the policy file**: If the policy says `dial: 70`
   and production is at `dial: 80`, policy apply lowers the dial. The policy file is
   the authoritative state. This is intentional and should be documented to operators
   before they enable policy-as-code.

5. **Shadow mode ADR is a hard gate**: No shadow mode code is written until
   `docs/decisions/ADR-082.md` is committed. The decision (Redis vs ClickHouse) has
   significant architectural consequences. Do not start implementation and then
   write the ADR — that defeats the purpose.

6. **Analytics node work is in scope for Phase 82**: Shadow mode requires new code in
   `analytics/signal_retention.py` and `analytics/simulation_runner.py`. These are
   not delegated to Phase 12 retrospectively — Phase 82 owns them.

---

## 12. Business Track

The shadow mode and policy-as-code features should be demonstrated to enterprise
prospects in a product trial environment:

- Trial environment setup: `docker compose -f docker-compose.poc.yml up`
- Seed 30 days of synthetic traffic: `python3 scripts/generate_synthetic_traffic.py --days 30`
- Run shadow mode simulation: `python3 scripts/ja4proxy-policy.py simulate --dial 80 --days 30`
- The simulation report is the artifact a CISO uses to justify raising the dial
