# Phase 82: Policy-as-Code, Shadow Mode & Governance

> **Prerequisite: Phase 79 (Management API) must be complete.**

> **API extension required:** Phase 79's resource catalogue must include `POST /api/v1/simulation/run` and `GET /api/v1/simulation/{id}/report` before Phase 82 can begin. Confirm these endpoints are in scope with the Phase 79 team before starting implementation.

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

```
git commit policy change to feature branch
    │
    ▼
CI: ja4proxy-cli policy validate --file ja4proxy-policy.yaml
    │  (calls POST /api/v1/config/validate in dry-run mode)
    │  Exits non-zero if: invalid YAML, unknown fields, expired TTLs,
    │  dial increase > 20 points without shadow_mode_approved flag
    ▼
PR review (human, or auto-approve for watchlist additions)
    │
    ▼
Merge to main
    │
    ▼
CI: ja4proxy-cli policy apply --file ja4proxy-policy.yaml --env prod --token $OPERATOR_TOKEN
    │  (calls PATCH /api/v1/dial, POST /api/v1/allowlist, POST /api/v1/blocklist, etc.)
    │  Idempotent: no-op for entries that already exist with matching content
    │  Reports: N added, M removed, P unchanged
    ▼
Audit log entry: actor=ci_pipeline, token=deploy-token-prod, changes=[...]
```

### 2.3 Drift Detection

A scheduled CI job (every 4 hours) runs:
```bash
ja4proxy-cli policy diff --file ja4proxy-policy.yaml --env prod
```

This calls `GET /api/v1/allowlist?managed_by=terraform` (and equivalent for other
resource types) and compares against the YAML file. Unexpected entries — those
added via the UI or direct API call with `managed_by=operator` — are reported as
drift, not automatically removed. The drift report is posted to a monitoring channel.

### 2.4 CI/CD Templates

Ship ready-to-use CI/CD workflow files:

- `.github/workflows/ja4proxy-policy.yml` — GitHub Actions
- `.gitlab-ci/ja4proxy-policy.yml` — GitLab CI
- `Jenkinsfile.ja4proxy-policy` — Jenkins Pipeline
- `deploy/ansible/playbooks/apply-policy.yml` — Ansible (for AWX/AAP)

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
This is additional storage in the analytics node's Redis or a time-series store.
Estimate: ~500 bytes per connection × 14M connections/month = ~7 GB/month.
Redis with compression, or ClickHouse for larger deployments.

### 3.3.1 Storage Backend — Decision Gate (Required Before Implementation)

The storage backend for shadow mode signal data must be decided and recorded in an ADR before any implementation begins. The two options have significantly different operational implications:

| | Option A: Redis (compressed) | Option B: ClickHouse |
|---|---|---|
| **Additional infrastructure** | None (uses existing Redis) | New ClickHouse container/cluster |
| **Estimated size (90 days)** | ~63 GB compressed (7 GB/month × 0.4 compression ratio = ~17 GB/month → ~63 GB at 90 days) | Same data, columnar — ~8–12 GB |
| **Query performance** | Adequate for ≤ 10M connections/period | Better for > 10M; supports SQL aggregations |
| **Operational complexity** | Low — no new service | High — ClickHouse backup, replication, monitoring |
| **Recommended for** | Single-site deployments, ≤ 50M connections/month | Multi-site or high-volume deployments |

**Decision process:**
1. Estimate the target deployment's connection volume (connections/month).
2. If ≤ 50M connections/month: use Option A (Redis).
3. If > 50M connections/month: use Option B (ClickHouse). Add it to `docker-compose.poc.yml` and Helm chart.
4. Record the decision in `docs/decisions/ADR-NNN.md` before writing any shadow mode code.

The acceptance criteria gate: no shadow mode implementation starts until the ADR is committed.

### 3.4 UI Integration

Shadow mode results are displayed in the Management UI with:
- Summary card on the dial configuration page: "Last simulation at dial=80: 0.09%
  of traffic would be blocked, 3 FP candidates identified."
- Drill-down to FP candidate list with "Add to allowlist" one-click action
- "Apply dial change" button that pre-fills the policy YAML with the new setting
  and the recommended allowlist additions, ready for PR creation

---

## 4. Four-Eyes Approval Workflow

Regulated industries (financial services, government) require that security rule
changes are reviewed by a second person before taking effect. This applies
particularly to: dial increases, new IP bans, bypass toggle changes, and new
fingerprint blocklist entries.

### 4.1 Built-in Pending Queue

The Management UI maintains a pending queue for changes requiring approval:

1. An Operator proposes a change (e.g., `POST /api/v1/bans` with `requires_approval: true`)
2. The change is written to `decisions:pending:{id}` with status `pending_approval`
3. The pending queue is visible to all Operators and Admins in the UI
4. A second Operator or Admin approves via `POST /api/v1/decisions/{id}/approve`
5. Only then does the change take effect (the ban is written to Redis)
6. Audit log records both the proposer and approver identities

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

## 6. Acceptance Criteria

- [ ] ADR committed to `docs/decisions/` recording shadow mode storage backend choice (Option A or B) before any implementation
- [ ] Shadow mode simulation endpoints (`POST /api/v1/simulation/run`, `GET /api/v1/simulation/{id}/report`) confirmed in Phase 79 API catalogue
- [ ] Policy YAML schema validated and documented in `docs/policy/schema.md`
- [ ] `ja4proxy-cli policy validate` catches invalid YAML, unknown fields, TTL violations
- [ ] `ja4proxy-cli policy apply` is idempotent across all resource types
- [ ] `ja4proxy-cli policy diff` correctly identifies drift vs policy file
- [ ] GitHub Actions, GitLab CI, and Jenkins pipeline templates ship in repo
- [ ] Shadow mode simulation endpoint returns results within 5 minutes for 30-day window
- [ ] Simulation report includes FP candidates with enriched context
- [ ] Shadow mode results visible in Management UI dial configuration page
- [ ] "Add FP candidates to allowlist" one-click action working
- [ ] Four-eyes pending queue visible to all Operators and Admins
- [ ] Approval gate enforced — changes do not apply until approved
- [ ] `approval_required` config respected per change type
- [ ] ServiceNow auto-change-record creation working when configured
- [ ] All rule changes attributed in audit log with source, actor, approver
- [ ] Audit log exported as evidence for SOC 2 auditor review
