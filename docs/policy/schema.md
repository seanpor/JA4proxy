<!--
title: Policy Schema
audience: Operators
last_reviewed: 2026-04-07
phase: 82
-->

# JA4proxy Policy YAML Schema

This document describes the `ja4proxy-policy.yaml` file. Security operators use this
reference to understand every field they can configure.

---

## Overview

`ja4proxy-policy.yaml` is a single YAML file that expresses all mutable JA4proxy
rules. It lives in the customer's git repository, is reviewed via pull request, and
applied to a running proxy via the management API during CI/CD.

**Where it lives:** anywhere in your repository. The CI/CD templates default to
`ja4proxy-policy.yaml` at the repository root.

**How it gets applied:**

```
git commit policy change
    │
    ▼
CI: python3 scripts/ja4proxy-policy.py validate --file ja4proxy-policy.yaml
    │  (runs offline — no API call required)
    ▼
PR review → merge to main
    │
    ▼
CI: python3 scripts/ja4proxy-policy.py apply \
      --file ja4proxy-policy.yaml --url $JA4PROXY_URL --token $OPERATOR_TOKEN
```

The policy file is the **source of truth**. If the file says `dial: 70` and
production is at `dial: 80`, `policy apply` will lower the dial. This is intentional.

**Phase 83 note:** Phase 82 ships a Python stopgap script (`scripts/ja4proxy-policy.py`).
Phase 83 replaces it with the compiled `ja4proxy-cli` Go binary. The interface is
identical; CI/CD templates need no changes.

---

## Full Annotated Example

```yaml
# ja4proxy-policy.yaml
# Managed by: git + CI/CD. Manual changes via UI are tracked via managed_by field.

meta:
  version: "1.0"                         # Schema version. Always "1.0" for Phase 82.
  environment: prod                       # Target environment (prod, staging, dev).
  last_updated: "2026-04-04T14:23:01Z"   # ISO 8601 timestamp. Set by the CI runner.
  last_updated_by: "j.smith@company.com" # Identity of person who authored the change.

dial:
  setting: 70                            # Integer 0–100. 0 = monitor mode (never blocks).
  changed_by: "m.jones@company.com"      # Identity of person authorising the dial change.
  ticket: "CHG0001234"                   # ITSM change ticket reference.
  notes: "Raised from 60 after 30-day shadow mode validation"
  shadow_mode_approved: true             # Required when the increase is > 20 points.

allowlist:
  fingerprints:
    - ja4: "t13d1516h2_aabbccddeeff_aabbccddeeff"  # Must match JA4 pattern (see §Validation).
      reason: "Internal monitoring tool — Chrome 131 on macOS"
      added_by: "j.smith@company.com"
      ticket: "CHG0001100"                # Optional ITSM reference.
    - ja4: "t13d1516h2_112233445566_aabbccddeeff"
      reason: "Partner API client — known good fingerprint"
      added_by: "m.jones@company.com"
      expires: "2027-01-01T00:00:00Z"    # Optional. Must be a future ISO 8601 timestamp.
  ips:
    - cidr: "10.0.0.0/8"                 # IPv4 or IPv6 CIDR. Must be valid CIDR notation.
      reason: "Internal network — never block"
      added_by: "ops-team"

blocklist:
  fingerprints:
    - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
      reason: "Known Cobalt Strike default profile"
      source: "threat_intel_feed"        # Optional. Free-text source description.
      added_by: "auto_feed_ingest"
      ticket: "INC0005432"
    - ja4: "t13d190900_9dc949161b6c_e7d705d9851f"
      reason: "Confirmed scanner — Masscan with TLS"
      added_by: "j.smith@company.com"
      ticket: "INC0005100"
      expires: "2026-07-01T00:00:00Z"   # Block entry auto-expires on this date.

watchlist:
  ips:
    - ip: "198.51.100.0/24"             # Can be a single IP or CIDR.
      reason: "Suspicious /24 — monitoring before ban decision"
      added_by: "j.smith@company.com"
      ticket: "INC0005500"
      expires: "2026-04-11T00:00:00Z"

bypass_toggles:
  # Each toggle maps to a bypass condition in config/proxy.yml security_policy.
  # true = bypass enabled (default behaviour). false = route through scorer instead.
  # WARNING: disabling ALLOW bypasses increases false positive risk.
  alpn_browser_bypass: true    # h2/h1 ALPN → ALLOW without scoring
  ja4_whitelist_bypass: true   # JA4 in whitelist → ALLOW without scoring
  mtls_bypass: true            # Valid mTLS client cert → ALLOW without scoring
  spamhaus_bypass: true        # Spamhaus DROP/EDROP match → hard block
  tls_version_bypass: true     # TLS 1.0/1.1 → immediate RST
```

---

## Field Reference

### `meta`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `version` | string | yes | Policy schema version | Must be `"1.0"` |
| `environment` | string | yes | Target environment name | Free text (e.g. `prod`, `staging`) |
| `last_updated` | string | no | Timestamp of last change | ISO 8601 format |
| `last_updated_by` | string | no | Author of the last change | Free text |

---

### `dial`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `setting` | integer | yes | Dial value to apply | 0–100 |
| `changed_by` | string | no | Identity authorising the change | Free text |
| `ticket` | string | no | ITSM change ticket reference | Must match `ticket_pattern` if ITSM integration is enabled |
| `notes` | string | no | Human-readable rationale | Free text |
| `shadow_mode_approved` | boolean | conditional | Confirms shadow mode review was done | Required when the new `setting` is more than 20 points above the current production value |

---

### `allowlist`

#### `allowlist.fingerprints[]`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `ja4` | string | yes | JA4 fingerprint to allow | Must match `[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}` |
| `reason` | string | yes | Why this fingerprint is allowed | Free text |
| `added_by` | string | yes | Identity of the person adding the entry | Free text |
| `ticket` | string | no | ITSM reference | Free text |
| `expires` | string | no | Expiry timestamp | ISO 8601; must be a future date |

#### `allowlist.ips[]`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `cidr` | string | yes | IP address or CIDR to allow | Valid IPv4 or IPv6 CIDR notation |
| `reason` | string | yes | Why this IP/range is allowed | Free text |
| `added_by` | string | yes | Identity of the person adding the entry | Free text |
| `ticket` | string | no | ITSM reference | Free text |
| `expires` | string | no | Expiry timestamp | ISO 8601; must be a future date |

---

### `blocklist`

#### `blocklist.fingerprints[]`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `ja4` | string | yes | JA4 fingerprint to block | Must match `[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}` |
| `reason` | string | yes | Why this fingerprint is blocked | Free text |
| `added_by` | string | yes | Identity of the person adding the entry | Free text |
| `source` | string | no | Origin of the block intelligence | Free text (e.g. `threat_intel_feed`) |
| `ticket` | string | no | ITSM reference | Free text |
| `expires` | string | no | Expiry timestamp | ISO 8601; must be a future date |

---

### `watchlist`

#### `watchlist.ips[]`

| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `ip` | string | yes | IP address or CIDR to watch | Valid IPv4 or IPv6 address or CIDR |
| `reason` | string | yes | Why this IP/range is being monitored | Free text |
| `added_by` | string | yes | Identity of the person adding the entry | Free text |
| `ticket` | string | no | ITSM reference | Free text |
| `expires` | string | no | Expiry timestamp | ISO 8601; must be a future date |

---

### `bypass_toggles`

All fields are boolean and optional. Omitting a field leaves the current production
value unchanged.

| Field | Default | Description |
|-------|---------|-------------|
| `alpn_browser_bypass` | `true` | `h2`/`h1` ALPN connections bypass scoring and are always allowed. Disabling increases false positive risk for browser traffic. |
| `ja4_whitelist_bypass` | `true` | JA4 fingerprints in the allowlist bypass scoring. Disabling routes them through the scorer. |
| `mtls_bypass` | `true` | Connections presenting a valid mTLS client certificate bypass scoring. |
| `spamhaus_bypass` | `true` | IPs matching Spamhaus DROP/EDROP are hard-blocked. Disabling routes them through the scorer with a +80 risk signal instead. |
| `tls_version_bypass` | `true` | Connections using TLS 1.0 or 1.1 are immediately reset. Disabling routes them through the scorer instead. |

Any change to `bypass_toggles` returns `202 Accepted` from the management API (by
default) and enters the four-eyes pending queue. CI reports `PENDING APPROVAL` and
exits non-zero until an Admin approves the change.

---

## Validation Rules

The `validate` command runs entirely offline — no API call is required. It checks:

1. **YAML must be parseable.** A malformed YAML file exits non-zero with the line
   number of the syntax error.

2. **No unknown top-level keys.** Only `meta`, `dial`, `allowlist`, `blocklist`,
   `watchlist`, and `bypass_toggles` are permitted. Any other key is an error.

3. **`expires` fields must be future dates.** An `expires` value in the past raises
   a validation error. Use ISO 8601 format: `"2027-01-01T00:00:00Z"`.

4. **`dial.setting` must be 0–100.** Any value outside this range is an error.

5. **Dial increase > 20 points requires `shadow_mode_approved: true`.** If
   `dial.setting` is more than 20 points above the current production value and
   `shadow_mode_approved` is absent or `false`, the command exits non-zero.
   Pass `--current-dial N` to `validate` to supply the current production value
   for offline checking.

6. **CIDR notation must be valid.** Both IPv4 and IPv6 CIDRs are accepted.
   `"not-a-cidr"` is an error.

7. **JA4 fingerprints must match the pattern** `[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}`.
   Any fingerprint that does not match is an error.

8. **No duplicate JA4 fingerprints within the same list.** Two identical fingerprints
   in `allowlist.fingerprints` or two identical fingerprints in `blocklist.fingerprints`
   raise an error. A fingerprint may appear in both the allowlist and blocklist
   (though this is unusual and produces a warning).

---

## Apply Behaviour

`policy apply` calls the management API to synchronise the running state with
the policy file.

- **Idempotent:** entries already present in the API with matching content produce
  no API call. The command reports `N added, M removed, P unchanged`.
- **Source of truth:** the policy file governs. If the proxy has `dial: 80` and
  the file has `dial: 70`, apply will lower the dial.
- **Drift — operator-added entries are not auto-removed.** Entries added via the
  Management UI or direct API call (`managed_by=operator`) are reported as drift
  by `policy diff` but are never deleted by `policy apply`. Only entries previously
  applied by policy (`managed_by=policy`) are removed when absent from the YAML file.

**Drift detection** runs every 4 hours in CI:

```bash
python3 scripts/ja4proxy-policy.py diff \
  --file ja4proxy-policy.yaml --url $JA4PROXY_URL --token $OPERATOR_TOKEN
```

Unexpected entries are reported to a monitoring channel. Nothing is deleted
automatically.

---

## Approval Rules

Some changes require a second person to approve before they take effect. When the
management API requires approval for a change, it returns `202 Accepted` with a
`decision_id`. The apply script prints `PENDING APPROVAL: {decision_id}` and exits
with code 2. The CI job fails until the change is approved.

**Approval is required (default configuration) for:**
- Any dial increase (`approval_required.dial_increase: true`)
- New CIDR bans (`approval_required.new_cidr_ban: true`)
- Any `bypass_toggles` change (`approval_required.bypass_toggle_change: true`)

**Approval is not required by default for:**
- Dial decreases
- Per-IP bans (to allow fast incident response)
- Individual fingerprint additions to the allowlist or blocklist

These defaults are configurable in `config/proxy.yml` under `governance.approval_required`.

**Approving a pending change:**

```bash
POST /api/v1/decisions/{decision_id}/approve
```

Only Operators and Admins can approve. An Operator cannot approve their own proposal.

**Policy apply is not a governance bypass.** The four-eyes rules apply equally to
changes made via the UI, the API, or `policy apply`.
