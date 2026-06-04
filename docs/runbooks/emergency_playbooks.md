<!--
title: Runbook: Emergency Playbooks
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# Emergency Runbook Playbooks

Three pre-packaged Ansible playbooks for the most common JA4proxy incident response
scenarios. Each playbook calls the Management API with Bearer token authentication
and includes optional ServiceNow/Slack integration steps.

**Location:** `deploy/ansible/playbooks/emergency/`

---

## Prerequisites

- Ansible 2.14+ installed on the operator workstation
- `JA4PROXY_TOKEN` environment variable set to a valid Management API bearer token
- (Optional) `SLACK_WEBHOOK_URL` for Slack notifications
- (Optional) `SERVICENOW_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` for ServiceNow

---

## Playbook 1: `emergency-ban-cidr.yml`

**Use when:** An active scanning campaign originates from a known CIDR range.

```bash
ansible-playbook deploy/ansible/playbooks/emergency/emergency-ban-cidr.yml \
  -e cidr=198.51.100.0/24 \
  -e reason="Active scanning campaign from this /24" \
  -e ticket=INC0005432 \
  -e ttl_hours=24 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

**What it does:**
1. URL-encodes the CIDR (`/` → `%2F`) for the API path
2. POSTs to `/api/v1/bans/{cidr_encoded}` with TTL in seconds
3. Asserts the API confirms the ban (fail-fast on error)
4. (Optional) Creates a ServiceNow incident
5. (Optional) Posts to `#security-ops` Slack channel

**Notes:**
- The `[emergency]` prefix in the reason helps distinguish playbook-created bans
- TTL defaults to 24 hours; use `ttl_hours=720` for 30-day bans

---

## Playbook 2: `temp-whitelist-ip.yml`

**Use when:** A partner IP needs temporary access for debugging an integration.

```bash
ansible-playbook deploy/ansible/playbooks/emergency/temp-whitelist-ip.yml \
  -e ip=203.0.113.5 \
  -e reason="Debugging partner integration" \
  -e ttl_hours=2 \
  -e ticket=CHG0001500 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

**What it does:**
1. Computes `expires_at` = now + `ttl_hours` (ISO 8601)
2. POSTs to `/api/v1/allowlist` with mandatory `expires_at`
3. Asserts the API returns an entry ID (fail-fast on error)
4. (Optional) Posts expiry reminder to Slack

**Notes:**
- The `[temporary]` prefix in the reason distinguishes from permanent allowlist entries
- `expires_at` is mandatory — entries without expiry are rejected by the API

---

## Playbook 3: `maintenance-dial-zero.yml`

**Use when:** A maintenance window requires temporarily reducing all blocking to zero.

```bash
ansible-playbook deploy/ansible/playbooks/emergency/maintenance-dial-zero.yml \
  -e duration_minutes=60 \
  -e reason="Maintenance window for backend upgrade" \
  -e ticket=CHG0001600 \
  -e ja4proxy_token="${JA4PROXY_TOKEN}"
```

**What it does:**
1. GETs the current dial value and saves it
2. Steps dial down to 0 in ±10 increments (API enforces max ±10 per request)
3. If any step returns 422 → **ABORTS** (four-eyes approval pending — do not bypass)
4. Waits for `duration_minutes`
5. Steps dial back up to the original value in ±10 increments
6. (Optional) Creates a ServiceNow change record

**Safety:**
- The ±10 step-down is enforced by the API — the playbook respects this
- A 422 response at any step triggers an immediate abort with a clear message
- The dial is automatically restored after the maintenance window

---

## Testing

All playbooks are tested via YAML structure validation:

```bash
make test-phase-93
```

This verifies:
- All playbooks require `ja4proxy_token` and pass Bearer auth
- Correct API endpoints, methods, and body fields
- Optional integrations (ServiceNow, Slack) are properly gated
- CIDR encoding uses `%2F`
- Dial playbook includes wait + restore steps

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Missing required variable` | Forgot `-e ja4proxy_token=...` (or `cidr` / `ip` / `reason` / `ticket` / `duration_minutes`) | Export `JA4PROXY_TOKEN` or pass via `-e`. The `assert` task in each playbook lists the full set of required vars. |
| `401 Unauthorized` | Token expired or wrong | Regenerate token via Management API |
| `403 Forbidden` | Token lacks the required scope (e.g. `bans:write`, `dial:write`) | Re-issue the token with the correct scopes — do not downgrade the API's RBAC to work around it |
| `422 Unprocessable Entity` on `/api/v1/dial` | Dial change > ±10 or four-eyes pending | Contact approver — do not suppress the gate. Playbook 3 aborts automatically on 422. |
| `422 Unprocessable Entity` on `/api/v1/bans` or `/api/v1/allowlist` | Validation failure — malformed CIDR, missing `expires_at`, or bad TTL | Check the `ban_result` / `whitelist_result` register in the playbook output; fix the input and re-run |
| `Connection timed out` after 30s | Management API unreachable or slow | Confirm `ja4proxy_url` is correct and the API container is healthy (`curl -sf ${JA4PROXY_URL}/health`); `uri` module uses `timeout: 30` on API calls (10s for Slack) |
| Playbook hangs on `wait_for` | `duration_minutes` is large | Use `Ctrl+C` — dial will NOT be restored. Run restore manually. |
