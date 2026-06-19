<!--
title: "Audit Trail — what is logged, where, for how long"
audience: security
last_reviewed: 2026-04-25
phase: 105
-->

# Audit Trail

> Authoritative source for **what** JA4proxy logs, **where** it stores it,
> and **how long** it keeps it. Every Redis key cited below is documented
> in [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md). If a key is not in the
> schema, it is not part of the audit trail.

This document covers three streams an auditor must be able to inspect:

1. **Policy-change audit** — every change to a security-policy bypass or
   the dial setting.
2. **Operator action log** — every Management UI / API admin action.
3. **GDPR erasure log** — every data-subject erasure executed via the
   tooling in [`docs/compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md).

A fourth stream (`ja4proxy:events`) carries per-connection decisions; it
is operationally important and consumed by the SIEM pipeline, but is
**not** the primary evidence for change-control or operator-action audit.
It is summarised at the end.

---

## 1. Policy-change audit — `management:policy_audit`

| Property | Value |
|----------|-------|
| Redis key | `management:policy_audit` |
| Type | LIST |
| Retention | **last 1000 entries**, **no TTL** (entries are bounded by length, not by time) |
| Written by | Management UI, config reload (per [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) §Phase 0) |
| What it records | Security-policy bypass changes |

`CLAUDE.md` §Bypass Rules states the invariant:

> Every change to `security_policy` is appended to `management:policy_audit`
> (LIST, last 1000 entries, no TTL), attributed to the session IP for UI
> changes or `"config_reload"` for file reloads.

### Why an auditor cares

This list is the load-bearing evidence that every change to a bypass
toggle (e.g. disabling `spamhaus_bypass`, narrowing `tls_version_bypass`,
toggling `mtls_bypass`) is recorded with attribution. There is no path
in the codebase to mutate `security_policy` that does not append to this
list — UI mutations and SIGHUP-driven config reloads both write here.

### Auditor evidence mapping

- **SOC 2 CC7.1 (Detection of configuration changes)** — see
  [`docs/compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md)
  §CC7.1, which references this list directly.
- **ISO 27001 A.12.1.2 (Change management)** — see
  [`docs/compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md)
  line 141.

### Inspection (read-only)

```bash
# Most recent 50 entries
redis-cli LRANGE management:policy_audit 0 49

# Total length (capped at 1000)
redis-cli LLEN management:policy_audit
```

---

## 2. Operator action log — `management:audit_log`

| Property | Value |
|----------|-------|
| Redis key | `management:audit_log` |
| Type | LIST |
| Retention | **last 1000 entries**, **no TTL** |
| Written by | Management UI / Management API |
| What it records | All secops admin actions |

Per [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) §Phase 0, each entry is
a JSON object (Phase 79 C5 enhanced schema) containing:

```
timestamp        ISO 8601 UTC
actor_id         token identity or username
actor_ip         client IP
action_type      dot-separated verb (e.g. `allowlist.created`)
resource_type
resource_id
before_value     null on creates
after_value      null on deletes
session_id
role             actor role at time of action
```

### Coverage

This stream covers role assignments, allowlist/blocklist/watchlist
mutations, dial changes (subject to four-eyes approval per
[`docs/compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md)
§CC7.1), bearer-token issuance/rotation/revocation, webhook subscription
changes, and every other write to a Management API resource.

### Auditor evidence mapping

- **SOC 2 CC6.1 (Access control policies)** — see
  [`docs/compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md)
  §CC6.1: "Role assignments are recorded in the audit log
  (`management:audit_log`) with actor, timestamp, and IP address."
- **SOC 2 CC7.1 (Detection of configuration changes)**.

### Inspection

```bash
# Last 100 entries, pretty-printed
redis-cli LRANGE management:audit_log 0 99 | python3 -m json.tool
```

---

## 3. GDPR erasure log — `management:gdpr_erasure_log`

| Property | Value |
|----------|-------|
| Redis key | `management:gdpr_erasure_log` |
| Type | LIST of JSON entries |
| Retention | **last 1000 entries**, **no TTL** |
| Written by | `scripts/gdpr_delete.py` |
| Per-entry fields | `{timestamp, ip, dry_run, keys_deleted, keys_skipped_hll, zset_members_removed, invoked_by}` |

Source of truth: [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) §Phase 0.
Procedure documentation:
[`docs/compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md) §5.3.

This is the load-bearing evidence for GDPR Article 17 (right to erasure)
requests. Each invocation — including dry runs — is recorded.

---

## Per-Redis-key retention summary

The table below lists every key in this audit document and the retention
it carries. **Each row is verifiable against
[`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md).**

| Key | Type | Retention | Source of truth |
|-----|------|-----------|-----------------|
| `management:policy_audit` | LIST | last 1000 entries, no TTL | REDIS_SCHEMA §Phase 0 |
| `management:audit_log` | LIST | last 1000 entries, no TTL | REDIS_SCHEMA §Phase 0 |
| `management:gdpr_erasure_log` | LIST | last 1000 entries, no TTL | REDIS_SCHEMA §Phase 0 |
| `config:dial` | String | none (current value only — history is in `management:audit_log`) | REDIS_SCHEMA §Phase 0 |
| `ja4proxy:events` | Stream | maxlen=100,000 (and purged by `gdpr.retention_days` via `POST /api/v1/compliance/purge-expired`) | REDIS_SCHEMA §Phase 12 / §Phase 84 |
| `gdpr:purge:last_run` | String | none | REDIS_SCHEMA §Phase 84 |
| `gdpr:purge:last_summary` | String (JSON) | none | REDIS_SCHEMA §Phase 84 |
| `decisions:history` | Stream | none (append-only governance log) | REDIS_SCHEMA §Phase 82 |

### Notes

- "**No TTL**" means the key has no per-key expiry. The three audit lists
  are bounded by **length** (1000 entries) rather than by time. An
  organisation requiring longer retention must export entries to durable
  storage on a schedule (e.g. via the SIEM pipeline — see
  [`../SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md)
  once available, or directly via `ja4proxy:events`).
- `ja4proxy:events` retention is a **dual ceiling**: a Redis-side
  `maxlen=100,000` cap and a GDPR-driven purge enforced by
  `POST /api/v1/compliance/purge-expired` against the configured
  `gdpr.retention_days` (default 30; see
  [`../compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md)
  §5.2 and `config/proxy.yml`).
- `decisions:history` (Phase 82 governance) is an append-only Stream
  recording every approve/reject for the four-eyes dial workflow. No
  TTL; bounded only by Redis storage and any operator-managed
  `XTRIM` policy.

---

## Connection event stream (informational)

`ja4proxy:events` is the per-connection event Stream. It is the
**operational** record of each decision (`ip`, `ja4`, `risk_score`,
`action_taken`, `dial_setting`, `counterfactuals`) and feeds the
analytics node and the SIEM pipeline. Per
[`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) §Phase 12 and §Phase 84,
it is bounded by `maxlen=100,000` and purged by GDPR retention. It is
not the primary evidence for **change-control or operator-action**
audit; for those, use the three lists above.

---

## Cross-references

- [`docs/reference/REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) — authoritative key schema for every key cited above.
- [`docs/compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md) — erasure procedure and retention policy.
- [`docs/compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md) — SOC 2 narrative referencing `management:audit_log` and `management:policy_audit`.
- [`docs/compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) — ISO 27001 / NIST CSF / PCI DSS mapping.
- [`CHANGE_MANAGEMENT.md`](CHANGE_MANAGEMENT.md) — how config changes flow into these logs.
