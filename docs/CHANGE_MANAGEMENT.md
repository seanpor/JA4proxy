<!--
title: "Change Management — proposing, reviewing, applying, and reverting config changes"
audience: compliance
last_reviewed: 2026-04-25
phase: 105
-->

# Change Management

> How configuration changes to JA4proxy are **proposed**, **reviewed**,
> **applied**, and **reverted**, and which Redis-backed evidence
> supports each step. Designed for compliance reviewers verifying
> change-control evidence; cross-references the canonical control
> narratives in [`../compliance/`](../compliance/).

---

## What counts as a "config change"

JA4proxy configuration consists of:

- **`config/proxy.yml`** — the file-backed authoritative configuration.
- **Runtime overrides in Redis** — entries written by the Management
  UI / API (allowlists, blocklists, watchlists, dial setting,
  bearer-token records, webhook subscriptions, threat-intel feed
  toggles).
- **`security_policy` bypass toggles** — the high-risk subset called
  out in `CLAUDE.md` §Bypass Rules; every change is appended to
  `management:policy_audit` (see [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) §1).

All three categories are subject to the change flows below.

---

## The three change flows

### 1. SIGHUP — file-driven reload

**Trigger:** an operator edits `config/proxy.yml` on a node and sends
`SIGHUP` to the proxy process (typically `docker compose kill -s SIGHUP proxy`,
documented in
[`../runbooks/feed_management.md`](../runbooks/feed_management.md)).

**Behaviour:**

- The config loader re-reads `config/proxy.yml`.
- An `INFO`-level config-reload event is emitted to the JSON log
  (Phase 14a logging schema in
  [`../OBSERVABILITY_STANDARDS.md`](../OBSERVABILITY_STANDARDS.md)).
- The Prometheus counter `ja4proxy_config_reloads_total` is incremented.
- For every change to a `security_policy` bypass, an entry is appended
  to `management:policy_audit` (see
  [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) §1) attributed as `"config_reload"`.
- Live connections drain on the previous configuration; new connections
  use the new configuration.

**When to use:** static configuration changes (thresholds, signal
weights, feed URLs, log levels). The default and intended day-2 path.

### 2. Management UI / API — Redis-backed mutation

**Trigger:** an authenticated operator performs an action via the
Management UI (`docs/for-operators/`, when present) or the Management
API directly. Examples: add a JA4 to the allowlist, raise the dial,
toggle a threat-intel feed, rotate a bearer token.

**Behaviour:**

- The action is RBAC-checked against the operator's role
  (Auditor < Analyst < Operator < Admin) per
  [`../compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md)
  §CC6.1.
- The mutation is written to Redis (e.g. `allowlist:entry:{uuid}`,
  `blocklist:entry:{uuid}`, `config:dial`).
- A JSON entry is appended to `management:audit_log` with full
  attribution (`actor_id`, `actor_ip`, `action_type`, `before_value`,
  `after_value`, `session_id`, `role`) — see
  [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) §2.
- For dial changes above the four-eyes threshold (Phase 82), a
  pending entry is recorded under `decisions:pending:{id}` and the
  approve/reject decision is recorded in the `decisions:history`
  Stream — see
  [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) §Phase 82.

**When to use:** day-to-day operational changes that benefit from
RBAC, attribution, and (for high-risk changes) two-person integrity.

### 3. Pub/Sub propagation — multi-node fan-out

**Trigger:** flow 1 or flow 2 completes on one instance and needs to
take effect on every replica.

**Behaviour:**

- A message is published on the `config:reload` Pub/Sub channel with
  payload `{"type":"config_reload"}` (see
  [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) §Phase 0).
- Every running proxy instance subscribed to that channel re-reads
  the relevant Redis-backed state and (where applicable) re-reads
  `config/proxy.yml`.
- Each instance independently emits its own config-reload INFO log
  and increments `ja4proxy_config_reloads_total`.

**When to use:** automatic — pub/sub fires whenever flow 1 or flow 2
needs to propagate. There is no operator-initiated pub/sub-only path.

`config.hot_reload_enabled: true` (default; `config/proxy.yml` line
~384) governs whether SIGHUP and `config:reload` pub/sub are honoured.

---

## What **cannot** hot-reload

Per `CLAUDE.md` §Config-Driven & Hot-Reloadable, three categories of
configuration **require a process restart**:

- **Listen port**
- **Redis URL**
- **TLS certificate paths**

Changes to these settings are still recorded the same way (file edit
plus, where the change is made via the Management API, an
`management:audit_log` entry), but they will not take effect until the
proxy process is restarted. Operators must plan a maintenance window
or rolling restart (see
[`../runbooks/rolling_upgrade.md`](../runbooks/rolling_upgrade.md)).

---

## Reverting a change

| Source of change | Revert path |
|------------------|-------------|
| `config/proxy.yml` edit | Revert the file (`git revert` if version-controlled, otherwise restore previous content) and re-issue SIGHUP. The reload appears in `management:policy_audit` (if a bypass changed) and as a fresh INFO log entry. |
| Management API mutation | Issue the inverse API call (`DELETE` for `POST`, restore previous value for `PUT`). Both the original mutation and its inverse appear in `management:audit_log` with `before_value`/`after_value`, giving auditors a complete history. |
| Dial change above four-eyes threshold | Use the same approval workflow to lower the dial. The reverse decision is recorded in `decisions:history`. |
| Operator wishes to roll the entire Redis state back | Use `BackupRestorer` (Phase 19/40); each restore writes `backup:last_restore` and `backup:restored_from` per [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) §Phase 57. |

---

## Auditor evidence mappings

The following mappings tie this document's flows to specific control
clauses. Each is sourced from an existing compliance document.

| Control | Evidence in this system | Reference |
|---------|--------------------------|-----------|
| **SOC 2 CC8.1 — Change-management** | Every `security_policy` bypass change appended to `management:policy_audit` (LIST, last 1000 entries, no TTL). Operator API actions appended to `management:audit_log` with full attribution (Phase 79 C5 schema). For high-risk dial changes, four-eyes workflow records pending and decided entries via `decisions:pending:{id}` and the `decisions:history` Stream (Phase 82). | [`../compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md) §CC7.1; [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) §1 and §2 |
| **ISO 27001 A.12.1.2 — Change management** | Configuration hot-reload via SIGHUP and `config:reload` pub/sub emits an INFO-level config-reload event log and increments `ja4proxy_config_reloads_total`; bypass changes are additionally captured in `management:policy_audit`. | [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) line 141 (A.12.1.2: "✅ Configuration hot-reload") |
| **ISO 27001 A.14.3.2 — Change management (development)** | Source-controlled `config/proxy.yml`, GitHub Actions CI workflows, Phase manifest gates. | [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) line 181 |
| **ISO 27001 A.15.1.3 — Supplier change management** | Threat-intel and GeoIP feed changes follow the procedures in [`../runbooks/feed_management.md`](../runbooks/feed_management.md). | [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) line 190 |

---

## Policy-as-code (Phase 82)

Phase 82 layers an approval workflow and shadow mode on top of the
flows above. Relevant for compliance reviewers because it changes the
**review** step, not the apply or revert steps:

- High-risk mutations (dial increases above the configured threshold,
  certain bypass changes) require a second approver before the change
  is applied.
- Pending entries live at `decisions:pending:{id}` (Hash, no TTL,
  explicit delete on approve/reject); the durable record of every
  approve/reject lands in the `decisions:history` Stream. See
  [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) §Phase 82.
- The simulation tooling (`sim:job:{sim_id}`, 7-day TTL) lets
  reviewers test the impact of a hypothetical dial before
  application.

This is the load-bearing evidence for two-person-integrity claims in
SOC 2 CC8.1 and ISO 27001 A.6.1.2 (Segregation of duties).

---

## Cross-references

- [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) — what each of these flows writes, retention, inspection commands.
- [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) — full ISO 27001 / NIST CSF / PCI DSS mapping (A.12.1.2, A.14.3.2, A.15.1.3 and adjacent rows are the change-management controls).
- [`../compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md) — SOC 2 CC6.1, CC7.1 narratives referencing the audit lists.
- [`../compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md) §"Changes to retention periods" — change-control posture for retention changes specifically.
- [`../runbooks/feed_management.md`](../runbooks/feed_management.md) — operator procedure for SIGHUP-driven feed configuration changes (auditor-evidence reference for supplier-change management).
- [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) — authoritative source for every Redis key cited above.
- `CLAUDE.md` §Config-Driven & Hot-Reloadable — invariants for what can and cannot reload without restart.
