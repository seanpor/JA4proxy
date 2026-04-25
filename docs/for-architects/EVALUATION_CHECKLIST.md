<!--
title: "Evaluation Checklist for Architects"
audience: architects
last_reviewed: 2026-04-25
phase: 105
-->

# Evaluation Checklist

Two checklists for architects running a structured proof-of-concept:

1. **7-day POC** — establish that JA4proxy runs cleanly in your environment,
   produces sensible telemetry, and does **not** block legitimate users.
2. **30-day evaluation** — progressively raise the dial from monitor-only to
   partial enforcement, validate cost-of-evasion, and confirm SIEM/SOAR
   integration is operationally viable.

Each item is a yes/no criterion. Track results in a spreadsheet alongside the
date answered, the responsible engineer, and any deviation notes.

> **Default dial = 0 (monitor-only).** JA4proxy never blocks on first deploy.
> The dial is raised consciously, in the steps below, with explicit success
> criteria and rollback triggers at each stage. See
> [`docs/security/threat-model.md`](../security/threat-model.md) §"Bypass
> Rules" for the asymmetry rationale.

---

## 7-Day POC

### Day 0 — Environment readiness

- [ ] Production runtime (`bin/proxy`, the Go binary) is deployed, not the
      Python prototype (`proxy.py`)
- [ ] Redis is reachable from every JA4proxy instance and is **not** exposed
      to the public internet
- [ ] All container images are pulled from a signed, verified source (Cosign
      signatures verified for `go-proxy` image)
- [ ] `config/proxy.yml` parsed successfully on startup; no validation errors
      in the first 60 seconds of logs
- [ ] Initial dial confirmed at `0` (`ja4proxy_dial_setting{} == 0` in
      Prometheus)
- [ ] Time synchronisation verified — `ntpq -p` or `chronyc tracking` shows
      drift `< 100 ms` on every node

### Day 1 — Traffic visibility

- [ ] At least one connection per minute appears in JA4proxy logs (proves the
      proxy is on the data path)
- [ ] `ja4proxy_connections_total` Prometheus counter increments
- [ ] At least one connection has a non-empty `ja4proxy.fingerprint.ja4` field
      (proves the ClientHello parser is working)
- [ ] `event.action: allowed` is the dominant action (>= 95% of decisions)
- [ ] No unexpected 5xx responses or TCP RSTs reported by the load balancer
- [ ] Backend application reports normal request rate (within ±5% of
      pre-deployment baseline)

### Day 2 — Telemetry pipeline

- [ ] SIEM ingestion verified end-to-end (synthetic event reaches SIEM within
      60 seconds of emission — see
      [`SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md))
- [ ] Grafana dashboard shows live `ja4proxy_*` metrics without gaps
- [ ] Alertmanager has at least one routing path configured (email,
      PagerDuty, or webhook) and a test alert reaches the destination
- [ ] Log retention configured: hot tier ≥ 7 days, cold/archive ≥ 90 days

### Day 3 — Bypass rules and false-positive baseline

- [ ] `h2`/`h1` ALPN browser traffic is bypassing the scorer (verify by
      filtering logs for `event.action: allowed` AND
      `ja4proxy.alpn IN ["h2","h1"]` — these should be the majority of allows)
- [ ] No browser user-agent (Chrome, Firefox, Safari) has triggered a `blocked`
      action — these would all be false positives at this stage
- [ ] mTLS bypass tested if applicable (corporate clients with valid client
      certs are unscored)
- [ ] JA4 whitelist correctly bypasses scoring for any pre-approved
      fingerprints

### Day 5 — Mid-week health check

- [ ] No process restarts unrelated to deploys in the last 3 days
- [ ] CPU usage per JA4proxy instance ≤ 50% of allocated quota at peak
- [ ] Memory usage stable (no upward drift indicating a leak)
- [ ] Redis memory usage tracking expected sizing in
      [`docs/REDIS_SCHEMA.md`](../REDIS_SCHEMA.md)
- [ ] Connection-decision latency p99 ≤ 10 ms (p99 of
      `ja4proxy_request_duration_seconds`)

### Day 7 — Go/no-go to extended evaluation

- [ ] Reviewed all `event.action: blocked` events from the past 7 days; every
      one is a credible bot or known-bad fingerprint, **none** are real users
- [ ] Reviewed all `event.action: flagged` events; risk score distribution is
      sensible (most flagged events score 20–40)
- [ ] No alerts fired for the asymmetry-violating events (browser blocked,
      whitelist bypass failed, etc.)
- [ ] Operations team has run through the
      [`docs/INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) playbook in a
      tabletop exercise

#### 7-day POC success criteria (all must be yes)

- [ ] Proxy stable for 7 consecutive days with no operator-initiated restarts
- [ ] Zero confirmed false-positive blocks of real users
- [ ] SIEM ingestion stable; no missed events in any 1-hour window
- [ ] Backend application latency and error rate unchanged from
      pre-deployment baseline

#### Rollback triggers (any one triggers immediate dial → 0 and review)

- [ ] Confirmed false-positive block of a real user
- [ ] Backend error rate increases by > 1% sustained over 15 minutes
- [ ] Connection-decision latency p99 exceeds 50 ms
- [ ] Proxy CPU saturates (≥ 95% sustained for 5+ minutes)

---

## 30-Day Evaluation

### Week 2 — Dial 0 → 25 (introduce flagging)

- [ ] Dial raised to `25` via Management UI (audit entry visible in
      `management:policy_audit`)
- [ ] At dial 25, only `flag` and `rate_limit` actions can occur — no `block`
      or `ban`
- [ ] Number of `flagged` events is consistent with bot population estimate
      from Day 7 review
- [ ] No customer support tickets attributable to JA4proxy
- [ ] SIEM correlation rules (see
      [`SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md)) tuned against real flag
      volume — no rule firing more than 5x per hour without operator
      acknowledgement

### Week 3 — Dial 25 → 50 (partial enforcement)

- [ ] Dial raised to `50`; `tarpit` action now possible
- [ ] Tarpit action verified to delay (not drop) connections — backend sees
      slowed but eventual completion of legitimate-but-suspect sessions
- [ ] Reviewed all `tarpitted` events from the first 48 hours at dial 50;
      each is a credible suspect, none are real users
- [ ] AbuseIPDB / Spamhaus / RDAP signal contributions reviewed; no signal is
      contributing > 60 points alone (no single-signal hard blocks)
- [ ] Cost-of-evasion check: simulated bot using a residential-mimicking JA4
      fingerprint is **flagged** but not blocked — this is correct
      (asymmetry rule)

### Week 4 — Dial 50 holding period

- [ ] Dial held at `50` for at least 7 consecutive days
- [ ] Operator dashboard reviewed daily; no unexplained spikes in `block` or
      `ban` rate
- [ ] False-positive corpus check: top 10k legitimate domains tested via
      `make fp-check` (or equivalent) shows ≤ 0.1% block rate
- [ ] Webhook deliveries succeeding ≥ 99.5% (DLQ depth in
      `webhooks:dlq` Redis Stream remains < 100)
- [ ] Backup and restore procedure tested against a non-production Redis
      instance

### 30-day success criteria (all must be yes)

- [ ] Dial held at ≥ 50 for the last 7 consecutive days with no rollback
- [ ] Zero confirmed false-positive blocks attributable to scoring (excluding
      explicit blacklist matches)
- [ ] Bot block volume materially exceeds the pre-JA4proxy baseline
      (validated against application logs / WAF reports)
- [ ] Operations team independently produced and resolved one incident
      following [`docs/INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md)
- [ ] Compliance team has reviewed
      [`docs/compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md)
      and accepted residual risks
- [ ] SIEM correlation rules in production with documented runbook entries

### 30-day rollback triggers (any one triggers dial → 0)

- [ ] Confirmed false-positive block of a paying customer or executive user
- [ ] Sustained backend error rate increase > 0.5% for 30+ minutes
      attributable to JA4proxy
- [ ] Critical CVE in JA4proxy or a hot dependency without a same-week patch
- [ ] Redis data loss without successful restore from backup
- [ ] SIEM ingestion gap exceeding 1 hour (compliance / forensic gap)

---

## After the 30-Day Evaluation

If all success criteria are met, escalate to dial `100` per the **graduated
rollout** schedule documented in
[`docs/operator/BLOCKING_OPERATIONS.md`](../operator/BLOCKING_OPERATIONS.md#how-to-change-the-dial). Continue
the daily monitoring rhythm; transition operational ownership to the SecOps
team using
[`docs/SECOPS_OPERATIONS.md`](../SECOPS_OPERATIONS.md).

If any rollback trigger fired, treat the trigger as the primary investigation
artefact: file an ADR for the residual risk, document the mitigation, and
restart the affected stage of the evaluation rather than abandoning the
exercise.

---

## Related reading

- [`docs/for-architects/SCOPE_AND_LIMITATIONS.md`](SCOPE_AND_LIMITATIONS.md)
  — what JA4proxy will and will not detect
- [`docs/for-architects/SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md) — log
  forwarding recipes
- [`docs/SECOPS_OPERATIONS.md`](../SECOPS_OPERATIONS.md) — daily operations
- [`docs/operator/BLOCKING_OPERATIONS.md`](../operator/BLOCKING_OPERATIONS.md#how-to-change-the-dial)
  — dial progression playbook
- [`docs/runbooks/ja4proxy_dial_change_unexpected.md`](../runbooks/ja4proxy_dial_change_unexpected.md)
  — incident runbook for unexpected dial changes
- [`docs/INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) — incident response
  procedures
