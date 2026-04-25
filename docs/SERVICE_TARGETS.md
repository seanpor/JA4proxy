<!--
title: "Service Targets — SLA / SLO / SLI"
audience: architects, operators, buyers, secops
last_reviewed: 2026-04-24
phase: 106
-->

# JA4proxy — Service Targets

This page is the single, consolidated answer to "what does JA4proxy commit to?".
It enumerates the Service Level Indicators (SLIs) the proxy emits, the Service
Level Objectives (SLOs) those indicators are measured against, and the
Service Level Agreement (SLA) posture of the project.

This document **summarises** the per-SLO runbooks; it is **not** a substitute
for them. Each row links to its authoritative runbook. Numeric targets in
this page are mirrored from those runbooks — if the two ever drift, the
runbook wins.

---

## Core asymmetry

JA4proxy's dominant quality attribute is **false-positive rate**. Per
`CLAUDE.md`, blocking a real user costs more than missing a bad bot. Every
threshold default, cache TTL, and fallback behaviour in the system reflects
that asymmetry, and so does this page: the FP-rate SLI is treated as a
per-incident urgent observation, not a rolling error budget.

---

## Service Level Indicators

| SLI | What it measures | Target (SLO) | Measurement window | Source runbook | Alert |
|---|---|---|---|---|---|
| **Availability** | Connections that reached a policy decision vs. those that tripped `ja4proxy_connection_errors_total` before a decision | 99.9% (28-day error budget = 40 bad minutes) | 5m / 1h / 28d burn windows | [`runbooks/slo_availability.md`](runbooks/slo_availability.md) | `JA4ProxyAvailabilityFastBurn`, `JA4ProxyAvailabilitySlowBurn` |
| **False-positive rate** | Blocking rate at `ja4proxy_dial_current >= 50`. Dominant quality attribute (see above). | Trigger if blocking rate > 2% — per-incident, no rolling budget | 5m observation | [`runbooks/slo_fp_rate.md`](runbooks/slo_fp_rate.md) | `JA4proxyHighBlockingRate`, `JA4ProxyHighBlockRate` |
| **Pipeline latency p50/p99** | Fraction of `ja4proxy_pipeline_duration_seconds` observations in the `le="0.005"` (p50 reference) and `le="0.01"` (p99) buckets — per-connection scoring path, not proxied request. The p99 is the SLO; the p50 is reported alongside as a tail-vs-median sanity check. | p99 under 10 ms (99% target); p50 typically under 5 ms — drift triggers `ScoreDriftDetected` rather than the latency burn alerts | 5m / 1h / 28d burn windows | [`runbooks/slo_latency.md`](runbooks/slo_latency.md) | `JA4ProxyLatencyFastBurn`, `JA4ProxyLatencySlowBurn` |
| **Redis correctness** | Successful Redis operations / total Redis operations. A breach degrades policy enforcement (proxy fails open) — security issue, not user-impact. | 99.5% | 5m / 1h / 28d burn windows | [`runbooks/slo_redis_correctness.md`](runbooks/slo_redis_correctness.md) | `JA4ProxyRedisCorrectnessFastBurn`, `JA4ProxyRedisCorrectnessSlowBurn` |
| **Signal-collection error rate** | Fraction of `ja4proxy_signal_collection_errors_total` over `ja4proxy_signal_collection_attempts_total` across all signal modules (TLS, SNI, TCP, ASN, FCrDNS, beaconing, AbuseIPDB, RDAP, analytics). Fail-open means the connection still reaches the scorer, but a missing signal degrades the score's confidence. | < 1% per module | 5m / 1h / 28d burn windows | [`OBSERVABILITY_STANDARDS.md` §6](OBSERVABILITY_STANDARDS.md) | `JA4ProxySignalCollectionDegraded` |
| **Feed freshness** | Time since last successful blocklist feed download | < 24h per feed | continuous | [`OBSERVABILITY_STANDARDS.md` §6](OBSERVABILITY_STANDARDS.md) | `BlocklistFeedStale`, `TorListStale` |
| **Score stability** | Risk-score distribution drift vs. 7-day baseline (KS-test / z-score) | within 2 standard deviations | 1h rolling | [`OBSERVABILITY_STANDARDS.md` §6](OBSERVABILITY_STANDARDS.md) | `ScoreDriftDetected`, `BrowserShadowScoreElevated` |

All numeric targets above are mirrored from their listed source. Where a
runbook does not yet specify a target, this page would say `TARGET TBD —
see <runbook>` rather than guess; no such gap exists today.

---

## SLA posture

JA4proxy is open-source under the **MIT license** (see [`LICENSE`](../LICENSE)).
The project commits to **community best-effort support** via GitHub Issues
and the security disclosure process documented in
[`SECURITY.md`](../SECURITY.md). **Commercial support is not currently
offered.**

The SLOs above are operational targets a deployer can hold themselves
accountable to using the metrics the proxy exports; they are **not** a
contractual commitment from the project to any consumer. A self-hosted
deployment owns its own availability, alerting, and incident response.

---

## Error-budget policy

When a fast-burn alert fires (`*FastBurn` rules — short + long window
exceeded simultaneously per SRE Workbook Ch.5):

1. **Page on-call.** Treat as an active incident. Use the listed runbook.
2. **Pause feature work** on the affected subsystem until the burn rate
   recovers and the budget consumed in the rolling window is back below
   25% of the period's total.
3. **Mitigate with the dial first** when the burned SLI is FP rate — lower
   `config:dial` via the management API (preferred — captures
   `management:policy_audit`). The dial hot-reloads via Redis pub/sub
   within seconds; no restart required.
4. **Roll back** the most recent deploy or policy change if it correlates
   with the burn. The Go proxy is stateless — rollback is safe.
5. **Post-mortem expected** for any fast-burn page and any sustained
   slow-burn (`*SlowBurn`) lasting more than one full burn window.
   Post-mortems land under `docs/engineering-method/retrospectives/`.

Specific mitigation steps per SLI live in each runbook's "Step 4 —
Mitigate" section; do not duplicate them here.

---

## Reporting cadence

- **Per-incident:** alert fires → on-call follows the source runbook →
  post-mortem if criteria above are met.
- **Quarterly retrospective:** SLO compliance over the prior 90 days,
  budget consumption trends, and any target adjustments are reviewed and
  recorded under
  [`docs/engineering-method/retrospectives/`](engineering-method/retrospectives/).
  Review owners: maintainer + SRE lead.
- **On runbook change:** any numeric target change in a source runbook
  must be mirrored into the table above in the same commit. CI sync tests
  (Phase 106 Wave 5) enforce this.

---

## Cross-references

- [`docs/RISK_REGISTER.md`](RISK_REGISTER.md) — consolidated risk register (Phase 106b)
- [`docs/QUALITY_PLAN.md`](QUALITY_PLAN.md) — quality plan (Phase 106h)
- [`docs/OBSERVABILITY_STANDARDS.md`](OBSERVABILITY_STANDARDS.md) — metrics, log schema, SLI definitions (§6)
- [`docs/runbooks/slo_availability.md`](runbooks/slo_availability.md) — availability SLO runbook
- [`docs/runbooks/slo_fp_rate.md`](runbooks/slo_fp_rate.md) — false-positive rate SLO runbook
- [`docs/runbooks/slo_latency.md`](runbooks/slo_latency.md) — latency SLO runbook
- [`docs/runbooks/slo_redis_correctness.md`](runbooks/slo_redis_correctness.md) — Redis correctness SLO runbook
- [`SECURITY.md`](../SECURITY.md) — security disclosure process
- [`LICENSE`](../LICENSE) — MIT license text
