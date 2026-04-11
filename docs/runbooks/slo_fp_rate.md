<!--
title: "SLO FP rate Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook — SLO: False Positive Rate

> **Alert sources:** `JA4proxyHighBlockingRate`, `JA4ProxyHighBlockRate`
> **SLI:** `job:ja4proxy_false_positive_rate:ratio_rate5m`
> **Trigger:** blocking rate > 2% at `ja4proxy_dial_current >= 50`
> **Phase:** 63

The false-positive SLI does **not** have a rolling error budget. It is a
per-incident observation alert. The asymmetry stated in `CLAUDE.md`
(blocking a real user costs more than missing a bad bot) makes any
sustained breach urgent.

---

## Step 1 — Confirm there is no declared attack campaign

If a campaign was declared, the inhibit rule for
`JA4proxyAttackCampaignDetected` should already have suppressed the alert.
Double-check the campaign tracker before rolling back any policy.

```bash
curl -s http://management-ui:8090/api/v1/incidents/active | jq '.[] | select(.type=="attack_campaign")'
```

## Step 2 — Confirm the blocking rate

```bash
# 5-minute observation
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_false_positive_rate:ratio_rate5m' | jq '.data.result'

# Current dial setting (alert only fires when ≥ 50)
curl -sg 'http://prometheus:9090/api/v1/query?query=ja4proxy_dial_current' | jq '.data.result'
```

## Step 3 — Break down by action and signal

```promql
sum by (action) (rate(ja4proxy_connections_total{action=~"block|ban|tarpit|rate_limit"}[5m]))
topk(10, sum by (name) (rate(ja4proxy_signal_total[5m])))
```

If a single signal (e.g. `beaconing`, `abuseipdb`, `asn_datacenter`) is
suddenly responsible for the blocking spike, that signal's threshold or
score may need to be raised — or a known-good source needs an explicit
allowlist entry.

Cross-check the policy audit log:

```bash
redis-cli LRANGE management:policy_audit 0 20
```

A recent policy or threshold change in the last hour is the most common
cause of an FP wave.

## Step 4 — Mitigate

The safe, immediate action is to **lower the dial**, which retroactively
softens every block decision without losing scoring data:

```bash
# Lower the dial via the management API (preferred — captures audit log)
curl -X PATCH http://management-ui:8090/api/v1/dial \
     -H 'Content-Type: application/json' \
     -d '{"dial": 0, "reason": "FP wave investigation"}'

# Or via Redis directly (no audit trail — last resort)
redis-cli SET config:dial 0
```

The dial is hot-reloaded via Redis pub/sub and takes effect within
seconds — no proxy restart required. If a config file change is also
needed, the standard hot-reload signals apply:

```bash
systemctl kill --signal=HUP ja4proxy.service
docker kill --signal=HUP ja4proxy
podman kill --signal=HUP ja4proxy
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1
```

After the immediate spike subsides, raise the dial back gradually
(0 → 25 → 50 → 100) verifying the FP rate at each step.

## Escalation

- Primary on-call: [FILL IN]
- Security operations: [FILL IN]
- Customer communications (if user impact is reported): [FILL IN]
- Slack channel: [FILL IN]
