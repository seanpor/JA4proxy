# Runbook — SLO: Latency (p99 < 10 ms)

> **Alert sources:** `JA4ProxyLatencyFastBurn`, `JA4ProxyLatencySlowBurn`
> **SLI:** `job:ja4proxy_latency_p99_good:ratio_rate*`
> **Target:** 99% of pipeline evaluations under 10 ms
> **Phase:** 63

The latency SLI is the fraction of `ja4proxy_pipeline_duration_seconds`
observations that landed in or below the `le="0.01"` bucket. The pipeline is
the per-connection scoring path, **not** the proxied request lifetime.

---

## Step 1 — Confirm the regression

```bash
# Current ratio (closer to 1.0 is better)
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_latency_p99_good:ratio_rate5m' | jq '.data.result'

# Raw histogram p99 in seconds
curl -sg 'http://prometheus:9090/api/v1/query?query=histogram_quantile(0.99,sum(rate(ja4proxy_pipeline_duration_seconds_bucket[5m]))%20by%20(le))' | jq '.data.result'
```

## Step 2 — Identify the slow signal

Pipeline duration is dominated by Redis round-trips and signal modules.
Check Redis first:

```bash
redis-cli -h <redis-host> --latency-history -i 1
redis-cli -h <redis-host> --latency-dist
redis-cli -h <redis-host> CLIENT LIST | wc -l
```

If Redis latency is normal, look for a noisy signal:

```promql
topk(10, sum by (name) (rate(ja4proxy_signal_total[5m])))
sum by (le) (rate(ja4proxy_pipeline_duration_seconds_bucket[5m]))
```

A new flood of beaconing or AbuseIPDB enqueues causes pipeline contention.

## Step 3 — Check load and tarpit saturation

```promql
ja4proxy_active_connections
ja4proxy_tarpit_concurrent
rate(ja4proxy_connections_total[1m])
```

Tarpit saturation pushes overflow connections back through the scoring
path, raising p99 indirectly.

## Step 4 — Mitigate

Short term: lower the dial to reduce blocking-related work, or scale out.

```bash
# Scale via deployment platform
kubectl scale deployment ja4proxy --replicas=<N>           # Kubernetes
docker compose up -d --scale ja4proxy=<N>                  # Compose
systemctl start ja4proxy@<N>.service                       # systemd templated

# Hot-reload config after edit
systemctl kill --signal=HUP ja4proxy.service
docker kill --signal=HUP ja4proxy
podman kill --signal=HUP ja4proxy
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1
```

If a specific signal module is the culprit, disable it via
`config/proxy.yml` and reload.

## Escalation

- Primary on-call: [FILL IN]
- Secondary / SRE: [FILL IN]
- Slack channel: [FILL IN]
- PagerDuty service: [FILL IN]
