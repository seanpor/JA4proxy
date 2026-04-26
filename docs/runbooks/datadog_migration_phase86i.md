# Runbook — Datadog Two-Layer Migration (Phase 86i)

**Audience:** SRE / oncall handling the OpenMetrics → narrowed-custom-check
migration introduced in Phase 86i.

**When to use this runbook:**
- Rolling out the Datadog Agent OpenMetrics integration to a new node fleet
- Validating that the narrowed custom check (`ja4proxy.node_health`,
  `ja4proxy.redis_health`) is reporting after the layer-2 cutover
- Diagnosing missing or duplicated metrics during the transition window

> **PHASE_101 H16:** This runbook closes a deferred Phase 86i acceptance gap —
> previously the migration order was lore-only and the smoke-check command
> set was undocumented.

---

## Migration order — DO NOT REVERSE

The migration is **two layers, in this order**:

1. **Layer 1 — OpenMetrics integration (`openmetrics.d/ja4proxy.yaml`).**
   Deploy this first. It scrapes the proxy's `/metrics` endpoint and ships
   every allowlisted metric to Datadog as native gauge/rate/histogram.
   Wait **24 hours minimum** before proceeding to layer 2 — dashboards must
   populate end-to-end with real data first.
2. **Layer 2 — narrowed custom check (`checks/ja4proxy/check.py`).**
   This adds the two service checks (`ja4proxy.node_health`,
   `ja4proxy.redis_health`) on top. It must NOT re-emit any metric that
   layer 1 already publishes (Phase 86i Gap 1).

If you reverse the order — deploy layer 2 first — the custom check will
not have any metrics to derive its service checks from, and you will get
spurious `unknown` health states for ~24h while OpenMetrics is brought up.

---

## Pre-flight verification commands

Run these on the target node **before** declaring the layer-1 rollout
healthy. Each command must print the indicated success line. Failures
indicate a config-file path mismatch, agent restart needed, or proxy
metrics endpoint unreachable.

### 1. Confirm the openmetrics integration is registered

```
datadog-agent check openmetrics
```

Expected: a YAML-style report block ending with `Total Runs: ≥1`,
`Metric Samples: Last Run: >0`, and **no** lines containing
`ConfigurationError` or `Connection refused`.

### 2. Confirm the ja4proxy custom check is registered

```
datadog-agent check ja4proxy
```

Expected: a report block showing `Service Checks: 2` (one for
`ja4proxy.node_health`, one for `ja4proxy.redis_health`). Both should be
in `OK` state on a healthy node. `WARNING` is acceptable transiently;
`CRITICAL` requires investigation per `runbooks/node_health.md`.

### 3. Cross-validate both checks are running together

```
datadog-agent status | grep -A5 "openmetrics ja4proxy"
```

Expected: two adjacent stanzas, one for `openmetrics` and one for
`ja4proxy`, both with `Total Runs:` non-zero and `Last Run:` within the
last 60 seconds. If either is missing, that check did not load — re-check
the YAML/Python file paths under `/etc/datadog-agent/conf.d/`.

---

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `openmetrics check` reports `0 metrics` | Proxy `/metrics` endpoint unreachable from agent | `curl -s http://localhost:9091/metrics \| head` from the node — must return the standard `# HELP` lines |
| `ja4proxy check` reports `unknown` service check | Layer 1 didn't have time to populate; or metric allowlist regex mismatch | Wait 5 min after layer 1 deploy; if still unknown, check `openmetrics.d/ja4proxy.yaml` `metrics:` matches metric names from `/metrics` |
| Both checks duplicate the same gauge in the Datadog UI | Layer 2 still emits a metric layer 1 already publishes (Gap 1 regression) | Check `check.py` for any `self.gauge()` / `self.rate()` call that produces a metric name in the Prometheus exposition — remove it |
| `Connection refused` on `datadog-agent check` | Agent not running | `systemctl status datadog-agent`; restart and re-run |
| `ConfigurationError: invalid YAML` | Hand-edited file has tabs or bad indentation | `yamllint /etc/datadog-agent/conf.d/openmetrics.d/ja4proxy.yaml` |

---

## Post-migration smoke checks

After both layers are deployed, validate from the Datadog UI side:

1. The `ja4proxy` dashboard widgets populate within 1 scrape interval (default 15s).
2. The `Node Health` and `Redis Health` service-check widgets show two
   separate node statuses (one per layer), not a duplicated count.
3. No metric in the dashboard shows a sudden 2× spike at the layer-2
   cutover timestamp — that would indicate a metric is being emitted by
   both layers (Gap 1 regression).

---

## Rollback

To roll back layer 2 only (keep OpenMetrics):
```
mv /etc/datadog-agent/checks.d/ja4proxy.py /etc/datadog-agent/checks.d/ja4proxy.py.disabled
systemctl restart datadog-agent
```

To roll back fully (remove both layers):
```
mv /etc/datadog-agent/conf.d/openmetrics.d/ja4proxy.yaml{,.disabled}
mv /etc/datadog-agent/checks.d/ja4proxy.py{,.disabled}
systemctl restart datadog-agent
```

Confirm with `datadog-agent status` that neither check appears.
