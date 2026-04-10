<!--
title: GameDay Scenarios
audience: Operators, SRE, Security Teams
last_reviewed: 2026-04-10
phase: 64d
-->

# Runbook: GameDay Scenarios

## Purpose

GameDay exercises validate that the team can detect, diagnose, and recover from
production failures without consulting the runbook first. Each exercise injects
a specific fault, measures detection and recovery time against an RTO target,
and surfaces gaps in alerting, documentation, or muscle memory.

Run each exercise quarterly. Record results in the "Runbook Exercise History"
section of `disaster_recovery.md`.

---

## Prerequisites (all exercises)

- Local stack running via `docker compose up -d` (v2 syntax).
- Prometheus scraping all proxy instances and Redis.
- Alertmanager configured with the project's alert rules.
- Management API reachable at `http://localhost:8090/api/v1/health/deep`.
- A stopwatch or wall clock visible to the team.
- One designated **observer** who does not participate but records timestamps.

---

## Exercise 1: Redis Outage

### Objective

Verify the team can detect a Redis failure within 2 minutes and restore full
proxy-to-Redis connectivity within 5 minutes, confirming that all proxy
instances operated in fail-open mode during the outage window.

### Environment

| Component | Requirement |
|---|---|
| Stack | `docker compose up -d` with at least 1 proxy instance and Redis |
| Monitoring | Prometheus scraping `ja4proxy_redis_operations_total{result="error"}` |
| Alerting | Alert rule for `ja4proxy_redis_operations_total{result="error"}` increase configured |
| Observer tools | Terminal with `watch -n1 docker compose ps` and Prometheus UI |

### Duration

15 minutes total (5 min setup, 5 min exercise, 5 min debrief).

### Trigger

```bash
# Observer runs this command at T=0 and starts the stopwatch
docker compose stop redis
```

### Team actions (before opening the runbook)

The team must detect and respond using only their existing knowledge and
monitoring dashboards. They should NOT open `disaster_recovery.md` until
the observer tells them the detection phase is complete. Expected actions:

1. **Detect** -- notice `ja4proxy_redis_operations_total{result="error"}` climbing in Prometheus
   or Alertmanager firing a Redis connectivity alert.
2. **Triage** -- confirm Redis is the root cause, not a proxy crash:
   ```bash
   docker compose ps
   docker compose logs --tail=20 redis
   ```
3. **Assess impact** -- confirm proxies are still accepting connections in
   fail-open mode by checking the health endpoint:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```
4. **Recover** -- restart Redis:
   ```bash
   docker compose start redis
   ```
5. **Verify** -- confirm `ja4proxy_redis_operations_total{result="error"}` stops climbing and
   proxy logs show reconnection:
   ```bash
   docker compose logs --tail=10 ja4proxy
   ```

### Success criteria

| Metric | Target | Pass/Fail |
|---|---|---|
| Time to detect (alert or verbal identification) | < 2 minutes | |
| Time to full recovery (Redis up + proxies reconnected) | < 5 minutes | |
| Any legitimate traffic blocked during outage | 0 (fail-open held) | |
| Proxy instances required restart | 0 | |

### Related runbook

`disaster_recovery.md` -- Scenario 1 (Redis outage).

---

## Exercise 2: Single Node Failure

### Objective

Verify the team can detect a single proxy node failure within 1 minute and
restore the node within 2 minutes, confirming that the remaining node(s)
continued serving traffic.

### Environment

| Component | Requirement |
|---|---|
| Stack | `docker compose up -d` with at least 2 proxy instances (`ja4proxy-1`, `ja4proxy-2`) |
| Monitoring | Prometheus scraping per-instance `up` metric or health checks |
| Load balancer | HAProxy or equivalent distributing across both proxy instances |
| Observer tools | Terminal with `docker compose ps` and Prometheus targets page |

### Duration

10 minutes total (3 min setup, 4 min exercise, 3 min debrief).

### Trigger

```bash
# Observer runs this command at T=0 and starts the stopwatch
docker compose stop ja4proxy-1
```

### Team actions (before opening the runbook)

1. **Detect** -- notice the missing target in Prometheus or a health-check
   failure alert. HAProxy should mark the backend as down.
2. **Triage** -- identify which node is down:
   ```bash
   docker compose ps
   ```
3. **Assess impact** -- confirm the remaining node is still serving traffic:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   echo "Q" | openssl s_client -connect localhost:8080 -servername localhost 2>&1 | head -5
   ```
4. **Recover** -- restart the failed node:
   ```bash
   docker compose start ja4proxy-1
   ```
5. **Verify** -- confirm both nodes are running and accepting connections:
   ```bash
   docker compose ps
   ```

### Success criteria

| Metric | Target | Pass/Fail |
|---|---|---|
| Time to detect (alert or verbal identification) | < 1 minute | |
| Time to full recovery (node up + serving traffic) | < 2 minutes | |
| Traffic interruption on surviving node | 0 | |

### Related runbook

`disaster_recovery.md` -- Scenario 2 (node failure).

---

## Exercise 3: Total Fleet Failure

### Objective

Verify the team can identify root cause of a complete proxy fleet outage
within 5 minutes and restore the full fleet within 15 minutes.

### Environment

| Component | Requirement |
|---|---|
| Stack | `docker compose up -d` with at least 2 proxy instances |
| Monitoring | Prometheus, Alertmanager with fleet-down alert |
| Observer tools | Terminal with `docker compose ps`, Prometheus UI, system logs |

### Duration

25 minutes total (5 min setup, 15 min exercise, 5 min debrief).

### Trigger

```bash
# Observer runs this command at T=0 and starts the stopwatch
docker compose stop ja4proxy-1 ja4proxy-2
```

### Team actions (before opening the runbook)

1. **Detect** -- all proxy health checks fail simultaneously. Alertmanager
   fires a critical fleet-down alert.
2. **Triage** -- determine if the cause is proxy-specific or infrastructure-wide:
   ```bash
   docker compose ps
   docker compose logs --tail=30 ja4proxy-1
   docker compose logs --tail=30 ja4proxy-2
   redis-cli PING
   ```
3. **Assess scope** -- check if Redis, Management API, and HAProxy are still
   functional. A total fleet failure with healthy infrastructure points to a
   proxy-specific issue (bad config push, OOM, etc.).
4. **Root-cause** -- review recent config changes, resource usage, and logs
   for crash signatures. Check if a recent dial change or config hot-reload
   preceded the failure.
5. **Recover** -- restart the fleet:
   ```bash
   docker compose start ja4proxy-1 ja4proxy-2
   ```
6. **Verify** -- confirm all nodes are healthy:
   ```bash
   docker compose ps
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

### Success criteria

| Metric | Target | Pass/Fail |
|---|---|---|
| Time to root-cause identification | < 5 minutes | |
| Time to full fleet recovery | < 15 minutes | |
| Data loss (Redis state, ban lists, scores) | 0 | |
| Post-recovery config drift from pre-failure state | 0 | |

### Related runbook

`disaster_recovery.md` -- Scenario 3 (total fleet failure).

---

## Exercise 4: Dial Corruption

### Objective

Verify the team can detect an unexpected dial change to 100 (full blocking
mode) within 3 minutes and restore safe operation (dial=0) within 5 minutes,
then correct the dial to the intended value.

### Environment

| Component | Requirement |
|---|---|
| Stack | `docker compose up -d` with at least 1 proxy instance and Redis |
| Monitoring | Prometheus scraping `ja4proxy_dial_current` gauge |
| Alerting | Alert on `ja4proxy_dial_current` sudden change (optional but recommended) |
| Observer tools | Terminal with Redis CLI and Prometheus UI |

### Duration

15 minutes total (5 min setup, 5 min exercise, 5 min debrief).

### Trigger

```bash
# Observer runs these commands at T=0 and starts the stopwatch
redis-cli SET config:dial 100
redis-cli PUBLISH config:dial:change 100
```

### Team actions (before opening the runbook)

1. **Detect** -- notice `ja4proxy_dial_current` jump to 100 in Prometheus, or
   observe unexpected blocks in proxy logs / Management UI.
2. **Assess impact** -- at dial=100, all scored connections above threshold are
   blocked. Check for false positives:
   ```bash
   docker compose logs --tail=30 ja4proxy | grep -i block
   ```
3. **Immediate mitigation** -- drop to dial=0 (monitor-only) to stop all
   blocking immediately:
   ```bash
   redis-cli SET config:dial 0
   redis-cli PUBLISH config:dial:change 0
   ```
4. **Investigate** -- determine who or what changed the dial. Check the
   policy audit log:
   ```bash
   redis-cli LRANGE management:policy_audit -10 -1
   ```
5. **Correct** -- set the dial to the intended operational value (consult the
   team's agreed dial setting, typically documented in the deployment config):
   ```bash
   redis-cli SET config:dial <INTENDED_VALUE>
   redis-cli PUBLISH config:dial:change <INTENDED_VALUE>
   ```

### Success criteria

| Metric | Target | Pass/Fail |
|---|---|---|
| Time to detect dial corruption | < 3 minutes | |
| Time to emergency dial=0 (stop blocking) | < 3 minutes | |
| Time to correct dial to intended value | < 5 minutes | |
| False positives caused by corruption window | Documented (count logged) | |

### Related runbook

`disaster_recovery.md` -- Scenario 4 (dial corruption / misconfiguration).

---

## Post-Exercise Debrief Template

After each exercise, the observer leads a 5-minute debrief and records:

1. **Exercise:** (name and date)
2. **Participants:** (names/roles)
3. **Detection time:** (measured)
4. **Recovery time:** (measured)
5. **RTO met?** (yes/no)
6. **Gaps found:** (alerting, documentation, tooling, knowledge)
7. **Action items:** (with owners and due dates)

Append results to `disaster_recovery.md` under the "Runbook Exercise History"
section using this format:

```markdown
### [DATE] -- [Exercise Name]

- **Participants:** ...
- **Detection time:** X min Y sec
- **Recovery time:** X min Y sec
- **RTO met:** Yes / No
- **Gaps found:** ...
- **Action items:** ...
```
