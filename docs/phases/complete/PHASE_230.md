---
phase: 230
title: Interface & Container Architecture — Critical Review & Rationalisation
status: PLANNING
size: LARGE
created: 2026-06-11
audience: [architect, operator, secops]
---

# Interface & Container Architecture — Critical Review & Rationalisation

## Goal

Conduct a thorough architectural review of every container and user-facing
interface in the JA4proxy stack, answering three hard questions for each:

1. **Why does this exist?** What problem does it solve that cannot be absorbed
   by an adjacent service without meaningful trade-off?
2. **Is it actually needed?** Is the complexity cost justified relative to the
   operational and security value delivered?
3. **How does a SecDevOps engineer actually interact with it at 2 AM?** Not the
   happy path — the incident path.

The output is a set of concrete, prioritised **findings** and a **recommended
target architecture** that reduces complexity, closes UX gaps, and surfaces the
right information in the right place — specifically making the Management
Console a genuinely useful Tier-1 response tool rather than a configuration
accessor bolted on as an afterthought.

This is a **design-only phase**. No code changes. The deliverable is a reviewed,
agreed architectural decision record that becomes the input spec for one or more
follow-on implementation phases.

---

## Scope

### In scope

- Every container defined in `deploy/docker/docker-compose.poc.yml`,
  `docker-compose.prod.yml`, and `docker-compose.monitoring.yml`.
- Every user-facing interface: Management Console UI, HAProxy stats page,
  Grafana/Prometheus, admin-api, analytics service.
- The `admin-api` / `management` service split — why are there two?
- What the Management Console currently shows vs. what it *should* show to be
  genuinely useful for incident response.
- The operational "how do I…" questions that currently have no answer in the UI.
- Network topology and blast-radius analysis per container.

### Out of scope

- Modifying the Go proxy core or signal modules.
- Changing the Redis schema or stream format.
- CI/CD pipeline (covered by Phases 224–228).

---

## The Full Container Inventory (current state)

### Production stack (`docker-compose.prod.yml`)

| Container | Image | Networks | Ports exposed to host | Role |
|---|---|---|---|---|
| `haproxy` | `haproxy:2.8.24-alpine` | frontend, backend | 443, 80, 127.0.0.1:8404 | TLS termination, L4 load balancer |
| `proxy` | `ja4proxy:2.0.0` | backend | 8080, 9090 (internal) | Go JA4 fingerprinting proxy |
| `redis` | `redis/redis-stack:7.4.0-v8` | backend | none | State, streams, blocklist |
| `analytics` | `ja4proxy-analytics:1.0.0` | backend | 8082 (internal) | ML/stats engine |
| `tarpit` | `ja4proxy-tarpit:1.0.0` | backend | 8888, 9099 (internal) | Slow-loris attacker sink |
| `redis-exporter` | `oliver006/redis_exporter` | backend | none | Prometheus metrics bridge |
| `prometheus` | `prom/prometheus:v3.12.0` | backend + monitoring | 127.0.0.1:9091 | Metrics store |
| `grafana` | `grafana/grafana:13.0.2` | monitoring | 127.0.0.1:3001 | Dashboards |
| `loki` | `grafana/loki:3.7.2` | monitoring | 3100 (internal) | Log aggregation |
| `promtail` | `grafana/promtail:3.6.11` | monitoring | none | Log shipper |

### POC stack additions (`docker-compose.poc.yml`)

| Container | Role |
|---|---|
| `management` | Management Console UI + API (FastAPI/HTMX) |
| `admin-api` | Second API — what is this? (see Finding 1) |
| `backend` | Mock backend (dev/test only) |
| `tarpit` | Tarpit (also in POC) |
| `trafficgen` | Traffic generator for testing (profile: traffic) |
| `test` | Test runner container (profile: test) |
| `analytics` | Analytics engine |

### Monitoring-only stack (`docker-compose.monitoring.yml`)

| Container | Role |
|---|---|
| `prometheus` | Metrics scraping |
| `alertmanager` | Alert routing |
| `grafana` | Dashboards |
| `loki` | Log aggregation |
| `promtail` | Log shipper |
| `node-exporter` | Host metrics |
| `redis-exporter` | Redis metrics |
| `haproxy-exporter` | HAProxy metrics |
| `cadvisor` | Container resource metrics |
| `docker-socket-proxy` | Sandboxed Docker API for Promtail |

---

## Deep Analysis: Container-by-Container

### A — HAProxy (`haproxy`)

**Why it exists:** TLS termination and L4/L7 routing before the JA4 proxy.
Historically needed because the Go proxy was not the TLS entry point, and
HAProxy provides SNI routing, connection limiting, and a stats page.

**Critical question:** *Is HAProxy justified now that the Go proxy does its own
TLS fingerprinting?*

In the current architecture, HAProxy sits in front of the Go proxy. The Go
proxy *also* terminates TLS (or inspects the ClientHello before HAProxy).
This creates a tension: **JA4 fingerprinting requires seeing the raw TLS
ClientHello, which HAProxy can destroy** by re-originating the connection.
The current haproxy.cfg must be using TCP proxy mode (not HTTP/S termination)
to preserve the ClientHello — which means HAProxy provides connection limiting
and SNI routing at L4, not L7 termination.

**Verdict:** HAProxy is justified *only if* it is operating in TCP proxy mode
and not re-originating TLS. If it is doing TLS termination+re-origination, it
is actively breaking JA4 fingerprinting and should be removed. This needs
explicit verification. The stats page at `:8404` is the only direct
operator-visible interface from HAProxy — it is a raw CSV/HTML page that is
not integrated into the Management Console at all.

**SecDevOps interaction at 2 AM:** The operator SSHes to the host, navigates
to `http://127.0.0.1:8404/stats`, and eyeballs raw connection counts in a 1990s
HTML table. There is no alerting on HAProxy-level anomalies (connection flood,
backend marked DOWN) surfaced in the Management Console.

**Gap:** HAProxy stats are invisible to the Management Console. A DDoS that
hits HAProxy's connection limits would not appear in the UI at all.

---

### B — Go Proxy (`proxy`)

**Why it exists:** Core JA4 fingerprinting, risk scoring, action enforcement.
The primary value-creation container in the entire stack.

**Interfaces exposed:**
- `:8080` — proxied traffic (HAProxy upstream)
- `:9090` — Prometheus metrics AND a health endpoint

**Critical question:** *The metrics and health endpoints are on the same port.
Is this a security concern?*

Yes. Port 9090 currently exposes unauthenticated Prometheus metrics. The
`docker-compose.poc.yml` binds this to `${AGENT_BIND_IP}` (default
`127.0.0.1`) which is correct. In `docker-compose.prod.yml`, port 9090 has no
`127.0.0.1:` binding — it is exposed as `"9090"` which Docker maps to
`0.0.0.0:9090`. **This is an attack surface finding** (unauthenticated metrics
including connection counts, ban counts, fingerprint distributions exposed to
anyone who can reach the host on port 9090).

**SecDevOps interaction at 2 AM:** The proxy emits structured log lines and
Prometheus metrics. There is no way to inspect *current live connection state*
(i.e., what is traversing the proxy right now) except via Redis `XRANGE` of the
events stream — which requires redis-cli access. The Management Console's
"Live Connection Feed" reads this stream, which is the right pattern, but it
is N seconds behind.

---

### C — Redis (`redis`)

**Why it exists:** Shared state between the Go proxy (writes), the Python proxy
(reads/writes), the analytics engine (reads), and the management service
(reads/writes). Also provides the event stream (`ja4proxy:events`).

**Critical question:** *Is `redis/redis-stack` (which includes RedisSearch and
RedisJSON modules) justified vs plain `redis:7-alpine`?*

Redis Stack is ~3x larger than plain Redis. The JA4proxy code does not appear
to use RedisSearch or RedisJSON — it uses plain Redis commands (XADD, XRANGE,
HSET, GET, SET, KEYS). **Redis Stack is almost certainly unnecessary overhead**,
bringing a larger attack surface and more CVEs for no functional benefit.

**SecDevOps interaction at 2 AM:** Redis is completely opaque from the Management
Console. There is no visibility into:
- Redis memory usage / eviction events
- Stream length (`XLEN ja4proxy:events`)
- Key expiry patterns (are blocklist entries expiring correctly?)
- Whether Redis is running in degraded mode (maxmemory reached → allkeys-lru
  evictions silently dropping security state)

The `redis-exporter` → Prometheus → Grafana path gives *some* of this, but
requires navigating to a separate Grafana dashboard. A SecDevOps engineer
responding to an incident needs this information in the same window as the
blocklist and ban management.

---

### D — Analytics (`analytics`)

**Why it exists:** Cross-instance ML/statistical analysis — beaconing detection,
distribution drift, campaign detection — running as a separate Python service
that consumes the Redis event stream and writes enriched signals back.

**Critical question:** *Why is this a separate container rather than a Go
goroutine pool in the proxy?*

The analytics engine uses Python-specific libraries (numpy, scipy, scikit-learn)
for ML workloads that have no Go equivalent of equivalent maturity. This
justifies the separation. However:

- Analytics runs on the `ja4proxy-mgmt` network only. The Management Console
  is also on `ja4proxy-mgmt`. **But the Management Console never queries the
  analytics service directly** — all data flows via Redis. This means the
  analytics service could be on `ja4proxy-data` only, reducing its network
  attack surface.

- The analytics service exposes port `8080` to the host in the POC
  (`HOST_PORT_ANALYTICS:-8080`). Looking at `src/analytics/main.py`, it exposes
  a health endpoint and Prometheus metrics. **These metrics are not scraped by
  the Prometheus in the monitoring stack** — there is no scrape target for
  `analytics:8080` in `monitoring/prometheus/prometheus.yml`. This is dead
  infrastructure that no one reads.

- Analytics results (beaconing suspects, campaign detections, drift alerts)
  are **not surfaced in the Management Console**. An operator has no way to
  see what the analytics engine has concluded without querying Redis directly.

**SecDevOps interaction at 2 AM:** The operator has no idea what the analytics
engine is doing. Its findings are invisible. Its own health is not in the
Management Console. If it silently crashes and stops consuming the event stream,
no alert fires (the stream just grows unbounded).

---

### E — Tarpit (`tarpit`)

**Why it exists:** A slow-loris HTTP server that wastes attacker resources.
Blocked connections are forwarded here by the proxy to tie up the attacker's
connection pool.

**Critical question:** *Is this justified?*

Yes, conceptually — the tarpit is a valuable defensive tool. However:

- Its metrics port (`:9099`) is **not scraped by Prometheus**. There is no
  visibility into how many connections are currently tarpitted, how long they
  are held, or whether the tarpit itself is under resource pressure.
- The tarpit is on `ja4proxy-origin` (internal). This is architecturally
  correct — it sits where the backend sits.
- The tarpit configuration (`TARPIT_DURATION=60` seconds) cannot be changed
  without restarting the container. There is no runtime configuration path.

**SecDevOps interaction at 2 AM:** The operator knows connections are being
"tarpitted" because the management console shows `action: tarpit`, but has no
way to see how many concurrent tarpit connections exist, whether the tarpit is
saturated, or whether a sustained attack has exhausted it.

---

### F — Management Console (`management`)

**Why it exists:** The primary operator-facing web UI for configuration,
monitoring, and incident response.

**What it currently offers:**
- Dashboard: health cards (Redis, proxy instances, GeoIP), live connection feed,
  enforcement dial widget.
- Lists: allowlist, blocklist, watchlist management.
- Bans: active ban management.
- Audit Log: action history from the Redis stream.
- Threat Intelligence: TI feed status.

**Critical gap analysis — what a SecDevOps engineer actually needs at 2 AM:**

| Question | Currently answerable? | Notes |
|---|---|---|
| Is the proxy running and healthy? | YES (health cards) | Proxy instance count via heartbeat keys |
| Is Redis healthy? | YES (health card) | Binary OK/degraded |
| What are the top attacking IPs right now? | NO | No "top N" view |
| What JA4 fingerprints are currently blocked? | NO | No fingerprint analytics |
| What did the analytics engine conclude? | NO | Completely absent |
| Is the tarpit saturated? | NO | No tarpit metrics |
| Is Redis running out of memory? | NO | No memory pressure indicator |
| What is the HAProxy connection state? | NO | No HAProxy integration |
| Is the event stream growing unboundedly? | NO | No stream length metric |
| What is the current enforcement dial value? | YES (dial widget) | Shows value; "why" requires Redis queries |
| Can I temporarily raise/lower the dial? | YES (dial endpoint) | Works |
| Can I add an IP to the blocklist with an expiry? | YES (lists) | Works |
| Can I export a compliance report? | PARTIAL | API works; no UI |
| What signals fired on this specific IP? | NO | No per-IP signal breakdown |
| What is the current GeoIP distribution of traffic? | NO | No geo view |
| What are my most-seen JA4 fingerprints in the last 1h? | NO | No analytics view |
| Are my TI feeds healthy? | YES (threat intel page) | Shows circuit state |

**Verdict:** The Management Console covers the easy configuration tasks well but
fails as an incident-response tool. A security engineer responding to an active
incident needs the first 10 rows above answered in a single page — not spread
across Grafana, Redis CLI, and the management console.

---

### G — Admin API (`admin-api`)

**Why does this exist separately from the Management Console?**

Looking at `deploy/docker/Dockerfile.admin`, this container serves
`src.management.app:app` — but the Management Console container
(`Dockerfile.management`) serves `management.api.main:app`. These are **two
different FastAPI applications** running from the same codebase, potentially
exposing the same or overlapping routes, on two different ports (`8090` and
`8091`).

**This is an architectural anomaly.** It creates:
- Two surfaces to authenticate and authorise.
- Two Redis connection pools.
- Two sets of JWT secrets to manage.
- Potential for inconsistent behaviour when both are running simultaneously.
- Confusion about which to call from automation scripts.

**Critical question:** *Can the admin-api be eliminated entirely?*

If the admin-api was added to provide a machine-readable API for automation
(Ansible, Terraform, CLI) without the UI overhead, this is a valid use case —
but a dedicated container is not necessary. The Management Console's FastAPI
already exposes a full JSON API (`/api/v1/*`). The CLI tool (see
`deploy/docker/Dockerfile.cli`) should target the management API directly.

**Verdict:** The `admin-api` container appears to be a development artefact or
an unresolved duplication that should be eliminated. The Management Console API
is sufficient. **Confirm by mapping every `/api/v1/` route in each service and
identifying actual differences.**

---

### H — Prometheus + Grafana + Loki + Promtail + Alertmanager

**Why they exist:** Industry-standard observability stack. Prometheus scrapes
metrics, Loki aggregates logs, Grafana visualises, Alertmanager routes alerts.

**Critical questions:**

1. *Why is this a separate `docker-compose.monitoring.yml` rather than part of
   the main compose?*

   Deliberate decoupling: monitoring can be run separately, by a different team,
   or pointed at multiple JA4proxy instances. This is architecturally correct
   for a product that will be deployed in enterprise environments where the
   monitoring stack already exists (Datadog, Splunk, etc.).

2. *Why does the Management Console not embed any Grafana panels?*

   Grafana panels can be embedded via iframes (with appropriate auth). The
   Management Console could surface the most critical Grafana panels (connection
   rate, threat score distribution, Redis memory) inline, eliminating the
   context switch for the most common incident-response scenarios.

3. *Is Alertmanager configured and tested?*

   Unknown from static analysis — this is a gap. If Alertmanager is not sending
   alerts anywhere useful (PagerDuty, Slack, email), it is dead infrastructure.

4. *cAdvisor runs with `SYS_PTRACE` + `DAC_READ_SEARCH` and mounts `/rootfs`,
   `/var/run`, `/sys`, `/var/lib/docker` — this is a significant privilege
   footprint.*

   cAdvisor is the highest-privilege container in the stack. Its compromise has
   a wide blast radius (read access to Docker container filesystems). This is
   acceptable for a monitoring deployment but should be documented explicitly.

---

### I — `backend` (mock backend)

**Why it exists:** Development/POC-only mock of the upstream web application.
Has no role in production.

**Verdict:** Correctly scoped to the POC compose. The `profiles:` mechanism
for `trafficgen` and `test` is the right pattern; `backend` should also be
under a `dev` profile to make the profile intent explicit.

---

## Architectural Findings

### Finding 1 — CRITICAL: `admin-api` is an unresolved service duplication

**Risk:** Two independent FastAPI services with overlapping APIs create
inconsistent state, duplicated secrets management, and a confused integration
surface for automation.

**Recommendation:** Audit the route inventory of both services. If the routes
are identical or subsets, eliminate `admin-api` and route all API consumers
to the `management` service. If `admin-api` provides unique routes, migrate
them to `management` and delete the container.

**Implementation:** One PR, no behaviour change from the consumer's perspective
if the routes are equivalent.

---

### Finding 2 — HIGH: Management Console is blind to 80% of operational state

**Risk:** An engineer responding to an active attack has no way to answer "what
is the current top-10 attacking JA4 fingerprint?" or "is the tarpit saturated?"
or "what has the analytics engine concluded?" without leaving the Management
Console and opening Redis CLI or Grafana.

**Recommendation — new dashboard sections:**

**A. "Threat Posture" row (polling, not SSE):**
- Top 10 source IPs by risk score in last 15 minutes.
- Top 10 JA4 fingerprints by connection count in last 15 minutes.
- Active tarpit connection count (from Redis key `tarpit:active_count`).
- Analytics engine last-seen timestamp (heartbeat key).
- Event stream depth (`XLEN ja4proxy:events`) — leading indicator of stream
  backpressure.

**B. "Infrastructure" row:**
- Redis memory used / maxmemory (from Redis INFO command).
- Redis eviction count (evictions = security state silently dropped).
- HAProxy backend state (DOWN = proxy unreachable via normal path).
- Per-container health status (from Docker healthcheck state via daemon API
  or a polling sidecar).

**C. "Analytics Intelligence" panel:**
- Current beaconing suspects list (from `analytics:beaconing:suspects` Redis
  key/sorted set).
- Active campaigns detected (from analytics campaign detection output).
- Drift alerts (from `analytics:drift:alerts` Redis stream).

---

### Finding 3 — HIGH: Redis memory pressure is silent and catastrophic

**Risk:** Redis is configured with `--maxmemory-policy allkeys-lru`. When Redis
reaches `maxmemory`, it begins evicting keys using LRU — including blocklist
entries. **This means a memory-pressure event silently un-blocks previously
blocked IPs.** There is no alert, no log in the Management Console, no
visibility at all.

**Recommendation:**
1. Add `redis_evicted_keys` to the Management Console health card (query Redis
   `INFO stats` for `evicted_keys`).
2. Add a Prometheus alert rule: `redis_evicted_keys_total > 0` → CRITICAL
   (evictions in a security proxy are a P0 event, not a capacity warning).
3. Consider `maxmemory-policy noeviction` for the `security:blocklist:*` keyspace,
   implementing selective eviction only on non-security keys. This requires
   a more careful Redis ACL/keyspace design.

---

### Finding 4 — HIGH: HAProxy stats are completely disconnected from operations

**Risk:** HAProxy is the entry point for all traffic. A connection flood that
overwhelms HAProxy's connection table, or a proxy backend going DOWN, is
invisible in the Management Console. The only interface is
`http://127.0.0.1:8404/stats` — a raw HTML page that requires a logged-in SSH
session.

**Recommendation:**
1. The Management Console should poll the HAProxy stats socket (via the
   `haproxy-exporter` Prometheus metrics endpoint, which is already scraped)
   and surface backend health, connection rate, and error rate.
2. Add an alert rule for `haproxy_backend_status == 0` (backend DOWN).

---

### Finding 5 — HIGH: Analytics engine findings are completely invisible

**Risk:** The analytics container runs ML-based beaconing detection, campaign
detection, and statistical drift analysis. None of these findings are visible
to the operator. If the analytics engine detects a coordinated campaign, the
operator has no way to know without querying Redis directly.

**Recommendation:**
1. Define a Redis contract for analytics output: analytics writes human-readable
   summaries to `analytics:summary:*` keys (beaconing suspects, active campaigns,
   drift alerts) with TTLs.
2. The Management Console polls these keys and surfaces the summaries in a
   dedicated "Intelligence" panel on the dashboard.
3. Optionally, analytics pushes high-confidence detections to the Management
   Console via the webhook mechanism already in place.

---

### Finding 6 — MEDIUM: `redis/redis-stack` vs plain `redis`

**Risk:** Redis Stack includes RedisSearch, RedisJSON, and other modules that
the JA4proxy codebase does not use. Each additional module is an additional
attack surface. Redis Stack images are also larger, slower to pull, and have
a different CVE profile.

**Recommendation:** Replace `redis/redis-stack:7.4.0-v8` with
`redis:7.4-alpine` (or the pinned digest equivalent). Verify no code uses
`FT.*` (RedisSearch) or `JSON.*` (RedisJSON) commands before doing so.

---

### Finding 7 — MEDIUM: Tarpit metrics are unscraped and invisible

**Risk:** The tarpit exposes Prometheus metrics on port 9099. This port is not
a scrape target in `monitoring/prometheus/prometheus.yml`. The tarpit could be
saturated, crashing, or holding zero connections, and no one would know.

**Recommendation:**
1. Add `tarpit:9099` as a scrape target in Prometheus.
2. Add a Grafana panel for active tarpit connections.
3. Surface active tarpit connection count in the Management Console dashboard.

---

### Finding 8 — MEDIUM: Analytics metrics are unscraped

**Risk:** The analytics container exposes Prometheus metrics on port 8080. This
is not a scrape target. Analytics health is invisible.

**Recommendation:**
1. Add `analytics:8080` as a scrape target in Prometheus.
2. Add a Management Console health card for analytics engine status.

---

### Finding 9 — MEDIUM: Production `proxy` port 9090 may be exposed on 0.0.0.0

In `docker-compose.prod.yml`, the proxy service defines:
```yaml
ports:
  - "9090"   # Prometheus metrics / Health API
```

Without an explicit IP binding, Docker publishes this on `0.0.0.0:9090`,
exposing unauthenticated Prometheus metrics to any network interface.

**Recommendation:** Change to `"127.0.0.1:9090:9090"` in the production
compose, consistent with the POC compose's `${AGENT_BIND_IP}` pattern.

---

### Finding 10 — LOW: `backend` container should use `profiles: [dev]`

The mock backend has no role in production but is defined without a profile
guard in the production compose. Adding `profiles: [dev]` prevents accidental
inclusion.

---

### Finding 11 — LOW: HAProxy TLS mode needs explicit documentation

The current architecture is ambiguous about whether HAProxy terminates TLS or
passes it through. If HAProxy terminates TLS, the Go proxy never sees the
original ClientHello and **JA4 fingerprinting is broken**. This needs a clear
architectural diagram and a documented, tested assertion in CI.

---

## Target Architecture — Proposed Container Inventory (production)

| Container | Justification | Action |
|---|---|---|
| `haproxy` | L4 load balancing + connection limiting. Must be TCP-proxy mode. | Keep, document TLS mode explicitly |
| `proxy` (Go) | Core fingerprinting. | Keep |
| `redis` | State. Replace with plain redis:7.4-alpine. | Simplify image |
| `analytics` | ML workloads require Python. Move to data-only network. | Keep, fix network |
| `tarpit` | Attacker sink. | Keep, add metrics scraping |
| `management` | Management Console. Absorb `admin-api`. | Keep, expand |
| `admin-api` | Duplication. | **Eliminate** |
| `prometheus` | Metrics. | Keep |
| `grafana` | Visualisation. | Keep |
| `loki` | Logs. | Keep |
| `promtail` | Log shipping. | Keep |
| `alertmanager` | Routing. | Keep, verify config |
| `redis-exporter` | Redis metrics. | Keep |
| `haproxy-exporter` | HAProxy metrics. | Keep |
| `node-exporter` | Host metrics. | Keep |
| `cadvisor` | Container metrics. | Keep, document privilege rationale |
| `docker-socket-proxy` | Sandbox Docker API. | Keep |

---

## Proposed Management Console: "Single Pane of Glass" Target

The Management Console should answer every Tier-1 incident response question
without requiring any other tool. Target information architecture:

```
Dashboard
├── Row 1: System Health (existing, expanded)
│   ├── Proxy instances + heartbeat age
│   ├── Redis: status, memory%, eviction count
│   ├── Analytics engine: status + last seen
│   ├── Tarpit: status + active connection count
│   └── HAProxy: backend status + connection rate
│
├── Row 2: Threat Posture (NEW — 30s polling)
│   ├── Top 10 attacking IPs (last 15 min, by risk score)
│   ├── Top 10 JA4 fingerprints (last 15 min, by count)
│   ├── Action distribution: allow/monitor/challenge/block/tarpit
│   └── Event stream depth (backpressure indicator)
│
├── Row 3: Intelligence (NEW — from analytics Redis output)
│   ├── Beaconing suspects
│   ├── Active campaigns detected
│   ├── Drift alerts
│   └── TI feed health summary
│
└── Row 4: Live Feed (existing)
    └── Last 50 events with JA4, IP, score, action

Lists      — (existing, no change)
Bans       — (existing, no change)
Audit Log  — (existing, no change)
Threat Intel — (existing, no change)

NEW: Fingerprint Detail (drill-down from live feed / ban list)
├── JA4 fingerprint → historical frequency graph
├── Associated IPs
├── Associated signal firings
└── One-click block (with confirmation + audit note)

NEW: IP Detail (drill-down)
├── IP → historical risk score
├── Associated fingerprints
├── Which signals have fired
├── Geo / ASN / RDAP data
└── One-click block / tarpit / allow (with confirmation)

NEW: Infrastructure tab
├── Redis memory graph (poll INFO command)
├── HAProxy connection rate (from haproxy-exporter)
├── Analytics engine metrics
└── Container health summary
```

---

## Implementation Plan (follow-on phases)

| Phase | Title | Size | Description |
|---|---|---|---|
| 231 | Eliminate `admin-api` duplication | SMALL | Audit routes, merge uniques, delete container |
| 232 | Management Console: Threat Posture + Infrastructure rows | LARGE | New dashboard rows with top IPs, top JA4, stream depth, Redis health |
| 233 | Analytics intelligence visibility | MEDIUM | Analytics writes Redis output; Management Console reads it |
| 234 | Prometheus scrape config: tarpit + analytics | SMALL | Add scrape targets, alert rules, verify Alertmanager |
| 235 | Redis: switch to plain `redis:7.4-alpine` | SMALL | Remove Redis Stack overhead |
| 236 | Fingerprint & IP drill-down pages | MEDIUM | Per-JA4 and per-IP detail pages with one-click actions |
| 237 | Fix prod port binding + document HAProxy TLS mode | SMALL | Fix 0.0.0.0:9090, assert TCP proxy mode in CI |

---

## Test Strategy

This is a **design-only phase** — no code is written. The acceptance criteria
are documentation-based:

1. Every finding is documented with: risk level, supporting evidence, and a
   concrete recommendation.
2. The target container inventory is agreed and documented.
3. Each follow-on phase is scoped and numbered.
4. The review has been assessed by both a cyber-architect perspective and a
   usability perspective (see review section below).
5. `make lint-phases` exits 0 after this document is added to the manifest.

---

## Acceptance Criteria

- [ ] This document reviewed and approved by user.
- [ ] All 11 findings have explicit risk ratings and actionable recommendations.
- [ ] Target architecture diagram (text) agreed.
- [ ] Follow-on phases 231–237 added to manifest as PLANNED.
- [ ] `make lint-phases` exits 0.
- [ ] No code changes in this phase.

---

## Out of Scope

- Any implementation work (deferred to Phases 231–237).
- Changes to the Go proxy core.
- Redis schema changes beyond the analytics output contract definition.
- HAProxy configuration changes beyond clarifying TLS mode.
- Changes to CI/CD (covered by Phases 224–228).

---

## Appendix: Review Assessments

*(To be completed during Phase 230 review)*

### Cyber-Architect Assessment

*[Reviewer signature and date to be added during review]*

**Key concerns to evaluate:**
- Is the recommended single-API-surface (eliminating admin-api) operationally
  sound for enterprises that separate automation from human consoles?
- Does the proposed "single pane of glass" dashboard create a dangerous
  single point of failure for incident response?
- Is the Analytics → Redis → Management Console data path appropriately
  secured and authenticated, or does it create a Redis-mediated injection
  surface?
- Is the recommendation to remove cAdvisor's `SYS_PTRACE` capability
  operationally viable, or is it necessary for accurate container metrics?
- Does the proposed architecture adequately support multi-tenancy and RBAC
  for enterprise SecOps teams where L1 analysts should see the live feed
  but not the configuration controls?

### Usability / SecDevOps Practitioner Assessment

*[Reviewer signature and date to be added during review]*

**Key concerns to evaluate:**
- Is the proposed 4-row dashboard layout cognitively manageable under
  incident stress, or does it create information overload?
- Should the "Threat Posture" row default to a time window selector
  (last 5m / 15m / 1h) or always show 15m fixed?
- Is the one-click block/tarpit/allow from drill-down pages safe enough,
  or does it need a confirmation dialog with audit note?
- Is there a missing "triage queue" concept — a list of IPs at the threshold
  between monitor and block that the analyst should actively review?
- How should the Management Console behave when the proxy is down but Redis
  is up? The current health card shows "0 proxy instances" which is easy to
  miss under stress.
- Are there accessibility concerns with the current dark-mode-only design
  that would disadvantage engineers using screen readers or working in
  high-ambient-light environments?
