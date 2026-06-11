---
phase: 310
title: Collision-Free Dev Environments + Clean Good/Bad Load Test
status: PLANNED
created: 2026-06-11
audience: [developer, operator]
---

# Collision-Free Dev Environments + Clean Good/Bad Load Test

> **Goal.** Let multiple people/agents run the POC stack on the **same host**
> without port, container, network, or volume collisions, and give them a
> one-command way to drive a **good/bad traffic mix** at a stack and watch it in
> that stack's own Grafana. Today every checkout defaults to the same
> `HOST_PORT_*` values *and* the same `COMPOSE_PROJECT_NAME=ja4proxy`, so the 17
> agent worktrees + any human all clash (e.g. two `ja4pd` instances fighting over
> `:9090`).

## Background — what exists vs what's missing

- **Exists:** the compose is fully parameterised — 12 `HOST_PORT_*` vars,
  `AGENT_BIND_IP`, `AGENT_CPU_SET`, `COMPOSE_PROJECT_NAME`. The knobs are there.
- **Missing:** any *allocation* of those knobs. Every var has a fixed default and
  `scripts/start-poc.sh` hard-codes `COMPOSE_PROJECT_NAME=ja4proxy`. There is no
  per-setup namespacing.
- **Key simplification:** Prometheus scrapes proxies by **service DNS inside the
  compose network**, so it is unaffected by host-port remapping. Only
  **host-published ports** (human access + the load-test target) and the
  **project name** (container/network/volume isolation) need namespacing.

## Design (agreed + refined)

1. **Namespace unit = the git worktree/checkout.** The lane is derived from the
   worktree's absolute path, so each of the 17 agent dirs + the main checkout
   auto-gets its own lane with zero config.
2. **Per-lane network does the heavy lifting; only *published* ports get
   offset.** Compose already creates a network named per `COMPOSE_PROJECT_NAME`,
   so each lane is fully network-isolated and **internal service ports never
   collide** — we therefore do **not** offset internal container ports at all.
   Only the handful of **host-published** ports are lane-offset:
   `base + lane×100`, with free-check + auto-bump (verify the published set is
   free at startup; bump the lane if any is taken). The chosen lane is
   **persisted in `.env`** so it is stable across restarts.
3. **Publish only what you reach from outside** — `HOST_PORT_DIRECT` (proxy /
   load-test target), `HOST_PORT_METRICS`, `HOST_PORT_GRAFANA`,
   `HOST_PORT_MANAGEMENT` (and `HOST_PORT_PROMETHEUS` for convenience). Nothing
   else is published. All bound to `${AGENT_BIND_IP:-127.0.0.1}`.
4. **No HAProxy in the default lane.** HAProxy is a load balancer for *multiple*
   proxies; a single-proxy dev lane doesn't need it (the load test hits the proxy
   directly), and it removes the privileged-`443` problem entirely. HAProxy +
   multiple proxies live behind an explicit opt-in (`make start-scaled` /
   `WITH_HAPROXY=1`). Matches the SCALING_GUIDE "HAProxy is optional" stance.
5. **Reach in straightforwardly:** `make lane` prints this checkout's lane + the
   exact published URLs; `make open SVC=grafana|management|metrics` opens one;
   `make tunnel` SSH-forwards the lane's loopback ports for a remote host. No new
   ingress infra. *(Deferred alternative: a single Traefik ingress routing
   `lane<N>.localhost` by docker labels — one fixed entry point for all lanes —
   only if a unified multi-lane view is wanted later.)*
6. **Load test = bridge POC + auto-dial + good/bad mix.** `make loadtest` brings
   up the lane's stack, raises the dial (so block/ban panels populate), runs
   `ja4p test benchmark` with a configurable good/bad rate for a set duration,
   and prints **that lane's** Grafana URL.

`LANE_COUNT = 40`.

## Scope (files)

- **New:** `scripts/lane-env.sh` — derive lane from `$PWD` (git worktree root),
  free-check + auto-bump, write/refresh the per-setup `.env` with the 12
  `HOST_PORT_*` + `COMPOSE_PROJECT_NAME=ja4proxy-lane<N>`. Idempotent.
- **New:** `make lane` — show this checkout's lane + its port map + Grafana URL.
- **New:** `make open SVC=grafana|management|metrics|prometheus` — open the
  lane's published URL for a service.
- **New:** `make loadtest` — ensure the lane stack is up, set the dial, run the
  good/bad mix, print the Grafana URL. Knobs: `GOOD_RATE`, `BAD_RATE`,
  `DURATION`, `WORKERS`, `DIAL` (all defaulted).
- **Edit:** `scripts/start-poc.sh` — source `lane-env.sh` first; bring up the
  default lane **without HAProxy** (publish only direct/metrics/grafana/
  management/prometheus); gate HAProxy + multi-proxy behind `WITH_HAPROXY=1` /
  `make start-scaled`. (Shared file — coordinate per the multi-agent rules;
  preserve all existing behaviour.)
- **Docs:** `docs/start/POC_QUICKSTART`, `docs/operate/SCALING_GUIDE`, and
  `MAKEFILE_TARGETS.md` get the `make lane` / `make loadtest` workflow.

## Implementation plan

1. `lane-env.sh`: compute worktree root (`git rev-parse --show-toplevel`), hash →
   lane, derive the 12 ports + project name, free-check each (via `ss`/bind
   probe), auto-bump on conflict, persist to `.env` (merge, don't clobber
   secrets). Re-runs are stable.
2. `make lane` prints the resolved map + Grafana URL.
3. Wire `start-poc.sh` to call `lane-env.sh` first.
4. `make loadtest`: `start-poc` (idempotent) → `ja4p management dial set $DIAL` →
   `ja4p test benchmark --host 127.0.0.1:$HOST_PORT_DIRECT --good-rate $GOOD_RATE
   --bad-rate $BAD_RATE --workers $WORKERS --duration $DURATION` → echo Grafana
   URL.
5. Docs + Makefile help.

## Test strategy

- **Unit (bash/py):** lane derivation is deterministic for a given path; two
  different paths get different lanes; free-check bumps the lane when a port is
  occupied; a lane's 12 ports never self-collide; `.env` merge preserves existing
  secrets.
- **`test_container_config`-style:** the generated `.env` maps every
  `HOST_PORT_*` the compose references; `COMPOSE_PROJECT_NAME` is set and unique.
- **Integration (manual + scripted):** two checkouts run `make start-poc`
  concurrently with no collision; `make loadtest` makes the lane's Grafana panels
  move.
- **Idempotency:** re-running `lane-env.sh` yields the same lane/ports.

## Acceptance criteria

- [ ] Two different worktrees `make start-poc` **simultaneously** with no port /
      container / network / volume collision.
- [ ] `make lane` shows this checkout's lane, port map, and Grafana URL.
- [ ] Lane/ports are **deterministic per worktree** and **stable across
      restarts**, and **auto-bump** when a port is already taken.
- [ ] `make loadtest` drives a good/bad mix and the lane's Grafana dashboards
      populate (block/ban panels too, via the auto-dial).
- [ ] Existing single-stack workflow still works (default lane); secrets in
      `.env` are preserved.
- [ ] Docs + `MAKEFILE_TARGETS.md` updated; `make help` lists the new targets.

## Out of scope

- **Production** multi-tenancy / orchestration (this is dev/test on one host).
- Non-loopback / remote binding (stays `127.0.0.1`; the existing `AGENT_BIND_IP`
  knob already covers the rare remote case).
- Changing the **production** compose port model.
- Host-native capacity benchmarking — `make bench-hostnative` already covers it;
  `make loadtest` is the "watch Grafana" path.
- A shared Traefik/ingress entry point (deferred; see Design note 5).
