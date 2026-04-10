# Phase 64g — Rolling upgrade notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** S
> **Status:** COMPLETE

## Deliverable
- `docs/runbooks/rolling_upgrade.md` (Docker Compose, Kubernetes, rollback for both)

## What was done

- Created `docs/runbooks/rolling_upgrade.md` with all four required sections:
  prerequisites, Docker Compose rolling upgrade, Kubernetes rolling upgrade,
  and rollback for both models.
- Docker Compose section covers: version check, HAProxy drain via admin socket,
  connection drain wait (30s), force-recreate single service, health check,
  HAProxy re-enable, and 30-second stagger between nodes.
- Kubernetes section covers both Deployment and DaemonSet (maxUnavailable: 1).
- Rollback section gives single-command answers for both Docker Compose and
  Kubernetes.
- All commands use `docker compose` v2 (space-separated).

### Dry-run walkthrough

Walked through the Docker Compose upgrade path mentally against the
`docker-compose.poc.yml` topology:

1. `docker compose exec ja4proxy-1 /app/bin/proxy --version` -- confirms
   binary path matches the Go production layout (`/app/bin/proxy`).
2. HAProxy drain via socat -- requires admin socket; documented fallback if
   socat or socket is missing.
3. `sleep 30` -- conservative for TLS passthrough connections (most complete
   in under 5s; 30s covers slow clients).
4. `docker compose up -d --no-deps --force-recreate ja4proxy-1` -- `--no-deps`
   avoids cascading recreates of Redis/analytics; `--force-recreate` ensures
   the container is replaced even if only the image tag changed.
5. Health check via management API deep endpoint confirms Redis connectivity.
6. Re-enable in HAProxy completes the cycle.

Kubernetes path relies on native rollout mechanics; `--wait` on helm upgrade
ensures the command blocks until pods are ready.

## Decisions made

- No deviations from the spec in PHASE_64.md.
- Documented the HAProxy admin socket as optional (not required) with a clear
  fallback to health-check-based detection, since not all HAProxy deployments
  expose the admin socket.

## Prerequisite verification

These checks could not be run live (no running Docker environment in this
session). The runbook documents the verification commands and the fallback
path if either `socat` or the admin socket is missing: rely on HAProxy
health checks (`fall` x `inter` for down detection, `rise` x `inter` for
recovery detection) instead of explicit drain/enable commands.

## Reviewer checklist (complete before merging)
- [ ] All four sections present (prerequisites, Docker upgrade, K8s upgrade, rollback)
- [ ] All commands use `docker compose` (v2), not `docker-compose` (v1)
- [ ] Rollback subsections give a single-command answer for each model

## Phase 101 entries surfaced

- None identified. The runbook covers both deployment models and rollback paths
  as specified.
