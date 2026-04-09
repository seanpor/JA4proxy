# Phase 64g — Rolling upgrade notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** S
> **Status:** NOT STARTED

## Deliverable
- `docs/runbooks/rolling_upgrade.md` (Docker Compose, Kubernetes, rollback for both)

## What was done
<!-- Record that the rollback path was at minimum dry-run-walked through. -->

## Decisions made
<!-- Note any deviations from the spec in PHASE_64.md. -->

## Prerequisite verification
<!-- Record the output of these checks:
- `docker compose exec haproxy which socat`
- `docker compose exec haproxy ls /var/run/haproxy/admin.sock`
If either is missing, note the fallback documented in the runbook. -->

## Reviewer checklist (complete before merging)
- [ ] All four sections present (prerequisites, Docker upgrade, K8s upgrade, rollback)
- [ ] All commands use `docker compose` (v2), not `docker-compose` (v1)
- [ ] Rollback subsections give a single-command answer for each model

## Phase 101 entries surfaced
<!-- File any gaps that fell out of this work. -->
