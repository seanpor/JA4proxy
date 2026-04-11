# Phase 64g — Rolling Upgrade Notes

## Artifacts Created

| File | Purpose |
|------|---------|
| `docs/runbooks/rolling_upgrade.md` | Rolling upgrade + rollback procedures |

## Acceptance Checklist

- [x] Prerequisites section: HAProxy health check config, ≥ 2 instances, smoke test
- [x] Docker Compose rolling upgrade: drain, recreate, wait, re-enable, 30s stagger
- [x] Kubernetes rolling upgrade: helm upgrade with --wait, rollout status
- [x] Docker Compose rollback: recreate with PREVIOUS_TAG, re-enable
- [x] Kubernetes rollback: `kubectl rollout undo`
- [x] Rollback decision criteria table with specific thresholds
- [x] All Docker commands use `docker compose` (v2), never `docker-compose` (v1)
- [x] Rollback subsections give single-command answers for each model

## Out of Scope

- Blue/green deployments (Phase 43 covers this separately)
- Canary deployments (deferred)
- GitOps/ArgoCD automated rollout (Phase 94 — K8s operator)
