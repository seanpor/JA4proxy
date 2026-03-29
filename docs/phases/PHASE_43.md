# Phase 43 — Blue/Green Deployment & Rollback Tooling

Status: PROPOSED

## Goal

Provide a robust framework for performing blue/green upgrades of the entire proxy container stack, integrated with upstream load balancing for true zero-downtime releases and rapid emergency rollbacks.

## Background

While Phase 42 handles data files, core code changes still require container updates. A simple `docker compose up -d` can cause brief interruptions. By running "Blue" (current) and "Green" (new) versions in parallel and shifting traffic at the load balancer layer, we achieve 100% availability.

## Sub-Tasks

### 43a — Blue/Green Orchestration Scripts
- Develop `scripts/deploy-bg.sh` to manage parallel container sets.
- Use Docker Compose project names (e.g., `ja4proxy-blue`, `ja4proxy-green`) to isolate environments.
- Implement automated version detection and environment selection.

### 43b — Upstream Traffic Shifting
- Integrate with the HAProxy management socket to dynamically update backends.
- Implement a "drain" phase: gradually move new connections to the Green environment while allowing Blue connections to complete.
- **Verification:** Ensure HAProxy health checks (from Phase 41) pass on the Green environment before shifting traffic.

### 43c — Automated Rollback Tooling
- Implement `ja4-admin.sh rollback` to instantly revert HAProxy to the Blue environment.
- Add "panic button" logic: automatic rollback if the error rate exceeds a threshold in the first 5 minutes of a deployment.

### 43d — Shared State Consistency
- Ensure that both Blue and Green environments share the same Redis persistence layer.
- Validate that signals generated in one environment are correctly interpreted by the other during the transition window.

## Acceptance Criteria

- [ ] New versions of the proxy can be deployed without dropping a single active TLS connection.
- [ ] Deployment script automatically validates health of new version before traffic shift.
- [ ] Rollback to previous container set completes in < 500ms at the HAProxy level.
- [ ] Comprehensive logs detailing the start, traffic shift, and cleanup of deployment environments.
