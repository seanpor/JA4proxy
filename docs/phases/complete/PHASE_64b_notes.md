# Phase 64b — Helm + Kind Smoke Test Notes

## Environment

- **Host:** $(hostname)
- **kind version:** $(kind version 2>/dev/null || echo "not installed")
- **Helm version:** $(helm version --short 2>/dev/null || echo "not installed")
- **kubectl version:** $(kubectl version --client --short 2>/dev/null || echo "not installed")
- **Chart path:** deploy/helm/ja4proxy/

## Artifacts Created

| File | Purpose |
|------|---------|
| `scripts/smoke/test_helm_kind.sh` | Helm + kind smoke test script |
| `Makefile` target `smoke-k8s` | Makefile entry point |

## Shellcheck Result

- `shellcheck scripts/smoke/test_helm_kind.sh` — **PASS** (zero findings)

## Acceptance Checklist

- [x] Script skips cleanly (exit 0, no error) when `kind` is absent
- [x] Script fails (non-zero) when `helm` is missing but `kind` is present
- [x] Creates single-node kind cluster named `ja4proxy-smoke`
- [x] Installs Helm chart with `--wait --timeout=120s`
- [x] Checks rollout status (handles both Deployment and DaemonSet)
- [x] Runs in-pod health check via `kubectl exec`
- [x] Writes `PASS` to `test-results/smoke/helm-kind.result` on success
- [x] Cluster deleted by trap on exit (clean or error)
- [x] Uses `docker compose` (v2) — no references to v1
- [x] Tries alternate label selector (`app.kubernetes.io/name`) if `app` not found

## Out of Scope

- Helm chart modifications (if chart needs fixing, file Phase 101 entry)
- Podman/Quadlet smoke test (no Quadlet artifacts exist)
- Docker Compose smoke test (Phase 64a)
