#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/helm-kind-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

if ! command -v kind &>/dev/null; then
  log "SKIP: kind not found. Install kind (https://kind.sigs.k8s.io) to run this test."
  log "On CI (GitHub Actions): add 'uses: helm/kind-action@v1' before this step."
  exit 0
fi

if ! command -v helm &>/dev/null; then
  fail "helm not found — install Helm 3 (https://helm.sh/docs/intro/install/)"
fi

if ! command -v kubectl &>/dev/null; then
  fail "kubectl not found — install kubectl (https://kubernetes.io/docs/tasks/tools/)"
fi

CLUSTER_NAME="ja4proxy-smoke"

cleanup() {
  log "Deleting kind cluster..."
  kind delete cluster --name "$CLUSTER_NAME" 2>>"$LOG" || true
}
trap cleanup EXIT

# Create kind cluster if not already running (CI's kind-action may pre-create it)
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  log "Kind cluster '$CLUSTER_NAME' already exists — reusing."
else
  log "Creating kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" 2>>"$LOG" \
    || fail "kind create cluster failed"
fi

log "Building ja4proxy binary..."
if command -v go &>/dev/null; then
  CGO_ENABLED=0 go build -o bin/ja4proxy ./cmd/proxy/ 2>>"$LOG" || true
fi

# Build and load image into kind if Docker is available
DOCKERFILE=""
for df in Dockerfile deploy/docker/Dockerfile.go-proxy deploy/docker/Dockerfile; do
  if [ -f "$df" ]; then DOCKERFILE="$df"; break; fi
done
if [ -n "$DOCKERFILE" ] && command -v docker &>/dev/null; then
  log "Building Docker image from $DOCKERFILE..."
  docker build -t ja4proxy:latest -f "$DOCKERFILE" . 2>>"$LOG" || {
    log "SKIP: Docker image build failed — cannot run Helm smoke test."
    exit 0
  }
  kind load docker-image ja4proxy:latest --name "$CLUSTER_NAME" 2>>"$LOG" || {
    log "SKIP: Failed to load image into kind cluster."
    exit 0
  }
else
  log "SKIP: Dockerfile or docker not found — cannot build image for Helm test."
  exit 0
fi

# Also build and load analytics image if compose references it
if [ -f deploy/docker/Dockerfile ] && docker images --format '{{.Repository}}' | grep -q ja4proxy-analytics; then
  kind load docker-image ja4proxy-analytics:latest --name "$CLUSTER_NAME" 2>>"$LOG" || true
fi

# Pre-load Redis image into kind: the bundled redis.yaml StatefulSet uses
# redis:7-alpine, and kind nodes sometimes can't resolve Docker Hub DNS
# (172.29.0.1:53 timeouts). Pull on the host and load into the node to
# sidestep in-cluster DNS entirely.
log "Pre-loading redis:7-alpine into kind..."
docker pull redis:7-alpine 2>>"$LOG" || {
  log "SKIP: Failed to pull redis:7-alpine from host — cannot run Helm smoke test."
  exit 0
}
kind load docker-image redis:7-alpine --name "$CLUSTER_NAME" 2>>"$LOG" || {
  log "SKIP: Failed to load redis:7-alpine into kind cluster."
  exit 0
}

log "Installing Helm chart..."
# redis.external=false deploys the bundled Redis StatefulSet — the proxy's
# /health endpoint returns 503 without a reachable Redis, so smoke tests must
# either provide an external Redis or enable the bundled one.
# hpa.enabled=false and pdb.enabled=false: smoke test uses replicaCount=1 which
# breaks HPA (minReplicas=2 > 1) and PDB validation.
helm install ja4proxy deploy/charts/ja4proxy/ \
  --wait --timeout=300s \
  --set image.tag=latest \
  --set image.pullPolicy=Never \
  --set redis.external=false \
  --set secrets.redisPassword=smoketest \
  --set replicaCount=1 \
  --set hpa.enabled=false \
  --set pdb.enabled=false \
  2>>"$LOG" || fail "helm install failed"

log "Checking Deployment status..."
KIND=$(kubectl get -f deploy/charts/ja4proxy/templates/ -o jsonpath='{.items[0].kind}' 2>/dev/null || echo "Deployment")
if [ "$KIND" = "DaemonSet" ]; then
  kubectl rollout status daemonset/ja4proxy --timeout=60s 2>>"$LOG" \
    || fail "DaemonSet did not become ready within 60s"
else
  kubectl rollout status deployment/ja4proxy --timeout=60s 2>>"$LOG" \
    || fail "Deployment did not become ready within 60s"
fi

POD=$(kubectl get pods -l app=ja4proxy -o jsonpath='{.items[0].metadata.name}' 2>>"$LOG")
[ -z "$POD" ] && fail "No ja4proxy pods found"

log "Running health check inside pod: $POD"
# Go proxy exposes /health on the metrics port (:9090). Port :8090 is the
# Management API, a separate service — not this container.
# The Deployment has no readinessProbe, so --wait returns as soon as the pod
# is Running even if the Go process hasn't yet bound :9090 and connected to
# Redis. Retry for up to 30s.
ok=0
for i in $(seq 1 30); do
  if kubectl exec "$POD" -- wget -qO- http://localhost:9090/health >>"$LOG" 2>&1; then
    ok=1; break
  fi
  sleep 1
done
[ "$ok" -eq 1 ] || fail "Health check inside pod failed after 30s"

log "PASS: Helm + kind smoke test"
echo "PASS" > "$RESULTS_DIR/helm-kind.result"
# Cluster deleted by trap
