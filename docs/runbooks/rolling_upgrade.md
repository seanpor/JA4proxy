<!--
title: "rolling upgrade Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Rolling Upgrade

> **Scope:** Zero-downtime upgrade of JA4proxy across Docker Compose and
> Kubernetes deployments. Each node is upgraded one at a time while HAProxy
> or Kubernetes routes traffic to healthy nodes.
>
> **Audience:** SREs, Operations Engineers
>
> **Last updated:** 2026-04-10 (Phase 64g)

---

## 1. Prerequisites

Before performing a rolling upgrade:

1. **HAProxy health checks are configured** with the following parameters:
   ```
   option httpchk GET /api/v1/health/deep
   http-check expect status 200
   default-server inter 2s rise 2 fall 2
   ```
   - `inter 2s`: Health check every 2 seconds
   - `rise 2`: Mark UP after 2 consecutive successful checks (4 seconds)
   - `fall 2`: Mark DOWN after 2 consecutive failed checks (4 seconds)

2. **At least 2 proxy instances** are running (one to upgrade, one to
   serve traffic).

3. **Smoke test passes** in the staging environment:
   ```bash
   bash scripts/smoke/test_docker_compose.sh
   ```

4. **New image is built and tagged:**

   > **Note:** The Go proxy is built via `make go-build` (produces `bin/proxy`).
   > The Docker image is built using the project's `Dockerfile` with the
   > `--target go-proxy` build stage (or your CI's equivalent).

   ```bash
   # Build Go binary
   make go-build

   # Build Docker image (adjust Dockerfile path for your deployment)
   docker build -t ghcr.io/org/ja4proxy:NEW_TAG \
     --target go-proxy \
     -f Dockerfile .
   docker push ghcr.io/org/ja4proxy:NEW_TAG
   ```

5. **Verify HAProxy `socat` is available** (needed for drain/re-enable):
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy which socat
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy ls /var/run/haproxy/admin.sock
   ```
   If `socat` is not available, the Docker Compose path cannot drain backends
   gracefully. Fall back to waiting for health checks to re-route traffic.

---

## 2. Docker Compose rolling upgrade

This procedure upgrades one proxy instance at a time with a 30-second
stagger between nodes. Traffic is drained from the old instance before
it is replaced.

### For each node (repeat for ja4proxy-1, ja4proxy-2, ...):

1. **Drain the backend via HAProxy admin socket:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
     bash -c 'echo "set server ja4proxy/ja4proxy-1 state drain" \
       | socat stdio unix-connect:/var/run/haproxy/admin.sock'
   ```
   This stops new connections from being routed to this node while
   existing connections complete.

2. **Wait for active connections to drain** (check HAProxy stats):
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
     bash -c 'echo "show stat" \
       | socat stdio unix-connect:/var/run/haproxy/admin.sock' \
       | grep ja4proxy-1 | cut -d, -f1,2,5,6,33
   # Wait until active sessions (field 33) reaches 0
   ```

3. **Stop the old instance:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml stop ja4proxy-1
   ```

4. **Recreate with the new image:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml up -d --no-deps \
     ja4proxy-1 \
     --image "ghcr.io/org/ja4proxy:NEW_TAG"
   ```

5. **Wait for the health check to pass:**
   ```bash
   for i in $(seq 1 30); do
     STATUS=$(docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
       bash -c 'echo "show stat" \
         | socat stdio unix-connect:/var/run/haproxy/admin.sock' \
       | grep "ja4proxy-1" | cut -d, -f18)
     [ "$STATUS" = "UP" ] && echo "Node ja4proxy-1 UP after ${i}s" && break
     sleep 1
   done
   ```

6. **Verify the node is healthy:**
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

7. **Wait 30 seconds** before moving to the next node. This stagger
   prevents multiple nodes from upgrading simultaneously and gives time
   to detect issues before they affect the entire fleet.

---

## 3. Kubernetes rolling upgrade

This procedure uses Helm's rolling update with readiness probes to
ensure zero-downtime upgrades.

### Prerequisites:

1. **Readiness probe is configured** in the Helm chart:
   ```yaml
   readinessProbe:
     httpGet:
       path: /api/v1/health/deep
       port: 8090
     initialDelaySeconds: 5
     periodSeconds: 5
     failureThreshold: 3
   ```

2. **Rolling update strategy is set:**
   ```yaml
   strategy:
     rollingUpdate:
       maxSurge: 1
       maxUnavailable: 0  # For DaemonSet: maxUnavailable: 1
     type: RollingUpdate
   ```

### Procedure:

1. **Upgrade with Helm:**
   ```bash
   helm upgrade ja4proxy deploy/helm/ja4proxy/ \
     --set image.tag=NEW_TAG \
     --wait --timeout=300s
   ```

2. **Monitor the rollout:**
   ```bash
   kubectl rollout status deployment/ja4proxy --timeout=300s
   # Or for DaemonSet:
   # kubectl rollout status daemonset/ja4proxy --timeout=300s
   ```

3. **Verify all pods are running the new image:**
   ```bash
   kubectl get pods -l app=ja4proxy \
     -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.containers[0].image}{"\n"}{end}'
   # All pods should show ghcr.io/org/ja4proxy:NEW_TAG
   ```

4. **Verify the health endpoint:**
   ```bash
   POD=$(kubectl get pods -l app=ja4proxy -o jsonpath='{.items[0].metadata.name}')
   kubectl exec "$POD" -- \
     wget -qO- http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

---

## 4. Rollback

If the upgrade causes issues (increased error rate, health check failures,
security decision anomalies), roll back immediately.

### Docker Compose rollback:

1. **Drain the upgraded backend** (same as step 1 in the upgrade procedure):
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
     bash -c 'echo "set server ja4proxy/ja4proxy-1 state drain" \
       | socat stdio unix-connect:/var/run/haproxy/admin.sock'
   ```

2. **Recreate with the previous image:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml up -d --no-deps \
     ja4proxy-1 \
     --image "ghcr.io/org/ja4proxy:PREVIOUS_TAG"
   ```

3. **Wait for the backend to return UP** (same as upgrade step 5):
   ```bash
   for i in $(seq 1 30); do
     STATUS=$(docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
       bash -c 'echo "show stat" \
         | socat stdio unix-connect:/var/run/haproxy/admin.sock' \
       | grep "ja4proxy-1" | cut -d, -f18)
     [ "$STATUS" = "UP" ] && echo "Node ja4proxy-1 rolled back, UP after ${i}s" && break
     sleep 1
   done
   ```

4. **Verify the health endpoint:**
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

5. **Re-enable the backend via HAProxy admin socket:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
     bash -c 'echo "set server ja4proxy/ja4proxy-1 state ready" \
       | socat stdio unix-connect:/var/run/haproxy/admin.sock'
   ```

### Kubernetes rollback:

1. **Undo the rollout** (Kubernetes keeps the previous ReplicaSet):
   ```bash
   # For Deployment:
   kubectl rollout undo deployment/ja4proxy

   # For DaemonSet:
   kubectl rollout undo daemonset/ja4proxy
   ```

2. **Monitor the rollback:**
   ```bash
   kubectl rollout status deployment/ja4proxy --timeout=300s
   ```

3. **Verify all pods are running the previous image:**
   ```bash
   kubectl get pods -l app=ja4proxy \
     -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.containers[0].image}{"\n"}{end}'
   ```

4. **Verify the health endpoint:**
   ```bash
   POD=$(kubectl get pods -l app=ja4proxy -o jsonpath='{.items[0].metadata.name}')
   kubectl exec "$POD" -- \
     wget -qO- http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

---

## Rollback Decision Criteria

Roll back immediately (do not troubleshoot first) if:

| Metric | Threshold | Source |
|--------|-----------|--------|
| 5xx error rate | > 1% of requests over 1 minute | HAProxy stats / Prometheus |
| Health check failures | Any pod/instance marked DOWN for > 30s | HAProxy stats / K8s events |
| Block rate anomaly | Block rate changes > 50% from baseline | Grafana `ja4proxy_blocks_total` |
| Redis connection errors | Any new errors after upgrade | Prometheus `ja4proxy_redis_errors_total` |
| Latency P99 | > 2× baseline | Grafana SLO dashboard |

If any of these thresholds are breached, **roll back first, investigate later.**
The rollback procedure takes < 2 minutes per node — significantly faster
than debugging an active production issue.
