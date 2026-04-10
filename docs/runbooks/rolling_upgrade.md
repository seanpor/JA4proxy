<!--
title: Rolling Upgrade
audience: DevOps, SRE Teams
last_reviewed: 2026-04-10
phase: 64
-->

# Runbook: Rolling Upgrade

> **Audience:** DevOps, SRE Teams
> **Scope:** Upgrading JA4proxy instances with zero downtime
> **Trigger:** New proxy version, security patch, or configuration change requiring binary restart.

---

## 1. Prerequisites

Before starting a rolling upgrade, verify the following:

- **HAProxy health checks are configured** with appropriate intervals:
  ```
  server ja4proxy-1 ja4proxy-1:8080 check inter 2s rise 2 fall 2
  server ja4proxy-2 ja4proxy-2:8080 check inter 2s rise 2 fall 2
  ```
  HAProxy must detect a downed node within ~4 seconds (`fall 2` x `inter 2s`)
  and mark a recovered node healthy within ~4 seconds (`rise 2` x `inter 2s`).

- **At least 2 proxy instances** are running behind the load balancer.
  A single-instance deployment cannot do a rolling upgrade without downtime.

- **Smoke tests pass in staging** before touching production:
  ```bash
  make smoke-docker
  ```

- **New image or binary is available and tested.** For Docker deployments, the
  new image tag should already be pulled or available in the registry. For bare
  metal, the new binary should be staged on disk.

- **HAProxy admin socket access** (optional but recommended). Graceful
  drain/re-enable requires `socat` in the HAProxy container and the admin
  socket at `/var/run/haproxy/admin.sock`. Verify:
  ```bash
  docker compose exec haproxy which socat
  docker compose exec haproxy ls /var/run/haproxy/admin.sock
  ```
  If either command fails, you cannot drain or re-enable nodes gracefully via
  the admin socket. Fall back to waiting for HAProxy health checks to
  automatically detect the node going down and coming back up. The procedure
  still works -- it just relies on the `fall`/`rise` timers instead of
  explicit drain commands.

---

## 2. Docker Compose Rolling Upgrade

Upgrade one node at a time with a 30-second stagger between nodes. This
ensures at least one healthy instance is always serving traffic.

### Step 1: Check current version

```bash
docker compose exec ja4proxy-1 /app/bin/proxy --version
```

Record the current version for rollback reference.

### Step 2: Drain node from HAProxy (if admin socket available)

```bash
echo "disable server backend/ja4proxy-1" | socat stdio /var/run/haproxy/admin.sock
```

This puts the node into MAINT mode. HAProxy stops sending new connections but
allows existing connections to complete.

If the admin socket is not available, skip this step -- HAProxy health checks
will detect the node going down after `fall` x `inter` seconds.

### Step 3: Wait for active connections to drain

```bash
sleep 30
```

30 seconds is sufficient for most TLS connections to complete. Adjust if your
traffic profile includes long-lived connections.

### Step 4: Recreate the service with the new image

```bash
docker compose up -d --no-deps --force-recreate ja4proxy-1
```

The `--no-deps` flag prevents dependent services from being recreated.
The `--force-recreate` flag ensures the container is replaced even if the
compose file has not changed (useful when only the image tag changed).

To use a specific image tag, update the `image:` field in your compose file
or override via environment variable before running the command.

### Step 5: Wait for health

```bash
curl -sf http://localhost:8090/api/v1/health/deep
```

Retry until the deep health check returns 200. This confirms the proxy has
started, connected to Redis, and loaded its configuration.

### Step 6: Re-enable in HAProxy

```bash
echo "enable server backend/ja4proxy-1" | socat stdio /var/run/haproxy/admin.sock
```

If the admin socket is not available, HAProxy health checks will
automatically mark the node as healthy after `rise` x `inter` seconds.

### Step 7: Repeat for remaining nodes

Wait 30 seconds, then repeat steps 2-6 for `ja4proxy-2` (and any additional
instances). The stagger ensures at least one node is always healthy and
serving traffic.

```bash
# Example for second node:
echo "disable server backend/ja4proxy-2" | socat stdio /var/run/haproxy/admin.sock
sleep 30
docker compose up -d --no-deps --force-recreate ja4proxy-2
# Wait for health...
curl -sf http://localhost:8090/api/v1/health/deep
echo "enable server backend/ja4proxy-2" | socat stdio /var/run/haproxy/admin.sock
```

---

## 3. Kubernetes Rolling Upgrade

Kubernetes handles rolling upgrades natively through Deployment or DaemonSet
update strategies.

### Deployment

Trigger the upgrade by updating the image tag:

```bash
helm upgrade ja4proxy deploy/helm/ja4proxy/ --set image.tag=NEW_TAG --wait
```

The `--wait` flag blocks until all pods are ready, so the command exits only
when the rollout is complete.

Monitor progress:

```bash
kubectl rollout status deployment/ja4proxy
```

Verify all pods are running the new version:

```bash
kubectl get pods -l app=ja4proxy -o wide
```

### DaemonSet

For DaemonSet deployments (one proxy per node), set `maxUnavailable: 1` in
the update strategy to ensure only one node is upgraded at a time:

```yaml
# In values.yaml or deploy/helm/ja4proxy/templates/daemonset.yaml
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1
```

Then trigger the upgrade the same way:

```bash
helm upgrade ja4proxy deploy/helm/ja4proxy/ --set image.tag=NEW_TAG --wait
kubectl rollout status daemonset/ja4proxy
```

Verify:

```bash
kubectl get pods -l app=ja4proxy -o wide
```

---

## 4. Rollback

If the new version exhibits errors, roll back immediately.

### Docker Compose rollback

Recreate the affected node(s) with the previous image tag. Update the image
reference in your compose file (or override via environment variable), then
recreate:

```bash
# Option A: edit docker-compose.yml to restore the previous image tag, then:
docker compose up -d --no-deps --force-recreate ja4proxy-1

# Option B: override via environment variable (if your compose file uses ${JA4PROXY_IMAGE:-...}):
JA4PROXY_IMAGE="ghcr.io/org/ja4proxy:PREVIOUS_TAG" docker compose up -d --no-deps --force-recreate ja4proxy-1
```

Then re-enable in HAProxy if previously drained:

```bash
echo "enable server backend/ja4proxy-1" | socat stdio /var/run/haproxy/admin.sock
```

Repeat for each node that was upgraded.

### Kubernetes rollback

Roll back the entire deployment or daemonset with a single command:

```bash
kubectl rollout undo deployment/ja4proxy
```

Or for DaemonSet:

```bash
kubectl rollout undo daemonset/ja4proxy
```

Monitor rollback progress:

```bash
kubectl rollout status deployment/ja4proxy
```
