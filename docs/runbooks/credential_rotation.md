<!--
title: Credential Rotation
audience: Operators, Security Teams
last_reviewed: 2026-04-10
phase: 64e
-->

# Runbook: Credential Rotation

## Scope

This runbook covers zero-downtime rotation procedures for all credentials
used by JA4proxy and its supporting services. Each procedure follows the
same pattern: add the new credential alongside the old, verify, cut over,
then remove the old credential.

**Hot-reload signal target -- Go production only:**

```bash
# systemd-managed deployment
systemctl kill --signal=HUP ja4proxy.service

# Docker Compose deployment
docker kill --signal=HUP ja4proxy

# Kubernetes
kubectl exec -it <pod> -- kill -HUP 1

# Bare process (development only)
pkill -HUP -f bin/proxy
```

---

## 1. Redis Auth Password Rotation

### Overview

Redis password rotation uses Redis ACL to support two passwords simultaneously,
allowing a rolling update of all proxy nodes without any connection failures.

### Prerequisites

- Redis 6.0+ (ACL support required).
- Access to `redis-cli` on the Redis host or via `docker compose exec`.
- The new password generated and stored in a secrets manager before starting.

### Procedure

**Step 1 -- Add the new password alongside the old.**

Run on the Redis server (or via `docker compose exec redis`):

```bash
redis-cli ACL SETUSER default on >NEW_PASSWORD >OLD_PASSWORD ~* &* +@all
```

Both passwords are now valid. All existing proxy connections continue to
authenticate with the old password.

**Step 2 -- Verify dual-password state.**

```bash
# Test old password still works
redis-cli -a OLD_PASSWORD PING
# Expected: PONG

# Test new password works
redis-cli -a NEW_PASSWORD PING
# Expected: PONG
```

**Step 3 -- Update proxy configuration.**

Update the Redis password in `config/proxy.yml` (or the environment variable /
secret mount used by your deployment):

```yaml
redis:
  password: "NEW_PASSWORD"  # rotated [DATE]
```

**Step 4 -- Hot-reload all proxy nodes.**

Roll through each node, one at a time. Wait for the node to confirm
reconnection before moving to the next:

```bash
# Docker Compose -- reload each proxy service
docker kill --signal=HUP ja4proxy
```

For multi-node deployments:

```bash
# Kubernetes -- roll through pods
for pod in $(kubectl get pods -l app=ja4proxy -o name); do
  kubectl exec "$pod" -- kill -HUP 1
  sleep 5  # wait for reconnection
  kubectl exec "$pod" -- wget -qO- http://localhost:8090/api/v1/health/deep
done
```

**Step 5 -- Verify all nodes are using the new password.**

```bash
# Check proxy logs for successful Redis reconnection
docker compose logs --tail=20 ja4proxy | grep -i redis

# Confirm health endpoint reports healthy
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool

# Confirm no Redis auth errors in Prometheus
# ja4proxy_redis_operations_total{result="error"} should not be climbing
```

**Step 6 -- Remove the old password from Redis ACL.**

Once all nodes are confirmed on the new password, use the `<` prefix to
explicitly remove the old password:

```bash
redis-cli ACL SETUSER default on <OLD_PASSWORD ~* &* +@all
```

The old password is now invalid. (The `<` prefix removes a password from the
user's allowed password list, while `>` adds one.)

**Step 7 -- Final verification.**

```bash
# Old password should fail
redis-cli -a OLD_PASSWORD PING
# Expected: NOAUTH or ERR

# New password should succeed
redis-cli -a NEW_PASSWORD PING
# Expected: PONG

# Proxy health still green
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
```

### Rollback

If any proxy node fails to reconnect after hot-reload in Step 4:

1. **Immediately re-add the old password** to Redis ACL:
   ```bash
   redis-cli -a NEW_PASSWORD ACL SETUSER default on >NEW_PASSWORD >OLD_PASSWORD ~* &* +@all
   ```
2. Revert `config/proxy.yml` to the old password.
3. Hot-reload the failed node(s):
   ```bash
   docker kill --signal=HUP ja4proxy
   ```
4. Investigate the failure (typo in new password, config file syntax, etc.)
   before retrying the rotation.

If the failure occurs after Step 6 (old password already removed):

1. Re-add the old password:
   ```bash
   redis-cli -a NEW_PASSWORD ACL SETUSER default on >NEW_PASSWORD >OLD_PASSWORD ~* &* +@all
   ```
2. Revert config and hot-reload as above.

---

## 2. AbuseIPDB API Key Rotation

### Overview

AbuseIPDB API keys are used by the enrichment pipeline for IP reputation
lookups. The rotation is a simple swap: verify the new key works, update
config, hot-reload, confirm traffic is flowing, then revoke the old key.

### Prerequisites

- New AbuseIPDB API key generated from the AbuseIPDB dashboard.
- Access to modify `config/proxy.yml` or the environment variable / secret
  mount providing the key.

### Procedure

**Step 1 -- Verify the new API key works.**

```bash
curl -s -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: NEW_API_KEY" \
  -H "Accept: application/json" \
  | python3 -m json.tool
```

Confirm the response contains `"data"` with an `"abuseConfidenceScore"` field.
If you get a 401 or 429, the key is invalid or rate-limited -- do not proceed.

**Step 2 -- Update proxy configuration.**

```yaml
enrichment:
  abuseipdb:
    api_key: "NEW_API_KEY"  # rotated [DATE]
```

**Step 3 -- Hot-reload all proxy nodes.**

```bash
# Docker Compose
docker kill --signal=HUP ja4proxy

# systemd
systemctl kill --signal=HUP ja4proxy.service

# Kubernetes
kubectl exec -it <pod> -- kill -HUP 1
```

**Step 4 -- Verify lookups are succeeding with the new key.**

Monitor Prometheus and logs for 30 seconds:

```bash
# Confirm the AbuseIPDB enrichment queue is draining (not stuck at zero
# or climbing with no progress). The queue depth should fluctuate:
# ja4proxy_abuseipdb_enrichment_queue_depth
# ja4proxy_abuseipdb_queue_dropped_total should NOT be climbing

curl -sf http://localhost:9090/api/v1/query?query=ja4proxy_abuseipdb_enrichment_queue_depth \
  | python3 -m json.tool
```

Also check proxy logs for AbuseIPDB errors:

```bash
docker compose logs --tail=20 ja4proxy | grep -i abuseipdb
```

**Step 5 -- Revoke the old API key.**

After confirming 30 seconds of successful lookups with no errors:

1. Go to the AbuseIPDB dashboard.
2. Revoke/delete the old API key.

**Step 6 -- Final verification.**

```bash
# Confirm lookups continue working after old key revocation
# (the proxy is using the new key, so revoking the old should have no effect)
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
```

### Rollback

If lookups fail after hot-reload in Step 3:

1. Revert `config/proxy.yml` to the old API key.
2. Hot-reload:
   ```bash
   docker kill --signal=HUP ja4proxy
   ```
3. Confirm `ja4proxy_abuseipdb_queue_dropped_total` stops climbing and
   proxy logs show no AbuseIPDB errors.
4. Investigate the new key (wrong key copied, account issue, rate limit).

If the old key was already revoked (Step 5) and the new key stops working:

1. Generate a replacement key from the AbuseIPDB dashboard.
2. Update config and hot-reload as in Steps 2-3.
3. The enrichment pipeline fails open during the gap -- no traffic is blocked
   due to missing AbuseIPDB data.

---

## 3. Cloud Storage Credentials (S3/GCS -- Phase 57)

### Overview

Cloud storage credentials are used by the backup system (`src/backup/worker.py`,
`src/backup/restorer.py`) for Redis snapshot uploads. This is the Python backup
service, not the Go proxy binary. A brief restart of the backup container is
required; the proxy itself is unaffected.

### Prerequisites

- New IAM key (AWS) or service account key (GCS) generated and stored in
  a secrets manager.
- Access to modify the secret mount or environment variable used by the
  backup container.
- The backup container name (typically `backup` in Docker Compose).

### Procedure

**Step 1 -- Generate the new IAM / service account key.**

**AWS S3:**
```bash
aws iam create-access-key --user-name ja4proxy-backup
# Record AccessKeyId and SecretAccessKey
```

**GCS:**
```bash
gcloud iam service-accounts keys create new-key.json \
  --iam-account=ja4proxy-backup@PROJECT.iam.gserviceaccount.com
```

**Step 2 -- Update the secret.**

Update the environment variable, secret mount, or `.env` file used by the
backup container:

**AWS S3 (environment variables):**
```bash
# In .env or docker compose override file
AWS_ACCESS_KEY_ID=NEW_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=NEW_SECRET_KEY
```

**GCS (service account key file):**
```bash
# Replace the mounted key file
cp new-key.json config/gcs-backup-key.json
```

**Step 3 -- Restart the backup container.**

The backup service does not support hot-reload; a container restart is required.
This does not affect the proxy or live traffic.

```bash
docker compose restart backup
```

**Step 4 -- Verify the new credentials work.**

Trigger a manual backup and confirm it succeeds:

```bash
# Run a manual backup
docker compose exec backup python -m src.backup.worker --once

# Check logs for success
docker compose logs --tail=20 backup | grep -iE "upload|success|error"
```

For S3, verify the object was written:
```bash
aws s3 ls s3://BUCKET/ja4proxy-backups/ --recursive | tail -5
```

For GCS:
```bash
gsutil ls gs://BUCKET/ja4proxy-backups/ | tail -5
```

**Step 5 -- Delete the old IAM / service account key.**

Only after Step 4 confirms the new credentials work:

**AWS S3:**
```bash
aws iam delete-access-key --user-name ja4proxy-backup \
  --access-key-id OLD_ACCESS_KEY_ID
```

**GCS:**
```bash
gcloud iam service-accounts keys delete OLD_KEY_ID \
  --iam-account=ja4proxy-backup@PROJECT.iam.gserviceaccount.com
```

**Step 6 -- Final verification.**

```bash
# Run one more backup to confirm the old key deletion didn't break anything
docker compose exec backup python -m src.backup.worker --once

# Check backup container health
docker compose ps backup
```

### Rollback

If the manual backup fails in Step 4:

1. Revert the secret/environment variable to the old credentials.
2. Restart the backup container:
   ```bash
   docker compose restart backup
   ```
3. Verify the old credentials still work:
   ```bash
   docker compose exec backup python -m src.backup.worker --once
   ```
4. Investigate the new key (wrong permissions, wrong bucket, IAM policy issue).

If the old key was already deleted (Step 5) and the new key fails:

1. Generate a replacement key immediately (Steps 1-2 of the procedure).
2. Restart the backup container.
3. The proxy is unaffected -- only scheduled backups are interrupted during the gap.

---

## Rotation Schedule

| Credential | Recommended interval | Mandatory maximum |
|---|---|---|
| Redis password | Every 90 days | 180 days |
| AbuseIPDB API key | Every 90 days | 365 days (per provider policy) |
| Cloud storage IAM key | Every 90 days | 90 days (AWS best practice) |

Track rotation dates in your secrets manager or a shared calendar.
