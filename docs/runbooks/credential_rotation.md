<!--
title: "credenTIal rotaTIon Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Credential Rotation

> **Scope:** Zero-downtime rotation of Redis auth, AbuseIPDB API key,
> and cloud storage credentials.
>
> **Audience:** Operators, Security Engineers
>
> **Last updated:** 2026-04-10 (Phase 64e)

---

## 1. Redis auth password rotation

**Type:** Redis ACL password for the `default` user.
**Impact if leaked:** Full read/write access to all Redis data including
ban state, rate limit counters, and dial values.
**Rotation frequency:** Every 90 days (or immediately on suspected compromise).

### Procedure

This rotation is **zero-downtime**. The new password is added alongside
the old one, all nodes are updated, then the old password is removed.

1. **Generate a new password:**
   ```bash
   NEW_PASSWORD=$(openssl rand -base64 32)
   echo "$NEW_PASSWORD" > /tmp/redis-new-password.txt
   chmod 600 /tmp/redis-new-password.txt
   ```

   > **Compliance note (SOC 2 / ISO 27001):** Generated passwords must have
   > ≥ 128 bits of entropy. `openssl rand -base64 32` provides 256 bits. Never
   > use manually created passwords with fewer than 20 random characters. Do not
   > store generated passwords in plain text beyond the rotation window.

2. **Add the new password to Redis ACL (alongside the old):**
   ```bash
   OLD_PASSWORD=$(grep REDIS_PASSWORD .env | cut -d= -f2)
   redis-cli -a "$OLD_PASSWORD" ACL SETUSER default on \
     ">$NEW_PASSWORD" ">$OLD_PASSWORD" \
     '~*' '&*' '+@all'
   ```

3. **Update the proxy config** with the new password:
   - Edit `.env` or your deployment's secret store:
     ```
     REDIS_PASSWORD=<value from /tmp/redis-new-password.txt>
     ```
   - If using Kubernetes, update the Secret:
     ```bash
     kubectl create secret generic ja4proxy-redis \
       --from-literal=password="$NEW_PASSWORD" \
       --dry-run=client -o yaml | kubectl apply -f -
     ```

4. **Hot-reload all proxy nodes** to pick up the new password:
   ```bash
   # Docker Compose
   docker kill --signal=HUP ja4proxy

   # Kubernetes
   kubectl exec ja4proxy-xxxxx -- kill -HUP 1

   # systemd
   systemctl kill --signal=HUP ja4proxy.service
   ```

5. **Verify all nodes reconnected with the new password:**
   ```bash
   # Check proxy logs for successful Redis connection
   docker compose -f docker/docker-compose.poc.yml logs --tail=10 ja4proxy \
     | grep -i "redis.*connect"

   # Verify Redis auth with new password
   redis-cli -a "$NEW_PASSWORD" PING
   # Should return PONG

   # Verify old password still works (dual-auth period)
   redis-cli -a "$OLD_PASSWORD" PING
   # Should also return PONG
   ```

6. **Wait 30 seconds** for any in-flight connections to complete, then
   **drop the old password:**
   ```bash
   redis-cli -a "$NEW_PASSWORD" ACL SETUSER default on \
     ">$NEW_PASSWORD" \
     '~*' '&*' '+@all'
   ```

7. **Verify old password no longer works:**
   ```bash
   redis-cli -a "$OLD_PASSWORD" PING
   # Should return: NOAUTH Authentication required
   ```

8. **Securely delete the temporary password file:**
   ```bash
   shred -u /tmp/redis-new-password.txt
   ```

### Rollback

If hot-reload fails (proxy nodes cannot reconnect with the new password):

1. **Re-add the old password immediately:**
   ```bash
   redis-cli -a "$NEW_PASSWORD" ACL SETUSER default on \
     ">$NEW_PASSWORD" ">$OLD_PASSWORD" \
     '~*' '&*' '+@all'
   ```
2. **Revert the proxy config** to the old password.
3. **Hot-reload all proxy nodes** again.
4. Investigate why the new password was rejected.

---

## 2. AbuseIPDB API key rotation

**Type:** AbuseIPDB v2 API key.
**Impact if leaked:** Quota consumption, potential account suspension.
**Rotation frequency:** Every 90 days (or immediately on suspected compromise).

### Procedure

1. **Generate a new key** in the AbuseIPDB dashboard:
   - Log in to https://www.abuseipdb.com/account/api
   - Click "Create New Key" (the old key remains active until revoked)
   - Copy the new key: `NEW_API_KEY="..."`

2. **Verify the new key works:**
   ```bash
   curl -sS "https://api.abuseipdb.com/api/v2/check" \
     -H "Key: $NEW_API_KEY" \
     -H "Accept: application/json" \
     -d "ipAddress=8.8.8.8" \
     | python3 -m json.tool
   # Expected: 200 OK with abuseConfidenceScore
   ```

3. **Update the proxy config:**
   - Edit `.env` or your secret store:
     ```
     ABUSEIPDB_API_KEY=<new key>
     ```

4. **Hot-reload all proxy nodes:**
   ```bash
   docker kill --signal=HUP ja4proxy
   ```

5. **Verify the proxy is using the new key:**
   ```bash
   # Check Prometheus metrics for successful lookups
   curl -sf http://localhost:9090/metrics \
     | grep 'ja4proxy_abuseipdb_lookups_total{result="hit"}'
   # Should show increasing counter
   ```

6. **Wait 30 seconds**, then **revoke the old key** in the AbuseIPDB dashboard.

### Rollback

If the new key fails verification (step 2):

1. **Revert the proxy config** to the old API key.
2. **Hot-reload all proxy nodes.**
3. Contact AbuseIPDB support to investigate the new key failure.

---

## 3. Cloud storage credentials (Phase 57 backup system)

**Type:** IAM access key + secret key for S3/GCS backup storage.
**Impact if leaked:** Unauthorized access to backup archives (ban state,
rate limit data, config snapshots).
**Rotation frequency:** Every 90 days (or per your cloud provider's policy).

### Procedure

This procedure assumes Phase 57's backup system is configured with cloud
storage (S3 or GCS) for backup archives.

1. **Create a new IAM access key** (AWS) or service account key (GCS):

   **AWS:**
   ```bash
   aws iam create-access-key --user-name ja4proxy-backup \
     | python3 -c "import sys,json; d=json.load(sys.stdin)['AccessKey']; \
       print(f'AWS_ACCESS_KEY_ID={d[\"AccessKeyId\"]}'); \
       print(f'AWS_SECRET_ACCESS_KEY={d[\"SecretAccessKey\"]}')"
   ```

   **GCS:**
   ```bash
   gcloud iam service-accounts keys create /tmp/ja4proxy-backup-key.json \
     --iam-account=ja4proxy-backup@PROJECT.iam.gserviceaccount.com
   ```

2. **Update the backup config** with the new credentials:
   - Edit `config/proxy.yml` or `.env`:
     ```yaml
     backup:
       storage: s3  # or gcs
       bucket: ja4proxy-backups
       credentials:
         access_key_id: <new key>
         secret_access_key: <new secret>
     ```

3. **Restart the backup worker** (not the proxy — the backup is a separate process):
   ```bash
   # Docker Compose
   docker compose -f docker/docker-compose.poc.yml restart backup-worker

   # systemd
   systemctl restart ja4proxy-backup
   ```

4. **Verify a manual backup works** with the new credentials:
   ```bash
   # Trigger a backup (method depends on your Phase 57 implementation)
   # Verify the backup appears in the bucket
   aws s3 ls s3://ja4proxy-backups/ --profile ja4proxy-backup
   ```

5. **Delete the old IAM key** after verifying the backup succeeds:
   ```bash
   aws iam delete-access-key \
     --user-name ja4proxy-backup \
     --access-key-id <OLD_KEY_ID>
   ```

6. **Securely delete any temporary key files:**
   ```bash
   shred -u /tmp/ja4proxy-backup-key.json  # GCS only
   ```

### Rollback

If the backup verification fails (step 4):

1. **Revert the backup config** to the old credentials.
2. **Restart the backup worker.**
3. Verify the backup works with the old credentials.
4. Investigate why the new credentials were rejected (IAM policy, bucket
   permissions, region mismatch).

---

## Rotation Schedule Summary

| Credential | Frequency | Owner | Zero-downtime? |
|---|---|---|---|
| Redis ACL password | 90 days | SRE | Yes — dual-auth period |
| AbuseIPDB API key | 90 days | Security Engineer | Yes — new key created before old revoked |
| Cloud storage IAM key | 90 days | Cloud Engineer | Yes — restart backup worker only |
| TLS server certificate | Per cert expiry (see [TLS Certificate Rotation](tls_certificate_rotation.md)) | SRE | Yes — rolling SIGHUP |
| mTLS CA certificate | Per CA expiry (see [TLS Certificate Rotation](tls_certificate_rotation.md)) | Security Engineer | Yes — dual-CA trust period |
