<!--
title: "tls cerTIficate rotaTIon Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# TLS Certificate Rotation

> **Scope:** Server-side TLS certificate and mTLS CA certificate rotation.
> Both procedures are zero-downtime (rolling SIGHUP reload).
>
> **Audience:** SREs, Security Engineers
>
> **Last updated:** 2026-04-10 (Phase 64f)
>
> **Monitoring:** The proxy exposes `ja4proxy_tls_cert_expiry_timestamp_seconds`
> (Phase 63 gauge). Alert rules in `monitoring/alertmanager/rules/tls_alerts.yml`
> fire at < 30 days (warning) and < 7 days (critical).

---

## 1. Certificate expiry monitoring

The proxy exposes a gauge metric that reports the **Unix timestamp** of the
server-side TLS certificate's expiry:

```
ja4proxy_tls_cert_expiry_timestamp_seconds 1776009600
```

Alert rules consume this gauge directly — no `absent_over_time` guard is
needed because the gauge is set at proxy startup and updated on each
hot-reload.

**PromQL queries:**

Days until expiry:
```promql
(ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400
```

Is the certificate expiring within 30 days?
```promql
(ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400 < 30
```

**Grafana dashboard:** Add a single-stat panel with the above query
formatted as `{{ $value | humanize }}d` for at-a-glance expiry tracking.

---

## 2. Server-side TLS certificate rotation

**Type:** Server certificate presented to clients during TLS handshake.
**Impact if expired:** TLS handshake failures for all clients. **Complete
outage** — no traffic passes.
**Rotation frequency:** Before expiry (alert at 30 days, critical at 7 days).

### Procedure

This rotation is **zero-downtime** — one node at a time with SIGHUP reload.

1. **Generate or obtain the new certificate:**
   ```bash
   # Example: Let's Encrypt (Certbot)
   certbot certonly --standalone -d ja4proxy.example.com \
     --agree-tos --email admin@example.com \
     --cert-name ja4proxy
   # Certificate: /etc/letsencrypt/live/ja4proxy.example.com/fullchain.pem
   # Private key: /etc/letsencrypt/live/ja4proxy.example.com/privkey.pem
   ```

2. **Place the certificate where the proxy can read it:**
   ```bash
   # Docker Compose — copy to host mount point
   cp /etc/letsencrypt/live/ja4proxy.example.com/fullchain.pem \
     config/certs/server.crt
   cp /etc/letsencrypt/live/ja4proxy.example.com/privkey.pem \
     config/certs/server.key
   chmod 644 config/certs/server.crt
   chmod 600 config/certs/server.key
   ```

3. **Hot-reload the proxy to pick up the new certificate:**
   ```bash
   # Docker Compose
   docker kill --signal=HUP ja4proxy

   # Kubernetes
   kubectl exec ja4proxy-xxxxx -- kill -HUP 1

   # systemd
   systemctl kill --signal=HUP ja4proxy.service
   ```

4. **Verify the new certificate is served:**
   ```bash
   openssl s_client -connect localhost:8080 -servername ja4proxy.example.com \
     </dev/null 2>/dev/null \
     | openssl x509 -noout -dates -subject
   # Expected: new notBefore/notAfter dates, correct subject
   ```

5. **Verify the expiry gauge updated in Prometheus:**
   ```bash
   curl -sf http://localhost:9090/api/v1/query \
     --data-urlencode 'query=ja4proxy_tls_cert_expiry_timestamp_seconds' \
     | python3 -c "import sys,json; \
       d=json.load(sys.stdin)['data']['result'][0]['value'][1]; \
       from datetime import datetime; \
       print(f'New expiry timestamp: {d} = {datetime.utcfromtimestamp(float(d))}')"
   ```

6. **For multi-node deployments**, repeat steps 2-3 for each node with a
   30-second stagger between nodes.

### Rollback

If the new certificate fails to load (proxy logs show TLS init error):

1. **Restore the old certificate:**
   ```bash
   git checkout HEAD -- config/certs/server.crt config/certs/server.key
   ```
2. **Hot-reload the proxy:**
   ```bash
   docker kill --signal=HUP ja4proxy
   ```
3. Verify the old certificate is served again (step 4 above).
4. Investigate why the new certificate was rejected (format, permissions,
   chain order, CN/SAN mismatch).

---

## 3. mTLS CA certificate rotation

**Type:** Certificate Authority certificate used to verify client certificates
during mutual TLS handshakes.
**Impact if expired:** All client mTLS handshakes fail. **Complete outage**
for mTLS clients.
**Rotation frequency:** Before CA expiry (typically multi-year CA validity).

### Procedure

mTLS CA rotation requires a **dual-CA trust period** where both the old and
new CA certificates are trusted simultaneously. This allows clients to
migrate gradually.

**Phase 1 — Create combined trust bundle (zero-downtime):**

1. Concatenate the old and new CA certificates into the trust bundle:
   ```bash
   cat config/certs/old-ca.crt config/certs/new-ca.crt \
     > config/certs/ca-bundle.pem
   chmod 644 config/certs/ca-bundle.pem
   ```

2. **Hot-reload the proxy** to pick up the combined trust bundle:
   ```bash
   docker kill --signal=HUP ja4proxy
   ```

3. Verify the proxy accepts client certificates signed by **either** CA:
   ```bash
   # Test with old CA-signed client cert
   openssl s_client -connect localhost:8080 \
     -cert config/certs/old-client.crt \
     -key config/certs/old-client.key \
     -CAfile config/certs/ca-bundle.pem \
     </dev/null 2>&1 | grep -i "verify return code"

   # Test with new CA-signed client cert
   openssl s_client -connect localhost:8080 \
     -cert config/certs/new-client.crt \
     -key config/certs/new-client.key \
     -CAfile config/certs/ca-bundle.pem \
     </dev/null 2>&1 | grep -i "verify return code"
   ```
   Both should show `Verify return code: 0 (ok)`.

**Phase 2 — Migrate clients to the new CA:**

4. Issue new client certificates signed by the new CA.
5. Deploy new client certificates to all clients (this may take hours or
   days depending on the client count).
6. Monitor the ratio of old vs. new client connections:
   ```bash
   # Check proxy logs for client cert issuer
   docker compose -f docker/docker-compose.poc.yml logs ja4proxy \
     | grep -i "client.*issuer" | sort | uniq -c
   ```

**Phase 3 — Drop the old CA (after all clients migrated):**

7. Once **zero** connections use the old CA (confirm via step 6 for at
   least 24 hours), remove the old CA from the trust bundle:
   ```bash
   cp config/certs/new-ca.crt config/certs/ca-bundle.pem
   chmod 644 config/certs/ca-bundle.pem
   ```

8. **Hot-reload the proxy:**
   ```bash
   docker kill --signal=HUP ja4proxy
   ```

9. Verify the proxy **rejects** old CA-signed client certificates:
   ```bash
   openssl s_client -connect localhost:8080 \
     -cert config/certs/old-client.crt \
     -key config/certs/old-client.key \
     -CAfile config/certs/ca-bundle.pem \
     </dev/null 2>&1 | grep -i "verify return code"
   # Expected: non-zero verify return code (certificate unknown)
   ```

10. Securely archive the old CA certificate (do not delete — you may need
    it to verify historical connections during an audit):
    ```bash
    cp config/certs/old-ca.crt config/certs/archived/old-ca-$(date +%Y%m%d).crt
    chmod 444 config/certs/archived/old-ca-$(date +%Y%m%d).crt
    ```

### Rollback

If clients fail after the combined trust bundle is loaded (Phase 1):

1. **Restore the old trust bundle:**
   ```bash
   git checkout HEAD -- config/certs/ca-bundle.pem
   ```
2. **Hot-reload the proxy:**
   ```bash
   docker kill --signal=HUP ja4proxy
   ```
3. Investigate why the new CA was rejected (format, key usage constraints,
   path length constraints).

If clients fail after the old CA is dropped (Phase 3):

1. **Re-add the old CA to the trust bundle:**
   ```bash
   cat config/certs/new-ca.crt config/certs/old-ca.crt \
     > config/certs/ca-bundle.pem
   ```
2. **Hot-reload the proxy.**
3. Identify which clients still use the old CA and complete their migration.
