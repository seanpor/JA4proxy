# TLS Certificate Rotation

## 1. Certificate expiry monitoring

The Go proxy exports a Prometheus gauge that reports the Unix epoch at which the
server-side TLS certificate expires:

```
ja4proxy_tls_cert_expiry_timestamp_seconds
```

This gauge is live in production (shipped in Phase 63, defined in
`internal/metrics/metrics.go`).

Alert rules in `monitoring/alertmanager/rules/tls_alerts.yml` fire at two
thresholds:

| Alert | Severity | Threshold |
|-------|----------|-----------|
| `JA4proxyTLSCertExpiringSoon` | warning | < 30 days remaining |
| `JA4proxyTLSCertExpiryCritical` | critical | < 7 days remaining |

### Quick check

```bash
curl -s http://localhost:9090/api/v1/query?query=ja4proxy_tls_cert_expiry_timestamp_seconds \
  | python3 -c "import sys,json,datetime; v=json.load(sys.stdin)['data']['result'][0]['value'][1]; print(f'Expires: {datetime.datetime.fromtimestamp(float(v))} ({(float(v)-datetime.datetime.now().timestamp())/86400:.0f} days)')"
```

---

## 2. Server-side TLS certificate rotation

Perform a rolling rotation, one node at a time, to avoid downtime.

1. **Generate or obtain the new certificate** from your CA (Let's Encrypt,
   internal PKI, etc.).

2. **Copy the new certificate and key** to the first node's configured cert
   path (see `tls.cert_file` and `tls.key_file` in `config/proxy.yml`).

3. **Hot-reload the proxy** so it picks up the new certificate without
   dropping connections:

   ```bash
   # Docker
   docker kill --signal=HUP ja4proxy

   # systemd
   systemctl kill --signal=HUP ja4proxy.service
   ```

4. **Verify** the node is serving the new certificate:

   ```bash
   openssl s_client -connect <host>:8080 -servername <host> 2>/dev/null \
     | openssl x509 -noout -dates
   ```

   Confirm `notAfter` matches the new certificate's expiry.

5. **Repeat steps 2-4** for each remaining proxy node.

6. **Verify all nodes** serve the new certificate. A quick loop:

   ```bash
   for host in node1 node2 node3; do
     echo -n "$host: "
     openssl s_client -connect "$host":8080 -servername "$host" 2>/dev/null \
       | openssl x509 -noout -enddate
   done
   ```

---

## 3. mTLS CA certificate rotation

When rotating the CA that signs client certificates, use a dual-CA trust bundle
to avoid breaking existing clients during the migration window.

1. **Create a combined PEM** containing both the new and old CA certificates:

   ```bash
   cat new-ca.pem old-ca.pem > combined-ca.pem
   ```

2. **Deploy the combined CA bundle** to the proxy's configured `tls.client_ca`
   path on all nodes.

3. **Hot-reload all nodes** to pick up the combined bundle:

   ```bash
   docker kill --signal=HUP ja4proxy
   # or
   systemctl kill --signal=HUP ja4proxy.service
   ```

4. **Migrate clients** to certificates signed by the new CA. During the
   migration window both old-CA and new-CA client certificates are accepted.

5. **After the migration window**, remove the old CA from the bundle so only
   the new CA remains:

   ```bash
   cp new-ca.pem combined-ca.pem
   ```

6. **Hot-reload all nodes** again to enforce new-CA-only trust.

7. **Verify** a client certificate signed by the new CA is accepted:

   ```bash
   openssl verify -CAfile new-ca.pem client.pem
   ```
