# Runbook: ja4proxy_certificate_expiring

## Severity
WARNING (≤30 days) → CRITICAL (≤7 days)

## What is happening
The TLS certificate used by JA4proxy's listener is approaching expiry.
When it expires, clients will receive TLS handshake errors and no
traffic will be served through the proxy.

## Impact
- **High (CRITICAL):** Certificate expires within 7 days. If not rotated,
  all proxied TLS connections will fail with certificate errors.
  This is a complete service outage.
- **Low (WARNING):** Certificate expires within 30 days. Plan rotation
  at the next maintenance window.

## Diagnosis
1. Check current certificate details:
   ```bash
   echo | openssl s_client -connect localhost:8080 -servername localhost 2>/dev/null \
     | openssl x509 -noout -dates -subject
   ```
2. Check days remaining from health endpoint:
   ```bash
   curl -sf http://<node>:9090/health/deep | python3 -c "import sys,json; print(json.load(sys.stdin)['cert_days_remaining'])"
   ```
3. Identify the certificate file in use:
   ```bash
   grep -r 'cert\|tls' config/proxy.yml
   ```

## Resolution
Follow the TLS Certificate Rotation Runbook:
[`docs/runbooks/tls_certificate_rotation.md`](tls_certificate_rotation.md)

Quick rotation (if cert files are already prepared):
1. Replace cert and key files:
   ```bash
   cp /path/to/new-cert.pem /etc/ja4proxy/cert.pem
   cp /path/to/new-key.pem /etc/ja4proxy/key.pem
   chmod 600 /etc/ja4proxy/key.pem
   ```
2. Send SIGHUP to proxy to reload:
   ```bash
   kill -HUP $(pgrep -f ja4proxy)
   ```
3. Verify new cert is loaded:
   ```bash
   curl -sf http://<node>:9090/health/deep | python3 -c "import sys,json; print(json.load(sys.stdin)['cert_days_remaining'])"
   ```

## Escalation
Page SecOps lead immediately if certificate expires within 48 hours.
If certificate authority (e.g., Let's Encrypt) is failing, escalate
to Platform Engineering to investigate cert-manager or acme.sh.
