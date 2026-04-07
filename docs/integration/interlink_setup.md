<!--
title: Interlink Service Watch Integration Setup
audience: Operators, NOC Engineers
last_reviewed: 2026-04-07
phase: 81
-->

# Interlink Service Watch Integration Setup

This guide covers how to connect JA4proxy to Interlink Software Service Watch so that
security events appear in the NOC console, trigger correlation rules, and auto-create
ITSM tickets.

Interlink Service Watch is common in UK financial services, utilities, and telco. It
provides event correlation, topology-aware alerting, and native connectors to Remedy,
ServiceNow, and Jira Service Management.

---

## Prerequisites

Before starting:

- An Interlink Service Watch account with API access enabled.
- An Interlink API token with at least `device:create` and `event:ingest` permissions.
  Store the token in your secrets manager (HashiCorp Vault, AWS Secrets Manager, or
  equivalent) — never in plaintext config files.
- Vector installed as a sidecar on each proxy host or in each proxy container.
  Minimum version: 0.36.0. See [Vector installation docs](https://vector.dev/docs/setup/installation/).
- The CA certificate for the Interlink syslog TLS endpoint, placed at
  `/etc/ja4proxy/tls/interlink-ca.crt` on each proxy host.
- The Interlink syslog receiver hostname and port (typically TCP 6514 with TLS).
  Obtain these from your Interlink account team.

---

## Step 1: Register Each JA4proxy Node in Service Watch

Run this as part of your Ansible post-deploy role. It registers each proxy node in
Service Watch as a custom device class `"network_security_appliance"`, which enables
topology-aware alerting and ITSM auto-ticketing.

```yaml
# Ansible task: register JA4proxy node in Interlink Service Watch
- name: Register JA4proxy node in Interlink Service Watch
  uri:
    url: "{{ interlink_api_url }}/api/v2/devices"
    method: POST
    headers:
      Authorization: "Bearer {{ interlink_api_token }}"
    body_format: json
    body:
      name: "{{ inventory_hostname }}"
      class: "network_security_appliance"
      ip_address: "{{ ansible_host }}"
      attributes:
        version: "{{ ja4proxy_image_tag }}"
        upstream_lb: "{{ upstream_lb_host }}"
        downstream_backend: "{{ backend_host }}"
        environment: "{{ deploy_environment }}"
```

**Required Ansible variables:**

| Variable | Description | Example |
|---|---|---|
| `interlink_api_url` | Base URL of the Service Watch API | `https://servicewatch.example.com` |
| `interlink_api_token` | API bearer token (from Vault) | `sv_...` |
| `ja4proxy_image_tag` | Image tag currently deployed | `0.81.0` |
| `upstream_lb_host` | HAProxy LB hostname | `haproxy-1.internal` |
| `backend_host` | Downstream HTTPS backend | `origin.internal` |
| `deploy_environment` | Environment label | `production` |

Run this task once per node on first deploy and again after any image tag upgrade to
keep the `version` attribute current.

---

## Step 2: Deploy the Vector Config

Copy `config/integrations/vector-interlink.yaml` to the Vector config directory on
each proxy host (typically `/etc/vector/`) and set the `INTERLINK_SYSLOG_HOST`
environment variable.

The config reads JA4proxy's ECS JSON events, converts them to CEF format, and
forwards them to the Interlink syslog receiver over TLS.

```yaml
# config/integrations/vector-interlink.yaml
#
# Source: "stdin" is the correct choice for Docker/container deployments — the
# Go proxy writes to stdout and Docker captures it. "journald" is ONLY correct
# for bare-metal RHEL deployments where the proxy runs as a systemd service.

sources:
  ja4proxy_logs:
    type: stdin

transforms:
  parse_ecs:
    type: remap
    inputs: ["ja4proxy_logs"]
    source: |
      . = parse_json!(string!(.message))

  to_cef:
    type: remap
    inputs: ["parse_ecs"]
    source: |
      # CEF severity must be an integer 0-10.
      # risk_score is 0-100; divide by 10 and round to nearest integer.
      cef_severity = to_string(to_int(round(float!(.["event.risk_score"]) / 10.0)))

      .cef = "CEF:0|JA4proxy|JA4proxy Proxy|" + string(.["service.version"] ?? "unknown") +
             "|" + string!(.["event.action"]) +
             "|JA4proxy " + string!(.["event.action"]) +
             "|" + cef_severity +
             "|src=" + string!(.["source.ip"]) +
             " dst=" + string(.["destination.ip"] ?? "") +
             " act=" + string!(.["event.action"]) +
             " cs1=" + string(.["ja4proxy.fingerprint.ja4"] ?? "") +
             " cs1Label=JA4Fingerprint"

sinks:
  interlink_syslog:
    type: socket
    inputs: ["to_cef"]
    address: "${INTERLINK_SYSLOG_HOST}:6514"
    mode: tcp
    tls:
      enabled: true
      ca_file: "/etc/ja4proxy/tls/interlink-ca.crt"
```

**For bare-metal RHEL deployments** where the proxy runs as a systemd service, replace
the source block with:

```yaml
sources:
  ja4proxy_logs:
    type: journald
    units:
      - "ja4proxy-proxy.service"
      - "ja4proxy-analytics.service"
```

---

## Step 3: Set Required Environment Variables

Set the following environment variable on each host running the Vector sidecar:

| Variable | Description | Required |
|---|---|---|
| `INTERLINK_SYSLOG_HOST` | Interlink syslog receiver hostname (without port) | Yes |

For Docker deployments, add to the proxy service environment in your Compose file:

```yaml
services:
  vector-interlink:
    image: timberio/vector:0.36.0-debian
    environment:
      - INTERLINK_SYSLOG_HOST=${INTERLINK_SYSLOG_HOST}
    volumes:
      - ./config/integrations/vector-interlink.yaml:/etc/vector/vector.yaml:ro
      - /etc/ja4proxy/tls/interlink-ca.crt:/etc/ja4proxy/tls/interlink-ca.crt:ro
```

For bare-metal systemd deployments, set the variable in the Vector systemd drop-in:

```ini
# /etc/systemd/system/vector.service.d/ja4proxy-interlink.conf
[Service]
Environment=INTERLINK_SYSLOG_HOST=servicewatch-syslog.example.com
```

---

## Step 4: Verify Events Are Arriving

After starting Vector, generate a test event and confirm it appears in Service Watch.

**Docker / container deployments** — inject a synthetic CEF event directly to the
syslog receiver to test connectivity, bypassing Vector:

```bash
logger -n "${INTERLINK_SYSLOG_HOST}" -P 6514 \
  --rfc5424 --tcp \
  "CEF:0|JA4proxy|JA4proxy Proxy|test|blocked|JA4proxy blocked|8|src=198.51.100.1 act=blocked cs1=t13d1516h2_test cs1Label=JA4Fingerprint"
```

If `logger` on your system does not support `--tcp`, use `openssl s_client` instead:

```bash
echo "CEF:0|JA4proxy|JA4proxy Proxy|test|blocked|JA4proxy blocked|8|src=198.51.100.1 act=blocked" \
  | openssl s_client -connect "${INTERLINK_SYSLOG_HOST}:6514" \
      -CAfile /etc/ja4proxy/tls/interlink-ca.crt \
      -quiet 2>/dev/null
```

**Check Vector's own health** to confirm it is processing events and has no delivery
errors:

```bash
curl -s http://localhost:8686/health
# Expected: {"ok":true}

curl -s http://localhost:8686/metrics | grep interlink_syslog
# Look for: vector_sink_events_sent_total{component_id="interlink_syslog",...}
```

Allow up to 60 seconds for the first event to appear in the Service Watch console
after Vector starts.

---

## Troubleshooting

### Events not appearing in Service Watch

**Wrong port or host:**
Check that `INTERLINK_SYSLOG_HOST` is set correctly and that TCP 6514 is reachable
from the proxy host:

```bash
nc -zv "${INTERLINK_SYSLOG_HOST}" 6514
```

If the connection is refused, check firewall rules between the proxy network and the
Service Watch syslog receiver.

**TLS certificate error:**
Verify the CA certificate is correct and has not expired:

```bash
openssl verify -CAfile /etc/ja4proxy/tls/interlink-ca.crt \
  /etc/ja4proxy/tls/interlink-ca.crt
# Expected: /etc/ja4proxy/tls/interlink-ca.crt: OK

openssl s_client -connect "${INTERLINK_SYSLOG_HOST}:6514" \
  -CAfile /etc/ja4proxy/tls/interlink-ca.crt </dev/null 2>&1 | grep -E "Verify|error"
```

If expired or mismatched, obtain a fresh CA certificate from your Interlink account
team.

**Vector not reading proxy logs (Docker):**
Confirm Vector is consuming the proxy container's stdout. The `stdin` source requires
Vector to be run in a way that receives the proxy's stdout — typically via Docker log
piping or a shared pipe. Check that Vector is started with the proxy's stdout piped in,
not as a standalone container with no input.

**Vector not reading proxy logs (bare-metal):**
When using the `journald` source, confirm the proxy services are running under systemd
and that Vector has permission to read the journal:

```bash
journalctl -u ja4proxy-proxy.service -n 20 --no-pager
sudo usermod -aG systemd-journal vector
sudo systemctl restart vector
```

**CEF severity shows as 0:**
The `event.risk_score` field must be a number in the ECS event. If the proxy is in
monitor mode (dial=0), all connections produce a score but may score low. Confirm ECS
logging is enabled in `config/proxy.yml`:

```yaml
logging:
  format: ecs
```

**Events appear in Vector but not in Service Watch:**
Check the Service Watch ingest queue and confirm the device class `network_security_appliance`
is registered. Events from unregistered device classes may be silently discarded
depending on your Service Watch configuration. Re-run the Ansible registration task
from Step 1.
