# ECS Extension Field Reference

Elastic Common Schema (ECS) is a vendor-neutral JSON schema for security telemetry.
JA4proxy uses ECS 8.x as its canonical log format so that every connection decision
lands in your SIEM with correctly typed, consistently named fields — no
normalization required.

---

## Mandatory ECS Fields

These fields are present in **every** JA4proxy log event, regardless of action taken.

| Field | Type | Values | Meaning in JA4proxy |
|-------|------|--------|---------------------|
| `@timestamp` | string (ISO 8601) | `2026-04-07T10:00:00.000000Z` | UTC time the connection decision was made |
| `event.action` | string | `allowed`, `blocked`, `banned`, `tarpitted`, `rate_limited`, `flagged` | Action taken by the ActionDecider |
| `event.outcome` | string | `success` (allowed), `failure` (all other actions) | Outcome from the defender's perspective |
| `event.kind` | string | `event`, `alert`, `configuration` | Connection = `event`; campaign/drift = `alert`; dial change = `configuration` |
| `event.category` | array of strings | `["network", "intrusion_detection"]` | ECS category array; always both values for connection events |
| `event.type` | array of strings | `["connection"]` | ECS type array |
| `event.severity` | integer | 1–6 | Maps to action: allow=1, flag=2, rate_limited=3, tarpit=4, block=5, ban=6 |
| `event.risk_score` | number | 0–100 | Composite risk score from RiskScorer (same value as `ja4proxy.score`) |
| `service.name` | string | `ja4proxy` | Always `ja4proxy`; use this to scope SIEM queries |
| `network.transport` | string | `tcp` | Always `tcp` |
| `network.protocol` | string | `tls` | Always `tls` |
| `source.ip` | string | IPv4 or IPv6 | Real client IP; extracted from PROXY protocol header when behind HAProxy |
| `source.port` | integer | 1–65535 | Client source port |
| `destination.port` | integer | 1–65535 | Backend port (typically 443) |
| `host.name` | string | `proxy-01.example.com` | Hostname of the JA4proxy instance that processed the connection |
| `tls.version` | string | `1.0`, `1.1`, `1.2`, `1.3` | Negotiated TLS version |
| `tls.cipher` | string | `TLS_AES_256_GCM_SHA384` | Negotiated cipher suite (IANA name) |
| `log.level` | string | `info`, `warn`, `error` | Logrus log level |
| `message` | string | human-readable | Log message text |

---

## JA4proxy Extension Fields

All extension fields use the `ja4proxy.` namespace.

| Field | Type | Example value | Description |
|-------|------|---------------|-------------|
| `ja4proxy.fingerprint.ja4` | string | `t13d15h2_8daaf6152771_e5627efa2ab1` | JA4 TLS client fingerprint. Format: `t{ver}{alpn_count}{ext_count}{alpn}_{ciphers_sha256[:12]}_{extensions_sha256[:12]}` |
| `ja4proxy.fingerprint.ja4x` | string | `a0b1c2d3e4f5_6789012345ab_cdef01234567` | JA4X certificate fingerprint. Three 12-char hex segments: issuer hash, subject hash, SAN hash |
| `ja4proxy.fingerprint.ja4t` | string | `t65535_2_1460_6` | JA4T TCP fingerprint derived from SYN packet options |
| `ja4proxy.score` | number | `72` | Composite risk score 0–100 (alias of `event.risk_score` for backward compatibility) |
| `ja4proxy.dial_setting` | integer | `50` | Proxy dial position at decision time (0=monitor-only, 100=full enforcement) |
| `ja4proxy.sni` | string | `www.example.com` | TLS SNI hostname from the ClientHello |
| `ja4proxy.alpn` | string | `h2` | First ALPN protocol offered by the client |
| `ja4proxy.country_code` | string | `US` | ISO 3166-1 alpha-2 country code from MaxMind GeoLite2 |
| `ja4proxy.asn` | integer | `15169` | Autonomous System Number of the client IP |
| `ja4proxy.asn_org` | string | `GOOGLE` | ASN organisation name from MaxMind GeoLite2-ASN |
| `ja4proxy.tls_resumed` | boolean | `false` | True if the client reused a TLS session ticket |
| `ja4proxy.signals` | array | see below | Individual RiskSignal objects contributing to the score |
| `ja4proxy.node` | string | `proxy-01` | JA4proxy instance identifier (matches `host.name` in single-node deployments) |
| `ja4proxy.dial.old_value` | integer | `40` | Previous dial value (configuration events only) |
| `ja4proxy.dial.new_value` | integer | `60` | New dial value (configuration events only) |

**`ja4proxy.signals` item schema:**

Each element of the signals array is an object with:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Signal identifier (matches the `signal` Prometheus label on `ja4proxy_signal_score_total`) |
| `score` | number | Points contributed to the composite score by this signal |
| `reason` | string | Human-readable explanation of why the signal fired |

Example:
```json
[
  {"name": "tls_version_old", "score": 30, "reason": "TLS 1.1 is deprecated"},
  {"name": "asn_datacenter",  "score": 20, "reason": "ASN 14061 is DigitalOcean datacenter range"}
]
```

**Threat indicator fields** (set only on `ban` actions):

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `threat.indicator.ip` | string | `203.0.113.42` | Client IP flagged as a ban-level threat |
| `threat.indicator.type` | string | `ipv4-addr` or `ipv6-addr` | STIX indicator type |

---

## Event Types

JA4proxy emits three distinct event kinds. Use `event.kind` to route events to
different SIEM workflows.

### `event.kind = "event"` — Connection Decision

Emitted for every connection processed by the proxy.

```json
{
  "@timestamp": "2026-04-07T10:00:00.123456Z",
  "log.level": "info",
  "message": "connection decision",
  "event.kind": "event",
  "event.category": ["network", "intrusion_detection"],
  "event.type": ["connection"],
  "event.action": "blocked",
  "event.outcome": "failure",
  "event.severity": 5,
  "event.risk_score": 78,
  "service.name": "ja4proxy",
  "network.transport": "tcp",
  "network.protocol": "tls",
  "source.ip": "203.0.113.42",
  "source.port": 54321,
  "destination.port": 443,
  "host.name": "proxy-01.example.com",
  "tls.version": "1.3",
  "tls.cipher": "TLS_AES_256_GCM_SHA384",
  "ja4proxy.fingerprint.ja4": "t13d15h2_8daaf6152771_e5627efa2ab1",
  "ja4proxy.score": 78,
  "ja4proxy.dial_setting": 60,
  "ja4proxy.sni": "www.example.com",
  "ja4proxy.country_code": "RU",
  "ja4proxy.signals": [
    {"name": "asn_datacenter", "score": 20, "reason": "Datacenter ASN"},
    {"name": "abuseipdb_score", "score": 58, "reason": "AbuseIPDB confidence 83%"}
  ]
}
```

### `event.kind = "alert"` — Campaign or Score Drift

Emitted by the analytics node when it detects a coordinated campaign or
anomalous score drift across a subnet.

```json
{
  "@timestamp": "2026-04-07T10:05:00.000000Z",
  "log.level": "warn",
  "message": "campaign detected: /24 block_rate=0.82 density=0.19",
  "event.kind": "alert",
  "event.category": ["intrusion_detection", "threat"],
  "event.type": ["info"],
  "event.action": "flagged",
  "event.outcome": "failure",
  "service.name": "ja4proxy",
  "network.transport": "tcp",
  "network.protocol": "tls",
  "source.ip": "203.0.113.0",
  "host.name": "analytics-01.example.com",
  "ja4proxy.node": "analytics-01"
}
```

### `event.kind = "configuration"` — Dial Change

Emitted when the proxy dial setting changes (via Management UI, config reload, or
direct Redis write).

```json
{
  "@timestamp": "2026-04-07T10:10:00.000000Z",
  "log.level": "info",
  "message": "dial setting changed",
  "event.kind": "configuration",
  "event.category": ["configuration"],
  "event.type": ["change"],
  "event.action": "allowed",
  "event.outcome": "success",
  "service.name": "ja4proxy",
  "network.transport": "tcp",
  "network.protocol": "tls",
  "source.ip": "10.0.0.1",
  "host.name": "proxy-01.example.com",
  "ja4proxy.dial_setting": 60,
  "ja4proxy.dial.old_value": 40,
  "ja4proxy.dial.new_value": 60
}
```

---

## Log Format Configuration

Switch the proxy to ECS output by setting `logging.format` in `config/proxy.yml`:

```yaml
logging:
  format: ecs      # "legacy" (default) or "ecs"
  level: info      # debug | info | warn | error
```

The default is `legacy` (timestamp/level/message top-level keys). Existing Grafana
dashboards consume Prometheus metrics and are unaffected by this setting.

The Go proxy reads `logging.format` at startup and on `SIGHUP` reload. The Python
analytics container reads it via `setup_logging(format=...)` in
`src/utils/logging_config.py`.

Setting `format: legacy` retains the pre-Phase 80 log structure; no SIEM pipeline
changes are needed if you are not adopting ECS.

---

## Webhook Events

The webhook dispatcher (`internal/webhook/delivery.go`) delivers connection events
to configured HTTP endpoints. Each POST carries a JSON body with an HMAC-SHA256
signature.

### Payload structure

```json
{
  "id": "b3d9e2a1-4f5c-4b8d-9e1a-2c3d4e5f6a7b",
  "timestamp": "2026-04-07T10:00:00.123456Z",
  "event_type": "connection",
  "data": { ... ECS event fields ... },
  "signature": "sha256=3b4c5d6e7f8a..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Unique event identifier |
| `timestamp` | string (ISO 8601) | Time of the connection decision |
| `event_type` | string | One of `connection`, `alert`, `configuration` |
| `data` | object | Full ECS event (the same fields documented above) |
| `signature` | string | `sha256=` followed by HMAC-SHA256 hex digest |

### Signature verification

The signature is computed over the JSON encoding of the payload **without** the
`signature` field, then added as a top-level key. Reconstruct the pre-signature
payload to verify:

**Python:**
```python
import hmac, hashlib, json

def verify_webhook(body_bytes: bytes, secret: str, received_sig: str) -> bool:
    payload = json.loads(body_bytes)
    sig_received = payload.pop("signature", "")
    payload_for_hmac = json.dumps(payload, sort_keys=False, separators=(",", ":")).encode()
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_for_hmac, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_received)
```

**bash (for testing):**
```bash
# Given the raw payload in /tmp/payload.json and the secret in $WEBHOOK_SECRET:
body=$(cat /tmp/payload.json)
# Remove the signature field, then recompute:
body_no_sig=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d.pop('signature', None)
print(json.dumps(d, separators=(',', ':')))
")
expected_sig="sha256=$(printf '%s' "$body_no_sig" | \
  openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $2}')"
echo "Expected:  $expected_sig"
echo "Received:  $(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signature',''))")"
```

The delivery header is `X-JA4Proxy-Signature`. Failed deliveries are retried with
exponential backoff (default: 3 attempts). After all retries are exhausted the
payload is written to the `webhooks:dlq` Redis Stream for manual inspection.

---

## Schema Validation

`config/integrations/ecs-schema.json` is a JSON Schema (draft-07) that validates
the five mandatory fields present in every JA4proxy ECS event:

- `@timestamp`
- `event.action`
- `service.name`
- `network.transport`
- `source.ip`

The schema also constrains enum values for `event.kind`, `event.action`,
`event.outcome`, `tls.version`, `network.protocol`, and validates the regex pattern
of `ja4proxy.fingerprint.ja4`.

### Validate in CI

```bash
# Install: pip install jsonschema[format]
python3 -c "
import json, jsonschema
from jsonschema import Draft7Validator, FormatChecker
schema = json.load(open('config/integrations/ecs-schema.json'))
sample = json.load(open('config/integrations/ecs-sample-event.json'))
errors = list(Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(sample))
if errors:
    for e in errors:
        print('ERROR:', e.message)
    exit(1)
print('ECS schema validation: OK')
"
```

Note: `Draft7Validator` with `FormatChecker` is required because the schema uses
`oneOf` with `format` assertions for `source.ip` (IPv4/IPv6 discrimination).
The top-level `jsonschema.validate()` does not enforce format assertions by default
in jsonschema 4.x, which causes a false `oneOf` conflict.

Or via the Makefile target:

```bash
make validate-ecs-schema
```

Add a custom sample event at `config/integrations/ecs-sample-event.json` to test
your own field additions against the schema. The provided sample covers a `blocked`
connection event with all mandatory fields populated.
