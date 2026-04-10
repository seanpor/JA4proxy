# Phase 64f — TLS Certificate Rotation + Alerts Notes

## Artifacts Created

| File | Purpose |
|------|---------|
| `docs/runbooks/tls_certificate_rotation.md` | Server cert + mTLS CA rotation |
| `monitoring/alertmanager/rules/tls_alerts.yml` | Prometheus alert rules |

## Gauge Verification

- **Gauge name in `internal/metrics/metrics.go` line 174:** `ja4proxy_tls_cert_expiry_timestamp_seconds`
- **Gauge name in alert rules:** `ja4proxy_tls_cert_expiry_timestamp_seconds` ✅ Match
- **Gauge name in runbook:** `ja4proxy_tls_cert_expiry_timestamp_seconds` ✅ Match
- **No `absent_over_time` guard in alert rules** (only a comment explaining why it's not needed) ✅

## Alert Rules

- **Warning:** < 30 days to expiry, `for: 0m` (immediate fire)
- **Critical:** < 7 days to expiry, `for: 0m` (immediate fire)
- Both reference the TLS certificate rotation runbook in annotations

## Runbook Sections

1. Certificate expiry monitoring — PromQL queries, Grafana guidance
2. Server-side TLS certificate rotation — rolling SIGHUP reload
3. mTLS CA certificate rotation — three-phase dual-CA trust period

Each section has rollback instructions.

## Acceptance Checklist

- [x] Runbook exists with all three sections
- [x] Alert rule file exists with warning (< 30 days) and critical (< 7 days)
- [x] Gauge name matches `internal/metrics/metrics.go` exactly
- [x] No `absent_over_time` guard — the gauge is live
- [x] No mention of Phase 63 being incomplete or pending
- [x] All hot-reload commands use Go-production form
- [x] Each section has rollback instructions

## Out of Scope

- Certificate automation / ACME integration (deferred)
- OCSP stapling configuration (deferred)
- CT log monitoring (deferred)
