# Phase 64f — TLS certificate rotation + alerts notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** S
> **Status:** COMPLETE

## Deliverable
- `docs/runbooks/tls_certificate_rotation.md`
- `monitoring/alertmanager/rules/tls_alerts.yml`

## What was done

- Verified gauge `ja4proxy_tls_cert_expiry_timestamp_seconds` exists in
  `internal/metrics/metrics.go` (line 174) with accompanying test in
  `internal/metrics/metrics_test.go` (line 47-48).
- Created `monitoring/alertmanager/rules/tls_alerts.yml` with two alerts:
  - `JA4proxyTLSCertExpiringSoon` (warning, < 30 days)
  - `JA4proxyTLSCertExpiryCritical` (critical, < 7 days)
- Created `docs/runbooks/tls_certificate_rotation.md` covering monitoring,
  server-side rotation, and mTLS CA rotation.
- Created `tests/test_phase64f_tls_alerts.py` with TDD tests validating alert
  structure, gauge references, annotations, and runbook existence.
- No `absent_over_time` guard used — the gauge is live.
- All hot-reload commands use Go-production form (`docker kill --signal=HUP`
  or `systemctl kill --signal=HUP`).

## Decisions made
- No deviations from the spec in PHASE_64.md.

## Reviewer checklist (complete before merging)
- [ ] Runbook references Phase 63 gauge by real name
- [ ] No `absent_over_time` guard — the gauge is live
- [ ] Alert rules parse cleanly under alertmanager lint

## Phase 101 entries surfaced
<!-- File any gaps that fell out of this work. -->
