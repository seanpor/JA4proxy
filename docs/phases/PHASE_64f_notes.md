# Phase 64f — TLS certificate rotation + alerts notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** S
> **Status:** NOT STARTED

## Deliverable
- `docs/runbooks/tls_certificate_rotation.md`
- `monitoring/alertmanager/rules/tls_alerts.yml`

## What was done
<!-- Record the lint result (`make lint-alertmanager`) and a manual sanity check
that the gauge `ja4proxy_tls_cert_expiry_timestamp_seconds` exists in
`internal/metrics/metrics.go`. -->

## Decisions made
<!-- Note any deviations from the spec in PHASE_64.md. -->

## Reviewer checklist (complete before merging)
- [ ] Runbook references Phase 63 gauge by real name
- [ ] No `absent_over_time` guard — the gauge is live
- [ ] Alert rules parse cleanly under alertmanager lint

## Phase 101 entries surfaced
<!-- File any gaps that fell out of this work. -->
