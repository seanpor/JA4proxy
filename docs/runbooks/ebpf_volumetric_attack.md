# Runbook: Kernel-Level Volumetric Attack (eBPF)

**Status:** STUB - written in Phase 86h, to be expanded.

## Severity
CRITICAL

## What is happening
An eBPF probe has detected a kernel-level volumetric attack pattern (e.g. SYN flood
or packet rate anomaly) exceeding configured thresholds for sustained traffic.

## Impact
Proxy node CPU and NIC saturation; legitimate connections may be dropped at the
kernel before JA4proxy sees them.

## Diagnosis
See the Management UI and:
- `make test` for health baseline
- Grafana `ja4proxy-overview` dashboard
- Kernel-level `ss -s`, `nstat`, and eBPF counter exports

## Resolution
Refer to [security_incident_response.md](security_incident_response.md) for
standard incident paths. This stub will be expanded in a later phase.

## Escalation
Page the on-call SecOps engineer if impact is HIGH.
