# MITRE ATT&CK Technique Mapping

> **Status:** DRAFT — self-assessed mapping
> **Phase:** 107f (sub-phase 107f.1 scaffolding; rows to be filled by 107f.2/.3; CI gate added by 107f.4)
> **Framework:** MITRE ATT&CK Enterprise (current published matrix)

---

## Purpose

SOC teams consume ATT&CK technique IDs. This document maps JA4proxy's signal
modules and detections to the techniques they observe, so that JA4proxy events
can be correlated with the SOC's existing ATT&CK-based detection coverage.

Each forward-mapping row carries an honest **confidence** label
(`high` / `medium` / `low`) with a one-sentence justification. A signal that
*can* detect a technique under ideal conditions is not the same as reliably
detecting it.

---

## Confidence labels

| Label | Meaning |
|-------|---------|
| **high** | Reliably detects the technique across common variants |
| **medium** | Detects common variants; rare variants may evade |
| **low** | Detects only known samples; trivially evaded by an attacker who knows JA4proxy is in the path |

The `make test-attack-mapping` CI gate (added by sub-task 107f.4) enforces
that every forward-mapping row carries one of these three labels and that
every linked signal-module path exists on disk.

---

## Forward mapping (signal → ATT&CK)

<!-- TODO 107f.2 — fill TA0043 (Recon), TA0042 (Resource Development), TA0001 (Initial Access) rows -->
<!-- TODO 107f.3 — fill TA0011 (C2), TA0005 (Defense Evasion) rows -->

| Signal module | Detection | Tactic | Technique ID | Confidence (high/medium/low) | Source file |
|---------------|-----------|--------|--------------|------------------------------|-------------|
| <!-- TODO 107f.2 — TA0043 rows --> | | | | | |
| <!-- TODO 107f.2 — TA0042 rows --> | | | | | |
| <!-- TODO 107f.2 — TA0001 rows --> | | | | | |
| <!-- TODO 107f.3 — TA0011 rows --> | | | | | |
| <!-- TODO 107f.3 — TA0005 rows --> | | | | | |

---

## Reverse lookup (ATT&CK → signal)

<!-- TODO 107f.3 — populate reverse view from forward-mapping rows -->

| Technique ID | Technique | JA4proxy detection(s) |
|--------------|-----------|------------------------|
| <!-- TODO 107f.3 --> | | |

---

## SIEM integration

<!-- TODO 107f.3 — link `SIEM_INTEGRATION.md` with example Splunk / Sentinel / QRadar searches -->

See [`SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md) for example queries that
correlate JA4proxy events with the techniques mapped above.

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial mapping | Phase 107f.1 | Scaffolding only |
| Recon / Resource Development / Initial Access | 107f.2 | Pending |
| C2 / Defense Evasion + reverse view | 107f.3 | Pending |
| CI gate (`make test-attack-mapping`) | 107f.4 | Pending |
