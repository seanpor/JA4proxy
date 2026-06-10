<!--
title: JA4proxy — Attack Mapping
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# MITRE ATT&CK Technique Mapping

> **Status:** DRAFT — self-assessed mapping
> **Phase:** 107f (sub-phase 107f.1 scaffolding; 107f.2/.3 content; 107f.4 CI gate)
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

Each row maps a JA4proxy signal module to one MITRE ATT&CK technique. Where a
signal observes multiple techniques, the row appears once per technique.
Source-file paths point to the canonical Go production module. (The original
Python prototypes under `src/security/` were retired in v2.0.0 when Go became
the sole production runtime, so they no longer carry parallel rows.)

| Signal module | Detection | Tactic | Technique ID | Confidence | Source file |
|---------------|-----------|--------|--------------|------------|-------------|
| TCP analyser (per-IP rate) | High new-connection rate from a single source IP probing many ports/SNIs (active scanning) | TA0043 Reconnaissance | T1595 Active Scanning | medium — TCP/rate signal catches naive scanners reliably; distributed scanners across many IPs evade per-IP windows | internal/security/tcp_analyzer.go |
| Rate tracker (multi-strategy) | Sliding-window per-IP and per-(IP, JA4) rate breaches indicating brute scanning behaviour | TA0043 Reconnaissance | T1595.002 Vulnerability Scanning (best-fit — covers high-rate probe behaviour) | medium — multi-strategy 2-of-3 majority vote reduces false positives; heavy-NAT sources still produce false positives | internal/security/rate_limiter.go |
| ASN classifier (datacenter detection) | TLS connection sourced from a hosting/VPS ASN — common for attacker-rented infrastructure | TA0042 Resource Development | T1583.003 Acquire Infrastructure: Virtual Private Server | medium — datacenter ASN list is comprehensive but legitimate cloud-hosted clients also match (think monitoring, CI, federated services) | internal/security/asn_classifier.go |
| RDAP enrichment (org-name match) | Known-bad hosting-provider org names (e.g., bulletproof hosters) detected via RDAP lookup | TA0042 Resource Development | T1583.006 Acquire Infrastructure: Web Services | low — relies on a curated bad-org list that lags reality; sophisticated actors rotate provider relationships | internal/security/rdap_enrichment.go |
| Rate tracker (per-(IP, JA4) low threshold) | Many TLS connections from one source IP using one client fingerprint targeting an auth endpoint pattern | TA0001 Initial Access | T1110.004 Credential Stuffing | medium — catches single-host stuffing; distributed credential-stuffing across botnets evades per-IP rate windows | internal/security/rate_limiter.go |
| TLS enforcer + JA4 blacklist | Connection presents a known-scanner JA4 fingerprint (masscan, zgrab, exploit-toolkit signatures) targeting a public-facing service | TA0001 Initial Access | T1190 Exploit Public-Facing Application | low — JA4 blacklist matches only fingerprints that are already known and published; attackers who randomise their TLS stack evade trivially | internal/security/tls_enforcer.go |
| Pipeline JA4 blacklist (Sliver / CobaltStrike / Evilginx) | TLS ClientHello fingerprint matches a published C2-framework JA4 (e.g., Sliver `t13d190900_*`, CobaltStrike `t12d*`, Evilginx) | TA0011 Command and Control | T1573 Encrypted Channel | high — JA4 blacklist matches exact known C2 fingerprints with low ambiguity, but coverage is bounded by the curated fingerprint list | internal/security/pipeline.go |
| Pipeline JA4 blacklist (web-protocol C2) | C2-framework JA4 match where the underlying ALPN is `h2`/`http/1.1` (web-protocol C2 over TLS) | TA0011 Command and Control | T1071.001 Application Layer Protocol: Web Protocols | high — same fingerprint match as T1573 row; the ALPN context is what distinguishes T1071.001 | internal/security/pipeline.go |
| ASN classifier (Tor exit list) | Connection sourced from an IP on the published Tor exit-node list | TA0005 Defense Evasion | T1090.003 Proxy: Multi-hop Proxy | high — Tor exit list is authoritative for currently-advertised exit IPs; cost is false positives against legitimate Tor users | internal/security/asn_classifier.go |
| Beaconing detector (IAT coefficient of variation) | Repeated connections from the same source with low inter-arrival-time variance — characteristic of automated C2 beaconing over encrypted channels | TA0011 Command and Control | T1071 Application Layer Protocol (best-fit — encoded C2 traffic over TLS) | medium — catches naive beacons with fixed cadence; jittered or human-in-the-loop beacons require longer windows and may evade the 1h/24h thresholds | internal/security/beaconing_detector.go |
| Beaconing detector (Defense Evasion view) | Same beaconing signal viewed as low-and-slow C2 traffic designed to blend with normal HTTPS — an indicator-removal/evasion behaviour | TA0005 Defense Evasion | T1070 Indicator Removal (best-fit — beacon timing chosen to defeat naive volumetric detection) | low — IAT-CV detection is bypassed by adding randomised jitter; sophisticated implants already do this | internal/security/beaconing_detector.go |
| Rate tracker + tarpit/block | Aggregate per-IP connection floods triggering rate-limit and tarpit actions | TA0040 Impact | T1498 Network Denial of Service | medium — protects the proxy and backend from naive flood patterns; large distributed L7 floods need upstream scrubbing | internal/security/rate_limiter.go |

---

## Reverse lookup (ATT&CK → signal)

Inverted view of the forward table. For each technique ID, lists the JA4proxy
signal modules whose detections produce events tagged with that technique. If
forward and reverse views disagree, the forward table is authoritative.

| Technique ID | Technique | JA4proxy detection(s) |
|--------------|-----------|------------------------|
| T1595 | Active Scanning | TCP analyser per-IP rate (`internal/security/tcp_analyzer.go`) |
| T1595.002 | Vulnerability Scanning (best-fit) | Rate tracker multi-strategy (`internal/security/rate_limiter.go`) |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | ASN classifier datacenter detection (`internal/security/asn_classifier.go`) |
| T1583.006 | Acquire Infrastructure: Web Services | RDAP enrichment org-name match (`internal/security/rdap_enrichment.go`) |
| T1110.004 | Credential Stuffing | Rate tracker per-(IP, JA4) low threshold (`internal/security/rate_limiter.go`) |
| T1190 | Exploit Public-Facing Application | TLS enforcer + JA4 blacklist for known scanner fingerprints (`internal/security/tls_enforcer.go`) |
| T1573 | Encrypted Channel | Pipeline JA4 blacklist for Sliver/CobaltStrike/Evilginx (`internal/security/pipeline.go`) |
| T1071.001 | Application Layer Protocol: Web Protocols | Pipeline JA4 blacklist with ALPN h2/http1 context (`internal/security/pipeline.go`) |
| T1071 | Application Layer Protocol (best-fit, encoded C2 over TLS) | Beaconing detector IAT-CV (`internal/security/beaconing_detector.go`) |
| T1090.003 | Proxy: Multi-hop Proxy | ASN classifier Tor exit list (`internal/security/asn_classifier.go`) |
| T1070 | Indicator Removal (best-fit, beacon-timing evasion) | Beaconing detector IAT-CV viewed as evasion behaviour (`internal/security/beaconing_detector.go`) |
| T1498 | Network Denial of Service | Rate tracker + tarpit/block (`internal/security/rate_limiter.go`) |

---

## SIEM integration

JA4proxy events carry the source signal module name in the structured log,
which lets a SIEM pivot from a JA4proxy decision to its ATT&CK technique
using the forward table above. Once enriched, an analyst can correlate
JA4proxy detections with telemetry from EDR, network IDS, and identity-
provider logs that already carry ATT&CK technique tags.

The full ingestion guide for Splunk, Sentinel, QRadar, and Elastic lives at
[`SIEM_INTEGRATION.md`](SIEM_INTEGRATION.md). The examples below show how to
extend those pipelines with ATT&CK enrichment derived from this mapping.

### Example 1 — Splunk SPL: JA4 blacklist hits → T1573 / T1071.001

```spl
index=ja4proxy event.action=block bypass_reason="ja4_blacklist"
| eval mitre_technique=if(alpn IN ("h2","http/1.1"), "T1071.001", "T1573")
| eval mitre_tactic="TA0011"
| stats count by source.ip, ja4_fingerprint, mitre_technique, mitre_tactic
| `comment("Pivot to EDR: search index=edr T1573 OR T1071.001 source.ip=$source.ip$")`
```

### Example 2 — Splunk SPL: Tor exit detections → T1090.003

```spl
index=ja4proxy signal.module="asn_classifier" signal.detail="tor_exit"
| eval mitre_technique="T1090.003", mitre_tactic="TA0005"
| stats count, values(destination.path) by source.ip, mitre_technique
| where count > 5
```

### Example 3 — Generic pseudo-query: beaconing → T1071 / T1070 dual-tag

```pseudo
SELECT
  source.ip,
  ja4_fingerprint,
  beacon.iat_cv,
  ARRAY['T1071', 'T1070'] AS mitre_techniques,
  ARRAY['TA0011', 'TA0005'] AS mitre_tactics
FROM ja4proxy_events
WHERE signal.module = 'beaconing_detector'
  AND beacon.iat_cv < 0.15
  AND time BETWEEN now() - INTERVAL '24 hours' AND now()
GROUP BY source.ip, ja4_fingerprint, beacon.iat_cv;
```

The dual-tag reflects that one signal informs both the C2 (TA0011) and
Defense Evasion (TA0005) hypotheses; correlation rules downstream choose
which to act on based on adjacent telemetry.

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial mapping | Phase 107f.1 | Scaffolding only |
| Recon / Resource Development / Initial Access | 107f.2 | Done — see forward table rows |
| C2 / Defense Evasion + reverse view + SIEM examples | 107f.3 | Done — see forward/reverse tables and SIEM section |
| CI gate (`make test-attack-mapping`) | 107f.4 | Done — see `tests/test_attack_mapping.py` |

**Refresh trigger:** when a signal module is renamed, a new C2-framework JA4
is added to the blacklist, or the MITRE ATT&CK matrix publishes a new
relevant technique.
