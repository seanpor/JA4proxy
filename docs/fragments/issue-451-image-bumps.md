- **Monitoring image bumps (issue #451)**: `prom/prometheus` v3.13.2 → **v3.14.0**
  (8 HIGH → 0, nothing introduced), `prom/alertmanager` v0.33.1 → **v0.34.0**
  (20 HIGH cleared, 2 introduced — both already required for `grafana/alloy`),
  and `haproxy` 2.8.26-alpine → **2.8.27-alpine** (currency; both scan clean).
  Measured as raw CVE-ID set differences against a fresh Trivy DB, not release
  notes.
- **Closed a live gap in `.trivyignore.third-party` (issue #451)**:
  `CVE-2026-56864` and `CVE-2026-56865` (`golang.org/x/mod` in
  `grafana/alloy:v1.18.1`) entered the vulnerability database after the
  2026-08-18 renewal review, so `make scan-images` had begun failing on an image
  nobody had changed. The ignorefile now covers all 56 distinct HIGH/CRITICAL
  findings across the deployed set exactly.
- **Refreshed 18 stale exception justifications (issue #451)**: entries claimed
  to cover `promtail:3.6.11` (removed in phase-825), `grafana:13.0.4-ubuntu`
  (now 13.0.6) and `prom/haproxy-exporter:v0.15.0` (retired in phase-820) —
  images not present in the deployment. Each carrier claim is now generated from
  measured scan data. The dated history sections are unchanged; they record what
  was true at the time.
