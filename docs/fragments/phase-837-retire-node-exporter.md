- **Retire Node Exporter into Grafana Alloy & Sidecar Bumps (Phase 837)**:
  retired the standalone `prom/node-exporter:v1.12.1` container and activated
  Alloy's native `prometheus.exporter.unix` collector in `config.alloy`
  (mirroring Phase 829c's cAdvisor consolidation). Prometheus continues scraping
  host metrics under `job="node"` via Alloy's endpoint with preserved label
  contracts. Also upgraded Redis to `7.4.11-alpine` (0 CVEs) in prod and poc
  stacks, eliminating `CVE-2026-45447`. Removed `node-exporter` as a carrier
  for 8 Go stdlib/crypto CVEs and refreshed `.trivyignore.third-party`.
  See `docs/phases/PHASE_837.md`.
