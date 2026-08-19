- **Grafana bumped to 13.1.4-ubuntu (issue #451 §2)**: clears the image's only
  CRITICAL (`GHSA-r277-6w6q-xmqw`, kin-openapi auth bypass) **and**
  `CVE-2026-42151`, introducing nothing. 1C/14H → 0C/13H.
  `.trivyignore.third-party` drops from 21 to **19** entries, and no deployed
  image carries a CRITICAL any more.
- **The Grafana "policy call" turned out not to be one (issue #451 §2)**: it had
  been framed as *"is one CRITICAL worth thirteen HIGHs?"*, because 13.2.0 was
  the only candidate ever measured. Re-measured against a fresh database after
  phase-829c removed cadvisor, 13.1.4 clears the same CRITICAL for free while
  13.2.0 would cost 15 new waivers (21 → 34 entries). There was no trade to
  make.
