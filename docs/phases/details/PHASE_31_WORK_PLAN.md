# Phase 31 — Advanced Traffic Intelligence - Phase 3: Geographical Intelligence

Status: PROPOSED

## Goal

Add GeoIP lookup and country-based blocking capabilities to provide geographical threat analysis and perimeter control.

## Deliverables

- [ ] **GeoIP Integration**: Integrate MaxMind or IP2Location database into the connection pipeline.
- [ ] **Country Blocking**: Implement configuration and logic for blocking connections based on source country.
- [ ] **Geographical Scoring**: Add risk signals based on geographic origin (e.g., high-risk regions).
- [ ] **Caching**: Implement process-local caching for GeoIP lookups to minimize pipeline latency.
- [ ] **Metrics**: Add Prometheus metrics for connection counts per country and blocked country events.
