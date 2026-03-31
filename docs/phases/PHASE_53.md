# Phase 46: Advanced Traffic Intelligence - Phase 2: Secondary Feeds

Status: PROPOSED
Priority: MEDIUM (Post-Phase 23)

## Goal
Integrate specialized and private threat intelligence feeds to broaden the scope of identified malicious infrastructure.

## Sub-Tasks

### 46a — Specialized TI Connectors
- [ ] **MISP Integration:** Implement a provider for MISP (Malware Information Sharing Platform) to pull curated internal attributes.
- [ ] **ThreatFox:** Add support for Abuse.ch ThreatFox indicators (IOCs).
- [ ] **VirusTotal:** Implement a provider for VirusTotal IP reputation (requires API key).

### 46b — Feed Aggregation & Normalization
- [ ] **Normalization:** Ensure all secondary feeds map to the standard `RiskSignal` format.
- [ ] **Confidence Weighting:** Assign different weights to feeds based on historical accuracy (e.g., MISP attributes from trusted sources get higher scores).

### 46c — Advanced Caching & Rate Limiting
- [ ] **Adaptive TTL:** Implement different cache TTLs per feed based on the "volatility" of the data (e.g., C2 IPs expire faster than known VPN exits).
- [ ] **Quota Awareness:** Track and respect quotas for commercial TI feeds.

## Acceptance Criteria
- [ ] At least two new specialized feeds are integrated and producing signals.
- [ ] Cache hit rate for secondary feeds exceeds 90% in production.
- [ ] System handles feed downtime or API errors without impacting proxy latency.
