# Phase 47: Advanced Traffic Intelligence - Phase 5: Behavioral Attribution

Status: PROPOSED
Priority: MEDIUM (Post-Phase 32)

## Goal
Implement complex behavioral pattern matching and cross-IP correlation to identify coordinated attack campaigns.

## Sub-Tasks

### 47a — Attack Pattern Detection
- [ ] **Sequential Probing:** Detect clients that systematically probe different backend paths or ports using a consistent fingerprint.
- [ ] **Coordinated Burst:** Detect multiple IPs from the same subnet/ASN hitting the same target at the exact same millisecond interval.
- [ ] **Replay Detection:** Identify clients attempting to replay captured TLS sessions or headers from different source IPs.

### 47b — Cross-IP Correlation Logic
- [ ] **JA4 Clusters:** Group unique IPs that share a rare JA4 and exhibit similar behavioral timing.
- [ ] **Campaign Mapping:** Assign "Campaign IDs" to clusters of IPs that are likely controlled by the same botnet or adversary.

### 47c — Scoring & Alerting
- [ ] **Campaign Escalation:** If an IP is linked to an active campaign, apply a significant multiplier to its risk score.
- [ ] **Drift Alerting:** Alert SecOps when a new, previously unseen JA4 fingerprint starts appearing across multiple distinct IP blocks.

## Acceptance Criteria
- [ ] System correctly groups coordinated botnet nodes into a single campaign.
- [ ] Behavioral signals are integrated into the final composite risk score.
- [ ] Verification against a simulated "Coordinated Attack" corpus shows >90% detection rate.
