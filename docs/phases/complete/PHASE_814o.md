# Pentest: Purple Team — Detection and Response Validation

## Goal
Execute Phase 814o as the Stage 1 closer of the Phase 814 penetration testing campaign. Treat every attack executed across Stage 1 (`814d` through `814n`) as a detection and observability validation exercise:
1. Validate or downgrade confidence labels in `docs/security/ATTACK_MAPPING.md` against actual observed telemetry and pentest findings. Transition the document from `DRAFT` to `VALIDATED`.
2. Expand MITRE ATT&CK coverage with techniques tested during Stage 1 (e.g. credential access via SAML replay / brute force, defense evasion via seccomp / header tampering, and discovery / collection via unauthenticated stats and metrics).
3. Verify incident response readiness, MTTR harness resilience, and SOC runbook guidance.

## Scope
- `docs/security/ATTACK_MAPPING.md`: Confidence rating audit, transition to `VALIDATED`, and mapping coverage expansion for Stage 1 pentest findings.
- `tests/test_attack_mapping.py`: Automated CI verification of ATT&CK mapping integrity, confidence labels, and source file bindings.
- `scripts/measure_mttr.sh` & incident response runbooks: Review detection paths, metrics counters, and runbook coverage.

## Validation Matrix & Confidence Assessment
Based on findings from Stage 1:
- **T1595 (Active Scanning)** / **T1595.002**: Medium confidence holds. Multi-strategy rate tracking detects high-rate scanning but distributed/low-rate scans require threat intelligence feeds.
- **T1583.003 (VPS/Datacenter)** / **T1583.006 (Web Services/RDAP)**: Verified. RDAP enrichment confidence remains `low` due to lag in registry data.
- **T1110.004 (Credential Stuffing)** / **T1078 (Valid Accounts)**: Verified. SAML replay and authentication rate limits prevent automated stuffing across auth routes.
- **T1190 (Exploit Public-Facing Application)**: Downgraded/maintained at `low` for pure static JA4 lists, as modern custom TLS stacks evade static client fingerprinters.
- **T1573 (Encrypted Channel)** / **T1071.001 (Web Protocols)**: Maintained at `high` for known C2 frameworks in feed/corpus with exact fingerprint matches.
- **T1090.003 (Tor Proxy)**: Tor exit list feed validation holds at `high`.
- **T1071 / T1070 (Beaconing)**: Maintained at `medium` / `low` — fixed IAT-CV detects uniform beacons, but jittered C2 traffic evades fixed interval detection.
- **T1498 (Network Denial of Service)**: Maintained at `medium` — tarpit and sliding-window rate limiters defend single-host floods; distributed volume requires upstream mitigation.

## Implementation Plan
1. **Update `docs/security/ATTACK_MAPPING.md`**:
   - Update status from `DRAFT` to `VALIDATED — Stage 1 Purple Team Verified`.
   - Update `last_reviewed` to current date.
   - Refine confidence justifications with empirical observations from Phase 814 Stage 1.
2. **Verify CI Guardrails**:
   - Run `pytest tests/test_attack_mapping.py` in container to ensure all format and source-file requirements pass.
3. **Run Quality & Lint Checks**:
   - Run `make lint`, `make test`, and `make lint-phases`.
4. **Independent Expert Reviews**:
   - Run parallel Security, Concurrency, and Code Quality expert subagents.
5. **Phase Close-Out**:
   - Create changelog fragment `docs/fragments/phase-814o-purple-team-validation.md`.
   - Move plan to `docs/phases/complete/PHASE_814o.md` and set `manifest.yaml` to `COMPLETE`.
   - Run `scripts/close-phase.sh`, push, open PR, and auto-merge.

## Acceptance Criteria
- `docs/security/ATTACK_MAPPING.md` transitions to `VALIDATED` with grounded empirical rationales.
- `tests/test_attack_mapping.py` passes 100%.
- `make preflight` passes.
- All three expert reviews approve.
