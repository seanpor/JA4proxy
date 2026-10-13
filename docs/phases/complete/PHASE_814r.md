# Pentest: Independent Fix-Audit and Adjacent-Bug Hunt (Pass 3)

## Goal
Execute Phase 814r (Stage 3) of the Phase 814 penetration testing campaign in strict accordance with `PROGRAMME.md` Section 11 ("The fix-audit — pass 3"). Systematically audit all remediations landed across Stage 1 and Stage 2 (Waves 1-4: findings `JA4PROXY-2026-0074`, `JA4PROXY-2026-0089`, and `JA4PROXY-2026-0105` through `JA4PROXY-2026-0132`), evaluating the mandatory four-question framework (Q1: Actual fix & variation, Q2: Side effects & hot-path budget, Q3: Class search across codebase, Q4: Neighbourhood & sibling audit) and promote verified findings in the register.

## Scope
1. **Pass 3 Fix Audit (Questions Q1 through Q4)** for all Stage 1 & Stage 2 remediations:
   - Network edge & PROXY protocol parsing (`0110`, `0111`, `0113`)
   - Resource exhaustion & buffer lifecycle (`0114`, `0115`, `0116`, `0117`, `0118`, `0119`)
   - TLS handshake parser string safety & control chars (`0108`, `0109`)
   - Authentication, session, and single-use state (`0112`, `0124`, `0125`, `0126`, `0105`)
   - Supply chain, CI/CD, and agent boundaries (`0106`, `0107`, `0120`, `0131`)
   - Data layer, backup restore, and GDPR erasure (`0074`, `0089`, `0121`, `0122`, `0123`)
   - Container, host, and integration security (`0127`, `0128`, `0129`, `0130`, `0132`)
2. **Systemic Class Sweep (Q3)**:
   - Grep sweeps for unclosed sockets, missing write deadlines, unsafe string zero-copy pointers, unauthenticated admin endpoints, unpinned downloads, and formula injection prefixes.
3. **Neighbourhood Audit (Q4)**:
   - Callers/callees and sibling branches across `internal/server/`, `internal/tls/`, `internal/security/`, `management/api/`, and `deploy/`.
4. **Hot-Path Performance Re-verification**:
   - `BenchmarkClientHelloParse`, `BenchmarkJA4Compute`, and PROXY reassembly benchmarks.
5. **Register Promotion**:
   - Promote fully audited findings from `FIXED` to `VERIFIED` in `docs/security/findings.yaml`.

## Implementation Plan
1. **Execute Pass 3 Four-Question Audit Framework**:
   - Answer Q1, Q2, Q3, and Q4 in writing for each finding family.
   - Run original adversarial tests plus one-step variations (encoding, fragmented boundaries, parallel replays).
2. **Run Hot-Path Microbenchmarks**:
   - Confirm allocations, latency, and CPU budgets are preserved.
3. **Promote Findings in Register**:
   - Update `docs/security/findings.yaml` promoting audited findings to `status: VERIFIED`.
   - Validate with `python3 scripts/findings_register.py validate`.
4. **Independent Triad Review**:
   - Security, Concurrency, and Code Quality expert subagents must all APPROVE.
5. **Close-Out Phase 814r**:
   - Move plan to `docs/phases/complete/PHASE_814r.md`, update manifest (`814r: COMPLETE`), add news fragment, run `bash scripts/close-phase.sh`, and create auto-merge PR.

## Acceptance Criteria
- Written Q1–Q4 answers documented with actual grep commands and outputs.
- Zero adjacent bugs or unhandled residual bypasses discovered.
- Hot-path microbenchmarks within acceptable variance.
- Register entries promoted to `VERIFIED` and valid under schema.
- All 3 expert reviewers APPROVE.
