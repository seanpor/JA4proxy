# Phase 129: White-Box User Acceptance Testing (UAT)

> **Status:** IN_PROGRESS
> **Size:** MEDIUM
> **Depends on:** Phases 123-128
> **Owner:** Gemini CLI

## Goal

Perform a comprehensive "White-Box" UAT of the production Go proxy stack. This phase verifies that the security remediations and operational hardening implemented in Phases 123-128 function correctly in a live environment. We will trace specific traffic paths from entry to backend/enforcement, verifying logs, Redis state, and metric updates at each step.

## Scope

### Components in Scope
- **JA4proxy (Go)**: Connection handling, TLS reassembly, JA4 computation, SNI sanitization.
- **Security Pipeline**: Scored signals, dial enforcement, bypass logic.
- **State Store (Redis)**: Signed dial verification, signal storage, ban/block lists.
- **Observability**: Structured logging (logrus), Prometheus metrics, Cardinality Guard.

### Out of Scope
- Multi-DC synchronization (focus on single-node correctness).
- Performance benchmarking (covered in previous ad-hoc tasks).

---

## Implementation Plan

### Wave 1: Environment & "Good Path" Trace
*Focus: Verifying successful delivery of clean traffic.*

| ID | Task | Description |
|---|---|---|
| **129.1** | **Stack Ignition** | Start the POC stack with a known-good configuration. |
| **129.2** | **Trace: Clear TLS** | Send a valid, whitelisted TLS ClientHello; verify backend reachability and "allow" decision in logs. |
| **129.3** | **Trace: SNI Pass** | Verify that a valid SNI (e.g., `example.com`) is correctly extracted and logged. |

### Wave 2: Security Enforcement Trace
*Focus: Verifying "Hard" blocks and reassembly.*

| ID | Task | Description |
|---|---|---|
| **129.4** | **Trace: Fragmented CH** | Send a fragmented ClientHello across multiple records; verify successful reassembly and JA4 computation. |
| **129.5** | **Trace: JA4 Blacklist** | Add a JA4 to the Redis blacklist; verify immediate TCP RST on connection. |
| **129.6** | **Trace: Malformed SNI** | Send an invalid SNI hostname; verify it triggers the "malicious_sni" signal and score. |

### Wave 3: Behavioral & State Integrity
*Focus: Verifying dynamic enforcement and Redis safety.*

| ID | Task | Description |
|---|---|---|
| **129.7** | **Trace: Rate Limit** | Flood a specific JA4/IP; verify transition from ALLOW -> TARPIT -> BAN in Redis and logs. |
| **129.8** | **Trace: Signed Dial** | Manually tamper with the `config:dial` key in Redis without a signature; verify proxy fails closed to Dial 0. |

---

## Verification & Reporting

### UAT Report Template
The final output will be a **UAT Trace Report** containing:
1. **Timestamped Log Snippets** for each scenario.
2. **Redis `GET/TTL` results** proving state updates.
3. **Backend Access Logs** proving traffic delivery (or lack thereof).
4. **Final Verdict** for each traceability path.

---

## Acceptance Criteria

- [ ] All 8 trace scenarios (129.2 - 129.8) pass successfully.
- [ ] No panics or unhandled errors observed in proxy logs during UAT.
- [ ] Redis state matches the documented security logic for every enforcement action.
- [ ] A final "White-Box UAT Report" is generated and committed to `docs/reports/`.
