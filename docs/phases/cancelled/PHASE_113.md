# Phase 113 — Proxy Stability & Audit Instrumentation

> **Status:** PROPOSED
> **Size:** SMALL (3-4 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L1-015], [L1-016], [L4-022]

---

## Goal

Ensure the proxy remains stable under resource-exhaustion attacks and ensure all security-critical actions are audited.

---

## 113a. Bounded Beaconing Sets

### Problem
`beacon:{ip}:{ja4}` sorted sets in Redis can grow indefinitely, causing memory exhaustion.

### Fix
1.  In `internal/security/beaconing_detector.go`, add a `ZREMRANGEBYRANK` command after every `ZADD`.
2.  Maintain only the most recent `N` entries (e.g., 50). This is sufficient for the sliding-window analysis while preventing OOM.

---

## 113b. Non-Blocking Tarpit Handler

### Problem
The proxy goroutine can block indefinitely if the tarpit server is slow or saturated, leading to connection pool exhaustion.

### Fix
1.  In `cmd/proxy/main.go:tarpit`, use a `context.WithTimeout` for all writes to the `tarpitConn`.
2.  Implement the bidirectional copy using a small buffer and a select loop that closes the connection if the backend tarpit fails to consume data within 1 second.

---

## 113c. Complete Token Auditing

### Problem
Token mutations (create/delete/rotate) are not recorded in the management audit log.

### Fix
1.  In `management/api/routes/tokens.py`, add `write_audit` calls to the `POST`, `DELETE`, and `PATCH` (rotate) endpoints.
2.  Ensure the audit record includes the token name, ID, and the role associated with it.

---

## Acceptance Criteria
- [ ] Test: Saturated tarpit server does not cause the Go proxy's `activeConns` to spike or block.
- [ ] Test: Flooding TLS handshakes from one IP; verify Redis `ZCARD` for the beacon set never exceeds 50.
- [ ] Test: Rotate an API token and verify the action appears in the Audit UI.
