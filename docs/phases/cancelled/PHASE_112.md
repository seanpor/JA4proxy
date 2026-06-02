# Phase 112 — Session & Data Integrity Hardening

> **Status:** PROPOSED
> **Size:** MEDIUM (5-7 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L4-019], [L4-020], [L4-021]

---

## Goal

Remediate critical flaws in session management and data lifecycle to prevent arbitrary data deletion and session hijacking.

---

## 112a. Strict GDPR Erasure Validation

### Problem
The `dsar_erasure` endpoint allows glob characters like `*` in the IP parameter, enabling bulk deletion of the entire database.

### Fix
1.  Implement a strict IP validation middleware for all routes under `/api/v1/compliance/dsar/`.
2.  Use the `ipaddress` module to parse and normalize the input. If it is not a valid single IP, return 400/422 immediately.
3.  Ensure the Redis `SCAN` pattern is built using the normalized, escaped IP string.

---

## 112b. JWT Invalidation (JTI Blacklist)

### Problem
Logout only deletes the cookie; the server-side JWT remains valid until expiration (8 hours).

### Fix
1.  Add a `jti` (JWT ID) claim to all issued access tokens.
2.  In `auth.py:logout`, extract the JTI and expiry of the current token.
3.  Store the JTI in a Redis set `mgmt:token_blacklist` with a TTL matching the token's remaining lifetime.
4.  Update `get_current_user` to check this blacklist on every request.

---

## 112c. Reliable Audit Log (Redis Streams)

### Problem
The current `LTRIM` approach allows an attacker to "flush" evidence by flooding the log with 1000 entries.

### Fix
1.  Migrate `management:audit_log` from a LIST to a Redis STREAM.
2.  Use `XADD` with a `MAXLEN ~ 100000` (or higher) to provide a much larger, time-stable audit trail.
3.  Update the audit export logic to use `XREAD` / `XRANGE`.

---

## Acceptance Criteria
- [ ] Test: Attempt `DELETE /api/v1/compliance/dsar/*` returns 400.
- [ ] Test: Log out and attempt to use the old JWT cookie; must return 401.
- [ ] Test: Generate 2000 audit events; earlier events must still be present (verify stream length).
