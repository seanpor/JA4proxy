# Phase 111 — Security Logic & Tarpit Hardening

> **Status:** PROPOSED
> **Size:** SMALL (2-3 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L7-001]

---

## Goal

Improve the robustness of the security actions, specifically the tarpit overflow and the handling of non-TLS traffic.

---

## 111a. Tarpit Overflow "Fail-Closed" Policy

### Problem
If the tarpit is full and `overflowAction` is `allow`, attackers can bypass the tarpit by saturating it.

### Fix
Modify `cmd/proxy/main.go:tarpit`:
1.  Introduce a `risk_threshold` for the tarpit.
2.  If the tarpit is full:
    *   If the connection's `risk_score` is > `TarpitHardThreshold` (e.g. 50), the overflow action must be **BLOCK**, regardless of the `overflowAction` setting.
    *   Only "Low Risk" traffic may fall through to `allow` if configured.

---

## 111b. Non-TLS Traffic Enforcement

### Problem
JA4proxy forwards non-TLS traffic if it doesn't match a block rule, even if it's not recognizable.

### Fix
1.  Introduce a `BlockNonTLS` configuration flag (default: `false` for compatibility, but `true` for strict security).
2.  If `BlockNonTLS` is `true`, any connection that fails `tlsparse.ParseClientHello` and is not part of a bypass (like mTLS or a whitelist) should be **BLOCKED** instead of forwarded.

---

## 111c. Compliance Route Hardening

### Problem
`DSAR` and `Erasure` routes are vulnerable to Redis glob/regex injection via the `ip` parameter.

### Fix
1.  **Strict IP Validation**: Ensure the `ip` parameter in `dsar_export` and `dsar_erasure` is a valid single IP address (using `ipaddress` module) before using it in any Redis `SCAN` or `KEYS` pattern.
2.  **Escape Glob Chars**: If `SCAN` is used, escape any Redis glob characters (`*`, `?`, `[`, `]`) in the input.

---

## 111d. Secure JWT Secret Handling

### Problem
Management API falls back to a hardcoded insecure secret.

### Fix
1.  Remove the hardcoded fallback secret in `management/api/auth.py`.
2.  On startup, if `MANAGEMENT_JWT_SECRET` is missing, the API must fail to start (raise `RuntimeError`), unless `MANAGEMENT_DEV_MODE=1` is explicitly set.

---

## Acceptance Criteria
- [ ] Test: GET `/api/v1/compliance/dsar/*`; must return 422 or 400 (Invalid IP).
- [ ] Test: Start Management API without `MANAGEMENT_JWT_SECRET`; process must exit with error.
- [ ] Test: Saturated tarpit; low-risk connection (score 10) is ALLOWED if configured.
- [ ] Test: `BlockNonTLS: true`; sending raw HTTP to the proxy results in a connection RST.
