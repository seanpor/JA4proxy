# Phase 110 — Management API Security Hardening

> **Status:** PROPOSED
> **Size:** MEDIUM (5-7 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L4-001], [L4-002], [L4-003]

---

## Goal

Remediate critical and high-severity security vulnerabilities in the Management API authentication and request handling logic.

---

## 110a. CSRF Protection for Mutating Routes

### Problem
The API lacks CSRF protection, allowing cross-site attacks against logged-in administrators.

### Fix
1.  Implement a custom middleware in `management/api/auth.py` that enforces:
    *   **Same-Origin Policy**: Verify `Origin` or `Referer` headers for all mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`).
    *   **Custom Header**: Require a `X-CSRF-Token` header for all AJAX requests. The token can be stored in the JWT or a separate cookie.
2.  Update the Management UI (React) to include the token in all API calls.

---

## 110b. Secure Bearer Token Lookup (Bcrypt DoS Fix)

### Problem
Iterating through all tokens and calling `bcrypt.checkpw` on each is a major DoS vector.

### Fix
1.  **Hashed Lookup**: Instead of scanning, store tokens in Redis using a fast hash (SHA-256) of the token as the key (e.g., `mgmt:token:v1:<sha256(token)>`).
2.  **O(1) Verification**: The API can now perform a single Redis `HGETALL` to retrieve the token metadata.
3.  **Security**: Since the raw token is high-entropy, SHA-256 is sufficient for lookup. Bcrypt is redundant if the token itself is the secret.

---

## 110c. Trusted Proxy Validation for X-Forwarded-For

### Problem
The API blindly trusts `X-Forwarded-For`, allowing rate-limit bypass.

### Fix
1.  Add `MANAGEMENT_TRUSTED_PROXIES` (CIDR list) to the environment configuration.
2.  In `_client_ip`, only use `X-Forwarded-For` if the immediate `request.client.host` is in the trusted list.

---

## 110d. O(1) Health Check (Fix Redis Blocking)

### Problem
`/api/v1/health` uses `KEYS`, which blocks Redis.

### Fix
1.  **Switch to Heartbeat SET**: Proxy instances should add themselves to a `proxy:instances` SET with a TTL-based expiration for each instance's own key.
2.  **Use SCARD**: The health check should use `SCARD proxy:instances` to count live nodes. This is O(1) and safe.

---

## 110e. Webhook SSRF Protection

### Problem
Webhook URLs are not validated, allowing internal network probing.

### Fix
1.  Implement a `validate_webhook_url` helper in `management/api/routes/webhooks.py`.
2.  Reject any URL where the host resolves to a loopback, private, or link-local IP (RFC1918, RFC4193, RFC6598).
3.  Implement the same check in the Go `Dispatcher` before dialing.

---

## Acceptance Criteria
- [ ] Test: Attempt to create a webhook to `http://169.254.169.254/`; must return 400.
- [ ] Test: Flood `/api/v1/health` with 1000 req/s; Redis performance remains unaffected.
- [ ] Test: Perform 1000 concurrent requests with randomized bearer tokens; CPU usage must remain low (no Bcrypt storm).
- [ ] Test: Spoof `X-Forwarded-For` from an untrusted IP; the rate-limiter must correctly identify the real source IP.
