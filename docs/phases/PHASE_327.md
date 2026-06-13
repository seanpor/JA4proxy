# Operational Workflows & Dial Audit Hardening

## Goal

Hardens the security-critical operational endpoints (dial adjustments, IP/CIDR banning) against unauthorized modification. Ensure the management UI interacts exclusively with the existing audited, signed, and MFA-protected endpoints (such as `PUT /api/v1/dial`). This sub-phase prevents security regressions, enforces CIDR matching via the single `ban_cidr:{cidr}` trie structure, and implements a secure, audited background-polling mechanism for dial auto-reversion.

---

## A — UI Integration with Audited Endpoints

Integrate frontend controls with existing API routes:
- Frontend dial adjustments must invoke `PUT /api/v1/dial` (which enforces TOTP verification, role checks, and the ±10 dial guard).
- All changes must write to the canonical security audit log (`write_audit`), recording the actor's details, OIDC/SAML token metadata, and timestamp.
- Do **not** bypass existing MFA/HMAC guards or implement direct Redis bypass overrides.

---

## B — Trie-based CIDR Banning

Enforce a strict policy on CIDR blocklist updates:
- When a user submits a subnet ban (e.g. `1.2.0.0/16`), the API must write a single key: `ban_cidr:1.2.0.0/16` with value `true`.
- The Go proxy daemon matches incoming connections against this CIDR trie structure.
- Do **not** expand subnets into individual IP keys (e.g. generating 65,536 keys for a `/16` ban), which would flood the Redis key space and degrade performance.

---

## C — Audited Dial Auto-Reversion

Implement a secure dial auto-revert mechanism:
- When a temporary dial override is requested (e.g. change dial value for 1 hour), the console writes an override record in Redis: `config:dial_override` (storing the original value, override value, and expiration epoch).
- Do **not** rely on Redis keyspace notifications, which are disabled by default and not persistent.
- Implement a background loop in the management console's worker/scheduler that polls `config:dial_override` every 10 seconds.
- Upon expiration, the background worker issues a standard `PUT /api/v1/dial` request using its system credentials, updating the value back to the original setting, writing to the security audit logs, and removing the override key.

---

## D — Audit and Auto-Revert Tests

Write comprehensive testing:
- `management/tests/test_dial.py` — Assert that dial modifications write valid audit logs and enforce guards.
- Add integration tests validating the auto-reversion background task:
  - Simulate setting an override, advancing time, and asserting that the revert task fires, returns the dial to the baseline, and logs the action under a system actor label.

---

## Acceptance Criteria

- [ ] All UI dial/ban modifications are processed through authenticated endpoints and write to the audit log.
- [ ] Subnet bans are stored as a single `ban_cidr:{cidr}` key, never exploded into individual IP keys.
- [ ] Auto-reversion successfully restores original dial values after expiration.
- [ ] The ±10 guard remains active and cannot be bypassed from the UI.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/api/routes/dial.py` | Add temporary override setup to `PUT` handler |
| `management/api/routes/bans.py` | Update IP/CIDR banning logic to use `ban_cidr:{cidr}` |
| `management/cron/auto_revert.py` | New file — Background polling task executing dial restorations |
| `management/tests/test_dial.py` | Update — Add test cases covering dial auto-reversion and CIDR trie updates |
| `CHANGELOG.md` | Add Phase 327 entry |
