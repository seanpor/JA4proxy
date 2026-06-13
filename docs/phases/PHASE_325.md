# Fingerprint & IP Drill-Down Pages

## Goal

Implement the detail drill-down pages for specific IP addresses and JA4 fingerprints in the management console. Leverage existing API routes (e.g. `/api/v1/connections` and `/api/v1/fingerprints/{ja4}`) instead of inventing redundant endpoints. Perform geo-location and ASN lookups using the local MaxMind GeoLite2 MMDB files with clean error boundaries to prevent page rendering failures.

---

## A — UI Drill-down Templates

Create the HTMX-driven drill-down views:
- **IP Detail Page (`/ip/{ip}`):** Displays connection history, current risk score, active ban status, and MaxMind geo/ASN details.
- **Fingerprint Detail Page (`/fingerprint/{ja4}`):** Displays the breakdown of the JA4 parts (e.g. TLS version, ciphers, extensions) and a list of client IPs seen using this fingerprint.
- Make all IP and fingerprint strings in tables clickable links to their respective detail views.

---

## B — GeoIP & ASN Integration

Implement the backend lookup logic for IP attributes:
- Retrieve MaxMind database paths from config settings (e.g. `config/GeoLite2-ASN.mmdb` or environment variables).
- Use the `maxminddb` Python reader to retrieve country and ASN details.
- If MaxMind files are missing or unreadable, log the issue and fall back to displaying "Unknown" for country/ASN, rather than throwing a `FileNotFoundError` or crashing the API.

> ℹ️ **Use the existing `fp:*` fingerprint store — do not reinvent it.** Phase 20
> (TAP mode, COMPLETE) populates exactly the structures this page needs:
> `fp:ip:{ip}` (ZSET of fingerprints seen per IP), `fp:ja4:hll:{ja4}` (unique-IP
> estimate per JA4), and `fp:ja4_to_ja4s:{ja4}`. These are **not retired**; an
> earlier draft of this plan wrongly told implementers to avoid them. The
> "client IPs seen using this fingerprint" list and the JA4-parts breakdown
> should be sourced from `FingerprintStore` (`src/tap/fingerprint_store.py`),
> which already exposes this data. Only fall through to a capped
> `events:connection` scan (section C) for recent *connection history* that the
> fingerprint store does not retain. Confirm which `fp:*` keys are live in your
> deployment (TAP mode may be disabled) and degrade gracefully if absent.

---

## C — Connection History Search

To show recent connection logs for an IP or fingerprint, query the unified `events:connection` Redis stream:
- Scan the latest entries in the stream, filter by the target IP or fingerprint, and return the filtered list.
- Because Redis stream filtering requires client-side iteration, cap the stream scan size (e.g., last 1,000 events) to prevent blocking the Redis event loop.

---

## D — Page Rendering and Error Tests

Extend the test suite:
- `management/tests/test_pages.py` — Add tests to:
  - Mock MaxMind database responses and assert country/ASN appear on GET `/ip/{ip}`.
  - Verify that missing MMDB files do not cause GET `/ip/{ip}` to fail with `500 Internal Server Error` (fail-open/fail-gracefully design).
  - Assert GET `/fingerprint/{ja4}` returns `200` and displays the correct JA4 structure.

---

## Acceptance Criteria

- [ ] GET `/ip/{ip}` and GET `/fingerprint/{ja4}` render successfully with `200 OK` when authenticated.
- [ ] IP detail lookup falls back to "Unknown" when MaxMind MMDB files are absent or corrupted.
- [ ] Clicking a JA4 fingerprint on the main dashboard redirects the user to the corresponding `/fingerprint/{ja4}` view.
- [ ] No performance degradation (blocking calls) is observed when loading history from `events:connection`.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/templates/ip_detail.html` | New template — IP address details and connection logs |
| `management/templates/fingerprint_detail.html` | New template — JA4 fingerprint structure breakdown |
| `management/api/routes/detail.py` | New file — Detail views API handlers (handling IP and fingerprint detail calls) |
| `management/tests/test_pages.py` | Add integration tests for detail rendering and MMDB fallback |
| `CHANGELOG.md` | Add Phase 325 entry |
