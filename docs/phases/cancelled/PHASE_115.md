# Phase 115 — Web & Rendering Security

> **Status:** PROPOSED
> **Size:** SMALL (2-3 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L4-026], [L4-027]

---

## Goal

Secure the management plane against client-side injection attacks and Server-Side Request Forgery (SSRF) during report generation.

---

## 115a. HTML Escaping for HTMX Partials

### Problem
The `list-table` HTMX partial interpolates the `list` parameter directly into an error message, leading to Reflected XSS.

### Fix
1.  In `management/api/routes/partials.py`, import `html` and use `html.escape()` on the `list` parameter before interpolating it into the response content.
2.  Update the UI to handle 400 errors via HTMX `hx-on:htmx-response-error` rather than relying on the server to send rendered HTML for error states.

---

## 115b. Secure WeasyPrint URL Fetcher

### Problem
`WeasyPrint` allows external URL and local file fetching by default, leading to SSRF/LFI when rendering SVG logos.

### Fix
1.  In `management/compliance/report_renderer.py`, implement a custom `url_fetcher` function.
2.  The fetcher must only allow `data:` URIs (for logos).
3.  Any URL starting with `http://`, `https://`, or `file://` must be rejected with a security exception.
4.  Pass this fetcher to `weasyprint.HTML(..., url_fetcher=safe_fetcher)`.

---

## Acceptance Criteria
- [ ] Test: GET `/api/v1/partials/list-table?list=<script>alert(1)</script>`; verify the response body contains escaped entities (`&lt;script&gt;`).
- [ ] Test: Attempt to generate a report with an SVG logo containing an `<image href="http://169.254.169.254/">` tag; verify the report generation fails or the image is blocked.
- [ ] Test: Verify legitimate base64 PNG/SVG logos still render correctly in the PDF.
