# Accessibility Hardening & Infrastructure Documentation

## Goal

Automate accessibility verification of the management console HTML pages in the CI pipeline and deliver updated, accurate deployment topology documentation. This phase establishes a test gate to detect WCAG 2.1 AA violations using axe-core scanners, and ensures all codebase and configuration directories cited in operator manuals match the actual repository structure.

---

## A — Automated Accessibility Testing

Implement automated accessibility (a11y) checks:
- Set up a testing fixture in Python using `pytest-playwright` or equivalent headless browser testing tool integrated with `axe-core`.
- Add an integration test that logs into the management UI and runs the axe scanner against the core views:
  - Dashboard
  - IP and Fingerprint Drill-down pages
  - Settings and Ban Management pages
- Configure the scanner to assert zero critical/high accessibility violations (following WCAG 2.1 AA guidelines).

---

## B — HTML/CSS a11y Remediation

Address any accessibility findings discovered by the scanner:
- Ensure all interactive elements have valid focus indicators, aria-labels, and explicit role definitions.
- Ensure form inputs (like TOTP token verification and IP ban inputs) have corresponding `<label>` tags.
- Correct contrast ratios on the dark/light glassmorphic UI elements to meet minimum readability standards.

---

## C — Deployment Topology & Operator Docs Update

Review and correct operational documentation:
- Audit `docs/runbooks/management_ui.md` and all related files, ensuring every path matches the repository structure.
- Correct any occurrences of stale `JA4proxy2` paths.
- Document the single-pane architecture showing the connection flow from HAProxy, Go proxy, Redis, and the FastAPI console.

---

## Acceptance Criteria

- [ ] Automated a11y test scanner is integrated into the test suite and runs during `make test`.
- [ ] Core HTML templates pass the axe-core scan with zero WCAG 2.1 AA compliance violations.
- [ ] Documentation contains no references to incorrect checkout directories (like `JA4proxy2`).
- [ ] No remote CDN paths or scripts are added to base HTML templates.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/tests/test_accessibility.py` | New file — Automated Playwright/Axe UI scanner |
| `docs/runbooks/management_ui.md` | Update — Correct operational paths and single-pane description |
| `management/templates/base.html` | Update — Add landmarks, correct contrast, focus styling, and aria tags |
| `CHANGELOG.md` | Add Phase 328 entry |
