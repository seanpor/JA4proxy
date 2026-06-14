---
phase: 232a
title: Frontend Asset Vendoring & Static Compilation
status: COMPLETE
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [231]
---

# Frontend Asset Vendoring & Static Compilation

> **STATUS: COMPLETE**
> Part 1 of 4 of the split Phase 232. Deals with securing frontend assets by vendoring JS libraries locally and compiling static CSS, eliminating CDN dependencies.

## Goal

Vendor all third-party JavaScript dependencies (`htmx.min.js`, `htmx-sse.js`, `alpinejs.min.js`, `chart.umd.min.js`) into `management/static/vendor/` and compile static CSS via the Tailwind CSS CLI. Eliminate all remote CDN scripts and stylesheet links in the HTML base template and add a Content Security Policy (CSP) header, ensuring the Management Console can run fully offline and is secure against CDN supply-chain attacks.

## Scope

### Files to create/modify:
- [management/templates/base.html](../../../management/templates/base.html)
- [management/static/vendor/CHECKSUMS.txt](../../../management/static/vendor/CHECKSUMS.txt)
- [management/static/input.css](../../../management/static/input.css)
- [tailwind.config.js](../../../tailwind.config.js)
- [docs/OPERATIONS_GUIDE.md](../../../docs/OPERATIONS_GUIDE.md)

### Out of scope:
- Dashboard status widgets or situation bar html templates (deferred to 232b).
- Docker compose port changes (deferred to 232c).
- Removal of the `admin-api` container (deferred to 232d).

## Implementation Plan

1. **Create Vendor Directory**: Create `management/static/vendor/` to house the static assets.
2. **Download Frontend Libraries**:
   - Download `htmx.org@1.9.12` from unpkg to `management/static/vendor/htmx.min.js`.
   - Download `htmx-ext-sse@2.2.1` from unpkg to `management/static/vendor/htmx-sse.js`.
   - Download `alpinejs@3.14.0` from unpkg to `management/static/vendor/alpinejs.min.js`.
   - Download `chart.js@4.4.2` from jsdelivr to `management/static/vendor/chart.umd.min.js`.
3. **Verify Checksums**: Generate `CHECKSUMS.txt` containing the SHA256 hashes of the downloaded JS files and verify them against independent direct downloads.
4. **Compile Tailwind CSS**:
   - Create `management/static/input.css` containing the tailwind base directives.
   - Create `tailwind.config.js` at the repository root targeting the dashboard HTML templates.
   - Run `npx tailwindcss` CLI with `--minify` to output static `management/static/vendor/tailwind.css`.
5. **Update Base Template**:
   - Replace the CDN `<script>` and `<link>` tags in `management/templates/base.html` with the local vendored paths.
   - Add a Content Security Policy `<meta>` tag restricting script sources to `'self'`.
   - Remove the JIT inline `tailwind.config` configuration script block.
6. **Update Operations Guide**:
   - Modify `docs/OPERATIONS_GUIDE.md` to document that the Management Console now operates entirely self-contained without internet egress (allowing offline/air-gapped operation).

## Test Strategy

- **Static Asset Validation**: Assert that `tailwind.css` is successfully built and exceeds 100KB.
- **Page Rendering Verification**: Ensure that `tests/unit/test_pages.py` renders all routes correctly and verify via a new unit test that `base.html` contains zero CDN references (`unpkg.com`, `tailwindcss.com`, or `jsdelivr.net`).
- **Browser Developer Tools**: Load the console dashboard and confirm via the Network tab that zero external HTTP network calls are made for scripts/styles.

## Acceptance Criteria

- [ ] All four third-party JS libraries are vendored in `management/static/vendor/` with verified checksums.
- [ ] Tailwind CSS compiles cleanly to `management/static/vendor/tailwind.css`.
- [ ] `base.html` contains a CSP script-src `'self'` header and is completely free of CDN URLs.
- [ ] [docs/OPERATIONS_GUIDE.md](../../../docs/OPERATIONS_GUIDE.md) is updated to document the new offline capability.
- [ ] `make test` passes with zero errors/warnings.
