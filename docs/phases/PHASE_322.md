# Security Foundations & Admin API Cleanup

## Goal

Hardens the management interface by removing legacy unauthenticated entry points and updating the console's health indicators to use real-world data points. This phase removes the unauthenticated proof-of-concept admin API, validates that only local vendored JavaScript assets are loaded, and updates the proxy status indicators to read live heartbeats from the actual `mgmt:node:*` Redis keys.

---

## A — Legacy App Deletion

Completely remove the legacy unauthenticated admin API code and its Docker entry point:
- Delete `src/management/app.py` (which served unauthenticated routes).
- Delete `deploy/docker/Dockerfile.admin`.
- Remove references to `Dockerfile.admin` or the `admin-api` container in all `docker-compose` YAML templates.
- Update documentation and build scripts to omit references to this container.

---

## B — local Vendored JavaScript Verification

Assert that no external CDNs are referenced in the console HTML template files.
- The console's template base (`management/templates/base.html`) must load only local assets from `/static/` (e.g. `/static/htmx.min.js`, `/static/tailwind.css`), which are audited and pinned via `VENDOR.md`.
- No files should attempt to write to non-existent directories such as `management/static/vendor/`.
- Verify the CSP header enforces local-only scripts.

---

## C — Real Health Situation Bar

Fix the UI's "situation bar" (which shows if the proxy is active or down) to read real heartbeat data:
- The backend handler must scan for `mgmt:node:*` in Redis, which is where the Go proxy daemon writes its instance status and updates its TTL.
- If no keys matching `mgmt:node:*` are present (or if all have expired), the situation bar displays "PROXY UNREACHABLE".
- If at least one active key is present, the situation bar reads "PROXY ACTIVE".
- Do not use invented keys like `proxy:heartbeat:*` or read from dead stream keys.

---

## D — Container Configuration & Page Rendering Tests

Implement the two mandatory test files for security/configuration changes:
- `tests/integration/test_container_config.py` — Assert that environment variables and Redis passwords propagate correctly to the management server container, and no legacy unauthenticated ports are exposed.
- `management/tests/test_pages.py` — Add tests verifying that:
  - GET `/` (Dashboard) with a valid token returns `200` content-type `text/html`.
  - GET `/` without a token returns a redirect/401, not a 500 error.
  - The situation bar successfully transitions status based on mock `mgmt:node:*` Redis states.

---

## Acceptance Criteria

- [ ] Files `src/management/app.py` and `deploy/docker/Dockerfile.admin` are deleted.
- [ ] No external CDN URLs exist in CSS or script tags in `management/templates/`.
- [ ] The situation bar reads "PROXY ACTIVE" when a `mgmt:node:test:8080` key exists in Redis and "PROXY UNREACHABLE" when empty.
- [ ] `tests/integration/test_container_config.py` and `management/tests/test_pages.py` are executed and pass.

---

## Files to Modify

| File | Change |
|------|--------|
| `src/management/app.py` | Delete file |
| `deploy/docker/Dockerfile.admin` | Delete file |
| `docker-compose.poc.yml` | Remove `admin-api` service |
| `docker-compose.prod.yml` | Remove `admin-api` service |
| `management/templates/partials/situation_bar.html` | Update status rendering logic to query `mgmt:node:*` |
| `management/tests/test_pages.py` | New file — HTML page rendering and RBAC tests |
| `tests/integration/test_container_config.py` | Modify — Add container port/privilege regression check |
| `CHANGELOG.md` | Add Phase 322 entry |
