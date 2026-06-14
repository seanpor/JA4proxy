# Management UI — vendored front-end assets

The Management UI self-hosts all front-end assets (no CDN, no external fetch) so
the console works in an air-gapped DMZ and makes no third-party calls. This file
records the provenance of each vendored asset; `vendor/CHECKSUMS.txt` pins their content and
`tests/unit/test_vendored_assets.py` fails the build if a committed asset drifts
from its recorded hash (tamper / accidental-edit guard).

| File | Library | Version | Upstream source |
|------|---------|---------|-----------------|
| `vendor/alpinejs.min.js` | Alpine.js | 3.14.0 | https://cdn.jsdelivr.net/npm/alpinejs@3.14.0/dist/cdn.min.js |
| `vendor/htmx.min.js` | htmx | 1.9.12 | https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js |
| `vendor/htmx-sse.js` | htmx Server-Sent-Events extension | 2.2.1 | https://cdn.jsdelivr.net/npm/htmx-ext-sse@2.2.1/sse.js |
| `vendor/chart.umd.min.js` | Chart.js | 4.4.2 | https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.js |
| `custom.css` | first-party | — | hand-written (not vendored; not hashed) |
| `vendor/tailwind.css` | Tailwind CSS (pre-built, purged) | built locally | see below — generated, not vendored |

## Tailwind CSS — built, not the runtime "Play" build

`vendor/tailwind.css` is a **pre-built, purged** stylesheet, generated from the
template classes. It replaces the old `tailwind.min.js` Play/runtime build,
which compiles CSS in the browser and is explicitly **not for production**.

Rebuild after changing templates (requires `@tailwindcss/cli` v4):

```bash
npx @tailwindcss/cli -i ./management/static/input.css -o ./management/static/vendor/tailwind.css --minify
```

(The Tailwind theme configurations live in `tailwind.config.js` at the project root.)

## Updating a vendored library

1. Download the exact pinned version from the upstream URL above.
2. Replace the file under `management/static/vendor/`.
3. Recompute and update `CHECKSUMS.txt`:
   `cd management/static/vendor && sha256sum alpinejs.min.js chart.umd.min.js htmx.min.js htmx-sse.js > CHECKSUMS.txt`
4. Bump the version in this table and re-run `pytest tests/unit/test_vendored_assets.py`.
5. Check the new version against known-CVE advisories: `make scan-js` (retire.js).
   This also runs in CI (the Security Scan job) and fails on a vulnerable lib.
