# Management UI — vendored front-end assets

The Management UI self-hosts all front-end assets (no CDN, no external fetch) so
the console works in an air-gapped DMZ and makes no third-party calls. This file
records the provenance of each vendored asset; `SHA256SUMS` pins their content and
`tests/unit/test_vendored_assets.py` fails the build if a committed asset drifts
from its recorded hash (tamper / accidental-edit guard).

| File | Library | Version | Upstream source |
|------|---------|---------|-----------------|
| `alpine.min.js` | Alpine.js | 3.14.0 | https://cdn.jsdelivr.net/npm/alpinejs@3.14.0/dist/cdn.min.js |
| `htmx.min.js` | htmx | 1.9.12 | https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js |
| `sse.js` | htmx Server-Sent-Events extension | (htmx 1.9.x) | https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/ext/sse.js |
| `chart.umd.min.js` | Chart.js | 4.4.2 | https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.js |
| `custom.css` | first-party | — | hand-written (not vendored; not hashed) |
| `tailwind.css` | Tailwind CSS (pre-built, purged) | built locally | see below — generated, not vendored |

## Tailwind CSS — built, not the runtime "Play" build

`tailwind.css` is a **pre-built, purged** stylesheet (~27 KB), generated from the
template classes. It replaces the old `tailwind.min.js` Play/runtime build (407 KB),
which compiles CSS in the browser and is explicitly **not for production**.

Rebuild after changing templates:

```bash
cd management/tailwind
npx tailwindcss@3 -c tailwind.config.js -i input.css -o ../static/tailwind.css --minify
```

(The Tailwind theme colours live in `tailwind.config.js` — they used to be an inline
`tailwind.config` `<script>` in `base.html`.)

## Updating a vendored library

1. Download the exact pinned version from the upstream URL above.
2. Replace the file under `management/static/`.
3. Recompute and update `SHA256SUMS`:
   `cd management/static && sha256sum alpine.min.js chart.umd.min.js htmx.min.js sse.js > SHA256SUMS`
4. Bump the version in this table and re-run `pytest tests/unit/test_vendored_assets.py`.
5. Check the new version against known-CVE advisories: `make scan-js` (retire.js).
   This also runs in CI (the Security Scan job) and fails on a vulnerable lib.
