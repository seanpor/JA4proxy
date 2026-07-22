# Phase 512 — PDF Documentation Sync (Phase 511 changes)

## Status: OPEN

## Summary

Phase 511 changed how operators access JA4proxy in the field — SSH tunnel + HTTPS
dashboard, `make traffic-on/off`, pre-built GHCR images, and a Caddy TLS sidecar.
The three PDF documents (brochure, user-guide, reference-manual) have not been
updated and still describe the old `http://localhost:8090` pattern, `docker compose build`,
and a compose service table that predates the Caddy sidecar.

This phase syncs all three LaTeX documents to match current reality, then rebuilds
the PDFs so they are usable for offline reading by operators and evaluators.

---

## Why Now?

The PDFs are the offline deliverables operators download, print, and use in change
advisory board packs. A SecOps engineer deploying at 2am will reference the user
guide. If it says "open `http://localhost:8090`" they will fail. Phase 511 fixed
the runbook and EMERGENCY_DEPLOY.md; this phase closes the same gap in the PDFs.

---

## Scope — What Changed in Phase 511

### New infrastructure
- **Caddy TLS sidecar** (`management-tls`) listening on `127.0.0.1:8444`
- **Pre-built GHCR images** — `docker compose pull` works, no build step needed
  - `ghcr.io/seanpor/ja4proxy-go:main`
  - `ghcr.io/seanpor/ja4proxy-management:main`
- **`make traffic-on` / `make traffic-off`** — iptables PREROUTING redirect :443→:8443

### New primary dashboard URL
- Old: `http://localhost:8090` (broken remotely, HTTP)
- New: `https://127.0.0.1:8444` (HTTPS via Caddy, self-signed, tunnel-safe)
- Fallback: `http://127.0.0.1:8090` (still works locally)

### New emergency deploy pattern
- Old: `docker compose build && docker compose up -d` (requires build tools on host)
- New: `docker compose pull && docker compose up -d` (pre-built images, 30 seconds)

### New CLI tool
- `./scripts/ja4-admin.sh` is now the documented CLI for blocking fingerprints and
  adjusting the dial (was: raw `redis-cli` + `kill -HUP` in older docs)

---

## Acceptance Criteria

- [ ] All three PDFs build cleanly via `make -C docs/pdf all` (no LaTeX errors)
- [ ] No occurrence of `http://localhost:8090` in any `.tex` file (use `http://127.0.0.1:8090` or `https://127.0.0.1:8444`)
- [ ] Emergency deploy sections use `docker compose pull` not `docker compose build`
- [ ] Port table in user-guide ch02 includes port 8444 (Caddy/HTTPS) and 8443 (proxy public)
- [ ] Compose services table in reference-manual ch08 includes `management-tls` row
- [ ] SSH tunnel access pattern is documented in user-guide ch07 (incident response)
- [ ] `make traffic-on` / `make traffic-off` are described where traffic cutover is discussed
- [ ] GHCR image names documented in ch02 (installation) and ch08 (deployment reference)
- [ ] `ja4-admin.sh` replaces raw `redis-cli` one-liners in the emergency blocking section of ch07
- [ ] News fragment added under `docs/fragments/phase-512-pdf-sync.md`
- [ ] `manifest.yaml` updated to COMPLETE

---

## Files to Change

### User Guide (`docs/pdf/user-guide/chapters/`)

#### ch02-installation.tex (Installation)
- Port table: add rows for 8443 (proxy public TLS entry point) and 8444 (management HTTPS/Caddy).
  Update 8081→8443 (the quick-start compose file uses 8443, not 8081). Change 8090 description
  to include "(plain HTTP, loopback only — access via SSH tunnel)".
- "Local Development" section (Step 3 `make start`): note that `docker compose pull` fetches
  pre-built images from GHCR, no compile step needed. Add the image names in a note box.
- Verifying section: change `curl -s http://localhost:9090/health` to
  `http://127.0.0.1:8090/api/v1/health` (matching EMERGENCY_DEPLOY.md).
- Change `http://localhost:3000` → `http://127.0.0.1:3000` (minor — keep consistent with other chapters).

#### ch03-first-steps.tex (First Steps)
- Line 151: change `http://localhost:3000` → `http://127.0.0.1:3000` (Grafana).
- Add a note in the "opening the dashboard" section: the management dashboard is at
  `https://127.0.0.1:8444` (or `http://127.0.0.1:8090`); if working remotely, set up an SSH
  tunnel first — see Chapter 7.

#### ch06-monitoring.tex (Monitoring)
- Table lines 27-30: change all `localhost` → `127.0.0.1`. These are loopback-only services
  and corporate web proxies intercept `localhost` URLs.
- Line 36: change `http://localhost:9090` → `http://127.0.0.1:9090`.
- Line 44: change `http://localhost:3000` → `http://127.0.0.1:3000`.

#### ch07-incident-response.tex (Incident Response) — biggest changes
This chapter currently assumes you're physically on the server. The real use case is Colin
at 2am on a laptop over VPN. Add a new **§ Remote Access** section at the top of the chapter
(before "Detecting an Active Attack"):

```
\section{Accessing the Dashboard Remotely}
Corporate DMZ hosts are not directly accessible from a laptop browser.
Use an SSH port-forward to the management dashboard:
  ssh -J you@bastion you@dmz-host -L 8090:127.0.0.1:8090 -L 8444:127.0.0.1:8444 -N &
Then open: https://127.0.0.1:8444 (certificate warning expected — click through).
For the full procedure including two-DC setups, see docs/runbooks/dashboard_access.md.
```

- **Emergency Blocking — block a fingerprint**: replace the `kill -HUP` + `config/proxy.yml`
  flow with the `ja4-admin.sh` pattern as the primary path (immediate, no file edit):
  ```bash
  ./scripts/ja4-admin.sh block-ja4 t13d0912_a1b2c3d4e5f6_987654321abc
  ```
  Retain the Redis-direct tip box and config-file method as "persistent blocking" alternatives.

- **Traffic cutover**: add a new subsection "Inserting JA4proxy into the Live Traffic Path"
  after the dial section:
  ```bash
  make traffic-on    # inserts iptables PREROUTING redirect :443→:8443
  make traffic-off   # instant rollback
  ```
  Note that this requires `sudo iptables` on the DMZ host. If not available, see
  EMERGENCY_DEPLOY.md for HAProxy backend swap and DNS cutover alternatives.

- **Emergency deploy**: add a subsection note at the top (or in a tip box) that if JA4proxy
  is not yet deployed, use `docker compose pull && docker compose up -d` — pre-built images
  from GHCR, no build step, ~30 seconds.

- h2/h1 safety guarantee: add a callout box with the "Real browsers cannot be blocked"
  statement (mirrors the one in EMERGENCY_DEPLOY.md). This is what ops need to say on the
  incident call to reassure stakeholders.

#### ch05-operations.tex (Day-to-Day Operations)
- `kill -HUP` pattern: replace with `./scripts/ja4-admin.sh reload` (if that command exists)
  or `docker compose kill -s HUP ja4proxy` (simpler, doesn't need PID file). The
  `cat /var/run/proxy.pid` approach is fragile if the container is not using a PID file.

---

### Reference Manual (`docs/pdf/reference-manual/chapters/`)

#### ch08-deployment-ref.tex (Deployment Reference)
- Services table: add `management-tls` row (image: `caddy:2-alpine`, ports: `127.0.0.1:8444:8444`,
  role: "HTTPS TLS sidecar for management dashboard; auto-generated self-signed cert via Caddy").
- Update `proxy` service row: port `127.0.0.1:8080:8080` → `0.0.0.0:8443:8443` (quick-start
  compose maps the proxy port publicly so real traffic can reach it).
- Add a note about pre-built GHCR images:
  ```
  Both ja4proxy-go and ja4proxy-management are published to GHCR on every merge to main.
  docker compose pull fetches them automatically — no build tools required on the host.
  ```
- Add `make traffic-on` / `make traffic-off` to the "traffic insertion" section (or add such
  a section if it doesn't exist). Cross-reference EMERGENCY_DEPLOY.md.

#### ch05-metrics.tex (Metrics)
- Change `localhost` → `127.0.0.1` in URL references (cosmetic but consistent).

#### ch10-compliance.tex (Compliance)
- Change `localhost` → `127.0.0.1` in URL references.

---

### Brochure (`docs/pdf/brochure/brochure-body.tex`)

- Scan for `localhost` or `8090`: replace with `127.0.0.1` where found.
- No structural changes needed — the brochure doesn't go into operational detail.

---

## Implementation Notes

### Build environment

```bash
# Check LaTeX is available
which pdflatex && pdflatex --version

# Build all three PDFs
make -C docs/pdf all

# Build just one for rapid iteration
make -C docs/pdf user-guide
```

If `pdflatex` is not installed: `sudo apt install texlive-latex-extra texlive-fonts-recommended`.

The PDFs are committed to the repo. Run `make -C docs/pdf all` and `git add` the three
`.pdf` files along with the `.tex` source changes.

### Style conventions

Follow the existing LaTeX conventions in each document:
- `\code{command}` for inline commands
- `\bashcode` environment for shell blocks
- `\yamlcode` for YAML blocks
- `\url{}` for clickable URLs
- `\tipbox`, `\notebox`, `\warningbox`, `\dangerbox` for callout boxes

### What NOT to change

- The `localhost:3000` / `localhost:9091` / `localhost:9093` pattern in ch06 **for the
  full stack** (POC deploy) is correct — those services are not available in the quick-start
  compose. Change to `127.0.0.1` for consistency, but don't imply they're accessible
  in an emergency deploy that only starts the quick-start stack.
- Don't rewrite the full monitoring chapter — Phase 511 doesn't change Prometheus or Grafana.
- Don't update ch08 service image versions (that's a separate maintenance task).

---

## Open Questions

None — Phase 511 is complete and its outputs are stable. The PDF content is a direct
transcription of the runbooks and compose files already merged to main.

---

## Effort Estimate

- ch07 (incident response): ~2 hours — adds new sections, rewrites blocking procedure
- ch02 (installation) + ch08 (deployment): ~1 hour — port table + services table updates
- ch03, ch05, ch06, ch10 + brochure: ~45 minutes — mostly `localhost` → `127.0.0.1` + minor additions
- PDF builds + review: ~30 minutes

**Total: ~4 hours.**
