- **Phase 847g — clear `CVE-2026-111943` (Go `crypto/x509` MITM) from every image
  we build, and from four of the six we don't.** First-party bases moved to
  `golang:1.27.3-alpine` / `golang:1.26.10-alpine`, digest-pinned to the current
  multi-arch index; `make scan-first-party` is clean on all 8 images. The stale
  `Dockerfile.logtide` digest was a superseded index publication for the same
  tag, not a platform pin — all six now share one index digest.
- **Four third-party monitoring images bumped to tags that actually scan clean,
  each measured before and after rather than assumed to help**: `grafana/loki`
  3.7.7 → 3.7.9, `grafana/alloy` v1.19.2 → v1.21.2 (validated with `alloy
  validate` on both configs), `prom/prometheus` v3.15.0 → v3.15.1 (`promtool
  check config` + `check rules`), `oliver006/redis_exporter` v1.91.1 → v1.95.0
  (Ansible's `v1.86.0` pin too; `--help` flag set diffed, nothing removed).
- **Two surfaces have no fixed tag and are now waived with dates, not prose**:
  `grafana/grafana:13.2.4-ubuntu` and `prom/alertmanager:v0.34.1` are the newest
  published tags in their lines and are rebuilt by their publishers, not us —
  one `CVE-2026-111943` entry, `reachability: internal-monitoring-only`,
  expires 2027-01-21. `make scan-images` is 9/9 clean.
- **The waiver record shrank by ten**: the bumps cleared two Docker Engine CVEs
  in `grafana/alloy` and eight in `grafana/loki`, which were removed through
  `render_waivers.remove_entries` (the validated splice that refuses to narrow a
  carrier a surviving waiver still claims). Registry 37 → 28 entries.
