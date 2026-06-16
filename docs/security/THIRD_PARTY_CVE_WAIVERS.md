<!--
title: Third-Party Image HIGH-CVE Waiver Register
audience: Security, Operators, DevOps
last_reviewed: 2026-06-13
phase: 314
-->

# Third-Party Image HIGH-CVE Waiver Register

> **Purpose.** Honest, enumerated tracking of the **HIGH**-severity CVEs that
> remain in the pinned third-party container images because **no newer fixed
> upstream tag exists yet** — i.e. we cannot remediate them by bumping a tag or
> changing our own code. These are *reported* by `make scan-images` but do **not**
> gate the build (third-party images gate on **CRITICAL** only). This register
> keeps that advisory posture transparent rather than silently ignored.
>
> This is **not** a `.trivyignore` file. `.trivyignore` suppresses *gating*
> findings (CRITICAL on third-party / HIGH on first-party + Dockerfiles) and is
> capped at a 14-day window. This register tracks *advisory* HIGH findings whose
> only fix is an upstream image rebuild we don't control.

See [PHASE_314](../phases/PHASE_314.md) for the full background and the
differentiated-gating decision.

## Why these can't just be "bumped away"

The fresh Trivy scan (2026-06-13, `aquasec/trivy:0.71.0`, `--severity HIGH,CRITICAL`)
showed that **7 of 9** pinned third-party images are **already on their newest
stable tag**. Their HIGH findings are:

1. **Brand-new Go-stdlib CVEs** (e.g. `CVE-2026-42504`, fixed only in Go **1.26.4**,
   released days before this scan). The Go-based images (`node-exporter`,
   `prometheus`, `loki`, `promtail`, `grafana`) are built against older Go and
   will clear only when **upstream rebuilds** against 1.26.4+.
2. **Distro package patches** (`openssl`/`gpgv` in the Ubuntu/Debian-based images)
   awaiting an upstream base-image rebuild.
3. **A few genuinely-unfixed CVEs** with no upstream patch at any version yet
   (e.g. the `docker/docker` findings in `promtail`).

The two images that **did** have a fixed newer tag were bumped in this phase and
are **no longer** in this register:

- `prom/alertmanager` `v0.32.1` → **`v0.33.0`** (clears otel + Go-stdlib HIGH)
- `oliver006/redis_exporter` `v1.84.0` → **`v1.86.0`** (clears Go-stdlib HIGH)

## Register

Recheck date below = **2026-06-27** for all entries (re-scan fortnightly; bump any
image whose upstream has since shipped a fixed tag, then remove its row).

| Image (pinned) | CVE(s) | Package | Upstream fix status | Recheck |
|---|---|---|---|---|
| ~~`redis/redis-stack:7.4.0-v8`~~ | ~~CVE-2025-68973~~ | ~~`gpgv`~~ | ~~Fixed in Ubuntu base; awaiting redis-stack rebuild~~ | ~~2026-06-27~~ |
| ~~`redis/redis-stack:7.4.0-v8`~~ | ~~CVE-2026-45447~~ | ~~`libssl3`, `libssl-dev`~~ | ~~Fixed in OpenSSL; awaiting redis-stack rebuild~~ | ~~2026-06-27~~ |
| `redis:7.4.0-alpine` | — | — | Replaced `redis/redis-stack` — Phase 233; no CVE waivers required for this image | 2026-06-15 |
| `prom/prometheus:v3.12.0` | CVE-2026-42504 | Go `stdlib` | Fixed in Go 1.26.4; awaiting upstream rebuild (already newest tag) | 2026-06-27 |
| `prom/node-exporter:v1.11.1` | CVE-2026-32280/32281/32283/33810/33811/33814/39820/39823/39825/39836/42499/42504 | Go `stdlib` | Fixed in Go 1.25.9–1.26.4; awaiting upstream rebuild (already newest tag) | 2026-06-27 |
| `grafana/grafana:13.0.2-ubuntu` | CVE-2026-21728, CVE-2026-28377 | `grafana/tempo` | Fixed in tempo 2.8.4/2.9.2/2.10.2/2.10.3; awaiting grafana rebuild | 2026-06-27 |
| `grafana/grafana:13.0.2-ubuntu` | CVE-2026-42151 | `prometheus/prometheus` (lib) | Fixed in prometheus lib 0.311.3; awaiting grafana rebuild | 2026-06-27 |
| `grafana/grafana:13.0.2-ubuntu` | CVE-2026-45447 | `openssl`, `libssl3t64` | Fixed in Ubuntu OpenSSL `3.0.13-0ubuntu3.11`; awaiting grafana rebuild | 2026-06-27 |
| `grafana/grafana:13.0.2-ubuntu` | CVE-2026-33811/33814/39820/39823/39825/39836/42499/42504 | Go `stdlib` | Fixed in Go 1.25.10–1.26.4; awaiting grafana rebuild | 2026-06-27 |
| `grafana/loki:3.7.2` | CVE-2026-41602 | `apache/thrift` | Fixed in thrift 0.23.0; awaiting loki rebuild (already newest stable) | 2026-06-27 |
| `grafana/loki:3.7.2` | CVE-2026-42151, CVE-2026-42154 | `prometheus/prometheus` (lib) | Fixed in prometheus lib 0.311.3; awaiting loki rebuild | 2026-06-27 |
| `grafana/loki:3.7.2` | CVE-2026-33811/33814/39820/39823/39825/39836/42499/42504 | Go `stdlib` | Fixed in Go 1.25.10–1.26.4; awaiting loki rebuild | 2026-06-27 |
| `grafana/promtail:3.6.11` | CVE-2026-34040 | `docker/docker` | Fixed in moby 29.3.1; awaiting promtail rebuild (already newest stable) | 2026-06-27 |
| `grafana/promtail:3.6.11` | CVE-2026-41567, CVE-2026-42306 | `docker/docker` | **No upstream fix at any version yet** — monitor moby advisories | 2026-06-27 |
| `grafana/promtail:3.6.11` | CVE-2026-42151, CVE-2026-42154 | `prometheus/prometheus` (lib) | Fixed in prometheus lib 0.311.3; awaiting promtail rebuild | 2026-06-27 |
| `grafana/promtail:3.6.11` | CVE-2026-45447 | `openssl`, `libssl3t64` | Fixed in Ubuntu OpenSSL `3.0.13-0ubuntu3.11`; awaiting promtail rebuild | 2026-06-27 |
| `grafana/promtail:3.6.11` | CVE-2026-33811/33814/39820/39823/39825/39836/42499/42504 | Go `stdlib` | Fixed in Go 1.25.10–1.26.4; awaiting promtail rebuild | 2026-06-27 |

`haproxy:2.8.24-alpine` is HIGH/CRITICAL-clean and is not listed.

## Process

1. **Fortnightly** (or when Dependabot/the weekly scheduled scan flags movement),
   run `make scan-images` and `make scan-summary`.
2. For any image above whose upstream has shipped a fixed tag, **bump it** in
   `Makefile` (`TRIVY_IMAGES`) + the compose files + `docs/DOCKER_IMAGES.md`,
   re-scan to confirm, and **delete its row** here.
3. If a CVE here is ever upgraded by Trivy to **CRITICAL**, it stops being
   advisory — it gates `make scan-images` immediately and must be bumped or, if
   genuinely unfixable, given a dated `.trivyignore` entry per that file's policy.
4. These advisory HIGHs remain covered by the weekly scheduled scan and
   Dependabot; this register is the human-readable index, not a suppression.
