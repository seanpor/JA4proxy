---
phase: 231a
title: Single-Host Core — PROXY-Protocol Write, Manual-Ban Enforcement, CountKeys Fix
status: COMPLETE
created: 2026-06-11
completed: 2026-06-11
audience: [developer]
---

# Single-Host Core (Go daemon)

> Split from the original monolithic Phase 231 proposal. **231a is the Go
> production-daemon work** — independently shippable and unit-testable. The
> installer/wizard/systemd/firewall bootstrapping is **[[PHASE_231b]]**, which
> depends on this.

## Goal

Three focused changes to `ja4pd` that the single-host deployment needs, each
valuable on its own:

1. **Write** PROXY protocol (v1/v2) to the backend so a passthrough deployment
   preserves the real client IP without TLS decryption.
2. **Enforce manual bans** in the connection pipeline so a `ban:{ip}` blocks
   immediately — *even in monitor mode (`dial: 0`)*.
3. **Fix** the `CountKeys` ban-prefix bug so the active-bans metric is real.

## Corrections applied vs the original Phase 231 proposal (from review)

- **Ports:** the original cited `8113` (Management UI), `3023` ("syncagent"),
  and flipped Prometheus `9090`/`9091`. The real scheme is **Management UI
  `8090`**, metrics `9090`, Prometheus `9091`, Grafana `3000` — and there is no
  `3023` service. Port handling lives in 231b and must **read `HOST_PORT_*` from
  `.env`**, not hard-code (per phase-310 + the "don't lock ports" directive).
- **GeoIP:** it's MaxMind **GeoLite2** (`GeoLite2-ASN.mmdb` /
  `GeoLite2-Country.mmdb`), not IP2Location. (231b.)
- **Tests are Go.** PROXY-write + pipeline-ban are Go features → Go tests
  (`cmd/ja4pd/*_test.go`, `internal/security/*_test.go`), **not**
  `tests/unit/test_proxy_protocol.py`.
- **Build on the existing inbound parser.** `ja4pd` already *parses & strips*
  inbound PROXY headers (trusted-CIDR gated; `ja4proxy_proxy_protocol_parser_events_total`,
  `JA4PROXY-2026-0001/0002`). 231a adds the *outbound write* — a different
  direction — and **reuses the already-resolved `connCtx.ClientIP/ClientPort`**
  so the header carries the real client even behind a trusted upstream LB.

## Implementation

### A — PROXY-protocol write to backend (`cmd/ja4pd/main.go`, `internal/config/loader.go`)

- **Config (`ProxyConfig`):** add `write_proxy_protocol` (bool, default
  **false**) and `write_proxy_protocol_version` (int `1`|`2`, default **1**).
  The loader zero-initialises defaults *before* unmarshal, so a config file
  missing these fields loads with the safe defaults (fail-open, never crash —
  backwards-compat).
- **Plumb the real client into `forward()`:** `forward(clientConn, initialData)`
  → `forward(clientConn, initialData, srcIP, srcPort)`, called from `handleConn`
  with `connCtx.ClientIP` / `connCtx.ClientPort` (the value already resolved from
  a *trusted* inbound PROXY header, else the socket peer). `dst` = the proxy's
  own accept address (`clientConn.LocalAddr()`).
- **Header builders** (new `internal/proxyproto/write.go` or alongside the
  existing parser):
  - **v1** — ASCII `PROXY TCP4 <src> <dst> <sport> <dport>\r\n` / `TCP6`; if the
    family is indeterminate, `PROXY UNKNOWN\r\n`.
  - **v2** — 12-byte signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`
    + `0x21` (PROXY/v2) + `0x11` (TCP/IPv4) or `0x21` (TCP/IPv6) + 2-byte length
    + addresses/ports in network byte order.
- **Write order:** prepend the header to `backendConn` **before** the existing
  `backendConn.Write(initialData)` (the ClientHello). It must be the first bytes
  the backend sees.
- **FP-safe construction (asymmetry rule — never drop a valid client):** the
  builder *cannot* fail in a way that drops a connection. When src/dst families
  are indeterminate/mismatched or a port is out of range (0–65535), it emits the
  spec's "no address" form — v1 `PROXY UNKNOWN\r\n`, v2 LOCAL command
  (AF_UNSPEC) — so the connection proceeds and the backend falls back to the
  real socket address. The header is always the first bytes written to the
  backend (so un-annotated payload is never forwarded when the feature is on).
  The only abort path is a **backend write error**, which already aborts today
  (and increments `connection_errors_total{...="backend_proxy_header"}`).

### B — Manual-ban enforcement (`internal/security/pipeline.go`)

- In `processInternal`, **before `dial` is fetched** (currently line ~390),
  query Redis for the manual ban and, if present, return a hard block:
  `&PipelineResult{Action: "block", Score: 100, BypassReason: "manual_ban"}`.
- **Canonical key is `ban:{ip}`** (REDIS_SCHEMA; matches `client.go`,
  `redactor.go`, the cluster sync agent) — **not** `ja4proxy:ban:`. Exact-IP
  match for v1; `ban_cidr:{cidr}` (trie) is out of scope here (noted as
  follow-up — needs the in-process CIDR trie).
- Because this runs before the dial gate, a manual ban blocks at any dial,
  including `dial: 0`. **Verify first** that no existing path already enforces
  bans (the sync agent allow-lists `ban:` keys but nothing in the hot path reads
  one) so we don't double-implement.
- **Fail-open:** if Redis is unreachable, the ban lookup logs a warning and
  returns "not banned" — an outage must not start blocking legitimate traffic.

### C — CountKeys fix (`cmd/ja4pd/main.go`)

- Line ~1338: `CountKeys(ctx, "ja4proxy:ban:*")` → `CountKeys(ctx, "ban:*")` so
  the active-bans gauge counts the real keys (it currently always reads 0).

## Test strategy (all Go)

- `internal/proxyproto` (or `cmd/ja4pd`): build a v1 header for IPv4/IPv6 and a
  v2 header; assert byte-exact output incl. the v2 signature; assert
  `UNKNOWN`/abort on an unrepresentable address.
- `cmd/ja4pd` integration: a local TCP listener as the "backend" receives a
  valid PROXY v1 and v2 header followed by the ClientHello when the feature is
  on; nothing prepended when off (default).
- `internal/security`: pipeline returns `block`/`manual_ban` when `ban:{ip}` is
  present (fake Redis), at `dial: 0`; returns the normal decision when absent;
  fails open when Redis errors.
- Regression: `CountKeys` counts `ban:*` keys.

## Acceptance criteria

- [x] `write_proxy_protocol` (bool, default false) + `write_proxy_protocol_version`
      (int 1|2, default 1) exist; a config missing them loads with defaults.
- [x] With the feature on, the backend receives a valid PROXY v1 (and v2) header
      carrying the resolved client IP/port; with it off, nothing is prepended.
- [x] Header construction never drops a valid client: indeterminate/invalid
      addresses degrade to `PROXY UNKNOWN` / v2 LOCAL (FP-safe); only a backend
      *write* error aborts (metric + log), as before.
- [x] `ban:{ip}` in Redis → immediate `block` at `dial: 0`; absent → normal
      decision; Redis error → fail open.
- [x] `CountKeys` uses `ban:*`; the active-bans metric reflects real bans.
- [x] `go build ./...`, `go vet`, and the new Go tests pass; gofmt clean.

## Out of scope (→ 231b or later)

- The installer, `setup_wizard.py`, systemd units, firewall, logrotate, backups,
  offline tarball, uninstaller, diagnostics — all **[[PHASE_231b]]**.
- CIDR-level manual bans (`ban_cidr:{cidr}`) in the pipeline (needs the trie).
- Carrying the *original* dst through a chained upstream-LB PROXY header (v1
  uses the proxy's own accept address as dst; backends key on src).
