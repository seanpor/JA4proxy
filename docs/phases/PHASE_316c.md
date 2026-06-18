# PHASE 316c — Passive JA4T Fingerprint + Advisory Blocklist Signal (TAP)

> **STATUS: APPROVED — IN PROGRESS. Stacked on 316a + 316b.**
> Re-scoped from the original "full JA4 fingerprint family" outline after a
> critical review (see §1). The feasible, value-bearing first slice — JA4T plus a
> real consumer — is implemented here; the rest of the family is dropped or
> deferred per §6 with reasons.

## 1. Critical review — why the original outline could not ship as written

The 316c outline proposed computing the **full** JA4 family (JA4S, JA4T, JA4H,
JA4SSH, JA4L, JA4H2, JA4X, QUIC) in the passive sensor and writing the documented
`fp:*` keys. A codebase-grounded review found two load-bearing problems:

1. **Most of the family is physically impossible for a passive TLS TAP.**
   - **JA4H / JA4H2** are computed from plaintext HTTP/1.1 request headers and
     HTTP/2 SETTINGS frames. On port 443 those bytes are *inside* TLS — encrypted.
     The sensor never sees them.
   - **JA4SSH** fingerprints SSH KEXINIT on a different protocol/port (:22), not
     TLS traffic — out of this sensor's vantage entirely.
   - **JA4X** parses the TLS **Certificate** message; in **TLS 1.3 that message is
     encrypted**, so passively it is available only for TLS ≤1.2 — *and* 316a/b
     capture only ClientHello/ServerHello, not the Certificate record.
   - **QUIC** is UDP; the 316a reassembler is TCP-only.

2. **Nothing reads the keys.** A full-Go search found exactly **one** `fp:*`
   consumer: `fp:os:ip:{ip}` (the OS-mismatch signal lit up by 316b). `fp:ja4`,
   `fp:ja4s`, `fp:ja4t`, `fp:conn`, `fp:ip`, the HLLs/counts — **zero** Go readers.
   Writing them now would ship correct-but-dead keys.

**Conclusion (approved with the user):** implement the one feasible client-side
fingerprint that reuses data 316b already captures — **JA4T** — *paired with a
real consumer*, mirroring 316b's write-and-light-up pattern. Drop the impossible
fingerprints from the roadmap; defer the conditionally-feasible ones (§6).

## 2. Goal

Compute the canonical **JA4T** TCP fingerprint passively, write it to Redis, and
add an advisory `tap_ja4t_blocklist` signal the inline proxy actually consumes —
giving operators a passive-TAP-sourced JA4T enforcement knob the proxy could not
build on its own (the kernel completes the TCP handshake before `accept()`, so the
SYN's window/MSS/option-order are gone by the time the proxy sees the socket).

## 3. Scope (what this slice ships)

- **`internal/tap/ja4t.go` — `ComputeJA4T(StackFeatures) string`.** Canonical FoxIO
  format `{SYN window}_{option kinds}_{MSS}_{window scale}`, e.g.
  `65535_2-1-3-1-1-8-4_1460_7`. Option kinds are decimal, hyphen-joined, in wire
  order, including NOP (1); only the end-of-list terminator (0) is dropped. Window
  scale renders `00` when the option is absent (distinct from a present shift of
  0). Returns `""` when no client SYN was observed (`HasSYN` false) — we never
  fingerprint a stack we did not see open the connection. This is the numeric
  canonical form (interoperable with `foxio/ja4` and JA4T feeds), **not** the
  letter-coded variant the archived Python sensor emitted.
- **`internal/tap/store.go` — `Store.WriteJA4T(ctx, ip, ja4t)`.** Writes
  `fp:ja4t:ip:{ip}` (24h TTL), canonical IP (v4/v6), fire-and-forget and fail-open;
  skips empty JA4T and the nil/offline backend. New
  `ja4proxy_tap_ja4t_written_total{result}` counter.
- **`cmd/ja4-tap/main.go`.** Computes JA4T per event alongside the OS class and
  writes both under one time-bounded deadline; logs the JA4T per handshake.
- **`internal/security/tap_ja4t_consumer.go` — `JA4TConsumer`.** Reads
  `fp:ja4t:ip:{ip}` on the hot path (LRU-cached, short Redis timeout, fail-open),
  emits `tap_ja4t_blocklist` (Weight 1.0, configurable score) when the observed
  JA4T is on the operator's blocklist. **Empty blocklist (default) ⇒ no Redis
  lookup, never fires** — cannot cause a false positive on its own. Wired into
  `pipeline.go` next to the 203a OS-mismatch consumer. New
  `ja4proxy_tap_ja4t_lookups_total{result}` / `ja4proxy_tap_ja4t_signal_total{action}`.
- **Config.** `ja4t_consumer` block in `config/proxy.yml` (enabled, signal_score,
  redis_timeout_ms, cache_ttl_seconds, blocklist); YAML struct in
  `internal/config/loader.go`; mapping in `cmd/ja4pd/main.go`.

## 4. Key decisions / constraints

- **Advisory only.** `tap_ja4t_blocklist` is scored under the dial like any other
  signal; it never hard-blocks. Default dial 0 = monitor.
- **Silent by default.** Disabled, with an empty blocklist — the conservative
  default that honours the core asymmetry (a false block of a real browser is the
  expensive error).
- **Fail open everywhere.** Disabled config, empty blocklist, unparsable IP,
  Redis miss/error/timeout → no signal.
- **Canonical IP** matches the writer/reader convention already shared by the
  203a consumer (`netip.Addr.String()`, brackets/zone stripped).
- **Least-privilege Redis** for the sensor is unchanged: the `~fp:*` ACL in the
  runbook already covers `fp:ja4t:ip`.

## 5. Tests

- `internal/tap/ja4t_test.go` — table-driven canonical-format vectors (windows/
  linux/absent-WS/present-WS-0/EOL-drop/absent-MSS/no-options) + empty-on-no-SYN +
  determinism.
- `internal/tap/store_ja4t_test.go` — write success/skip-empty/nil-backend/
  redis-error/unparsable-IP/IP-canonicalisation, with metric assertions.
- `internal/security/tap_ja4t_consumer_test.go` — blocklisted fires, clean/miss
  silent, disabled & empty-blocklist short-circuit (no Redis call), redis error &
  timeout fail open, IPv6 canonicalisation, caching, nil-safe.
- `internal/tap/roundtrip_ja4t_test.go` — **closed loop** over miniredis: sensor
  computes+writes JA4T, consumer reads and fires on a blocklist match; non-
  blocklisted is silent; SYN-less writes nothing and stays silent. This is the
  end-to-end discipline the dormant 203a signal originally lacked.

## 6. Dropped / deferred (roadmap correction)

- **Dropped — infeasible on passive encrypted TLS:** JA4H, JA4H2, JA4SSH (require
  plaintext application/SSH data the sensor cannot see). Removed from the TAP
  fingerprint roadmap.
- **WON'T-DO (decided 2026-06-18) — low value / redundant for an inbound
  bot-protection proxy:**
  - **JA4S** (ServerHello) — fingerprints *our own backends'* responses, not the
    client; wrong threat surface for an inbound protective proxy (the client is
    the threat). No inbound allow/block decision depends on it.
  - **JA4L** (RTT/distance) — redundant with the existing GeoIP/ASN/RDAP geo
    signals (Phases 6/11), and a SPAN-port latency measurement is noisy and
    spoofable.
  - **JA4X** (cert) — the inline proxy already computes JA4X (`internal/tls/
    ja4x.go`) on the live connection; a passive TAP could only do TLS ≤1.2, a
    strict and shrinking subset of an existing capability.
- **Deferred (conditional) — QUIC / JA4Q:** needs a new UDP capture + QUIC
  Initial decode subsystem (the 316a reassembler is TCP-only). It is the one
  genuine blind spot (the inline TCP proxy cannot see QUIC at all), so it is
  *not* dropped — but it earns its cost only if QUIC/H3 actually appears in the
  protected traffic. The product's threat model is bots abusing web forms over
  HTTP(S) through the proxy; QUIC matters only when a QUIC-enabled backend lets
  that traffic bypass the TCP path. Revisit then.

The won't-do fingerprints would be write-only Redis keys with no decision to
drive — the dead-key trap this slice exists to avoid. A fingerprint earns its
place only when a consumer acts on it.
