# PHASE 316 — Go TAP / SPAN Passive Sensor (index)

> **Lineage:** this is the resurrected **Go TAP/SPAN passive sensor** work
> originally drafted as Phase 314. Phase numbers 313/314 were later repurposed
> (313 → CI lint/scan fix, #140; 314 → third-party image HIGH-CVE remediation,
> #141), orphaning this plan. It is restored here under fresh number **316**
> (sub-phases **316a–316e**), recovered verbatim from git `53a8e14` and
> renumbered. The gap is still live: the Go proxy ships only the TAP *consumer*
> (`internal/security/tap_consumer.go`) which reads `fp:*` keys that **nothing
> currently writes** — the Python Phase-20 sensor was archived in `5afeba26`.

> This umbrella was split into small, independently-reviewable sub-phases after a
> critical design review. The original single-phase draft (which under-sized the
> work ~4×) is superseded by:
>
> - **[PHASE_316a](PHASE_316a.md)** — Capture + bidirectional TCP reassembly +
>   ClientHello/ServerHello extraction (+ the capture-library ADR). Foundation
>   only. **COMPLETE.**
> - **[PHASE_316b](PHASE_316b.md)** — OS-mismatch **MVP**: minimal fingerprinting →
>   `fp:os:ip` using one canonical OS-class vocabulary shared with the consumer,
>   proving the dormant signal fires; Tranco FP test; advisory-only. **COMPLETE.**
> - **[PHASE_316c](PHASE_316c.md)** — Passive **JA4T** + advisory blocklist signal
>   (re-scoped from the infeasible "full JA4 family"). **COMPLETE.**
> - **[PHASE_316d](PHASE_316d.md)** — Out-of-band enforcement bridge reusing
>   `ban:{ip}`, advisory by default. **COMPLETE.**
> - **[PHASE_316e](PHASE_316e.md)** — Intelligence exporters (OUTLINE). **PROPOSED.**
>
> **Roadmap correction (2026-06-18) — the rest of the JA4 family is not happening:**
> JA4H/JA4H2/JA4SSH are **dropped** (infeasible on passive encrypted TLS), and
> **JA4S / JA4L / JA4X are WON'T-DO** — low value or redundant for an inbound
> bot-protection proxy (JA4S fingerprints our own backends; JA4L duplicates
> GeoIP/ASN/RDAP geo; JA4X is already computed inline in `internal/tls/ja4x.go`,
> and a passive TAP could only do TLS ≤1.2). **QUIC / JA4Q stays DEFERRED
> (conditional):** it is the one genuine blind spot (the inline TCP proxy cannot
> see QUIC at all), but it needs a new UDP + QUIC-Initial decode subsystem and
> only earns that cost if QUIC/H3 actually appears in the protected traffic — the
> product protects web forms from bots over HTTP(S) through the proxy, so QUIC
> matters only when a QUIC-enabled backend lets that traffic bypass the TCP path.
> See [PHASE_316c §6](PHASE_316c.md) for the reasoning.

## Why split

The original WP-1 alone was ~3,600–4,200 LOC plus the equivalent of ~584 Python
tests — several phases of work. Splitting lets each piece (capture, the
first useful signal, the rest of the family, enforcement, export) land and be
reviewed on its own. 316b is the first slice that delivers a *working* sensor.
