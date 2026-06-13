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
>   ClientHello/ServerHello extraction (+ the capture-library ADR). Foundation only.
> - **[PHASE_316b](PHASE_316b.md)** — OS-mismatch **MVP**: minimal fingerprinting →
>   `fp:os:ip` using one canonical OS-class vocabulary shared with the consumer,
>   proving the dormant signal fires; Tranco FP test; advisory-only. Depends on 316a.
> - **[PHASE_316c](PHASE_316c.md)** — Full JA4 fingerprint family (OUTLINE).
> - **[PHASE_316d](PHASE_316d.md)** — Out-of-band enforcement bridge, advisory by
>   default (OUTLINE).
> - **[PHASE_316e](PHASE_316e.md)** — Intelligence exporters (OUTLINE).
>
> All **PROPOSED — awaiting sign-off. No code until approved.** 316a/316b are
> detailed; 316c–e are outlines to be fleshed out before each starts.

## Why split

The original WP-1 alone was ~3,600–4,200 LOC plus the equivalent of ~584 Python
tests — several phases of work. Splitting lets each piece (capture, the
first useful signal, the rest of the family, enforcement, export) land and be
reviewed on its own. 316b is the first slice that delivers a *working* sensor.
