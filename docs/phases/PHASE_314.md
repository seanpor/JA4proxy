# PHASE 314 — Go TAP / SPAN Passive Sensor (index)

> This umbrella was split into small, independently-reviewable sub-phases after a
> critical design review. The original single-phase draft (which under-sized the
> work ~4×) is superseded by:
>
> - **[PHASE_314a](PHASE_314a.md)** — Capture + bidirectional TCP reassembly +
>   ClientHello/ServerHello extraction (+ the capture-library ADR). Foundation only.
> - **[PHASE_314b](PHASE_314b.md)** — OS-mismatch **MVP**: minimal fingerprinting →
>   `fp:os:ip` using one canonical OS-class vocabulary shared with the consumer,
>   proving the dormant signal fires; Tranco FP test; advisory-only. Depends on 314a.
> - **[PHASE_314c](PHASE_314c.md)** — Full JA4 fingerprint family (OUTLINE).
> - **[PHASE_314d](PHASE_314d.md)** — Out-of-band enforcement bridge, advisory by
>   default (OUTLINE).
> - **[PHASE_314e](PHASE_314e.md)** — Intelligence exporters (OUTLINE).
>
> All **PROPOSED — awaiting sign-off. No code until approved.** 314a/314b are
> detailed; 314c–e are outlines to be fleshed out before each starts.

## Why split

The original WP-1 alone was ~3,600–4,200 LOC plus the equivalent of ~584 Python
tests — several phases of work. Splitting lets each piece (capture, the
first useful signal, the rest of the family, enforcement, export) land and be
reviewed on its own. 314b is the first slice that delivers a *working* sensor.
