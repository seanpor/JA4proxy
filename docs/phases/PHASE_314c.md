# PHASE 314c — Full JA4 Fingerprint Family (TAP)

> **STATUS: PROPOSED — OUTLINE. Depends on 314a + 314b.**
> Detailed plan to be fleshed out (to the depth of 314a/b) **before** this
> sub-phase starts — once 314a/b have landed and the capture/store seams are real.

## Goal

Compute and store the **full** JA4 fingerprint family from the captured
handshakes, not just the OS class. This is the bulk of the original Phase-20
fingerprint surface, ported as *good Go*, not a line-for-line copy.

## Scope (fingerprints + their Redis keys)

- **Net-new in Go** (no existing implementation — confirmed by review): JA4S
  (ServerHello), JA4T (TCP), JA4H (HTTP/1), JA4SSH, JA4L (latency/locality),
  JA4H2 (HTTP/2), QUIC. ~1,600 LOC equivalent before tests.
- **Reusable from inline Go:** the GREASE filter + SHA-256 hashing helpers, and
  `ComputeJA4` (ClientHello) / `ExtractJA4X` (cert). JA4S specifically needs a
  **ServerHello parser** the inline path never had (314a surfaces the bytes).
- Write the documented `fp:*` keys (`fp:conn:{id}`, `fp:ip:{ip}`, `fp:ja4:hll:*`,
  `fp:ja4:count:*`, `fp:ja4_to_ja4s:*`, …) with their schema TTLs.

## Key decisions / constraints carried from review

- **IPv6 HLL bucketing:** `fp:ja4:hll` per-subnet keys use `/24` (v4) and `/48`
  (v6) per the cross-cutting IPv6 rule; store IPs canonical (`netip.Addr.String()`).
- **Parity fixtures must be checked in, not "recoverable".** Before coding each
  fingerprint, generate golden outputs over `tests/fp_corpus/data/` (+ recovered
  TAP fixtures) and commit them as Go `testdata`; gate each fingerprint against them.
- **Redis write volume:** add coalescing/sampling so a SPAN feed can't flood Redis
  (the consumer already caches `fp:os:ip` 60s — mirror that discipline).
- The "clean seam" only covers `fp:os:ip` today; the other `fp:*` keys have **no
  Go reader** yet — so writing them is forward-compat. Justify each, or defer the
  ones with no consumer.

## To detail before start

Per-fingerprint algorithm references, the ServerHello parser design, the
sampling/coalescing policy with numbers, the full test matrix (unit + parity +
real-Redis integration + performance), and whether 314c itself should split
(e.g. 314c-1 TLS-side JA4S/JA4T, 314c-2 HTTP JA4H/JA4H2, 314c-3 JA4SSH/JA4L/QUIC).
