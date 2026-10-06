<!--
title: Mutation Baseline
audience: developer
last_reviewed: 2026-10-06
phase: 606-0
-->

# Mutation Testing Baseline (Advisory)

**Date:** 2026-10-06  
**Phase:** 606-0  
**Tooling Note:** `github.com/go-gremlins/gremlins` and `github.com/zimmski/go-mutesting` (Advisory, Non-blocking in CI).

---

## Efficacy & Mutant Coverage by Package

| Package | Status | Efficacy (%) | Mutants Killed / Total | Top Surviving Mutant / Notes |
|---|---|---|---|---|
| `internal/tls` | Baseline | 82.4% | 42 / 51 | GREASE extension ordering check skips conditional mutation |
| `internal/security` | Baseline | 85.7% | 36 / 42 | Perm error fallback condition mutation |
| `internal/quic` | Baseline | 78.9% | 15 / 19 | Short packet header validation length boundary |
| `internal/tap` | Baseline | 91.3% | 21 / 23 | Redis circuit breaker failure counter increment |

---

## Top Surviving Mutants (Free Test Ideas for Phase 606a/606f)

1. **`internal/tls/parser.go:142`**: Conditional swap (`==` to `!=`) in SNI extension length parsing (Targeted in 606a invariant `INV-TLS-002`).
2. **`internal/tls/parser.go:189`**: Replacement of boundary check `len(data) < 2` with `len(data) <= 2` in ALPN extraction.
3. **`internal/tls/grease.go:34`**: Omission of GREASE check inside extension filter loop.
4. **`internal/security/permissions.go:45`**: Bitmask match `mode & os.W_OK` changed to `mode == os.W_OK`.
5. **`internal/quic/header.go:88`**: Connection ID length boundary mutation (`<=` to `<`).
