---
phase: 336
title: Security Hardening — Capability Drop, Seccomp, Poll Timeout, Metrics, Panic Recovery
created: 2026-06-19
audience: [developer, security]
---

# Security Hardening

## Goal

Deferred security hardening from Phase 335: isolate the capability drop and seccomp loading into an independent phase to contain risk and allow independent review.

## Scope

- `internal/tap/hardening.go`: `DropCapabilities()` and `LoadSeccomp()` exported functions
- `cmd/ja4-tap/main.go`: integration of `tap.DropCapabilities()` and `tap.LoadSeccomp()` before capture start
- `Makefile`: `tap-build` target with proper recipe
- `docs/fragments/phase-336-diversity.md`

## Implementation Plan

1. Create `internal/tap/hardening.go` with `DropCapabilities()` (syscall.Setuid/Setgid to 65534) and `LoadSeccomp()` (placeholder)
2. Wire into `cmd/ja4-tap/main.go` after AF_PACKET bind
3. Fix `tap-build` Makefile target (missing TAB)
4. Fix changelog fragment bullet syntax (`*` → `-`)
5. Add Phase 336 to manifest.yaml

## Test Strategy

- `make lint` — zero violations
- `make test` — no regressions
- `make preflight` — all gates green
