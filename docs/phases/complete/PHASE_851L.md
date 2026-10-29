<!--
title: CLI Command Parser & Output Contract Fuzzing
audience: developer
last_reviewed: 2026-10-29
phase: 851l
-->

# CLI Command Parser & Output Contract Fuzzing

> **Size:** SMALL
> **Dependencies:** [851k]
> **Branch:** `phase-851l-cli-parser-fuzzing`

---

## Goal

Harden the operator CLI (`cmd/ja4p`, `internal/cli`) against unhandled panics, malformed argument crashes, and output format contract violations. Implement native Go fuzz targets and Rapid property-based invariant tests covering flag parsing, sub-command argument tokenization, and end-to-end command output contracts with strict isolation to prevent `os.Exit` aborts or unwanted environment mutations.

---

## Scope

### In Scope
1. **Native Go Fuzzing Across Package Boundaries**:
   - `FuzzCLIArgumentParsing` in `internal/cli/engine/engine_fuzz_test.go`: Fuzz root command dispatch and flag unmarshaling across arbitrary CLI argument strings (`os.Args` token lists) for panic-freedom and proper error exits.
   - `FuzzOutputFormatter` in `internal/cli/output/output_fuzz_test.go`: Fuzz table and JSON formatters across arbitrary nested structures, Unicode symbols, and ANSI escape sequences.
2. **Harness Isolation & Security Guarantees**:
   - Override `osExit` in `internal/cli/engine` to panic with a custom error type, recovered cleanly inside the fuzz harness.
   - Silence stdout and stderr (`cmd.SetOut(io.Discard)`, `cmd.SetErr(io.Discard)`, `cmd.SilenceErrors = true`).
   - Mock API transport and filesystem configs so fuzzing does not mutate `~/.config/ja4proxy/` or issue real network calls.
3. **Rapid Property-Based Invariant Tests**:
   - **Command-Level JSON Output Contract**: For any command executed with `--output json`, stdout is guaranteed to parse as valid JSON (or empty on fatal failure) and never mix stderr warnings into stdout.
   - **Exit Code Monotonicity**: Malformed flags or invalid arguments strictly exit with code $\ne 0$ without invoking downstream network or file mutators.
4. **Micro-Benchmarks**:
   - `BenchmarkCLIParseAndFormat`: Measure CLI argument parsing and output rendering latency.
5. **Smoke Gate Integration**:
   - Wire new fuzz targets into `make test-go-fuzz-smoke`.

### Out of Scope
- Full interactive terminal TTY simulation.

---

## Implementation Plan

1. **Step 1: Remote Lease & Manifest Registration**
   - Claim `phase-851l-cli-parser-fuzzing`.
   - Update `docs/phases/manifest.yaml` marking Phase 851l `IN_PROGRESS`.
2. **Step 2: Rapid & Fuzz Test Suite (`internal/cli/engine/engine_fuzz_test.go`, `internal/cli/output/output_fuzz_test.go`)**
   - Author native Go fuzz targets with execution isolation.
   - Author Rapid property tests for command-level JSON contracts.
   - Author benchmarks.
3. **Step 3: Verification & Smoke Gate Integration**
   - Run fuzz targets with `-fuzztime=5s`.
   - Run Rapid property tests.
   - Update `Makefile` and `fuzzing.yml`.
4. **Step 4: Closeout**
   - Move phase doc to `docs/phases/complete/PHASE_851L.md`.
   - News fragment, `make preflight`, PR, auto-merge.

---

## Acceptance Criteria
- [x] 2 native Go fuzz targets added in their proper packages (`internal/cli/engine` and `internal/cli/output`).
- [x] Execution isolation guarantees zero process aborts via `os.Exit` and zero side-effect mutations.
- [x] Rapid property tests prove end-to-end command JSON output contracts.
- [x] Zero panics across 250,000+ fuzz inputs.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
