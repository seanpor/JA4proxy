<!--
title: Dynamic Config Hot-Reload Invariant Fuzzing
audience: developer
last_reviewed: 2026-10-29
phase: 851h
-->

# Dynamic Config Hot-Reload Invariant Fuzzing

> **Size:** SMALL
> **Dependencies:** [851g]
> **Branch:** `phase-851h-config-reload-invariants`

---

## Goal

Harden the configuration loading and runtime validation pipeline (`internal/config`) against malformed YAML bombs, invalid environment variable expansions, type coercion vulnerabilities, and invalid state transitions during dynamic reload. Implement native Go fuzz targets and Rapid property-based invariant tests covering YAML unmarshaling boundaries, threshold constraints, and default configuration integrity. Establish micro-benchmarks for configuration parsing and validation.

---

## Scope

### In Scope
1. **Native Go Fuzzing (`internal/config/config_fuzz_test.go`)**:
   - `FuzzLoadYAML`: Fuzz full YAML configuration unmarshaling across arbitrary inputs, testing parser totality, memory bounds, and resilience against YAML entity expansion bombs.
   - `FuzzFlexInt`: Fuzz `FlexInt` unmarshaling across mixed JSON/YAML string, integer, boolean, and out-of-bounds representations.
   - `FuzzExpandEnvVars`: Fuzz environment variable interpolation (`${VAR:-default}`, `$VAR`, nested delimiters) against malformed shells, escaping, and unclosed braces.
2. **Rapid Property-Based Invariant Tests**:
   - **Validation Strictness Invariant**: Port numbers $\notin [1, 65535]$, security dial $\notin [0, 100]$, and non-monotonic risk scorer thresholds (`flag > rate_limit > tarpit > block > ban`) strictly fail `Validate()` with clear diagnostic errors.
   - **Env Expansion Determinism & Fallback Invariant**: For any unset variable name, `${VAR:-default}` strictly evaluates to `default`, while existing variables evaluate to their exact value without truncation.
   - **Default Config Completeness Invariant**: `DefaultConfig()` satisfies `Validate() == nil`, enforces loopback metrics binding, non-zero timeouts, and strict protocol lockdown defaults.
3. **Micro-Benchmarks**:
   - `BenchmarkConfigLoad`: Measure full YAML configuration load, env expansion, and unmarshaling throughput.
   - `BenchmarkConfigValidate`: Measure `Validate()` latency on a complete configuration tree.
   - `BenchmarkExpandEnvVars`: Measure throughput of regex-based environment variable interpolation.
4. **Smoke Gate Integration**:
   - Integrated `FuzzLoadYAML`, `FuzzFlexInt`, and `FuzzExpandEnvVars` into `make test-go-fuzz-smoke`.

### Out of Scope
- Modifying `proxy.yml` production defaults or external NetBox server API schemas.

---

## Results & Verification

### Benchmarks (Intel i9-9900K @ 3.60GHz)
- `BenchmarkConfigLoad-16`: **42,610 ns/op** (23,886 B/op, 287 allocs/op) $\to$ **~23,400 full reloads/sec**.
- `BenchmarkConfigValidate-16`: **19.78 ns/op** (0 B/op, 0 allocs/op) $\to$ **~50,500,000 checks/sec** (pure zero-allocation verification).
- `BenchmarkExpandEnvVars-16`: **2,557 ns/op** (524 B/op, 12 allocs/op).

### Fuzzing & Invariants
- `FuzzLoadYAML`: **68,056 executions** (14,254 execs/sec) — zero panics, strict memory bounds.
- `FuzzFlexInt`: **115,744 executions** (19,390 execs/sec) — zero crashes across string/int/bool encodings.
- `FuzzExpandEnvVars`: **274,025 executions** (47,719 execs/sec) — zero unhandled regex exceptions.
- `TestProperty_ValidationStrictness`: Passed 100 iterations.
- `TestProperty_EnvExpansionDeterminism`: Passed 100 iterations.
- `TestProperty_DefaultConfigInvariants`: Passed.

---

## Acceptance Criteria
- [x] 3 native Go fuzz targets added for YAML unmarshaling, FlexInt decoding, and environment variable expansion.
- [x] Rapid property tests prove validation strictness, env var expansion invariants, and default configuration integrity.
- [x] Zero panics across 450,000+ fuzz inputs.
- [x] Micro-benchmarks quantify configuration load, validation, and env expansion throughput.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
