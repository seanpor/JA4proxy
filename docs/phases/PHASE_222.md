---
phase: 222
title: Comprehensive Performance Benchmarking – JA4proxy
status: PROPOSED
size: LARGE
created: 2026-06-05
audience: [security-team, developer]
---

# Phase 222 – Comprehensive Performance Benchmarking

## Goal
Generate reliable, reproducible performance metrics for JA4proxy under realistic load. Measure connections-per-second (CPS), latency, and blocking-mode behavior for **1, 2, 4** parallel proxy instances at dial thresholds 0, 25, 50, 75, 100, targeting ≥5% successful connections.

---

## Sub-Phase A – Load Generator (SMALL)
**Action:** Build a Go-based load tester `ja4bench` that drives parallel TLS connections.

### Files to Create
- `cmd/ja4bench/ja4bench.go` (main entry point)
- `cmd/ja4bench/worker.go` (worker goroutine)
- `cmd/ja4bench/metrics.go` (metrics export)
- `cmd/ja4bench/go.mod` (Go module)

### Step-by-Step Instructions
1. Create directory: `mkdir -p cmd/ja4bench`
2. Initialize Go module:
   ```bash
   cd cmd/ja4bench
   go mod init github.com/seanpor/JA4proxy/cmd/ja4bench
   go get golang.org/x/sync/errgroup
   go get github.com/prometheus/client_golang@v1.18.0
   ```
3. Copy ClientHello fixtures from `tests/fixtures/clienthello/` into `cmd/ja4bench/fixtures/`
4. Implement `ja4bench.go`:
   - Parse CLI flags: `-target`, `-connections`, `-rate`, `-dial`, `-workers`
   - Load binary fixtures (`*.bin`) into memory
   - Create TLS config matching production (no min version restriction)
   - Spawn N workers via errgroup
   - Each worker:
     - Connects to target with random fixture
     - Tracks success/failure counts
     - Sends `ClientHello` immediately
     - Waits for 1st server response (or timeout)
     - Records latency in `time.Microsecond`
5. Run locally after build:
   ```bash
   go build -o /tmp/ja4bench .
   /tmp/ja4bench -target 127.0.0.1:8443 -rate 1000 -workers 1
   ```
6. Expect output:
   ```
   cps_total: 987
   latency_p50_us: 12400
   latency_p95_us: 45000
   errors: 0
   ```

### Acceptance Criteria
- `go build ./cmd/ja4bench` exits 0
- Runs without panic against a local target
- Produces CSV output to stdout (or file if `-o` specified)

---

## Sub-Phase B – Test Matrix (SMALL)
**Action:** Define benchmark configuration matrix.

### Files to Create
- `tests/benchmark/bench.yaml` (matrix definition)
- `tests/benchmark/runner.sh` (shell wrapper)

### Step-by-Step Instructions
1. Create directory: `mkdir -p tests/benchmark`
2. Create `tests/benchmark/bench.yaml`:
   ```yaml
   variants:
     - id: "1p-monitor"
       target: "proxy-1:443"
       parallel: 1
       dial: 0
       blocking: false
     - id: "1p-block-25"
       target: "proxy-1:443"
       parallel: 1
       dial: 25
       blocking: true
     - id: "2p-monitor"
       target: "proxy-1:443,proxy-2:443"
       parallel: 2
       dial: 0
       blocking: false
     - id: "2p-block-50"
       target: "proxy-1:443,proxy-2:443"
       parallel: 2
       dial: 50
       blocking: true
     - id: "4p-monitor"
       target: "proxy-1:443,proxy-2:443,proxy-3:443,proxy-4:443"
       parallel: 4
       dial: 0
       blocking: false
     - id: "4p-block-75"
       target: "proxy-1:443,proxy-2:443,proxy-3:443,proxy-4:443"
       parallel: 4
       dial: 75
       blocking: true
   repeats: 5
   warmup: "30s"
   measurement: "180s"
   rate: 5000  # target CPS per worker
   ```
3. Validate YAML:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('tests/benchmark/bench.yaml'))" || go install github.com/mikefarah/yq/v4@latest && yq eval . tests/benchmark/bench.yaml > /dev/null
   ```
4. Create `tests/benchmark/runner.sh`:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   go build -o /tmp/ja4bench ./cmd/ja4bench
   for variant in $(yq eval '.variants[].id' tests/benchmark/bench.yaml); do
     for rep in $(seq 1 5); do
       /tmp/ja4bench -variant="$variant" -repeat="$rep"
     done
   done
   ```

### Acceptance Criteria
- YAML parses without error
- `runner.sh` is executable and enumerates all 6 variants × 5 repeats = 30 commands

---

## Sub-Phase C – Documentation Update (SMALL)
**Action:** Record benchmark results in markdown.

### Files to Create/Modify
- `docs/performance/BENCHMARK_HISTORY.md` (append results)
- `docs/performance/results/phase222/` (new directory for CSV/JSON)

### Step-by-Step Instructions
1. Create results directory: `mkdir -p docs/performance/results/phase222`
2. Append to `docs/performance/BENCHMARK_HISTORY.md`:
   ```markdown
   ## Phase 222 Benchmark Results
   | Variant | Parallel | Dial | CPS (mean) | CPS (stdev) | Latency p50 (μs) | Latency p95 (μs) | Notes |
   |---------|----------|------|------------|-------------|------------------|------------------|-------|
   | 1p-monitor | 1 | 0 |  |  |  |  | |
   ...
   ```
3. Generate plots:
   - Use CSV export from Sub-Phase A
   - Plot CPS vs parallelism using `gnuplot` or `matplotlib`
   - Save PNG to `docs/performance/results/phase222/`
4. Add anomaly notes under each variant in the markdown table.

### Acceptance Criteria
- Markdown renders correctly on GitHub
- Each variant has a populated row with numeric values
- At least one PNG chart embedded per document section

---

## Sub-Phase D – CI Integration (SMALL)
**Action:** Integrate benchmark in GitHub Actions.

### Files to Create
- `.github/workflows/ci-bench.yml`

### Step-by-Step Instructions
1. Create workflow file:
   ```yaml
   name: Benchmark Run
   on:
     push:
       branches: [main]
       paths:
         - 'cmd/ja4bench/**'
         - 'tests/benchmark/**'
     workflow_dispatch:
   jobs:
     bench:
       runs-on: ubuntu-24.04
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-go@v5
           with:
             go-version: '1.24'
         - run: go build -o /tmp/ja4bench ./cmd/ja4bench
         - run: |
             cd tests/benchmark
             ./runner.sh 2>&1 | tee bench-output.txt
         - uses: actions/upload-artifact@v4
           with:
             name: benchmark-results
             path: docs/performance/results/phase222/*.csv
   ```
2. Validate syntax:
   ```bash
   gh workflow validate .github/workflows/ci-bench.yml || ruby -e "require 'yaml'; YAML.load_file('.github/workflows/ci-bench.yml')"
   ```

### Acceptance Criteria
- Workflow file parses in GitHub Actions UI
- `workflow_dispatch` triggers manually
- Uploads at least one artifact

---

## Sub-Phase E – Reporting Template (SMALL)
**Action:** Create reusable report template.

### Files to Create
- `docs/performance/report-template.md` (Jinja-style, for future runs)

### Step-by-Step Instructions
1. Create `docs/performance/report-template.md`:
   ```markdown
   # Benchmark Report – {{date}}
   ## Variant: {{variant.id}}
   - Parallel: {{variant.parallel}}
   - Dial: {{variant.dial}}
   - Blocking: {{variant.blocking}}
   ### Metrics
   - CPS mean: {{cps_mean}}
   - CPS std: {{cps_std}}
   - Latency p50: {{latency_p50}} μs
   - Latency p95: {{latency_p95}} μs
   ### Anomalies
   ```{{anomalies}}```
   ```
2. Document usage in `docs/OPERATIONS_GUIDE.md` under "Running Benchmarks" section.

### Acceptance Criteria
- Template is valid Markdown
- Template keys match Sub-Phase A output keys (cps_mean, latency_p50, etc.)

---

## Test Strategy
- Run Sub-Phase A against local proxy target before pushing
- Validate Sub-Phase B YAML with parser tool
- Execute one full matrix (Sub-Phase B runner) in CI environment
- Compare numeric thresholds against `docs/performance/` existing values

## Acceptance Criteria (Overall Phase)
1. `go build ./cmd/ja4bench` exits 0
2. `tests/benchmark/runner.sh` executes all 30 runs without error
3. `docs/performance/BENCHMARK_HISTORY.md` has populated Phase 222 section
4. CI workflow can be triggered manually and completes
5. Template file exists and is referenced from operations guide