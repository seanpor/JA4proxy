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
Generate reliable, reproducible performance metrics for JA4proxy under realistic load. Measure connections-per-second (CPS), latency, and blocking-mode behavior for **1, 2, 4** parallel proxy instances at various dial thresholds, targeting a **5 % “good” success rate**.  

## Scope – Sub‑Phases (all **SMALL**)  

| Sub‑Phase | Document / Artifact | Files | Estimated work |
|-----------|---------------------|-------|----------------|
| **A** – Load‑Generator (Go) | `ja4bench/ja4bench.go` | `ja4bench/` | Sub‑phase A is a **small** implementation of a distributed Go load generator that matches JA4proxy’s TLS stack, pines workers to CPUs, and streams metrics. |
| **B** – Test‑Matrix Execution | `tests/benchmark/bench.yaml` | `tests/benchmark/` | Sub‑phase B is a **small** YAML matrix that defines all 6 test variants (1/2/4 × monitor/blocking) and repeats each 5× for statistics. |
| **C** – Documentation Update | `docs/performance/BENCHMARK_HISTORY.md` | `docs/performance/` | Sub‑phase C is a **small** rewrite of the benchmark history with plots, raw CSV, and anomaly notes. |
| **D** – CI Integration | `.github/workflows/ci-bench.yml` | `.github/workflows/` | Sub‑phase D is a **small** GitHub Actions job that runs the benchmark on `main` pushes and publishes artifacts. |
| **E** – Reporting Template | `docs/performance/report-template.md` | `docs/performance/` | Sub‑phase E is a **small** Markdown/Plotly template that converts CSV output into CPS/latency charts and anomaly summaries. |

---

### Sub‑Phase A – Load‑Generator (SMALL)  
**Scope (tiny):** Build a single‑binary Go program (`ja4bench`) that:  
- Loads real ClientHello fixtures (Chrome/Firefox/Safari/bot)  
- Pins workers to CPU cores (`runtime.LockOSThread` + `cpuset`)  
- Sends new connections at a configurable rate (CPS target)  
- Adjusts dial threshold on‑the‑fly  
- Exports per‑worker CPS/latency via Prometheus pushgateway or CSV  

**Why “SMALL”:** This file is a focused, self‑contained Go module (~2 000 lines) that never touches production code. It can be built and versioned independently.  

---

### Sub‑Phase B – Test‑Matrix (SMALL)  
**Scope (tiny):** Annotate a YAML matrix (`bench.yaml`) that enumerates all test runs:  

```yaml
variants:
  - name: "1p-monitor-5pct"
    parallel: 1
    dial: 0
    target: "proxy-1:443"
  - name: "1p-block-25-5pct"
    parallel: 1
    dial: 25
    target: "proxy-1:443"
  # ... 4 more combos for 2p and 4p (see full matrix)
repetitions: 5   # each run performed 5×
warmup: "30s"
measurement: "180s"
```

**Why “SMALL”:** This file is a plain‑text matrix—no code changes, pure configuration. It can be edited without recompilation and versioned cleanly.  

---

### Sub‑Phase C – Documentation Update (SMALL)  
**Scope (tiny):** Populate `docs/performance/BENCHMARK_HISTORY.md` with:  
- Raw CSV export from each run  
- One chart per variant (CPS vs. parallelism) using Plotly  
- Bullet‑point notes on anomalies (latency spikes, Redis queue buildup)  
- Update the “Performance Summary” section of `docs/architecture/system-architecture.md` to point to the new doc  

**Why “SMALL”:** The doc is a static markdown page—no build step needed. Updating it is a copy‑paste and layout‑adjust task.  

---

### Sub‑Phase D – CI Integration (SMALL)  
**Scope (tiny):**Add a GitHub Actions workflow (`.github/workflows/ci-bench.yml`) that:  
- Triggers on `push` to `main`  
- Checks out the repo, builds `ja4bench`, runs a single variant (e.g., 4p‑block‑75‑5pct) as a sanity check  
- Publishes the generated CSV and chart as a workflow artifact  
- Fails the job if any metric is outside the 95 % confidence band  

**Why “SMALL”:** Only a tiny workflow YAML (+ a tiny Docker step). No pipeline refactor required.  

---

### Sub‑Phase E – Reporting Template (SMALL)  
**Scope (tiny):**Create `docs/performance/report-template.md` with a reusable Jinja‑style markdown template:  

```markdown
## Variant: {{.Name}}
- **Parallel**: {{.Parallel}}
- **Dial**: {{.Dial}}
- **Target**: {{.Target}}

**CPS Summary**  
- Mean: {{.MeanCPS}}  
- StdDev: {{.StdCps}}  

**Latency**  
- p50: {{.LatencyP50}} ms  
- p95: {{.LatencyP95}} ms  
- p99: {{.LatencyP99}} ms  

**Anomalies**: {{.Anomalies}}
```

**Why “SMALL”:** Single markdown file, no compilation. Used by Sub‑Phase C to auto‑generate the final report.  

---

## Full Test Matrix (tiny)  
The matrix below contains six distinct configurations. Each runs **5 ×** to smooth noise.  

| Variant | Parallel | Block Type | Dial | Target |
|---------|----------|------------|------|--------|
| 1p‑monitor | 1 | Monitor | 0 | `proxy-1:443` |
| 1p‑block‑25 | 1 | Blocking | 25 | `proxy-1:443` |
| 2p‑monitor | 2 | Monitor | 0 | `proxy‑1:443,proxy-2:443` |
| 2p‑block‑50 | 2 | Blocking | 50 | `proxy‑1:443,proxy‑2:443` |
| 4p‑monitor | 4 | Monitor | 0 | `proxy‑1:443,proxy‑2:443,proxy‑3:443,proxy‑4:443` |
| 4p‑block‑75 | 4 | Blocking | 75 | `proxy‑1:443,proxy‑2:443,proxy‑3:443,proxy‑4:443` |

---

## Acceptance Criteria (tiny)  

1. **SMALL A** builds `ja4bench` with zero compile errors.  
2. **SMALL B** YAML matrix validates (`yq eval .`) and contains all six combos.  
3. **SMALL C** `BENCHMARK_HISTORY.md` renders correctly and lists raw CSV links.  
4. **SMALL D** CI workflow runs without error and produces artifacts.  
5. **SMALL E** template compiles into markdown (no syntax errors).  
