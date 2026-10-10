# LogTide Architectural Evaluation & Telemetry Stack Replacement

## Goal

Perform a comprehensive, empirical architectural evaluation of replacing heavy third-party telemetry sidecars (Loki, Promtail, Grafana, Alertmanager sidecars) with **LogTide** (and lightweight first-party telemetry agents) across `JA4proxy` deployment topologies. The primary objective is to evaluate reduction in memory/CPU footprint, eliminate JVM/heavy-runtime resource contention in edge/DMZ proxy deployments, and permanently eradicate upstream third-party container CVE waiver debt (`.trivyignore.third-party`).

---

## Scope

### Included
1. **Resource & Memory Footprint Analysis:**
   - Quantitative benchmarking of RAM usage, CPU overhead, and disk I/O between Loki/Promtail/Grafana/Java-based telemetry sidecars vs. LogTide and lightweight native sidecars under peak 10k conn/s load.
   - Evaluation of memory stability under high log volume (log bursts during volumetric DDoS attacks).
2. **Security & Supply Chain Conformance:**
   - Audit of container build provenance and base-image control (moving from third-party vendor images to first-party Alpine/distroless LogTide containers built from audited source).
   - Eradication of third-party Go stdlib and base OS CVE waiver debt (`CVE-2026-78667`, `CVE-2026-97031`).
3. **Functional & Protocol Compatibility:**
   - Log ingestion interface parity (Syslog RFC 5424, JSON over HTTP/UDS, OTLP log stream integration with `ja4pd`).
   - Query language and analytics capability matrix (LogQL vs. LogTide SQL/structured filters).
   - Dashboard & alerting integration (Grafana compatibility, native Webhook/Alertmanager routing).
4. **Architecture Evaluation Report & Migration Roadmap:**
   - Comprehensive decision framework (Go/No-Go criteria, migration risk matrix, multi-tenant deployment impacts).

### Out of Scope
- Production removal of Loki/Promtail in this evaluation phase (actual codebase replacement will occur in subsequent implementation phases based on this evaluation report).

---

## Architectural Evaluation Dimensions

### 1. Resource Consumption & Runtime Efficiency
- **Memory Footprint:** Heavy logging/metrics solutions (e.g. JVM-based collectors or Loki chunk indexers) often require 250 MB – 1 GB+ RAM per instance. LogTide is engineered for low-overhead, native execution, targeting < 50 MB resident set size (RSS).
- **CPU & Garbage Collection Impact:** Multi-gigabyte GC pauses in managed runtime collectors introduce tail latency in co-located proxy nodes. LogTide minimizes runtime GC overhead and lock contention.
- **Disk I/O & Storage Compaction:** Comparison of Loki chunking & WAL vs. LogTide zero-copy ingestion, indexing efficiency, and long-term retention compression ratios.

### 2. Supply-Chain & CVE Elimination
- **Third-Party Upstream Lag:** Grafana/Loki upstream containers rely on vendor release schedules, leaving unpatched Go stdlib / OS layer vulnerabilities active in DMZ environments for weeks.
- **First-Party Container Build Strategy:** Packaging LogTide into a pinned, distroless/minimal Alpine container built directly in `ja4proxy` CI (`Dockerfile.logtide`), integrated with `make check-updates` and automated dependency alignment (`scripts/check_toolchain_alignment.py`).

### 3. Log Ingestion & Query Parity
- **Ingestion Pipeline:** Compatibility with `ja4pd` structured log output (JSON over Unix Domain Socket / stdout), `ja4-tap` packet capture logs, and `management-api` audit events.
- **Filtering & Search:** Evaluating field extraction (JA4 fingerprints, client IPs, risk scores, rule IDs) performance under high ingestion rates.

---

## Implementation Plan

### Stage 1: Benchmark Harness & Baseline Data Collection
- [ ] Create benchmark scenario in `deploy/docker/docker-compose.logtide-eval.yml` running identical simulated traffic workloads (`make test-chaos` / traffic generator).
- [ ] Collect baseline resource metrics (cgroup RSS memory, CPU core utilization, disk write throughput, log loss percentage) for the current Loki/Promtail stack vs. LogTide sidecar.

### Stage 2: Security & Vulnerability Analysis
- [ ] Perform Trivy / Grype vulnerability comparison between third-party telemetry containers and the first-party LogTide container build.
- [ ] Verify zero CVE exceptions required in `.trivyignore.third-party`.

### Stage 3: Functional Parity & Query Capability Matrix
- [ ] Map all current Grafana dashboard panels (`deploy/monitoring/grafana/dashboards/`) and Loki queries to LogTide query primitives.
- [ ] Verify real-time alert triggering latency for high-risk threat scores (JA4 anomaly detection, brute force IP blocks).

### Stage 4: Architectural Evaluation Report & ADR
- [ ] Publish formal Architectural Decision Record (ADR-840) detailing trade-offs, performance gains, migration milestones, and enterprise SecOps operational impacts.

---

## Test Strategy & Validation Criteria

1. **Performance Test:**
   - Execute 10,000 requests/sec synthetic log load for 1 hour.
   - LogTide RSS memory must remain < 64 MB (compared to Loki's ~300+ MB baseline).
   - Zero log line drops during sustained 10k conn/s bursts.
2. **Security Scan Gate:**
   - `make scan` against LogTide container image must return 0 HIGH/CRITICAL CVEs with zero waivers.
3. **Query Latency Test:**
   - Top-10 JA4 fingerprint aggregation query across 10 million log lines must execute in < 200 ms.

---

## Acceptance Criteria

- [ ] Complete benchmark report comparing LogTide vs. Loki/Promtail sidecars across CPU, RAM, Disk I/O, and log ingestion throughput.
- [ ] Container build file `deploy/docker/Dockerfile.logtide` authored and verified clean via `make scan`.
- [ ] Functional parity matrix completed for all 14 core `ja4proxy` log signals.
- [ ] Formal ADR-840 published in `docs/architecture/decisions/` with enterprise SecOps recommendations.
- [ ] `make lint-phases` exits 0.

---

## Out of Scope

- Hard deprecation and immediate deletion of Loki configurations in default compose files (deferred to Phase 841 migration execution).
