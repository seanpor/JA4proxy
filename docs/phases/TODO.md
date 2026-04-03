# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🟡 Phases In Progress

### Phase 15 — Go Rewrite
*   **Gap:** No binary ClientHello fixtures in tests/fixtures/clienthello/ — JA4 parity vs Python untestable at fixture level
*   **Gap:** Cross-language parity integration tests are structural stubs only (make parity-check requires both proxies running)
*   **Gap:** Prometheus metric name alignment with Python not verified
*   **Gap:** Go: PubSub reconnect on channel close exits goroutine instead of reconnecting
*   **Status:** **IN_PROGRESS** (10-50x throughput improvement via CPython/Go transition. Config wiring complete for all signal modules. Remaining: ClientHello fixtures, live parity harness validation, Prometheus metric alignment.)
*   **Action Plan:** [PHASE_15.md](PHASE_15.md)

### Phase 59 — Advanced Traffic Intelligence - Phase 4: Feed Reliability & Resilience
*   **Gap:** P59-G1: Syntax error in misp.py preventing test execution
*   **Gap:** P59-G2: Feed health monitoring system not yet implemented
*   **Gap:** P59-G3: Circuit breaker pattern not yet implemented
*   **Gap:** P59-G4: Chaos testing for feed failures not comprehensive
*   **Status:** **IN_PROGRESS** (Enhance feeds with health monitoring, circuit breakers, and comprehensive chaos testing.)
*   **Action Plan:** [PHASE_59.md](PHASE_59.md)

---

## 🔵 Planned & Open Phases

### Phase 13 — Management UI - Phase 1: Backend API
*   **Status:** **DEFERRED** (FastAPI backend for real-time monitoring and configuration management.)
*   **Action Plan:** [PHASE_13.md](PHASE_13.md)

### Phase 34 — APT Hardening - Phase 1: Parser Isolation & Redis Security
*   **Status:** **PROPOSED** (Implement parser process isolation and Zero-Trust Redis ACLs with signatures.)
*   **Action Plan:** [PHASE_34.md](PHASE_34.md)

### Phase 35 — Advanced APT - Phase 1: Integrity Enforcement & Kernel-Level
*   **Status:** **PROPOSED** (Implement supply chain integrity monitoring and eBPF/XDP NIC-level blocking.)
*   **Action Plan:** [PHASE_35.md](PHASE_35.md)

### Phase 51 — Management UI - Phase 2: Frontend Dashboard
*   **Status:** **PROPOSED** (React-based dashboard for real-time visualization of proxy telemetry.)
*   **Action Plan:** [PHASE_51.md](PHASE_51.md)

### Phase 52 — Management UI - Phase 3: Administration Tools
*   **Status:** **PROPOSED** (Interactive tools for managing allowlists, bans, and system configuration.)
*   **Action Plan:** [PHASE_52.md](PHASE_52.md)

### Phase 55 — APT Hardening - Phase 2: Advanced Detection & Container Security
*   **Status:** **PROPOSED** (Implement subnet correlation, anti-evasion checks, and strict Seccomp/AppArmor profiles.)
*   **Action Plan:** [PHASE_55.md](PHASE_55.md)

### Phase 56 — Advanced APT - Phase 2: Deceptive Defense & Persistence Defense
*   **Status:** **PROPOSED** (Implement honey-fingerprints, honey-SNIs, and runtime process namespace isolation.)
*   **Action Plan:** [PHASE_56.md](PHASE_56.md)

### Phase 57 — Backup System Enhancements - Phase 3: Cloud & Incrementals
*   **Status:** **PROPOSED** (Add cloud storage adapters (S3/GCS) and incremental backup strategy.)
*   **Action Plan:** [PHASE_57.md](PHASE_57.md)

### Phase 60 — Master Plan and Governance
*   **Status:** **PROPOSED** (Comprehensive quality improvement roadmap and governance framework.)
*   **Action Plan:** [PHASE_60.md](PHASE_60.md)

### Phase 61 — Technical Quality Improvements
*   **Status:** **PROPOSED** (Code quality, architecture, performance, and reliability enhancements.)
*   **Action Plan:** [PHASE_61.md](PHASE_61.md)

### Phase 62 — Security Hardening
*   **Status:** **PROPOSED** (Penetration testing, threat modeling, incident response, and compliance.)
*   **Action Plan:** [PHASE_62.md](PHASE_62.md)

### Phase 63 — Observability and Monitoring
*   **Status:** **PROPOSED** (Technical observability, executive dashboards, alerting, and reporting.)
*   **Action Plan:** [PHASE_63.md](PHASE_63.md)

### Phase 64 — Operational Excellence
*   **Status:** **PROPOSED** (Process optimization, training, documentation, and continuous improvement.)
*   **Action Plan:** [PHASE_64.md](PHASE_64.md)

### Phase 65 — Performance Hardening & Go/Python Parity
*   **Status:** **PROPOSED** (Replace Python Scapy+subprocess TLS parser with pure-Python implementation (~20% latency improvement). Fix Go config gap so all 7 signal modules are enabled. Establish permanent cross-proxy parity tooling: binary fixtures, signal score registry, live decision comparison harness.)
*   **Action Plan:** [PHASE_65.md](PHASE_65.md)

### Phase 66 — Python 3.14 Compatibility Assessment
*   **Status:** **PROPOSED** (Zero-risk pre-upgrade phase: write PyPI wheel checker script, run full test suite on Python 3.14 locally to surface deprecation issues, capture Python 3.11 benchmark baseline for before/after comparison. No Dockerfile changes.)
*   **Action Plan:** [PHASE_66.md](PHASE_66.md)

### Phase 67 — Python 3.14 Base Image Upgrade
*   **Status:** **PROPOSED** (Upgrade nine non-analytics Dockerfiles from python:3.11.11-slim to python:3.14.0-slim. Update pyproject.toml target-version. Full test suite must pass. Benchmark before/after — expected ~25-35% CPU path improvement from tail-call interpreter and JIT.)
*   **Action Plan:** [PHASE_67.md](PHASE_67.md)

### Phase 68 — Python 3.14 Hot Path Optimizations
*   **Status:** **PROPOSED** (Make the JA4/scoring hot path JIT-friendly (remove try/except from inner loops, monomorphic call sites). Integrate uvloop as the asyncio event loop on Linux for 2-4x I/O throughput gain. Both changes are additive and independently revertable.)
*   **Action Plan:** [PHASE_68.md](PHASE_68.md)

### Phase 69 — Free-Threaded Python Proxy
*   **Status:** **PROPOSED** (Conditional on Phase 67 throughput < 600 conn/s. Switch proxy container to python:3.14t-slim (no-GIL). Thread safety audit; replace asyncio.Lock with threading.Lock in local_cache and config loader. Replace ProcessPoolExecutor with ThreadPoolExecutor for zero-IPC TLS parsing.)
*   **Action Plan:** [PHASE_69.md](PHASE_69.md)

### Phase 70 — Analytics Upgrade & Subinterpreter Experiment
*   **Status:** **PROPOSED** (Upgrade analytics container to Python 3.14 once numpy/scipy wheels confirmed. Optional: implement subinterpreter worker pool (Python 3.14 interpreters module) as a feature-flagged alternative to ThreadPoolExecutor; benchmark and keep or remove based on data.)
*   **Action Plan:** [PHASE_70.md](PHASE_70.md)
