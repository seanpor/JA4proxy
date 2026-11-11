# JA4proxy Strategic Product Plan: v3.0.0 & Future Horizons

**Document Type:** Strategic Product Plan & Release Roadmap  
**Target Milestone:** JA4proxy v3.0.0 ("Enterprise Line-Rate")  
**Date:** 2026-11-11  
**Audience:** Product Management, Enterprise SecOps, Principal Architects, Lead Maintainers  
**Status:** DRAFT / APPROVED FOR ROADMAP PLANNING  

---

## 1. Executive Summary & Vision

Since the `v2.0.0` milestone, JA4proxy has undergone an architectural transformation. The legacy Python proxy runtime was decommissioned, and the entire high-performance data-plane was re-engineered as a native, hermetic Go service (`cmd/ja4pd/`, `internal/`). Through extensive security hardening, fuzzing campaigns, and formal red-team audits (Phases 800–868), the Go proxy core currently operates with **zero known vulnerabilities, zero memory leaks, and sub-microsecond decision latencies** (<900 ns).

With foundational data-plane performance and low-level harness modernization delegated (Phases 869–873), JA4proxy must now transition from a hardened core engine into a **production-ready, enterprise-grade security product**.

This document outlines the **v3.0.0 Strategic Product Plan**, detailing the rationale for the major SemVer increment, the release readiness gates, and the subsequent strategic horizons covering cloud-native orchestration and global threat intelligence ecosystems.

---

## 2. Rationale for SemVer 3.0.0

Under Semantic Versioning (SemVer 2.0.0), a major version increment (`v3.0.0`) is required due to fundamental breaking architectural and operational changes landed since `v2.0.0`:

1. **Complete Runtime Shift (Go-Native Core)**:
   - The Python proxy daemon (`proxy.py`) and legacy Python pipeline packages (`src.security.pipeline`) have been retired.
   - The production proxy is now exclusively `cmd/ja4pd`, running on native Go networking with zero Python runtime dependency in the data-path.
2. **Configuration & Environment Variable Canonicalization**:
   - Environment variables, command-line arguments, and dynamic reload signals have been formalized around Go proxy flags (`docs/reference/ENV_VARS.md`).
3. **Distribution & Packaging Evolution**:
   - Container images migrated from multi-layer standard Linux distributions to minimal, distroless runtimes (`gcr.io/distroless/static-debian12`), reducing third-party CVE attack surfaces to zero.
4. **Protocol & Invariant Enforcement**:
   - Strict L4 stream forwarding semantics, ALPN negotiation bypasses, and atomic TCP reset (`SetLinger(0)`) enforcement for blocked connections replace legacy HTTP-level proxy behaviors.

---

## 3. The 3 Strategic Product Horizons

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ HORIZON 1: v3.0.0 Release Engineering & Operational Hardening (Immediate Milestone)   │
│  • Automated multi-ecosystem dependency maintenance (`make update-all`, Phase 873)     │
│  • Scientific load generation (ja4bench v2, open-loop Poisson arrival, Phase 869)      │
│  • Zombie harness deprecation (Phase 870) and dual-baseline CI regression gates (871)  │
│  • Automated 2-hour soak test verification & PGO compiler optimization (Phase 872)    │
│  • Changelog aggregation (80+ fragments), SLSA Level 3 attestations, v3.0.0 release    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ HORIZON 2: Cloud-Native Distribution & Enterprise Infrastructure (Post-v3.0.0)         │
│  • Official Helm Charts & Kubernetes Ingress / Gateway API Controller                  │
│  • Envoy / HAProxy sidecar & filter integrations                                       │
│  • Multi-region Active-Active Redis replication & cross-DC state sync                  │
│  • Hardware-accelerated kernel drop path via eBPF / XDP for volumetric mitigation     │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ HORIZON 3: Global Threat Intelligence Ecosystem & Regulatory Compliance (Next-Gen)     │
│  • Bidirectional STIX 2.1 / TAXII 2.1 threat feed ingestion & publishing engine        │
│  • Enterprise External Dynamic List (EDL) provider for edge firewalls (Palo Alto, etc)│
│  • Deep JA4+ protocol expansion (JA4X, JA4SSH, JA4T TCP stream fingerprinting)        │
│  • EU Cyber Resilience Act (CRA) compliance & automated SBOM distribution             │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Horizon 1: The v3.0.0 Release Readiness Blueprint

Before cutting the formal `v3.0.0` release tag, the following four release gates must be satisfied:

### 4.1. Gate A: Tactical Engineering Prerequisite Completion (Phases 869–873)
* **Dependency & Scanner Hygiene (Phase 873)**: Automated daily dependency updates (`make update-all`) operational; container-strict execution intact; Trivy/Rego scanner warnings eliminated.
* **Macro Benchmark Honesty (Phase 869)**: `ja4bench` v2 operating with an open-loop Poisson arrival model, eliminating Coordinated Omission, and accurately logging L4 transport verdicts.
* **Harness Cleanup (Phase 870)**: 2,500+ lines of dead Python benchmark scripts safely decommissioned.
* **CI Telemetry Realignment (Phase 871)**: Nightly benchmark regression gate fixed with dual baselines (CI runner vs host bare-metal).
* **Soak & Memory Safety (Phase 872)**: Continuous 2-hour soak test demonstrating zero goroutine growth, bounded heap usage (`GOMEMLIMIT`), and exporting `default.pgo` profiles.

### 4.2. Gate B: Documentation & Migration Guidance
* **Comprehensive Migration Guide (`docs/operations/V2_TO_V3_MIGRATION.md`)**:
  - Step-by-step instructions for operators migrating configuration from the Python proxy to `ja4pd`.
  - Port mapping updates (transition from legacy test ports `18080/18082` to direct ports `8080/8443`).
  - Redis schema and memory sizing recommendations for enterprise connection rates.
* **Changelog Assembly**:
  - Run `make changelog-assemble` to fold over 80 accumulated news fragments in `docs/fragments/` into the master `CHANGELOG.md` under `## [3.0.0]`.

### 4.3. Gate C: Security, Supply-Chain & SLSA Attestation
* Zero open findings in `docs/security/findings.yaml`.
* Automated SBOM generation (SPDX and CycloneDX JSON formats) via Syft/Goreleaser.
* Verification of SLSA Level 3 build provenance (`.github/workflows/release.yml`).
* GPG signing of all release binaries using the JA4proxy Release Key (`releases@ja4proxy.io`).

### 4.4. Gate D: Cold-Start & End-to-End Smoke Validation
* Zero-error execution of `scripts/start-poc.sh` in a clean environment.
* Automated validation of the Management UI, Prometheus OpenMetrics exporter, and Grafana dashboard provisioning.

---

## 5. Horizon 2: Enterprise Cloud-Native Distribution (Post-v3.0.0)

Following the `v3.0.0` release, adoption will depend on ease of deployment within modern cloud environments:

### 5.1. Kubernetes Cloud-Native Packaging
* **Helm Chart (`deploy/charts/ja4proxy`)**: Turnkey deployment supporting High Availability (HA), pod anti-affinity, horizontal pod autoscaling (HPA) driven by connection rate or CPU saturation, and automated TLS certificate mounting via `cert-manager`.
* **Gateway API & Ingress Controller**: A lightweight Kubernetes controller allowing JA4proxy to act as an ingress gatekeeper, classifying TLS connections before routing traffic to cluster service backends.

### 5.2. Kernel-Bypass Volumetric Attack Defense (eBPF / XDP)
* While `ja4pd` processes connections in userspace at multi-thousand CPS, volumetric layer-4 DDoS attacks (SYN floods or repeated connection storms from known bad actors) should be filtered before hitting userspace.
* **Architecture**: The Go proxy or management engine pushes malicious IP CIDRs or JA4TCP patterns into an eBPF BPF_MAP, allowing XDP (eXpress Data Path) programs at the network interface driver level to drop malicious packets with zero CPU penalty.

### 5.3. Multi-Datacenter Distributed State
* Multi-region enterprise deployments require synchronizing threat intelligence (blocked IPs, high-reputation offenders, rate-limit buckets) across geographically dispersed proxy instances.
* Document and validate Redis Cluster / Redis Sentinel active-active replication topologies, ensuring eventual consistency without introducing cross-region latency in the connection evaluation path.

---

## 6. Horizon 3: Threat Intelligence Ecosystem & Regulatory Compliance

To establish JA4proxy as the industry-standard TLS fingerprinting defense proxy, the product will interface with the broader threat intelligence and compliance ecosystem:

### 6.1. Automated Threat Feed Ingestion & Dynamic EDL Export
* **Bidirectional STIX 2.1 / TAXII 2.1**: Automated consumers pulling malicious JA4/JA4S fingerprints from commercial and open-source feeds (e.g., abuse.ch, MISP, AlienVault OTX) directly into Redis lookup tables.
* **External Dynamic List (EDL) Provider**: An authenticated HTTP server endpoint allowing enterprise edge firewalls (Palo Alto Networks, Fortinet, Check Point) to ingest JA4proxy's real-time blocked IP lists automatically.

### 6.2. Advanced Protocol Expansion (JA4+ Suite)
* Extend beyond standard TLS JA4/JA4S:
  * **JA4X**: TLS X.509 certificate fingerprinting to identify rogue or self-signed upstream origin certs.
  * **JA4SSH**: Passive SSH client/server fingerprinting for bastion host security.
  * **JA4T**: Deep TCP SYN packet option analysis to detect OS spoofing and tool tampering.

### 6.3. Regulatory Conformance & Cyber Resilience Act (CRA)
* The European Cyber Resilience Act (CRA) mandates strict vulnerability disclosure processes, software bill of materials (SBOM) distribution, and lifecycle support commitments for critical infrastructure software.
* Formalize the open-source compliance posture documented in `docs/compliance/CRA_CONFORMANCE.md`, ensuring all container images and binaries carry cryptographic attestations and machine-readable CVE vulnerability disclosures.

---

## 7. Immediate Product Management Action Items

1. **Track Tactical Sub-Phases**: Monitor completion of Sub-Phases `873a`–`873d` and `869a`–`872d` delegated to engineering.
2. **Draft Migration Artifacts**: Begin drafting `docs/operations/V2_TO_V3_MIGRATION.md` detailing the operational delta between v2 and v3.
3. **Schedule Release Dry-Run**: Schedule a formal Release Candidate build (`v3.0.0-rc1`) to validate artifact signing, Goreleaser pipelines, and SLSA provenance once Phase 872 lands.
