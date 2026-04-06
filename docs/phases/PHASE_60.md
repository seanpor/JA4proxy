# Phase 60: Product Strategy & Gap Registry

---

## 1. Purpose of This Document

Phase 60 is not an implementation phase. It is a living strategic reference for the 60–64 cluster. It maps what has been built, identifies what genuinely remains, and states the product's direction and limitations honestly. Teams working on phases 61–64 should read this document before starting. The original Phase 60 content (dated 2024, referencing budget tables, a Steering Committee, and Gantt charts) is superseded entirely by this document; the project is developed by AI agents operating in parallel with no human management hierarchy.

Note: The `manifest.yaml` entries for phases 61–64 carry legacy summary text (e.g., "Technical Quality Improvements", "Security Hardening") that predates the current phase specifications. The manifest summaries should be updated when each phase moves to IN_PROGRESS status to reflect the actual deliverables described in the phase documents.

---

## 2. Where the Product Is (April 2026)

### 2.1 Capability Summary

| Capability | Status | Key Phases |
|---|---|---|
| TLS fingerprinting — JA4, JA4X, JA4T | Production | 0, 5, 16 |
| Risk scoring (composite, 0–100) | Production | 1 |
| Dial system (0–100, monitor to full-block) | Production | 2 |
| Configurable bypass rules (ALLOW + BLOCK) | Production | 0–8 |
| Signal collection — TLS, SNI, TCP, ASN, DNS, blocklists, beaconing, AbuseIPDB, RDAP | Production | 3–11 |
| Redis-backed shared state (bans, rate limits, streams, HLL, bloom) | Production | 0 |
| Analytics node (cross-instance aggregation, campaign detection) | Production | 12 |
| TAP / SPAN mode (out-of-band, AF_PACKET capture) | Production | 20 |
| Go proxy (full signal parity with Python, compiles and passes all unit tests) | Complete | 15 |
| Helm / Kubernetes deployment (DaemonSet topology, chart included) | Complete | 72–75 |
| RHEL 8/9 via Podman and Quadlets | Complete | 76 |
| SIEM integration patterns (Wazuh, CrowdSec, Splunk, QRadar, Vector) | Documented | 77 |
| Enterprise scale, FIPS, GDPR masking | Documented | 78 |

### 2.2 Performance Baseline

Python proxy, single instance: **2,184 conn/s**, p50 0.50 ms, p99 1.62 ms.
Python proxy, 4 workers (HAProxy LB): **8,100 conn/s**.
Go proxy: implemented and all unit tests pass. Full signal parity verified against Python. Formal production-load benchmarks have not yet been run.

### 2.3 Test Coverage

**2,948 tests** across unit, integration, chaos, adversarial, and performance categories. The project maintains a ~1.3× test-to-code ratio. 21 tests are skipped in CI because they require live Docker services; all others pass in the standard `make test` run.

---

## 3. What Phases 61–64 Are (And Are Not)

Phases 61–64 are the quality and operational consolidation layer for the 60–86 programme. They do not add new proxy capabilities, new signals, or changes to the risk scoring model. A team starting Phase 61 should not attempt to improve detection rates; that is not the goal and any such work would be out of scope.

A significant portion of what was originally outlined for 61–64 in the 2024 governance document has already been completed through other phases — see §4 for the full list. What remains, documented in §5, is a smaller and more concrete set of genuine gaps. The enterprise integration phases (79–86) assume a quality baseline that 61–64 establishes: specifically, that supply chain integrity exists before distributing binaries (Phase 61), that known security regressions cannot silently resurface (Phase 62), that the product has measurable SLOs before connecting to a SIEM (Phase 63), and that deployment procedures have been exercised end-to-end before enterprise buyers run them (Phase 64).

---

## 3.5 Execution Order and Why It Matters

Phase 61 must come first. Without a CI/CD pipeline, every other phase's work cannot be validated reproducibly. A security regression harness (Phase 62) has nowhere to run if there is no pipeline to execute it. SLO instrumentation changes (Phase 63) cannot be tested consistently if builds are ad-hoc. Deployment procedures (Phase 64) cannot be validated if the artifacts being deployed are not signed and tracked. Phase 61 is the prerequisite for meaningful quality gates in every phase that follows.

Phase 62 and Phase 63 can run in parallel once Phase 61 completes. Phase 62 (security regression harness) has no dependency on Phase 63 (SLO framework definition); Phase 63 has no dependency on Phase 62. The two workstreams touch different parts of the codebase and infrastructure — Phase 62 modifies test infrastructure and adversarial fixtures, Phase 63 modifies Prometheus alert rules and runbooks — so they can be assigned to separate agent branches simultaneously.

Phase 64 depends on all three. It validates the full integrated stack that Phases 61–63 build: the signed artifact pipeline (61), the clean security baseline (62), and the actionable SLO thresholds (63). Running Phase 64 before all three are complete produces a deployment validation report against an incomplete foundation.

The phases carry size estimates of XL / L / L / M respectively. If capacity is limited, Phase 63 (L, no proxy code changes — only alert rules and runbooks) can be worked concurrently with Phase 62 (XL, code and test changes). The constraint is that Phase 62 branch and Phase 63 branch must not both touch the same Prometheus alert rule files simultaneously; coordinate via the standard shared-file protocol in `CLAUDE.md`.

---

## 4. Work Already Done (Context for Teams Starting 61–64)

Teams should review this table before writing any Phase 61–64 task. Do not re-do work that is already complete.

| Original Concern | Phase That Addressed It | Status |
|---|---|---|
| Type hints, linting, mypy, ruff, bandit | Phase 37 | COMPLETE |
| Documentation excellence (ADRs, runbooks, audience-first navigation) | Phase 21 | COMPLETE |
| Penetration testing and specific vulnerability remediation | Phase 27 | COMPLETE |
| Test audit (genuine assertions, no hollow tests) | Phase 44 | COMPLETE |
| Coverage improvement (>80% on critical modules) | Phase 46 | COMPLETE |
| Docker image version pinning and CVE scanning | Phase 25 | COMPLETE |
| Python throughput optimisation (parallel signals, Redis pipelining, Unix socket) | Phases 26–30 | COMPLETE |
| Circuit breaker patterns and feed reliability | Phase 59 | COMPLETE |
| Architecture Decision Records (13 ADRs) | Multiple phases | COMPLETE |
| Security audit documentation | docs/security/ | COMPLETE |
| Docker network isolation (DMZ/APP/ORIGIN zones) | Phases 71–75 | COMPLETE |

---

## 5. Real Remaining Gaps

### 5.1 Supply Chain Security & Build Integrity (Phase 61)

No CI pipeline exists — `.github/workflows/` is absent from the repository. No SBOM (Software Bill of Materials) is generated at build time. Container images are not signed; there is no build provenance record. Enterprise procurement processes increasingly require all four before approving a security appliance. This is the highest-priority uncovered gap because every subsequent enterprise phase (79–86) will produce artifacts — API binaries, CLI tools, container images — that need signing from the start. Retrofitting supply chain controls after images are already in the field is significantly harder.

### 5.2 Security Regression Testing (Phase 62)

Phase 27 identified and fixed specific penetration testing findings. There is no automated harness that would detect if those vulnerabilities resurface — for example, if a refactor reintroduced IP spoofing via untrusted X-Forwarded-For headers, or if the ClientHello parser gained a new code path that is not covered by adversarial fixtures. There is no fuzzer running against the ClientHello parser. There is no pre-enterprise validation report that can be provided to a security team during procurement. Before the enterprise integration phases introduce third-party buyers and SIEM connectors, a regression validation step is required.

### 5.3 SLI / SLO Framework (Phase 63)

The proxy exposes over 200 Prometheus metrics, but zero Service Level Objectives are defined. The question "is the product operating normally?" has no measurable answer. There are no error budgets, no on-call runbooks tied to burn-rate alerts, and no formal service definition that states what availability, latency, and correctness the product commits to. Connecting the proxy to a SIEM (Phase 80) or an observability platform (Phase 86) without defined SLOs will produce dashboards and alerts with no actionable thresholds. Phase 63 must define SLOs before those phases begin.

### 5.4 Deployment Validation & Disaster Recovery (Phase 64)

The RHEL/Podman deployment guide (Phase 76), the Helm chart, and the Docker Compose stack are all documented. None has been run end-to-end in a controlled environment and formally validated. There is no documented disaster recovery procedure — no defined RTO/RPO, no GameDay scenario, no runbook for "Redis is down and the proxy node has crashed simultaneously." Enterprise buyers require evidence of DR capability during procurement. Phase 64 closes this gap by running the deployment procedures, recording the results, and producing a DR runbook with tested recovery steps.

### 5.5 Credential and Secret Lifecycle

The proxy holds several long-lived secrets: a Redis auth password, an AbuseIPDB API key (Phase 10), RDAP enrichment credentials if used (Phase 11), and potentially AWS/GCS storage credentials (Phase 57 cloud backup). No documented procedure exists for rotating any of these. Enterprise procurement questions will include "how do you rotate credentials without a service outage?" and the current answer is that there is no documented procedure.

The rotation procedure for each secret must be written and tested before any enterprise pilot deployment. Rotation must be achievable without a proxy restart — the hot-reload path via SIGHUP supports this for most secrets that are loaded from `config/proxy.yml`. Redis password rotation is a special case because it requires coordinating the Redis server, all proxy instances, and the analytics node simultaneously. Phase 64 is the correct home for this gap: each rotation procedure should be documented as a runbook, tested in the validation environment, and its steps recorded in the phase notes.

### 5.6 TLS Certificate Lifecycle

The proxy's listen-side TLS certificate (presented to clients) and the mTLS CA certificate (Phase 5) used to verify client certificates both have expiry dates. No phase currently documents: what certificate expiry looks like in monitoring (a metric or alert for `cert_days_remaining`), what the rotation procedure is, or what happens if a certificate expires in production (connection failures visible as TLS handshake errors to clients).

This is a silent operational failure mode: unlike a crashed process, certificate expiry does not generate a loud alert unless someone explicitly monitors it. The first sign of expiry is typically a spike in client-visible TLS errors — at which point the damage is already occurring. Phase 64 should add certificate expiry monitoring (a Prometheus gauge exported at startup and on SIGHUP reload), a low-watermark alert rule (e.g., warn at 30 days, page at 7 days), and a tested rotation runbook covering both the listen-side cert and the mTLS CA.

### 5.7 Rolling Upgrade Procedure

When a new version of the proxy is released, the procedure for upgrading from the current version to the next without dropping traffic is not documented. The fail-open design and shared Redis state make rolling upgrades architecturally feasible — HAProxy can drain connections from one proxy node while it restarts on the new version — but the exact command sequence (drain → upgrade → health check → bring back into rotation → proceed to next node) has never been written down or tested.

Enterprise buyers with uptime commitments require evidence that software upgrades are non-disruptive. A rolling upgrade runbook is a standard procurement deliverable for any inline security appliance. Phase 64 should add this runbook alongside the disaster recovery runbook already planned for that phase. The runbook should cover Docker Compose, Kubernetes (rolling deployment strategy), and RHEL/Podman (Quadlet unit restart sequence) separately, as the drain and health-check commands differ across platforms.

---

## 6. Product Direction

### 6.1 Strategic Trajectory

JA4proxy is maturing from a security-hardened prototype into an enterprise security appliance for regulated industries. The 79–86 enterprise integration phases deliver the integration surface — Management API, SIEM connectors, SOAR playbooks, Terraform provider, compliance reporting, threat intel ingestion — that enterprise buyers require to adopt the product. Phases 60–64 are the foundation that makes the enterprise phases credible: without CI signing (61), regression safety (62), measurable SLOs (63), and validated deployments (64), the enterprise integration work sits on an unvalidated base.

### 6.2 Target Deployment Pattern

The intended production topology is: load balancer (HAProxy or F5) → JA4proxy ×N (inline) → backend HTTPS servers. JA4proxy is a transparent passthrough proxy that operates on TLS metadata before the handshake completes. It is not a WAF and should not be positioned as one.

### 6.3 Supported Deployment Platforms (after phases 61–64 complete)

- Docker Compose — development and staging environments
- Kubernetes — Helm chart, DaemonSet topology, three-tier network isolation
- RHEL 8/9 via Podman and Quadlets — enterprise bare-metal and VM deployments
- TAP / SPAN mode — out-of-band monitoring without inline deployment, suitable for initial evaluation or network segments where inline insertion is not possible

---

## 7. Product Limitations

This section is deliberately honest. Enterprise buyers and architects must understand these constraints before deployment.

### 7.1 Preprocessor, Not a WAF

JA4proxy operates on TLS metadata visible before and during the handshake. It never decrypts traffic. It cannot inspect HTTP content, detect SQL injection, XSS, or application-layer payloads. These capabilities are architecturally impossible given the design constraint that the proxy never holds TLS keys. Position this product as a complement to a WAF, not a replacement. The correct framing is: JA4proxy filters automated threats at the network layer before they consume WAF capacity.

### 7.2 Fingerprint Evasion

JA4 fingerprints can be forged. A sophisticated attacker who studies the allowlist and mimics a browser's fingerprint will pass through. The product's primary defensive value is against mass automation — C2 frameworks, credential stuffers, vulnerability scanners, and bot networks — that do not bother to mimic real browser TLS behaviour. Against a targeted attacker with knowledge of the proxy's configuration, protection is materially reduced. This limitation is inherent to any fingerprint-based system and should be disclosed during procurement.

### 7.3 Redis Failure = Fail-Open

During a Redis outage the proxy fails open — all connections are allowed through. This is intentional: false positives (blocking legitimate users) cost more than false negatives (missing a blocked connection during the outage window). However, it means the proxy provides zero active blocking during a Redis unavailability event. Rate limiting, bans, cross-instance coordination, and Spamhaus lookups all require Redis. The proxy logs the failure and continues forwarding. Operators must treat Redis availability as a direct dependency of the proxy's security function.

### 7.4 Python Throughput Ceiling

The Python proxy is limited to approximately 2,184 conn/s (single instance) and 8,100 conn/s (4 instances) by the Python GIL and asyncio overhead. This is sufficient for most enterprise DMZ deployments, but insufficient for very high-traffic environments above roughly 10 Gbps sustained ingress. The Go proxy removes this ceiling and is implemented with full signal parity. Formal Go benchmarks under production-representative load have not yet been run; operators targeting >10 Gbps should wait for Phase 65 benchmark results before committing to the Go proxy in production.

### 7.5 False Positive Guarantee Scope

The "0% false positive" claim applies specifically to browser traffic presenting h2 or h1 ALPN — these bypass the scorer entirely by design and can never be blocked. Legitimate API clients, monitoring tools, CI/CD health checks, and automated systems that do not send h2/h1 ALPN may trigger false positives under high dial settings. The dial=0 default, shadow mode simulation (Phase 82), and the majority-vote rate-limiting policy all mitigate this, but false positives cannot be eliminated for non-browser automated traffic without tuning.

### 7.6 Phases 61–64 Add No New Proxy Capabilities

These are quality and operational phases. They do not improve detection rates, add new signals, or change the risk scoring model. An enterprise buyer evaluating detection efficacy should focus on phases 0–20 (core proxy capabilities) and phases 79–86 (integration and policy surface). Phases 61–64 exist to make the product trustworthy and deployable in enterprise environments, not to make it more capable.

### 7.7 Redis as a Security Dependency — Write-Abuse Threat Model

Section 7.3 discloses that Redis unavailability causes the proxy to fail open. A complementary threat that is less visible but equally significant: Redis availability with unauthorised write access. An attacker or a misconfigured internal service with write access to the Redis instance can:

- Set `ja4proxy:dial 0` across the entire fleet, disabling all blocking silently
- Delete the Spamhaus DROP trie keys, removing the hard-block layer
- Zero out all active ban keys, releasing all banned IPs simultaneously
- Inject false positive entries into the rate-limit Sorted Sets, triggering false blocks against legitimate IPs

The proxy's Redis ACL, network segmentation, and audit logging are what prevent this. At minimum: Redis must not be network-accessible from untrusted segments; the proxy's Redis user must have only the specific command permissions it needs (not `+@all`); and `KEYS`, `DEBUG`, `CONFIG SET`, and `FLUSHALL/FLUSHDB` must be blocked on the proxy's Redis ACL. Phase 34 (Zero-Trust Redis ACLs) addresses this directly. This limitation is disclosed here because enterprise buyers in regulated industries will ask about the threat model for the proxy's shared state store during procurement, and the correct answer must reference both the fail-open design (§7.3) and the write-abuse protection (Phase 34 ACLs).

---

## 8. Relationship to Enterprise Phases (79–86)

| Enterprise Phase | What It Needs From 60–64 |
|---|---|
| Phase 79 (Management API) | Phase 61 CI pipeline — the API must be built with image signing and dependency scanning from day one; retrofitting later is harder. Phase 64 credential rotation procedure — JWT signing keys and session tokens follow the same hot-reload rotation pattern established for Redis and AbuseIPDB credentials. |
| Phase 80 (SIEM Integration) | Phase 63 SLOs — connecting a SIEM without defined thresholds produces unactionable alerts |
| Phase 82 (Policy / Shadow Mode) | Phase 62 regression testing — shadow mode block decisions must be based on a security baseline that is known to be clean |
| Phase 83 (Terraform Provider / CLI) | Phase 61 supply chain — CLI binaries require signing and provenance before distribution |
| Phase 84 (Compliance Reports) | Phase 62 pre-enterprise validation report — compliance evidence requires a clean, documented penetration test result |
| Phase 86 (Observability / Capacity Planner) | Phase 63 SLOs — the capacity calculator needs defined "healthy" thresholds to produce useful projections |
| Phase 64 (Deployment Validation) | Phases 61–63 foundation — credential rotation, cert lifecycle monitoring, and rolling upgrade runbooks are all validated in Phase 64 and referenced by the enterprise phases that follow |

---

*This document is updated whenever the project's strategic direction changes or a major gap is closed. Last updated: 2026-04-06.*
