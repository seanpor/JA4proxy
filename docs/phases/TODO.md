# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🟡 Phases In Progress

---

## 🔵 Planned & Open Phases

### Phase 60 — Master Plan and Governance
*   **Status:** **PROPOSED** (Comprehensive quality improvement roadmap and governance framework.)
*   **Action Plan:** [PHASE_60.md](PHASE_60.md)

### Phase 61 — Supply Chain Security & Build Integrity
*   **Status:** **PROPOSED** (GitHub Actions CI pipeline (Python + Go tests, SAST, dependency audit); SBOM generation (CycloneDX 1.4); Cosign keyless image signing; SLSA level 2 provenance for Go binary; action SHA pinning; branch protection rules.)
*   **Action Plan:** [PHASE_61.md](PHASE_61.md)

### Phase 62 — Security Regression Harness, Fuzzing & Pre-Enterprise Validation
*   **Status:** **PROPOSED** (Automated regression tests for all Phase 27 pentest findings; atheris + Go native fuzzing harnesses with CI smoke run; break-glass verification procedure; pre-enterprise validation report generator.)
*   **Action Plan:** [PHASE_62.md](PHASE_62.md)

### Phase 63 — Service Level Objectives
*   **Status:** **PROPOSED** (Four SLIs (availability 99.9%, latency 99% <10ms, Redis correctness 99.5%, FP rate <2%); multiwindow burn-rate alerts; Grafana SLO dashboard; on-call runbooks; metric naming prerequisite (ja4_ → ja4proxy_ rename + add missing counters).)
*   **Action Plan:** [PHASE_63.md](PHASE_63.md)

### Phase 64 — Deployment Validation & Disaster Recovery
*   **Status:** **PROPOSED** (Smoke test suite (Docker Compose, Helm/kind, Podman/Quadlet); DR runbook with 5 scenarios incl. Redis data loss; credential rotation runbooks; TLS certificate rotation; rolling upgrade procedure; MTTR baseline measurement.)
*   **Action Plan:** [PHASE_64.md](PHASE_64.md)

### Phase 79 — Management API v2, RBAC & Enterprise Identity
*   **Status:** **PROPOSED** (Production-grade REST API with stable IDs, full RBAC (Auditor/Analyst/Operator/Admin), SAML 2.0 + OIDC SSO (Okta, Entra ID), mandatory MFA for Admin/Operator, append-only audit trail. Critical dependency for phases 80-86.)
*   **Action Plan:** [PHASE_79.md](PHASE_79.md)

### Phase 80 — ECS Structured Logging & SIEM Integration Pack
*   **Status:** **PROPOSED** (Canonical ECS 8.x JSON log format for all events. Splunk TA (CIM-compliant, 5 dashboards, 5 correlation searches, alert action). Microsoft Sentinel content pack. IBM QRadar DSM. Elastic integration. HMAC-signed webhook event stream.)
*   **Action Plan:** [PHASE_80.md](PHASE_80.md)

### Phase 81 — SOAR, Webhooks & Enterprise Operations Platforms
*   **Status:** **PROPOSED** (XSOAR integration (8 commands, 2 playbooks). Splunk SOAR app. ServiceNow SecOps SIR auto-creation and close-loop release. ServiceNow Spoke. xMatters two-way mobile response (5 options). Interlink Software Service Watch (UK NOC). PagerDuty/OpsGenie runbook links.)
*   **Action Plan:** [PHASE_81.md](PHASE_81.md)

### Phase 82 — Policy-as-Code, Shadow Mode & Governance
*   **Status:** **PROPOSED** (Policy YAML schema versioned in git, applied via CI/CD. Shadow mode simulation (what would dial=X have blocked last week?). Four-eyes approval workflow. ServiceNow change record integration. Drift detection scheduled job.)
*   **Action Plan:** [PHASE_82.md](PHASE_82.md)

### Phase 83 — Infrastructure Automation — Terraform, CLI & Kubernetes Operator
*   **Status:** **PROPOSED** (ja4proxy-cli Go binary (full command set: ip, allowlist, blocklist, dial, policy, simulation). Terraform provider with drift protection and import workflow. Kubernetes operator + CRDs (JA4ProxyConfig, JA4ProxyAllowlist, JA4ProxyDial). CMDB/NetBox integration. Three emergency runbook Ansible playbooks.)
*   **Action Plan:** [PHASE_83.md](PHASE_83.md)

### Phase 84 — Compliance & Reporting
*   **Status:** **PROPOSED** (PCI-DSS v4.0 evidence pack (8 artefacts, auto-generated). SOC 2 Type II control narrative and monthly evidence collection. GDPR retention/purge/DSAR/erasure. Executive PDF report with value-of-product metric. ISO 27001 Annex A mapping.)
*   **Action Plan:** [PHASE_84.md](PHASE_84.md)

### Phase 85 — Threat Intelligence Ingestion
*   **Status:** **PROPOSED** (TAXII 2.1 client consuming JA4 fingerprint and IP indicators. JA4 STIX 2.1 extension definition (strategic moat — first standard for JA4 indicators). Recorded Future and CrowdStrike named connectors. Curated JA4 fingerprint community feed architecture.)
*   **Action Plan:** [PHASE_85.md](PHASE_85.md)

### Phase 86 — Observability & Capacity Planning
*   **Status:** **PROPOSED** (Datadog Agent integration tile with dashboard and 4 monitors. Dynatrace EF2 extension with topology entity type. Nagios check plugin and Zabbix template. Capacity sizing calculator script. make load-test harness. Published benchmark numbers. 7 operator runbooks.)
*   **Action Plan:** [PHASE_86.md](PHASE_86.md)

### Phase 88 — Multi-Datacenter Survivability & Failover
*   **Status:** **PROPOSED** (Redis Sentinel per-DC plus a new Go sync agent (cmd/syncagent) for cross-DC state replication. State Classification Table (25 key types: SYNC-IMMEDIATE, SYNC-ASYNC, LOCAL-ONLY, DIAL-PROTOCOL). Synchronous Dial Consistency Protocol (port 7380, 8s ACK timeout, last-writer-wins by origin_ts). Active-active and active-passive topology documentation. Seven failure scenario runbooks (WAN failure, DC dark, Redis-only failure, dial divergence, data loss, asymmetric degradation, split-brain). New multi-DC metrics on port 9382 with six alert rules including DialDivergence (critical). Cross-DC Grafana dashboard. Operational procedures for maintenance drain, DC expansion, and rolling upgrade.)
*   **Action Plan:** [PHASE_88.md](PHASE_88.md)

### Phase 89 — Dockerfile Base Image Hygiene
*   **Status:** **PROPOSED** (Standardise Python base images: upgrade python:3.11-slim to 3.14.0-slim in admin and management Dockerfiles; pin test infrastructure from python:3.14-slim to python:3.14.0-slim.)
*   **Action Plan:** [PHASE_89.md](PHASE_89.md)
