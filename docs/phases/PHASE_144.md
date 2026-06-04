# Phase 144: Operational Excellence & Repo Pruning

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 143
> **Owner:** Gemini CLI

## Goal
Optimize the project for Cyber Ops evaluation and production deployment by streamlining the repository, enhancing the CLI toolchain, and providing clear "Audit-to-Action" mappings.

## Scope

### 1. Repository Pruning & Hygiene
- **Legacy Migration**: Move the `archive/` directory and obsolete Python-related documentation to a dedicated `legacy-v1` branch.
- **Root Cleanup**: Remove transient files and ensure the `main` branch reflects only the stable v2.0.0 Go-centric stack.
- **Documentation Consolidation**: Merge overlapping operational docs into a single, high-authority `docs/OPERATIONS_GUIDE.md`.

### 2. "Single-Binary" CLI Enhancements
- **Config Validator**: Add `ja4p config validate` to the Go binary to verify YAML syntax and logical consistency (e.g., dial range, valid feed URLs) before service start.
- **IP Simulator**: Add `ja4p test ip <addr>` to simulate a pipeline decision for a given IP, allowing Ops to verify blocklist/reputation logic instantly.
- **Version Signal**: Ensure `ja4p version` includes the SLSA provenance hash and build timestamp.

### 3. MITRE ATT&CK & Ops Playbooks
- **Signal Mapping**: Create `docs/OPERATIONS_MAPPING.md` linking JA4proxy signals (e.g., JA4 mismatch, malformed SNI) to MITRE ATT&CK techniques.
- **Remediation Playbooks**: Provide "If-This-Then-That" (IFTTT) playbooks for the Top 5 most common security alerts.

### 4. Enterprise Helm v2
- **Kubernetes Native**: Relocate the Helm chart to `deploy/charts/ja4proxy` and update it to v2.0.0 standards.
- **Scaling & Observability**: Add native support for **Horizontal Pod Autoscaling (HPA)** using custom Prometheus metrics and include default **Grafana sidecars**.

## Acceptance Criteria
- [ ] `main` branch size reduced by >50% (by moving `archive/` to a branch).
- [ ] `ja4p config validate` successfully catches common misconfigurations.
- [ ] Formal MITRE ATT&CK mapping published and cross-linked in `README.md`.
- [ ] Helm chart successfully deploys a production-grade stack with one command.

---

## Strategic Intent
This phase transitions the repository from a "Researcher/Developer" focus to an "Operator/Production" focus. By removing historical clutter and adding immediate operational value tools, we make it trivial for a SecOps team to move from evaluation to a production "Passing" state.
