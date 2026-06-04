# EU Cyber Resilience Act — Conformance Statement

> **Status:** DRAFT — self-assessed conformance statement (not certification)
> **Phase:** 107a (sub-phases 107a.2/.3/.4/.5 — Annex I + II content + conformity assessment)
> **Regulation:** Regulation (EU) 2024/2847 — Cyber Resilience Act
> **Effective date:** December 2027 (full application)
> **Reviewer:** Self-assessed by the JA4proxy maintainers

---

## Cross-references

- See also: [`SSDF_MAPPING.md`](SSDF_MAPPING.md) — NIST SP 800-218 control mapping
- See also: [`iso27001-annex-a-mapping.md`](iso27001-annex-a-mapping.md) — ISO 27001 Annex A controls
- See also: [`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) — GDPR + ISO 29100 privacy mapping
- Vulnerability handling: [`../security/CVD_POLICY.md`](../security/CVD_POLICY.md) (sub-phase 107g)
- Build provenance: [`../decisions/ADR-107a-slsa-level-3.md`](../decisions/ADR-107a-slsa-level-3.md), [`../decisions/ADR-202d.md`](../decisions/ADR-202d.md)
- Threat model: [`../security/threat-model.md`](../security/threat-model.md)
- Comprehensive security audit: [`../security/COMPREHENSIVE_SECURITY_AUDIT.md`](../security/COMPREHENSIVE_SECURITY_AUDIT.md)
- Observability standards (logging schema, metrics registry): [`../OBSERVABILITY_STANDARDS.md`](../OBSERVABILITY_STANDARDS.md)
- Redis schema (data model, retention): [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md)

---

## Scope determination

JA4proxy is a TLS-aware passthrough security proxy distributed as source code
under an open-source licence, as a published container image
(`ghcr.io/seanpor/ja4proxy-go`), and as a standalone CLI binary
(`ja4proxy-cli`). It is a **product with digital elements** within the meaning
of Regulation (EU) 2024/2847 Article 3(1). JA4proxy is **self-assessed** as
falling under the **default** category of products with digital elements; it is
**not** within the **important** or **critical** classes (Annex III / Annex
IV) — JA4proxy is a general-purpose security product, not an
identity-management product, network management system, hypervisor, or any
other category enumerated as important-class or critical-class.

**Monetisation position (CRA "commercial activity" exemption analysis).** As of
the date of this statement the JA4proxy project does **not** have a paid
support offering, commercial licence tier, or other monetisation arrangement
that would convert open-source distribution into a commercial activity within
the meaning of Recital (15). The project nonetheless **treats the CRA as
in-scope** in this conformance statement, on the basis that any future
commercial-support offering would remove the exemption, and producing the
conformance evidence proactively is cheaper than producing it under deadline
pressure once a commercial offering exists. Where the present statement
identifies a gap, the project commits to closing it before any commercial
offering is announced.

This statement uses the language **"self-assessed"** and **"aligned with"**
throughout. It does **not** claim certification; no accredited body has
assessed JA4proxy against the CRA.

---

## Annex I — Essential cybersecurity requirements

The Annex I row numbering and titles below follow EU 2024/2847 Annex I
Section 1 ("Cybersecurity requirements relating to the properties of products
with digital elements"). Where the regulation lists a sub-paragraph rather
than a numbered "ER", the row title cites the sub-paragraph in parentheses so
the mapping is auditable against the regulation text directly. Harmonised
standards under the CRA are still being drafted by ETSI / CEN-CENELEC through
2026–2027; this statement maps against the regulation text and will be
refreshed once the harmonised standards are published.

| ER | Requirement | Current evidence | Gap | Remediation |
|----|-------------|------------------|-----|-------------|
| ER1 | Security by default (Annex I §1(2)(b)) — products delivered with a secure-by-default configuration | Default `dial=0` (monitor mode) on first deploy means the proxy never blocks until the operator consciously raises the dial — see CLAUDE.md "Decision Log" + `config/proxy.yml` `security_policy` defaults; bypass invariants (h2/h1 ALPN, JA4 whitelist, mTLS) documented in CLAUDE.md "Bypass Rules"; bypass-disabled startup `WARN` per CLAUDE.md "Cross-Cutting Requirements"; threat-model coverage in `docs/security/threat-model.md` | Default-secure posture is implemented but not yet verified by an external secure-baseline assessment | Schedule external configuration review against `docs/security/SECURITY_CHECKLIST.md` once a CRA harmonised secure-baseline standard is published (expected 2027) |
| ER2 | No known exploitable vulnerabilities at release (Annex I §1(2)(a)) | Per-release dependency audit jobs (govulncheck for Go, pip-audit for Python) run on every PR + push + weekly schedule in `.github/workflows/ci.yml`; SAST (Semgrep) runs in the same workflow; CVE exception register at `docs/security/CVE_EXCEPTIONS.md`; outstanding-finding register at `docs/security/FINDINGS_REGISTER.md`; severity rubric at `docs/security/SEVERITY_RUBRIC.md`; remediation waves tracked in `docs/security/REMEDIATION_WAVES.md` | "No known exploitable vulnerabilities at release" requires a release-time gate that explicitly checks the open-finding register against the severity rubric; the CI gate currently fails on new CVEs but does not formally block tag-push if a previously-known CVE remains open past its remediation deadline | Add release-gate task in a future phase that fails the release workflow if `docs/security/FINDINGS_REGISTER.md` contains any CRITICAL/HIGH finding past its target resolution date |
| ER3 | Protection from unauthorised access (Annex I §1(2)(c)) — appropriate authentication, identity, or access management | Management API uses bearer-token authentication with bcrypt-hashed token records (`mgmt:token:{id}` schema in `docs/REDIS_SCHEMA.md`); role-based access (`auditor`/`analyst`/`operator`/`admin`) per the same row; mTLS bypass for verified client certs documented in CLAUDE.md "Pipeline" section and STRIDE coverage in `docs/security/threat-model.md` (Spoofing); credential-rotation runbook at `docs/runbooks/credential_rotation.md`; secrets handling guarded by `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` finding #1 (default/weak secrets — RESOLVED); audit log of all admin actions at `management:audit_log` per `docs/REDIS_SCHEMA.md` | Token revocation is supported but there is no automated scheduled-rotation enforcement (rotation is operator-driven via runbook) | Track scheduled-rotation enforcement as a future Management-API enhancement (deferred Phase 13 work) |
| ER4 | Attack-surface minimisation (Annex I §1(2)(d)) | Container is built with `cap_drop: ALL`, `read_only: true`, `no-new-privileges` per `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` finding #7 (Excessive Capabilities — RESOLVED); metrics endpoint bound to `127.0.0.1:9090` per the same audit finding #6; only TLS metadata is parsed (no HTTP body inspection, no decryption) per CLAUDE.md "What This Project Is"; bypass surface enumerated in CLAUDE.md "Pipeline" with each bypass independently configurable in `config/proxy.yml` `security_policy` | Several historical findings remain DEFERRED to the Go production runtime (image pinning, Redis TLS) per `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` | Track DEFERRED items via `docs/security/REMEDIATION_WAVES.md`; close before any commercial-support offering is announced |
| ER5 | Data minimisation (Annex I §1(2)(e)) — process only data adequate, relevant and limited to what is necessary | Only TLS plaintext metadata visible before/during the handshake is processed; the proxy never decrypts traffic and forwards allowed connections byte-for-byte unchanged (CLAUDE.md "What This Project Is"); IP-derived data is the only PII handled and is bound by the per-key TTLs documented in `docs/REDIS_SCHEMA.md` (e.g. `lifespan:{ip}` 30 min, `concurrent:{ip}` 60 s, `visitor:{ip}` 7 d, `rdap:ip:{ip}` 24 h); GDPR erasure runbook at `docs/runbooks/gdpr_erasure.md` and operator script at `scripts/gdpr_delete.py` (audit trail in `management:gdpr_erasure_log` per `docs/REDIS_SCHEMA.md`); see also `docs/compliance/GDPR_COMPLIANCE.md` | None — the no-decryption design is the load-bearing data-minimisation control and is enforced by architecture, not by configuration | N/A |
| ER6 | DoS resilience (Annex I §1(2)(f)) — protect availability of essential functions | Fail-open principle documented in CLAUDE.md "The Core Asymmetry" and enforced throughout — every external service call returns a neutral result rather than propagating an error (`config/proxy.yml` `redis_timeout_ms: 50`, `enabled: false` defaults for new signal modules); tarpit concurrency caps (`max_concurrent_connections`, `max_per_ip`, `overflow_action`) per `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` finding #8 (RESOLVED) and `config/proxy.yml`; rate-limit strategies in `config/proxy.yml` `security_policy.rate_limit_strategies`; SLO runbooks at `docs/runbooks/slo_availability.md` and `docs/runbooks/slo_latency.md`; tarpit-pool-full alert runbook at `docs/runbooks/ja4proxy_tarpit_pool_full.md`; external-API-failure runbook at `docs/runbooks/external_api_failures.md` | None for the active inline path; passive TAP mode (Phase 20) has its own back-pressure model documented in `docs/runbooks/tap_mode.md` | N/A |
| ER7 | Security logging (Annex I §1(2)(g)) — record and monitor relevant internal activity | All log output is fixed-schema JSON, one object per line, with mandatory fields `ts`, `type`, `level` and connection-log fields `verb`, `ip`, `score`, `dial`, `action` per `docs/OBSERVABILITY_STANDARDS.md` §"Structured logging schema"; complete metric registry in the same document §"Metric registry"; Prometheus alert rule directory referenced in the same document; admin-action audit log at `management:audit_log` (Phase 79 schema) and policy-change audit log at `management:policy_audit` per `docs/REDIS_SCHEMA.md`; SIEM-readable log format documented for Splunk/Sentinel/QRadar consumers | None for log production; downstream retention is the operator's responsibility | N/A — operator guidance in `docs/OBSERVABILITY_STANDARDS.md` |
| ER8 | Integrity protection (Annex I §1(2)(h)) — protect integrity of data, software, and configurations | Container image is built reproducibly and signed keylessly via Sigstore cosign with Fulcio-issued OIDC certs and Rekor transparency-log entries — see `.github/workflows/go-proxy-image.yml` (signing job) and `docs/decisions/ADR-202d.md` (decision rationale); SBOM in CycloneDX format generated and OCI-attached in the same workflow; SLSA Level 3 build provenance is the next step per `docs/decisions/ADR-107a-slsa-level-3.md`; configuration-reload integrity via SIGHUP + Redis pub/sub (`config:reload` channel) with policy-change audit per `docs/REDIS_SCHEMA.md`; no proxy-internal write paths to backend traffic — passthrough by design (CLAUDE.md "What This Project Is") | SLSA Level 3 attestation is in design (ADR-107a) but not yet wired into the release workflow | Sub-phase 107c implements the SLSA L3 reusable workflow against `.github/workflows/go-proxy-image.yml` and `.github/workflows/release-cli.yml` |
| ER9 | Vulnerability handling process (Annex I §1(2)(i) and Annex I Section 2) | Coordinated vulnerability disclosure policy at `docs/security/CVD_POLICY.md` (sub-phase 107g) — submission channels, triage, fix targets, safe-harbour, and ISO/IEC 29147 + 30111 alignment; security-incident-response runbook at `docs/runbooks/security_incident_response.md`; intake runbook at `docs/security/INTAKE_RUNBOOK.md`; outstanding findings tracked in `docs/security/FINDINGS_REGISTER.md` with severity per `docs/security/SEVERITY_RUBRIC.md`; CVE exception register at `docs/security/CVE_EXCEPTIONS.md`; ownership map at `docs/security/OWNERSHIP.md` | `docs/security/CVD_POLICY.md` is in scaffold form during Phase 107; sub-phase 107g fills the substantive sections | Sub-phase 107g — track via Phase 107 acceptance criteria |
| ER10 | Secure-by-default configuration (per EU 2024/2847 Annex I §1(2)(j) — secure-by-default config, including ability to revert to secure state) | Config schema in `config/proxy.yml` ships with conservative defaults per CLAUDE.md "Config-Driven & Hot-Reloadable"; `dial=0` (monitor mode) is the load-bearing default — the proxy never blocks on first deploy; bypass categories (h2/h1 ALPN, JA4 whitelist, mTLS, JA4 blacklist, country, Spamhaus DROP) are independently configurable; security-policy runbook at `docs/runbooks/security_policy.md`; backup + restore semantics documented in `docs/runbooks/cloud_backup_operations.md` and `docs/runbooks/disaster_recovery.md` so an operator can revert to a known-good state | None for the runtime; backup of `config/proxy.yml` is operator-managed, not proxy-managed | N/A |
| ER11 | Secure update mechanism (per EU 2024/2847 Annex I §1(2)(k) — provide security updates) | Container image distribution via signed OCI artefacts in `ghcr.io/seanpor/ja4proxy-go` per `.github/workflows/go-proxy-image.yml`; image-update runbook at `docs/runbooks/docker_image_updates.md`; rolling-upgrade runbook at `docs/runbooks/rolling_upgrade.md`; zero-downtime rollouts at `docs/runbooks/zero_downtime_rollouts.md`; SBOM attached to every published image so consumers can audit the update before applying it (`docs/decisions/ADR-202d.md`); release tagging convention enforced via `.github/workflows/release-cli.yml` | No automatic update mechanism — updates are pull-mode, operator-initiated. Auto-update is intentionally out of scope: a security proxy must not silently mutate without operator action | N/A — design choice; documented in update runbook |
| ER12 | Confidentiality protection (per EU 2024/2847 Annex I §1(2)(l) — protect confidentiality including by encrypting data) | Proxy is TLS passthrough — it never holds TLS keys, never decrypts traffic (CLAUDE.md "What This Project Is"); no application content is recorded or transmitted to downstream systems; analytics events to Redis are TLS-metadata only; secrets handling per `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` finding #1 (RESOLVED — `:?` syntax in `deploy/docker/docker-compose.poc.yml`); credential-rotation runbook at `docs/runbooks/credential_rotation.md`; transport security for Redis is DEFERRED per the same audit (finding #5) and tracked in `docs/security/REMEDIATION_WAVES.md` | Redis TLS not yet enabled on the production runtime; mitigated by Docker-internal-network isolation (same audit) | Track DEFERRED Redis TLS via `docs/security/REMEDIATION_WAVES.md`; close before any commercial-support offering |
| ER13 | Limited-data-output / least-privilege output (per EU 2024/2847 Annex I §1(2)(m) — minimise externally-exposed attack surface and data exfiltration) | Metrics endpoint bound to `127.0.0.1:9090` per `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` finding #6; only TLS-handshake metadata leaves the proxy boundary; threat-intel feed clients are pull-only with explicit allowlists in `config/proxy.yml`; analytics events written via Redis Streams (single internal data plane) per CLAUDE.md "Redis Data Structure Quick Reference"; no telemetry-to-vendor channel exists in the codebase | None | N/A |

---

## Annex II — Vulnerability-handling and post-market obligations

The Annex II row format below maps each post-market obligation to repository
evidence. Where an obligation is met today, the evidence column links to the
implementing file or workflow; where the project takes a deliberate position
(rather than meeting a numeric obligation), the Notes column states the
position explicitly so a reviewer can decide whether it satisfies the
regulator's expectation.

| Annex II item | Evidence | Notes |
|---------------|----------|-------|
| Software Bill of Materials (SBOM) | `.github/workflows/go-proxy-image.yml` (CycloneDX SBOM generated by `anchore/sbom-action` and OCI-attached via `cosign attach sbom`); decision rationale in `docs/decisions/ADR-202d.md` | CycloneDX JSON format; OCI-attached to every published image so downstream consumers can `cosign download sbom` it without rebuild |
| Coordinated vulnerability disclosure (CVD) | `docs/security/CVD_POLICY.md` (sub-phase 107g — submission channels, triage, safe-harbour, ISO/IEC 29147 + 30111 alignment); intake runbook at `docs/security/INTAKE_RUNBOOK.md`; ownership map at `docs/security/OWNERSHIP.md` | Policy in scaffold during Phase 107; sub-phase 107g fills the substantive sections |
| Free security patches | Project position: security patches are published as part of the regular release stream and are available at no cost under the project's open-source licence. Evidence: `.github/workflows/go-proxy-image.yml`, `.github/workflows/release-cli.yml`, `docs/runbooks/docker_image_updates.md`, `docs/runbooks/rolling_upgrade.md` | Patch availability is independent of any commercial-support offering; the project does not gate security fixes behind a paid tier |
| Public vulnerability reporting / advisories | Advisories are published via GitHub Security Advisories and CVE assignment per `docs/security/CVD_POLICY.md`; outstanding-finding register at `docs/security/FINDINGS_REGISTER.md` | Advisory feed is the GitHub repo's standard advisory channel |
| Support period | No support-period commitment is made by the project at this time. JA4proxy is provided as-is under its open-source licence; any binding support obligation would require a downstream commercial entity. The CRA's harmonised standards on minimum support periods (expected via ETSI / CEN-CENELEC through 2026-2027) will be re-assessed once published | Position deliberately declined at the project-owner level; revisit when harmonised standards are final or a commercial-support entity exists |

---

## Conformity-assessment procedure

JA4proxy follows the **self-assessment** route under the CRA (default-class
products), per Article 24(1)(a). No notified body has been engaged; no
notified-body conformity-assessment certificate exists. The present document
**is** the self-assessment record: scope determination, Annex I mapping,
Annex II mapping, and post-market vulnerability management procedure.

A self-assessment is valid only if the underlying technical documentation
exists and is accurate. The cross-references at the top of this document
identify the technical-documentation surface a reviewer should walk through to
verify the Annex I and Annex II claims. The evidence column in each Annex I
row points at the canonical file or workflow.

### EU Declaration of Conformity (TEMPLATE — un-signed placeholder)

> **TEMPLATE — NOT SIGNED.** This is a placeholder. The CRA EU Declaration of
> Conformity must be signed by an EU-established manufacturer or its EU
> authorised representative (CRA Article 28). The JA4proxy project does not
> currently have an EU-established legal entity. This template will be filled
> in and signed only when such an entity exists, or by a downstream
> redistributor that brings the product to the EU market under their own
> name. A reviewer reading this document today should treat the EU DoC as
> NOT YET ISSUED.

```
EU Declaration of Conformity
(Cyber Resilience Act, Regulation (EU) 2024/2847, Article 28)

1. Product:                  JA4proxy — TLS-aware passthrough security proxy
   Type / model / batch:     <to be filled by signing entity>
   Software version:         <to be filled by signing entity>
   Container image digest:   <to be filled by signing entity>
   CLI binary SHA-256:       <to be filled by signing entity>

2. Name and address of the manufacturer (or authorised representative):
                             <TO BE FILLED — REQUIRES EU-ESTABLISHED ENTITY>

3. This Declaration of Conformity is issued under the sole responsibility of
   the manufacturer.

4. Object of the declaration:
                             JA4proxy — TLS-aware passthrough security proxy,
                             distributed as source code, container image
                             (ghcr.io/seanpor/ja4proxy-go), and standalone
                             CLI binary (ja4proxy-cli).

5. The object of the declaration described above is in conformity with the
   relevant Union harmonisation legislation:
                             Regulation (EU) 2024/2847 (Cyber Resilience Act)

6. References to the relevant harmonised standards used or references to the
   other technical specifications in relation to which conformity is
   declared:
                             <TO BE FILLED — harmonised standards under the
                             CRA are still being drafted by ETSI /
                             CEN-CENELEC through 2026-2027; references will
                             be added once the relevant standards are
                             published in the Official Journal>

7. Where applicable, the notified body … performed … and issued the
   certificate:
                             NOT APPLICABLE — self-assessment route under
                             Article 24(1)(a); no notified body engaged.

8. Additional information:
                             Self-assessment evidence is recorded in
                             docs/compliance/CRA_CONFORMANCE.md in the
                             project repository.

   Signed for and on behalf of:  <TO BE FILLED>
   Place and date of issue:      <TO BE FILLED>
   Name, function:               <TO BE FILLED>
   Signature:                    <TO BE FILLED>
```

---

## Post-market vulnerability management

Vulnerability handling and disclosure procedures are documented in
[`../security/CVD_POLICY.md`](../security/CVD_POLICY.md) (sub-phase 107g —
submission channels, triage workflow, safe-harbour language, and ISO/IEC
29147 (vulnerability disclosure) + ISO/IEC 30111 (vulnerability handling)
alignment).

Operational integration:

- **Intake** — `docs/security/INTAKE_RUNBOOK.md` describes how reports enter
  triage and who acknowledges them.
- **Severity rubric** — `docs/security/SEVERITY_RUBRIC.md` and
  `docs/decisions/ADR-121a-cvss-version.md` (CVSS v3.1) define the scoring.
- **Tracking** — open findings in `docs/security/FINDINGS_REGISTER.md`;
  exceptions in `docs/security/CVE_EXCEPTIONS.md` and
  `docs/security/EXCEPTIONS.md`; remediation waves in
  `docs/security/REMEDIATION_WAVES.md`.
- **Incident response** — `docs/runbooks/security_incident_response.md` is
  the on-call runbook.
- **Advisories** — published as GitHub Security Advisories with CVE
  identifiers per the CVD policy.

The project handles reports on a best-effort basis under the open-source
licence; specific operational SLA numbers (acknowledgement, triage, fix
targets) are stated in `docs/security/CVD_POLICY.md` and are flagged there
for human review before publication.

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial conformance assessment | Phase 107 | Self-assessed |
| Annex I expansion to all ERs | 107a.2/.3/.4 | Complete (this revision) |
| Conformity assessment + DoC template | 107a.5 | Complete (this revision — TEMPLATE only) |
| CVD policy substantive content | 107g | Pending — `docs/security/CVD_POLICY.md` substantive sections |
| SLSA L3 build provenance wired | 107c | Pending — `docs/decisions/ADR-107a-slsa-level-3.md` |
| Refresh after harmonised standards published | 2027 (planned) | ETSI / CEN-CENELEC harmonised standards still in draft through 2026-2027 |
