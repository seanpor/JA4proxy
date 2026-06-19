<!--
title: Independent Technical & Cyber Risk Review
audience: Security Leadership, Risk Officers, Auditors
last_reviewed: 2026-04-09
reviewer: Independent technical & cyber risk assessment
scope: JA4proxy (Go production runtime + Python prototype + supporting services)
-->

> **Archived snapshot — Phase 105 (2026-04-25).** This report reflects the
> project state at the time of writing (Phase 92). Current canonical reference:
> [`../../PROJECT_STATUS.md`](../../reference/PROJECT_STATUS.md) and the
> [phase manifest](../../phases/manifest.yaml).
> Body untouched below.

# JA4proxy — Technical & Cyber Risk Review

**Review date:** 2026-04-09
**Repository state at review:** `main` @ `7e971f6` (clean working tree)
**Reviewer perspective:** Independent technical & cyber risk
**Methodology:** Documentation review (CLAUDE.md, manifest, phase docs, threat model, prior audits), code structure review (`internal/`, `cmd/`, `src/`), control inventory against the project's own control mappings (ISO 27001 Annex A, SOC 2, GDPR), and a STRIDE-aligned residual-risk pass.

> **Disclaimer.** This is a documentation- and structure-level review, not a penetration test or formal audit. It does not replace the project's existing `COMPREHENSIVE_SECURITY_AUDIT.md`, the Phase 27 pentest remediation work, or a third-party assessment. It is intended as an independent risk read-out for leadership.

---

## 1. Executive Summary

JA4proxy is a TLS-aware passthrough security proxy that makes allow/block/tarpit decisions on plaintext handshake metadata, never decrypting traffic and never holding TLS keys. The Go runtime in `cmd/proxy` + `internal/` is the production target; a Python prototype is retained as a research surface. As of Phase 92 (with Phases 60–64, 85–88, 93–94, 101 still proposed), the project ships:

- 14 signal modules (TLS, SNI, TCP, ASN, DNS/FCrDNS, beaconing, AbuseIPDB, RDAP, blocklists, JA4/JA4X, mTLS, analytics, threat-intel feeds, deception)
- A composite scorer + dial-driven action decider with explicit "fail-open" semantics
- A management plane (FastAPI + Jinja2 admin UI), an analytics node, compliance reporting, backup/restore with AES-256-GCM at rest, RBAC + SSO/MFA (Phases 79/100), ECS structured logs and SIEM integration, policy-as-code, blue/green deploys, an eBPF/XDP enforcement sidecar, and a Docker isolation model with four network zones.

**Overall risk posture: MEDIUM, trending LOW** for the documented Docker-isolation deployment model. The architecture is unusually disciplined: the project's central design principle ("when in doubt, fail open; ALLOW caches long, BLOCK caches short; default dial = 0") is the right asymmetry for a network-edge filter, and it is consistently encoded across config defaults, cache TTLs, and fallback paths. The dominant residual risks are **not** in the data-plane crypto or signal logic — they are in **supply-chain assurance, deployment-time validation, operational SLOs, and the maturity gap between "feature complete" and "audit ready."** Several of those gaps are already scoped as PROPOSED phases (60–64, 88, 93–94), which is the right backlog but means they are not yet implemented.

### Top residual risks (ranked)

| # | Risk | Severity | Likelihood | Driver |
|---|------|----------|------------|--------|
| 1 | **Supply-chain & build integrity not yet enforced in CI** (Phase 61 PROPOSED): no SBOM, no Cosign signing, no SLSA L2 provenance, no SHA-pinned actions, no branch protection asserted in-repo. | High | Medium | Phase 61 manifest entry; absence of `.github/workflows` enforcement artefacts in repo tree. |
| 2 | **No SLOs or burn-rate alerting in production yet** (Phase 63 PROPOSED): availability/latency/correctness/FP-rate targets defined on paper but not wired to Alertmanager. | High | Medium | Phase 63 status PROPOSED; metric naming rename (`ja4_*` → `ja4proxy_*`) is a stated prerequisite. |
| 3 | **No DR drill / smoke-test corpus for fresh deployments** (Phase 64 PROPOSED): Docker Compose, Helm/kind, Podman/Quadlet smoke tests and a 5-scenario DR runbook are scoped but not delivered. MTTR has not been measured. | High | Medium | Phase 64 status PROPOSED. |
| 4 | **Adversarial / fuzz harness not yet running in CI** (Phase 62 PROPOSED): atheris + Go native fuzz, regression tests for the 18 Phase-27 pentest findings, and the break-glass procedure are not yet automated. | Medium-High | Medium | Phase 62 status PROPOSED. Phase 46 brought unit coverage to 99%, but coverage ≠ adversarial assurance. |
| 5 | **Single-DC failover model not yet defined** (Phase 88 PROPOSED). For an inline traffic component this is a customer-impacting gap once enterprise deployments scale beyond one site. | Medium | Low-Medium | Phase 88 status PROPOSED. |
| 6 | **Compliance Phase 84 has known second-review gaps deferred to Phase 101** (still PROPOSED). Compliance reporting ships, but nine review items are deferred. | Medium | Medium | `manifest.yaml` Phase 101 status. |
| 7 | **Two-runtime cognitive load (Go production, Python prototype)**: drift between Python and Go signal implementations is mitigated by Phase 36 / Phase 65 parity harnesses, but the dual codebase is a permanent operational tax and a recurring source of "where does this run in prod?" confusion. | Medium | Medium | `CLAUDE.md` runtime warning + 5,103 LOC of `internal/security/*.go` mirroring `src/security/`. |
| 8 | **Bypass-list management surface = high-blast-radius control plane**. JA4 whitelist, mTLS bypass, ALPN browser bypass, and country lists all sit ahead of the scorer and can fully neutralise enforcement if mis-edited. RBAC + audit log + Ed25519 config signing (Phases 35, 79, 82) mitigate this, but it remains the single most consequential operator action. | Medium | Low | `internal/security/pipeline.go` bypass section + `CLAUDE.md` bypass invariants. |
| 9 | **External dependency fail-open by design** (AbuseIPDB, RDAP, threat-intel feeds, MaxMind). Correct for a passthrough proxy — but means a sustained outage of those upstreams silently degrades enforcement quality without necessarily firing a page unless the SLO/feed-health work (Phase 59 done; Phase 63 not done) is fully wired. | Medium | Medium | "Fail Open" cross-cutting requirement, `CLAUDE.md`. |
| 10 | **Two CLOSED phases (24, 55) and one repeatedly-deferred review surface (Phase 101).** "Closed" without "complete" is a common audit red flag — it should be possible to point an external assessor at a one-line rationale per closure. | Low-Medium | — | `manifest.yaml` / `PROJECT_STATUS.md`. |

### What is genuinely strong

- **Architectural discipline.** The "score always, act on dial; ALLOW caches 30 min, BLOCK caches 30 s; local cache wins over Redis; h2/h1 ALPN browsers cannot be blocked" invariants are recorded in `CLAUDE.md` as load-bearing decisions and visible in the pipeline code. This is the right asymmetry for an inline traffic device and will be the single most important reason it does not cause an outage on first deploy.
- **Two implementations, one spec.** The Phase 65 parity harness and binary fixture ground truth are an unusually mature way to manage a dual-runtime project.
- **Defence-in-depth at the host level.** Phases 34/35/56/71–75 deliver seccomp, AppArmor, ephemeral fs, eBPF/XDP NIC blocking, network zoning, non-root, cpuset, log rotation, and a `check-isolation.sh` validator. Few inline-traffic projects are this disciplined about container surface.
- **No-decrypt design.** The proxy never holds TLS keys and never inspects HTTP — this materially reduces the regulatory and breach surface (no plaintext to exfiltrate, no key custody).
- **Compliance evidence pipeline exists** (Phase 84 + Phase 87 observability + ISO 27001 / SOC 2 / GDPR mapping documents). The mappings are present in `docs/compliance/`, which is uncommon for a project of this size.

---

## 2. Scope and Method

**In scope.** Go runtime under `cmd/proxy` + `internal/{security,proxy,config,redis,tls,compliance,metrics,logging,webhook,cache,cli}`; Python prototype under `proxy.py` + `src/`; management API + UI; analytics node; compliance reporter; backup/restore; deployment tooling (`deploy/docker/`, `deploy/`, `Makefile`); governance docs (`CLAUDE.md`, `AGENTS.md`, manifest, phase plans 0–101); existing security artefacts under `docs/security/`, `docs/compliance/`, `docs/reports/`, `docs/decisions/`.

**Out of scope.** Live network testing; reading the full source of every signal module; validating that every PROPOSED phase is in fact unimplemented vs. partially landed; assessing the actual deployment of any specific customer; cryptographic review of the Ed25519 signing implementation; review of third-party feed legal terms.

**Method.**
1. Read governance and architecture docs (`CLAUDE.md`, `PROJECT_STATUS.md`, threat model, comprehensive security audit, compliance mappings).
2. Walked the directory tree for `internal/`, `cmd/`, `src/security/`, `docs/phases/`, `docs/security/`, `docs/compliance/`, `docs/reports/`.
3. Sampled the pipeline orchestrator (`internal/security/pipeline.go`) to confirm bypass / scoring / fail-open structure matches the documented design.
4. Cross-checked claimed control coverage against the project's own ISO 27001 Annex A and SOC 2 narrative documents.
5. STRIDE-aligned residual-risk pass on the data plane, control plane, and supply chain.

---

## 3. Architecture & Threat Surface

The deployed shape is:

```
Internet → HAProxy (LB) → JA4proxy ×N → Backend
                              │
                              ├─ Redis (state, decisions, audit)
                              ├─ Analytics node (Streams consumer)
                              └─ Management UI (FastAPI + Jinja2)
```

The data plane is a TCP-level forwarder that observes the TLS handshake and decides allow/flag/rate-limit/tarpit/block/ban **before** completing the handshake to the backend. The bypass ladder (ALPN browser, JA4 whitelist, mTLS, JA4 blacklist, country, Spamhaus DROP) short-circuits the scorer, then signal modules run in parallel and produce `RiskSignal`s, then the composite scorer and dial-driven `ActionDecider` produce a single decision. Decisions and metadata are emitted to a Redis Stream consumed by the analytics node.

### STRIDE residual notes

| Threat | Where it lands | Residual rating | Notes |
|---|---|---|---|
| **Spoofing** of client IP | PROXY protocol parsing in `internal/proxy/proxy_protocol.go` from a trusted CIDR; Phase 27 specifically remediated an IP-spoofing finding. | Low | Trusted-upstream CIDR is the load-bearing assumption — operators MUST configure it correctly; misconfiguration silently lets clients claim arbitrary IPs. Worth a startup-time WARN if it is unset and PROXY protocol is expected. |
| **Tampering** with config / lists | Hot-reload via SIGHUP and Redis pubsub; Ed25519 config signing (Phase 35); policy audit log (`management:policy_audit`, last 1000 entries, no TTL); RBAC + SSO/MFA (Phases 79/100). | Low-Medium | The audit list has no TTL but is bounded at 1000 — for a hostile-insider model, that bound is a forensic gap. Consider tee-ing to the SIEM pipeline (Phase 80 ECS logs) so the long tail is preserved. |
| **Repudiation** | ECS structured logs (Phase 80) → SIEM; SHA-256 hash-chain audit log (Phase 35). | Low | Strong on paper. Key gap is whether the hash chain is anchored externally (e.g. periodic root publication) — not assessed here. |
| **Information disclosure** | Proxy never decrypts. Plaintext exposure is limited to handshake metadata, source IP, SNI, JA4 strings, and decision/score in logs. | Low | The biggest privacy surface is the analytics stream and the decision logs themselves, which contain IPs and SNIs. GDPR erasure path exists (Phase 91) — audit-relevant. |
| **Denial of service** | Tarpit concurrency caps (Phase 14c), circuit breakers, rate limiter, hot-path async-only invariant, `cap_drop ALL`, `read_only`, cpuset pinning. eBPF/XDP NIC-level blocking (Phase 35) for volumetric. | Medium | The proxy itself is well hardened. The harder DoS question is: what happens when Redis is unreachable for 30+ minutes? Documented behaviour is "local cache wins, fail open" — verify in a chaos run as part of Phase 64. |
| **Elevation of privilege** | Containers non-root (uid 1000), seccomp + AppArmor, no-new-privileges, ephemeral fs (tmpfs /tmp, /var/run), four network zones, Docker socket NOT mounted (verified by `check-isolation.sh`). | Low | This is the strongest part of the deployment model. |

---

## 4. Findings

### F-1 — Supply-chain assurance is the top open risk *(Severity: High)*

Phase 61 ("Supply Chain Security & Build Integrity") is PROPOSED, not COMPLETE. There is no in-repo evidence of:

- CycloneDX SBOM generation per release
- Cosign keyless image signing
- SLSA L2 provenance for the Go binary
- SHA-pinned GitHub Actions
- Branch protection asserted via `.github` policy
- Reproducible-build attestation for `bin/proxy`

For an inline traffic security control, this is the highest-leverage gap: the binary makes block/allow decisions on every TLS connection, so the integrity of the build pipeline is part of the trust boundary. **Recommendation:** treat Phase 61 as a release-blocker for any externally-distributed image. Until then, document the gap explicitly in `SECURITY.md` and the README so operators know what they are and are not getting.

### F-2 — Production SLOs and burn-rate alerting are not yet wired *(Severity: High)*

Phase 63 is PROPOSED. The four SLIs (availability 99.9 %, latency p99 < 10 ms, Redis correctness 99.5 %, FP rate < 2 %) are written down, but:

- The Prometheus metric naming convention (`ja4proxy_{subsystem}_{metric}_{unit}`) is documented in `CLAUDE.md`, yet Phase 63's own description flags a `ja4_*` → `ja4proxy_*` rename as a prerequisite. That implies the current emitted names are not aligned with the documented standard.
- No multiwindow burn-rate alert rules are present in the manifest as completed.
- No on-call runbook exists for "FP rate just exceeded 2 %" — which is the single most operationally-important alert this product can fire.

**Recommendation:** complete the metric rename **before** customers integrate dashboards (renames are a breaking change). Ship the FP-rate burn-rate alert first; it is the alert that protects the asymmetry the whole project is built around.

### F-3 — Deployment validation and DR are not exercised *(Severity: High)*

Phase 64 is PROPOSED. There is no smoke-test corpus that proves a fresh `docker compose up` or `helm install` produces a functioning proxy, no DR runbook covering the five scenarios (incl. Redis data loss), no measured MTTR baseline, and no documented credential or TLS-cert rotation procedure.

For a product where the failure mode is "blocks legitimate users," lack of a rehearsed DR drill is the most likely source of a future customer-visible incident. **Recommendation:** prioritise Phase 64 over any further feature work. The smoke-test suite alone (one Compose, one kind, one Podman) is high-leverage and low-effort.

### F-4 — Adversarial regression suite not in CI *(Severity: Medium-High)*

Phase 46 brought unit coverage to 99 %, which is genuinely impressive — but coverage is not adversarial assurance. Phase 62 (atheris + Go native fuzz, regression tests for the 18 Phase-27 pentest findings, break-glass procedure) is PROPOSED. The TLS handshake parser is the highest-value fuzz target on the system; until it has continuous fuzzing in CI, a future malformed-ClientHello CVE in an upstream parser is the most plausible "wake the on-call" scenario.

**Recommendation:** even a one-hour daily atheris smoke run on the TLS parser, with crash artefacts uploaded to the build, would close most of the gap. Pair with go-fuzz for `internal/tls`.

### F-5 — Bypass control plane is the highest-blast-radius operator action *(Severity: Medium)*

The bypass ladder in `internal/security/pipeline.go` (ALPN browser, JA4 whitelist, mTLS, JA4 blacklist, country list, Spamhaus DROP) precedes scoring. By design, ALLOW bypasses are immune to the dial — meaning a compromised or careless edit to `security_policy` can fully neutralise enforcement without changing the dial value the SOC is watching.

This is mitigated by: RBAC + SSO/MFA, the policy audit log, Ed25519 config signing, the startup WARN for disabled high-risk bypasses, and the Prometheus gauge for bypass state. Those are good controls. The residual gap is **detection**: is there an alert that fires when the JA4 whitelist gains a new entry, or when `mTLSBypass` flips on? If the answer is "the SIEM might catch it via audit log," that is a detective control with no specified response time.

**Recommendation:** add a Phase-63 SLI: "any change to `security_policy` produces an alert in < 60 s, attributed to a named principal." This is a small wiring task on top of the audit log that already exists.

### F-6 — Two-runtime tax is a permanent operational cost *(Severity: Medium)*

The Go runtime is production; the Python prototype is a research surface. `CLAUDE.md` is unambiguous about this, and the parity harness (Phases 36, 65) gives mechanical verification that signal scores match. Two operational concerns remain:

- **Cognitive load.** Every new signal module exists at least twice. Every CVE in a Python dependency requires asking "does this affect prod?" — and the answer is "no, but it affects the prototype that we sometimes run in shared infra." That is a perpetual triage cost.
- **Drift risk on bug-fix paths.** Parity checks catch score drift. They do **not** necessarily catch behaviour drift in error paths, fail-open semantics, or timeout handling. A Python-only bug fix that does not get ported can change the meaning of "fail open" between the two runtimes.

**Recommendation.** Either (a) commit to a sunset date for the Python prototype once Phase 85+ feature work is in Go, or (b) explicitly designate which subset of Python is allowed to run anywhere except a developer laptop, and gate the rest behind a clearly labelled "research only" build.

### F-7 — Compliance Phase 84 has known deferred items *(Severity: Medium)*

Phase 84 (Compliance & Reporting) is COMPLETE, but the recent commit history (`6306996 phase-84: second critical review fixes + defer 9 items to phase 101`) shows nine items deferred to Phase 101, which is itself PROPOSED. For an external auditor, "complete with nine known gaps deferred to a not-yet-started phase" reads as in-progress, not complete. **Recommendation:** explicitly list the nine items, their severity, and the compensating controls in a `PHASE_84_KNOWN_GAPS.md` so an auditor sees the deferral is deliberate, not forgotten.

### F-8 — CLOSED phases need a one-line rationale visible to auditors *(Severity: Low-Medium)*

Phases 24 (Go Strategy Assessment) and 55 (APT Hardening Phase 2) are CLOSED in the manifest. "Closed without complete" is a normal project-management outcome, but external assessors will ask. Adding a `closure_reason:` field to those manifest entries (e.g. "superseded by Phase 15," "merged into Phase 56") is a 10-minute fix that pays for itself the first time someone asks.

### F-9 — Fail-open externals lack a production-grade health story *(Severity: Medium)*

AbuseIPDB, RDAP, MaxMind, and the threat-intel feeds are all fail-open. Phase 59 added circuit breakers and a `FeedHealthMonitor`. What is missing is the bridge from "this feed has been degraded for 4 hours" to "page the on-call." Today this looks like a Prometheus counter that no alert rule consumes (pending Phase 63). **Recommendation:** ship a single composite alert "any signal feed degraded > 30 min" before Phase 63 lands in full.

### F-10 — `ja4proxy_plan.zip` in repo root *(Severity: Low — Hygiene)*

A `ja4proxy_plan.zip` is committed at the repo root. Project zips in repos are usually leftover scaffolding; they bloat clones and frequently contain stale credentials or paths. **Recommendation:** verify it is not sensitive, then either move it under `docs/archive/` or remove it.

---

## 5. Control Coverage Snapshot

Mapped against the project's own `docs/compliance/iso27001-annex-a-mapping.md` and `soc2-control-narrative.md` (not re-derived independently):

| Control family | Coverage | Confidence | Notes |
|---|---|---|---|
| Access control (RBAC, SSO, MFA) | Phases 79, 100 | High | Verify MFA enforcement is **mandatory** in default config, not opt-in. |
| Cryptography | TLS passthrough — no key custody. AES-256-GCM at-rest for backups (Phase 40). Ed25519 config signing (Phase 35). | High | Strong by virtue of design (no decrypt). |
| Operations security | Hardened containers, log rotation, hot reload, blue/green (Phases 14, 25, 35, 42, 43, 71–75) | High | Best-in-class for the project size. |
| Communications security | Four-zone Docker network (Phases 71–75); Redis-internal-only by default | Medium-High | Redis-TLS still deferred per the original audit; verify state. |
| System acquisition / supply chain | Phase 61 PROPOSED | **Low** | See F-1 — top open risk. |
| Supplier relationships (TI feeds) | Phase 59 health monitor | Medium | No documented contractual review of feed providers (out of scope here). |
| Incident management | `INCIDENT_RESPONSE.md` exists | Medium | Not exercised — Phase 64 will close this. |
| BCP / DR | Phase 88 PROPOSED | **Low** | See F-3. |
| Compliance / privacy (GDPR) | Phase 91 erasure path; `GDPR_COMPLIANCE.md` | Medium-High | Phase 91 specifically remediated a long-standing broken `make gdpr-delete`; verify the unit test guards against future regression. |
| Logging & monitoring | ECS logs, SIEM pack (Phase 80) | Medium-High | Alerting maturity gated on Phase 63. |

---

## 6. Recommendations (prioritised)

**Within the next phase cycle:**
1. **Complete Phase 61** (supply-chain). Block external image distribution on it. (F-1)
2. **Ship the Phase 63 metric rename and the FP-rate burn-rate alert.** Do the rename first because it is a breaking change. (F-2)
3. **Ship Phase 64 smoke tests** for Compose / Helm-kind / Podman, plus the Redis-data-loss DR drill. Measure MTTR. (F-3)
4. **Add bypass-change alerts** wired off the existing `management:policy_audit` list. (F-5)

**Within the next two cycles:**
5. **Ship Phase 62 fuzz harness**, even at "one-hour daily smoke" maturity. (F-4)
6. **Document the nine Phase 84 deferred items** in a single visible file with severity and compensating controls. (F-7)
7. **Add `closure_reason:` to CLOSED manifest entries.** (F-8)
8. **Wire the feed-health-degraded composite alert.** (F-9)

**Strategic / governance:**
9. **Decide and document the Python prototype's lifecycle.** Either commit a sunset date or formally label it research-only and gate it from any shared environment. (F-6)
10. **Phase 88 (multi-DC failover):** scope it before the first enterprise customer needs it, not after.
11. **Externalise the hash-chain audit anchor** (publish chain heads to an immutable store) — small effort, large evidentiary value.

---

## 7. What this review did **not** cover

- Live exploit testing of the TLS parser, signal modules, or management UI.
- Cryptographic primitives review (Ed25519 signing implementation, AES-GCM nonce hygiene).
- Third-party legal/contractual review of TI feed licences.
- Performance/benchmark validation beyond reading `docs/reports/PERFORMANCE_BENCHMARK.md`.
- Validation that every PROPOSED phase is in fact unimplemented; some may have partial code that is not yet manifest-marked.
- Review of every signal module's individual scoring weights for false-positive risk.

A formal third-party penetration test against a Phase 64–style reference deployment, plus an SBOM-driven dependency review, would be the natural next steps once Phases 61–64 close.

---

## 8. Bottom line for leadership

JA4proxy is, at the architecture and code-discipline level, a **better-than-typical** security product. The "fail open, score always, default dial = 0" doctrine is the right one and is consistently applied. The Go runtime, host hardening, and compliance mapping are all stronger than is normal for a project of this maturity.

The risk that should keep leadership awake is **not** in the data plane. It is in the gap between "we have built the controls" and "we have proven, in CI and in drills, that the controls hold." That gap is exactly what Phases 61–64 are scoped to close, and they are the four most important things on the backlog. Until they ship, treat any external deployment as **pre-GA**, regardless of the feature completeness of the runtime.

---

*Prepared independently of the Phase 84 / Phase 101 compliance workstream. Cross-references to existing artefacts: `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, `docs/security/threat-model.md`, `docs/compliance/*`, `docs/reference/PROJECT_STATUS.md`, `docs/phases/manifest.yaml`, `CLAUDE.md`.*
