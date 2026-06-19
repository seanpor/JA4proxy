# Phase 108 — Full-Stack Penetration Testing Campaign

> **Status:** PROPOSED
> **Size:** EXTRA-LARGE (14 sub-phases, ~25–35 engineer-days + external vendor)
> **Dependencies:** Phase 105 (audience docs), Phase 107 (CVD policy), Phase 202
> (SBOM + signing), Phase 203 (vuln management). Not all are strict blockers,
> but 107g (CVD policy) must land before external testing begins.
> **Triggered by:** Pre-1.0 / pre-enterprise-readiness gate; CRA Annex I
> "no known exploitable vulnerabilities at release" requirement; procurement
> questionnaires increasingly demand a third-party pentest report.
> **Review:** `docs/phases/complete/PHASE_108_review.md` (to be written on close)

---

## Goal

Plan, execute, and close-out a full-stack adversarial assessment of JA4proxy
that covers every layer of the system from TCP accept through the management
plane, including the build pipeline and the human-operational perimeter.
The campaign produces two artefacts that enterprise buyers and regulators
require: a **third-party pentest report** that can be shared under NDA, and
an **internal red-team evidence pack** that proves the signal pipeline holds
up against active evasion — not just against replayed traffic corpora.

The goal is not "pass a pentest". The goal is to find the things we have
missed, fix them, and leave behind a permanent adversarial testing surface
(fuzzing harnesses, DAST integration, purple-team exercises) so that the
next campaign is cheaper and more targeted than this one.

---

## Current State

| Layer | Existing coverage | Gap |
|-------|-------------------|-----|
| TCP accept / PROXY protocol | Unit + adversarial tests (`tests/adversarial/`) | No live adversarial test against the running proxy binary |
| TLS parsing (ClientHello, JA4) | FP corpus (`tests/fuzz/`), parity tests | No negative / malformed corpus beyond in-tree samples; no fuzzing-as-a-service |
| Signal bypass | Unit tests per module | Never stress-tested by a human trying to evade — only against replayed corpora |
| Management API + UI | `test_pages.py`, `test_container_config.py`, OWASP Top-10 adversarial | No session-management pentest, no CSRF/auth-bypass chaining, no chained-vuln assessment |
| Redis / container | ThreadSafety audit, secrets scan | No active privilege-escalation or container-escape test |
| Build pipeline | SHA-pin enforcement, TruffleHog, pip-audit, govulncheck | No modelled "what if a maintainer's laptop is compromised" scenario; no tamper test of the release artefact |
| Operational | `SECURITY.md`, credential rotation runbook | No phishing / social-engineering assessment; no log-injection test suite |
| External validation | Internal security audit only | No third-party pentest report; no CVE has been assigned through the policy |

**Threat models already exist** in `docs/security/threat-model.md`,
`docs/security/BACKUP_THREAT_MODEL.md`, and the per-phase ADRs. Phase 108
treats these as inputs, not deliverables — the campaign is the *test* of
the threat models, and findings feed back into them.

---

## 108a. Scoping, rules of engagement, and test-plan authoring

### Problem

A pentest without a written scope and rules-of-engagement (ROE) is
unprofessional and unsafe. It risks out-of-scope damage, produces
findings that cannot be acted on, and makes the deliverable useless to
buyers who expect to see the methodology. The internal red-team work must
operate under the same discipline as the external vendor engagement.

### Fix

Create `docs/security/pentest/SCOPE.md`:

- **In-scope targets**: Go proxy (`cmd/proxy`, `internal/*`),
  `ja4proxy-cli`, Management API (`cmd/management`), Management UI,
  Analytics node, Redis deployment, container images published to the
  registry, the `.github/workflows/*` build pipeline
- **Out-of-scope targets**: Python prototype proxy (`proxy.py`) — flagged
  as non-production in `CLAUDE.md`; third-party services (AbuseIPDB,
  Spamhaus, RDAP servers) — pentesting them is unlawful; the deployer's
  infrastructure
- **Objectives** (one per layer, specific): e.g. "achieve a block from a
  ClientHello crafted to evade all 14 signals", "obtain Management API
  admin session without valid credentials", "inject a crafted Redis key
  that causes the proxy to crash", "produce a signed container attestation
  that is not reproducible"
- **Allowed techniques**: fuzzing, fingerprint evasion, DoS-level attacks
  only against isolated lab instances
- **Disallowed techniques**: live-traffic interception, attacks against
  third-party APIs, physical access, social-engineering against actual
  staff (synthetic personas only)
- **Data handling**: all findings treated as embargoed per
  `docs/security/CVD_POLICY.md` (from Phase 107g); no finding disclosed
  externally until remediated or past SLA
- **Communication plan**: daily status during active campaign; severity-1
  findings escalated within 4 hours
- **Stop conditions**: any finding that could affect a production deployer
  triggers an immediate pause and backport assessment

Create `docs/security/pentest/TEST_PLAN.md`:

- One row per objective in SCOPE.md, mapped to the sub-phase that tests it
- Test environment (lab-only; never prod)
- Evidence capture standard: command, expected, actual, artefact hash
- Retest gating: each finding must have an automated regression test that
  fails before the fix and passes after

### Size

**M** — scope + test plan are load-bearing foundation documents.

---

## 108b. Threat-model reconciliation and attacker-persona matrix

### Problem

The existing threat models were written per-phase, not as a coherent
whole. An attacker-persona matrix (who is trying to get through, with
what capability and motivation) is the input to all subsequent layer
testing. Without it, layer-specific tests focus on the wrong evasion
shapes.

### Fix

Create `docs/security/pentest/ATTACKER_PERSONAS.md`:

| Persona | Capability | Motivation | Example techniques |
|---------|-----------|-----------|--------------------|
| Opportunistic scanner | Low; Shodan + script kit | Noisy enumeration | Mass ClientHello with default libraries |
| Credential-stuffing operator | Medium; residential-proxy farm | Financial fraud | Distributed low-rate, rotating JA4 |
| C2 framework operator | Medium–high; Sliver/CobaltStrike | Target compromise | Known-signature TLS fingerprints, beaconing |
| Targeted adversary | High; custom tooling | Specific target | Custom ClientHello, mTLS theft, signal-bypass chaining |
| Malicious insider (deployer-side) | High; knows config | Bypass own controls | Raise dial exploits, policy-audit tampering |
| Supply-chain adversary | High; upstream dep compromise | Broad impact | Malicious PR, action-reference swap, CI-runner compromise |

Reconcile existing threat models:

- Merge findings from `docs/security/threat-model.md`,
  `BACKUP_THREAT_MODEL.md`, and the Phase 20/34/62 audit artefacts
- Produce a single `docs/security/pentest/THREAT_MODEL_CONSOLIDATED.md`
  with STRIDE per layer
- Cross-reference the ATT&CK mapping from Phase 107f

### Size

**M** — synthesis of existing material plus persona grid.

---

## 108c. Layer 1 — Network / TCP and PROXY-protocol adversarial tests

### Problem

`internal/proxy/proxy_protocol*.go` parses PROXY-protocol v1 and v2
headers and extracts the real client IP. A malformed or spoofed header
is a prime vector: v1 string-parsing bugs, v2 TLV handling, oversized
headers, header injection when the upstream is untrusted. Existing
tests cover happy-path and some malformed cases but were written by the
implementer, not an attacker.

### Fix

Create `tests/adversarial/test_proxy_protocol_pentest.go` (Go, because
this is the production path):

- **Malformed v1**: missing terminator, long addresses, embedded CRLF,
  IPv6-in-v1, wrong family field, address-longer-than-declared-length
- **Malformed v2**: oversized length, truncated TLV, overlapping TLVs,
  family mismatch, PP2_TYPE_AUTHORITY spoofing
- **Trust-boundary bypass**: header from an untrusted upstream CIDR must
  be ignored — verify the real-client-IP is NOT taken from the header
- **Slow-loris on PROXY line**: partial v1 string delivered one byte per
  second; must time out, not block
- **Injection into logs**: newlines/escape sequences in the address
  field must not produce multi-line log entries

Add a lab harness `tests/pentest/layer1/` with scripted adversarial
sessions run against a live `bin/proxy` (not just unit-level).
Use `testcontainers-go` to spin up the proxy per test.

Findings go into `docs/security/pentest/findings/L1-*.md` — one file
per finding — regardless of whether they become CVE-worthy.

### Size

**M** — parser is small but attack surface is dense; lab harness is new.

---

## 108d. Layer 2 — TLS and fingerprint-evasion red-team

### Problem

The JA4 parser (`internal/tls/parser.go`, `ja4.go`, `ja4x.go`) is the
most security-sensitive parser in the system. A malformed ClientHello
that crashes the proxy, or a crafted ClientHello whose JA4 hash collides
with a whitelisted fingerprint, breaks every downstream control.

### Fix

Three tracks:

**108d.1 — Parser robustness**
- Replay public ClientHello corpora (BoringSSL, TLS-fingerprint,
  ja4db.com public samples) against the parser; assert no crash, no
  runaway allocation, bounded parse time
- Extend the existing fuzzing target in `tests/fuzz/` with additional
  seeds drawn from: truncated ClientHellos, oversized extensions,
  extension-within-extension pathological packings, GREASE-saturation,
  non-TLS bytes framed as TLS
- Add `go test -run=FuzzJA4 -fuzz=FuzzJA4 -fuzztime=30m` as a CI target
  (Phase 108j expands this)

**108d.2 — Fingerprint collision and evasion**
- Generate ClientHellos whose JA4 matches a whitelisted browser
  fingerprint but whose payload is from a known-bad tool
- Test whether the downstream score-only signals catch it (SNI,
  TCP behaviour, ASN) — this is the *real* test of the signal stack
- Produce a "JA4 alone is insufficient" evidence document for the
  architects' audience

**108d.3 — Downgrade and version shenanigans**
- Offer TLS 1.0/1.1 only, assert the parser handles it (downgrade is
  allowed; blocking is the backend's job — verify JA4proxy doesn't
  crash)
- Offer record-layer fragmentation that splits a ClientHello across
  many records
- Offer a fake ClientHello inside a TLS application_data record type
  (parser must reject cleanly)

Artefacts: `tests/fuzz/tls_corpus/` seed expansion;
`tests/pentest/layer2/` runnable scenarios; findings under
`docs/security/pentest/findings/L2-*.md`.

### Size

**L** — 108d.2 is the hardest part; generating meaningful collision
attempts requires real reverse-engineering time.

---

## 108e. Layer 3 — Signal-pipeline evasion (14 modules)

### Problem

Each signal module in `internal/security/` (`beaconing_detector`,
`rate_limiter`, `tcp_analyzer`, `sni_analyzer`, `analytics_signals`,
`asn_classifier`, `dns_enrichment`, `rdap_enrichment`, `abuseipdb`,
`tap_consumer`, `mtls`, `risk_scorer`, `blocklists`, `tls_enforcer`)
has its own evasion surface. The composite scorer can be gamed if an
attacker knows (or guesses) the weights.

### Fix

One adversarial play per module, tabulated in
`docs/security/pentest/findings/L3_EVASION_MATRIX.md`:

| Module | Evasion play | Expected result | Actual result | Finding |
|--------|-------------|-----------------|---------------|---------|
| beaconing_detector | Jitter interval with uniform noise larger than the CoV threshold | Should still detect if noise is not drawn from real human traffic | ? | L3-001 |
| rate_limiter | Slow-low-rate from 10k residential IPs | Per-IP limits don't fire; ASN classifier should | ? | L3-002 |
| tcp_analyzer | Perfect TCP handshake timing (no timestamp skew) | Should be *less* suspicious, not more | ? | L3-003 |
| sni_analyzer | SNI matches a major CDN but TLS fingerprint is a bot | Should flag | ? | L3-004 |
| asn_classifier | Traffic from an ASN marked "Tor" but via an unlisted relay | Should flag on ASN, not relay IP | ? | L3-005 |
| abuseipdb | Submit score > 50 IPs rotated every 30s | Fail-open if AbuseIPDB is throttled | ? | L3-006 |
| blocklists | JA4 that differs from blacklisted one by a single cipher | Should NOT match (exact-match only by design) | ? | L3-007 |
| mtls | Expired / wrong-CA cert | Should fall through to scoring, not bypass | ? | L3-008 |
| tls_enforcer | Hello with minimum version the enforcer accepts but cipher set deprecated | Should log + score | ? | L3-009 |
| dns_enrichment | PTR → host appears well-known but forward lookup doesn't match | FCrDNS should fail — should flag | ? | L3-010 |
| rdap_enrichment | Use a freshly-allocated /24 to evade reputation | Reputation-age signal should flag | ? | L3-011 |
| tap_consumer | Replay a legitimate session's tap events | Should not elevate trust | ? | L3-012 |
| analytics_signals | Submit a high-volume pattern from a CDN ASN | Should not auto-block (CDN whitelist wins) | ? | L3-013 |
| risk_scorer | Design a profile that straddles every individual threshold | Composite score still trips at the right dial setting | ? | L3-014 |

Each row becomes a test in `tests/pentest/layer3/`. Findings become
regression tests in `tests/adversarial/`.

**Constraint — core asymmetry**: a finding where the evasion is
theoretically possible but requires capabilities (e.g. distributed
residential proxy network) that also require multi-IP rate limiting on
the *deployer* side is acceptable — document the compensating control.

### Size

**XL** — the single biggest sub-phase; 14 modules × 1–2 days each.

---

## 108f. Layer 4 — Management API and UI web-app pentest

### Problem

`cmd/management/` (Go) serves the management API; the UI is a React SPA.
Together this is a classic web-app attack surface: auth, session,
CSRF, XSS, SSRF, IDOR, broken access control, mass assignment. OWASP
ASVS-style coverage is required for any enterprise procurement review.

### Fix

Reuse `tests/security/test_owasp_top10.py` as a baseline; expand under
`tests/pentest/layer4/`:

- **Authentication**: brute-force rate limit, credential stuffing,
  password-reset flow, session-fixation, JWT-signature verification,
  `alg: none` attempt, expired-token replay
- **Authorisation**: IDOR on every parameterised route, policy-audit
  read by non-admin, config write by read-only role
- **CSRF**: every state-changing route requires the expected token;
  token scope bound to session
- **SSRF**: config fields that accept URLs (webhook, remote feed) must
  be validated — the existing 101d SSRF test is the starting point,
  extend to cover metadata-service IPs (169.254.169.254), IPv6 link-local,
  DNS rebinding
- **XSS**: every UI-rendered field; test with a canonical XSS corpus;
  ensure CSP is present and restrictive
- **Injection**: SQL (analytics query builder), command (none expected —
  verify), log injection (newlines in policy names), YAML-bomb on config
  upload
- **Session management**: Secure + HttpOnly + SameSite on every cookie;
  session timeout enforcement; concurrent-session policy
- **File upload**: feeds / certs / policy imports — content-type
  validation, size limits, path traversal, zip-bomb

**Chained-vuln assessment**: at least three chains attempted (e.g.
read-only IDOR → exposed webhook URL → SSRF → metadata theft). A chain
that succeeds is a Critical finding regardless of individual step
severities.

**Deliverable**: ASVS-style coverage matrix at
`docs/security/pentest/findings/L4_ASVS_COVERAGE.md`.

### Size

**XL** — web-app pentest with chains is 4–6 engineer-days minimum.

---

## 108g. Layer 5 — Redis, container, and host pentest

### Problem

The Redis instance holds blocklists, rate-limit state, and the
policy-audit log. Compromise of Redis compromises the trust fabric.
Containers run the proxy, management, and analytics nodes — escape
from any of them to the host is catastrophic.

### Fix

Redis:

- **AuthN**: can the proxy authenticate with a rotated password mid-run?
  (tests credential rotation runbook)
- **AuthZ**: does the proxy have write access to only the keys it
  should? (ACL enforcement)
- **Injection**: crafted key names that contain Redis protocol bytes;
  key names that embed Lua escape sequences; SCAN with malicious
  MATCH patterns
- **Lua**: scripts used for sliding-window rate limit — verify they
  cannot be replaced; `SCRIPT LOAD` gated by ACL
- **Pub/Sub**: a connection with SUBSCRIBE-only ACL cannot PUBLISH a
  forged policy-reload
- **TLS**: even in Docker-internal networks, plain-text Redis is flagged;
  test the cert-pinning on the Redis TLS path (once Phase 15 completes)

Container:

- Read-only root filesystem holds under all operations
- `cap_drop: ALL` — verify the proxy still functions
- `no-new-privileges` set — attempt setuid binary execution
- AppArmor/seccomp profile applied — attempt blocked syscalls
- Container-to-host: mount-namespace escape, cgroup-based escape
  (using the Trivy container-escape corpus as input)
- Image scan: Trivy/Grype against the published image; zero Criticals,
  SBOM matches Cosign attestation

Host / orchestrator (Kubernetes path only):

- PodSecurityPolicy or PSA equivalent enforced
- NetworkPolicy prevents east-west traffic to non-proxy services
- Service-account token not mounted unless explicitly required

Deliverable: `tests/pentest/layer5/` scripts + findings under
`docs/security/pentest/findings/L5-*.md`.

### Size

**L** — thorough but many deliverables are scripted scans, not manual
exploitation.

---

## 108h. Layer 6 — Supply-chain red-team

### Problem

Phase 202 shipped SBOM + signing; Phase 107c targets SLSA Level 3.
But neither *tests* the supply chain against a modelled compromise.
The attack modes are well-known (malicious PR, typosquat dep, compromised
runner, action-reference swap). A table-top is not enough; we need
demonstrated evidence that a compromise is detected.

### Fix

Red-team the build, on a fork / lab copy only:

- **Malicious PR merge attempt**: open a PR that introduces a benign-
  looking backdoor (adds an env-var reading an attacker URL); verify
  SAST / CodeQL / manual review catches it
- **Dependency-confusion / typosquat**: pin a typo of a real dep in a
  branch; verify `pip-audit` / `govulncheck` / Dependabot or Renovate
  catches it
- **Action-reference swap**: change a SHA-pin to a mutable `main`
  ref on a branch; `tests/test_workflow_pinning.py` must fail the CI
  run — verify it does
- **Runner-side mutation simulation**: add a step to a workflow that
  modifies a binary between build and sign; verify the Cosign +
  SLSA verifier catches the mismatch on retrieval (requires Phase 107c
  in place — if not, document the gap)
- **Retraction test**: inject a known-bad CVE into the transitive Go
  dep graph; the weekly CVE sweep workflow must produce the finding
  within 24 hours
- **Developer-laptop compromise**: commit signed by a key that is not in
  the allowlist — verify the commit-signature policy (Phase 201/202)
  rejects it

Deliverable: `docs/security/pentest/findings/L6_SUPPLY_CHAIN.md` with
one row per attack, result, and detective/preventive control that
fired (or didn't).

### Size

**L** — each attack is small to simulate but needs a disposable repo
copy and careful cleanup.

---

## 108i. Layer 7 — Operational and insider threat

### Problem

Many pentest reports stop at the software. Real breaches go through
humans: phishing, credential reuse, log-viewer privilege escalation,
policy-audit tampering, operator-induced misconfiguration. The
`security_policy` audit log (LIST `management:policy_audit`) is the
tamper-evidence control; it has never been tested against an operator
who *wants* to hide a change.

### Fix

No live social engineering of real staff. Instead:

- **Synthetic phishing scenario**: craft a realistic phishing email
  targeting the "rotate Redis password" flow; does the credential-rotation
  runbook include a verification step that would catch it?
- **Log-injection / log-tamper**: can a Management API admin overwrite
  or truncate `management:policy_audit`? If yes, that's a Critical
  finding regardless of current threat model
- **Dial-raise smoke-screen**: operator raises the dial briefly to
  block a specific known-legitimate source during a suspicious window
  — does the dial-change audit capture it with attribution?
- **Secrets in logs**: run a full traffic capture with a canary API
  key in the config; grep every log / metric / Redis key for the canary;
  none must leak
- **Credential-rotation completeness**: rotate every secret in the
  runbook; verify no stale credential remains valid; document the
  time-to-rotate
- **Disaster-recovery drill**: trigger the DR runbook end-to-end in lab;
  capture time-to-recovery and any undocumented steps

Deliverable: `docs/security/pentest/findings/L7_OPERATIONAL.md` + a
runbook update PR for each gap found.

### Size

**M** — mostly runbook walkthroughs + specific log-tamper tests.

---

## 108j. Continuous fuzzing campaign

### Problem

Ad-hoc fuzzing runs find bugs once. Continuous fuzzing finds regressions
forever. The Go proxy's ClientHello parser, config loader, and Redis
protocol client are all fuzz-worthy — but only one has a fuzz target
today.

### Fix

Add / expand fuzz targets:

- `internal/tls/parser.go` — `FuzzParseClientHello` (extends existing)
- `internal/config/` — `FuzzLoadConfig` (YAML + env-var parse)
- `internal/security/pipeline.go` — `FuzzPipelineSignalExtraction`
  (synthetic connection struct)
- `cmd/management/` — HTTP handler fuzzing via `go-fuzz-headers`
- `internal/proxy/proxy_protocol.go` — `FuzzProxyProtocolParse`

CI integration:

- Short-run (5 min) per fuzz target on every PR
- Long-run (4 hr) nightly on a matrix job
- Corpus persistence via an artefact store (GitHub Actions cache +
  signed S3 bucket)
- Crash reproducer test added automatically to `tests/fuzz/regressions/`
- OSS-Fuzz application — JA4proxy is an open-source security tool, it
  qualifies; file the application and track to acceptance

Metrics:

- Each fuzz target must reach a documented coverage baseline before
  the phase closes; `make fuzz-coverage` reports it
- Zero crashes in 24 hours of cumulative fuzz time is the bar for
  "L2 complete"

### Size

**L** — five new fuzz targets + OSS-Fuzz application + CI plumbing.

---

## 108k. External pentest engagement

### Problem

An internal red-team is necessary but not sufficient. Enterprise buyers
and the CRA Annex I "no known exploitable vulnerabilities at release"
requirement expect a third-party report produced by an accredited
assessor. Internal testers know where the bodies are buried; external
testers bring a fresh eye and the authority of independence.

### Fix

Author `docs/security/pentest/EXTERNAL_ENGAGEMENT.md` covering:

- **Selection criteria**: CREST / OSCP / OSWE-accredited firm; experience
  with TLS middleboxes; willingness to sign the project CVD policy;
  prior-work references
- **Rules of engagement**: lifted from `SCOPE.md` + ROE addendum; legal
  authorisation letter; single named point of contact
- **Scope**: proxy core, management plane, Redis, container images,
  build pipeline (read-only); Python prototype explicitly out
- **Environment**: dedicated lab deployment, not shared, not prod
- **Test data**: synthetic traffic only; no real user data
- **Deliverables from vendor**: executive summary, technical report,
  findings with CVSS + CWE + reproducer, attestation letter
- **Sign-off**: Sean O'Riordain (project owner) is the single approver
- **Budget envelope**: document the target tier (small-scope is
  ~£8k–£15k in the UK / EU market at 2026 rates); note that procurement
  may push back and that's fine — don't compress scope
- **Timing**: schedule during a feature freeze; run only against a
  release candidate, not a development branch
- **Retest**: agreement to include a retest pass after remediation,
  included in the fee

Track engagement-related comms in `docs/security/pentest/vendor/`
(gitignored in the public repo; private branch only). Public-facing
output is the executive summary + letter of attestation.

### Size

**L** — coordination heavy; actual engagement run is vendor-time, not
engineering-time, but contract / scope / retest plumbing is real work.

---

## 108l. Bug-bounty program design

### Problem

A pentest is a point-in-time assessment. A bug-bounty is continuous
external scrutiny. For an open-source security product, a bug-bounty is
also the clearest possible signal to enterprise buyers that the project
welcomes scrutiny — which is what they're really checking for.

### Fix

Create `docs/security/BUG_BOUNTY.md`:

- **Scope**: same as pentest scope + the public container image
- **Rewards**: tiered by severity and quality; start small (symbolic
  reward — £100 critical, swag otherwise) and raise once volume is
  understood
- **Platform**: HackerOne / Intigriti / YesWeHack vs self-hosted via
  GitHub security advisories — recommend GitHub security advisories for
  year 1 (zero platform cost, integrates with CVD policy), migrate to
  a platform if volume warrants
- **Eligibility**: CVD-policy-aligned; safe-harbour applies; no
  disclosure prior to remediation
- **Exclusions**: explicit non-issues list (self-XSS, social
  engineering of maintainers, DoS, known false positives)
- **Response SLAs**: same as CVD policy (Phase 107g)

Integration:

- `SECURITY.md` links BUG_BOUNTY.md
- `README.md` links BUG_BOUNTY.md
- README badge added only after first live report is handled
  end-to-end (prevents over-promising)

### Size

**S** — policy writing; platform work deferred to execution.

---

## 108m. Continuous DAST and purple-team rotation

### Problem

A one-shot pentest ages badly. DAST (dynamic application security
testing) against the running Management UI gives per-PR assurance.
Purple-team exercises on a regular cadence keep detection capability
sharp and the threat model current.

### Fix

DAST:

- Integrate OWASP ZAP baseline scan into the docker-smoke workflow:
  runs against a live Management UI in the smoke-test environment
- Fail the workflow on any Medium+ finding not in the baseline
  `tests/pentest/dast/baseline.json`
- Nightly full-scan (not baseline) on a matrix job; report as artefact
- Extend to API fuzzing via `schemathesis` against the OpenAPI spec

Purple team:

- Quarterly exercise: a named red-team scenario (rotating through the
  personas from 108b) is run against a lab deployment; blue-team
  (i.e. operators) must detect and respond
- Each exercise produces a `docs/security/pentest/purple/YYYYQN.md`
  with detection coverage, MTTD, MTTR
- The calendar lives in `SECURITY_CADENCE.md`

CI wiring:

- `make pentest-ci` runs the subset of 108c–108e tests that are
  deterministic and fast
- `make pentest-full` runs all pentest tests (slow; not on every PR)

### Size

**M** — ZAP integration is small; purple-team schedule is light recurring.

---

## 108n. Findings management, remediation tracking, and retest discipline

> **Superseded implementation detail (2026-04-19, Phase 121e):** The
> register described below was built under Phase 121a/b and lives at
> `docs/security/findings.yaml` (machine-readable source of truth) with
> a generated human view at `docs/security/FINDINGS_REGISTER.md`.
> Scoring is CVSS v3.1 per **ADR-121a**, not v4. SLA tiers, state
> machine, and CI gates are governed by Phase 121a–k, not by this
> section. This §108n is retained only as the originating statement
> of the problem.

### Problem

Pentest findings rot without a disciplined intake. A finding without a
tracked remediation + retest is worse than no finding — it creates a
false sense of security. The existing `docs/security/EXCEPTIONS.md`
covers CVE exceptions but has no equivalent for pentest findings.

### Fix (as implemented under Phase 121)

Canonical register: `docs/security/findings.yaml` + generated
`docs/security/FINDINGS_REGISTER.md`:

- Row per finding: canonical ID `JA4PROXY-YYYY-NNNN`, title, severity
  (CVSS v3.1 per ADR-121a), discovered-by, date, status
  (OPEN / IN_PROGRESS / FIXED / VERIFIED / CLOSED / DUPLICATE),
  remediation PR link, regression test nodeid, `verified_by` +
  `verified_on` (required for VERIFIED/CLOSED), `closed_commit`
- Severity-to-SLA mapping (Phase 121a): CRITICAL 7d / HIGH 30d /
  MEDIUM 60d / LOW 120d. (Supersedes the earlier 30/60/90/next-release
  tiers first sketched here.)
- Automated freshness check: `python3 scripts/findings_register.py
  verify` fails CI if any open finding is past SLA, is missing
  required evidence fields, or has an invalid state transition.
- Deferred findings must have an ADR explaining the business /
  architectural reason and a compensating control.

Integration:

- Every finding from 108c–108i (and every subsequent phase) is a row
  in `findings.yaml` with `source_refs` pointing back at the phase doc.
- Every fix PR must reference the canonical ID in its commit message
  and in the PR template opt-in (`.github/PULL_REQUEST_TEMPLATE.md`).
- Every fix PR must add a regression test under `tests/pentest/` or
  `internal/security/pentest/` that fails before and passes after —
  enforced by the `verify-findings-green` Make target.
- Retest (VERIFIED → CLOSED) is a separate commit and requires all
  three of `verified_by`, `verified_on`, and `closed_commit`; the
  promote step refuses to advance without them. See
  `docs/security/CLOSURE_VERIFICATION.md`.

Reporting:

- Monthly `make pentest-report` generates a markdown snapshot for the
  project owner.
- Public-facing summary numbers (total findings by severity;
  time-to-fix median) appear in the next annual security report.

### Size

**M** — register + automation + reporting. (Delivered under Phase 121.)

## 108z. Adversarial Enhancements (Leader's Addendum)

### Problem
Standard pentests often follow a checklist. To truly test JA4proxy's "well-resourced" and "comprehensive" claims, we must move beyond checking boxes and into the mindset of a persistent, cunning adversary who understands the *systemic* weaknesses of fingerprint-based security.

### Fix
Incorporate the following "Leader's Plays" into the campaign execution:

**1. The "Fingerprint Poisoner" Persona**
*   **Concept**: An attacker who doesn't just evade, but *pollutes*.
*   **Attack**: Flooding the proxy with a massive volume of "Clean-JA4" traffic (legitimate-looking browser fingerprints) that are subtly malformed or associated with "noisy" but non-malicious behavior.
*   **Goal**: Force the analytics system to lower the weight of high-fidelity fingerprints, or trigger "alert fatigue" in the SecOps team.
*   **Test**: Measure the "signal-to-noise" ratio in the Management UI during a poison campaign.

**2. Protocol-Confusion & State-Machine Desync**
*   **Concept**: Exploiting the boundary between TCP, PROXY-protocol, and TLS parsing.
*   **Attack**: 
    *   **Partial-Write Hijacking**: Delivering a valid PROXY header, but stalling mid-TLS ClientHello. Then, "resuming" with a different protocol (e.g., raw HTTP or SSH) to see if the internal state machine in `cmd/proxy` leaks data from the initial parsing phase into the subsequent stream.
    *   **Multi-Packet Fragmentation**: Intentionally fragmenting the ClientHello across the maximum possible number of TCP packets (1 byte per packet) with randomized delays to hit reentrancy bugs or resource limits in the Go parser.

**3. Feedback-Loop Exploitation (The "Training" Attack)**
*   **Concept**: Gaming the "Risk Scorer" by training it to trust a malicious signature.
*   **Attack**: Conducting a week-long "conditioning" phase where a specific, custom JA4 fingerprint is used only for highly reputable traffic (matching SNI to Google/Microsoft, coming from high-reputation ASNs). Once "trusted" or "whitelisted" by the analytics node, the fingerprint is then used for the actual exploit.
*   **Goal**: Determine if the "Reputation" signal is sufficiently sticky or if it can be manipulated over time.

**4. Side-Channel Timing Probes**
*   **Concept**: Measuring micro-differences in proxy latency.
*   **Attack**: Precise timing of the "Time-to-First-Byte" (TTFB). Does the proxy take 5ms longer to respond when it's checking a fingerprint against a large Redis-based blocklist vs. a local cache?
*   **Goal**: Map the internal blocklist/whitelist without ever triggering a block.

**5. Management-to-Proxy "Backwash"**
*   **Concept**: Exploiting the internal control plane.
*   **Attack**: If the Management API allows uploading custom "Fingerprint Names" or "Descriptions," can we inject payloads that, when synced to the proxy's local cache, cause memory corruption or logic errors during the scoring phase?
*   **Goal**: Bridge the gap between the (usually lower security) management plane and the high-security proxy core.

**6. The "Clock-Skew" Evasion**
*   **Concept**: Desyncing time-based signals.
*   **Attack**: If the `beaconing_detector` or `rate_limiter` uses distributed timestamps (Redis + Local), can we manipulate network latency or NTP-skew (if possible) to "smear" our traffic across multiple time-windows, effectively lowering our calculated rate?

### Deliverable
These "Cunning Plays" will be documented as a separate **"Red Team Playbook"** in `docs/security/pentest/RED_TEAM_PLAYBOOK.md`, used to guide the internal red-team execution in sub-phases 108c–108h.

---

## Acceptance Criteria
... (rest of document)

**Planning**

- [ ] `docs/security/pentest/SCOPE.md` exists and names every in-scope
      and out-of-scope target
- [ ] `docs/security/pentest/TEST_PLAN.md` exists with one row per
      objective, each mapped to a sub-phase
- [ ] `docs/security/pentest/ATTACKER_PERSONAS.md` exists with ≥ 6
      personas
- [ ] `docs/security/pentest/THREAT_MODEL_CONSOLIDATED.md` exists,
      merging all prior threat-model fragments

**Layer execution — internal**

- [ ] `tests/pentest/layer1/` contains runnable adversarial sessions
      for PROXY-protocol parsing; `make pentest-layer1` exits 0
- [ ] `tests/pentest/layer2/` covers TLS parser robustness +
      fingerprint-collision attempts; `make pentest-layer2` exits 0
- [ ] `tests/pentest/layer3/` covers all 14 signal modules per the
      evasion matrix; every row has an actual result
- [ ] `tests/pentest/layer4/` covers OWASP ASVS Level 2 for the
      Management API + UI; at least 3 attempted chained attacks,
      documented outcome
- [ ] `tests/pentest/layer5/` covers Redis, container, host; zero
      Critical findings open
- [ ] `tests/pentest/layer6/` contains supply-chain red-team scripts
      and `L6_SUPPLY_CHAIN.md` documents the outcome of each
- [ ] `tests/pentest/layer7/` covers the operational scenarios;
      runbook updates merged for every gap

**Fuzzing**

- [ ] Five fuzz targets land, each reaching documented coverage baseline
- [ ] `make fuzz-ci` (5-min per target) runs on every PR
- [ ] Nightly 4-hour fuzz job runs with corpus persistence
- [ ] OSS-Fuzz application submitted; acceptance tracked in
      FINDINGS_REGISTER.md
- [ ] Zero crashes in 24 hours of cumulative fuzz time at phase close

**External validation**

- [ ] `docs/security/pentest/EXTERNAL_ENGAGEMENT.md` exists; vendor
      selected and contracted
- [ ] External pentest executed on a release candidate; report received
- [ ] Executive summary published at
      `docs/security/pentest/EXECUTIVE_SUMMARY_YYYY-MM.md`
- [ ] Every Critical and High finding from the vendor report has a
      merged fix PR OR an approved ADR deferring it with a compensating
      control
- [ ] Vendor retest pass completed; attestation letter stored

**Bug bounty + DAST**

- [ ] `docs/security/BUG_BOUNTY.md` published
- [ ] OWASP ZAP baseline scan wired into `docker-smoke` workflow
- [ ] `tests/pentest/dast/baseline.json` exists; any Medium+ finding
      outside baseline fails the build
- [ ] At least one full nightly DAST run has executed
- [ ] `SECURITY_CADENCE.md` publishes the purple-team
      calendar

**Findings discipline**

- [ ] `docs/security/pentest/FINDINGS_REGISTER.md` exists with every
      finding from 108c–108i + 108k + DAST + fuzz
- [ ] `tests/security/test_findings_register.py` enforces the SLA /
      PR-link requirement; passes in CI
- [ ] No open finding is past SLA at phase close
- [ ] Every fix PR includes a regression test; PR template updated to
      require the finding-ID reference

**Integration**

- [ ] `README.md` links the pentest summary and the
      bug-bounty programme
- [ ] `README.md` links the EXECUTIVE_SUMMARY + CRA
      conformance evidence
- [ ] `docs/compliance/CRA_CONFORMANCE.md` (Phase 107a) cites the
      pentest executive summary as evidence for Annex I
- [ ] `docs/security/RISK_REGISTER.md` (Phase 106b) updated with any residual
      risks from deferred findings

**Close-out**

- [ ] `docs/phases/manifest.yaml` has Phase 108 entry marked COMPLETE
- [ ] `CHANGELOG.md` has Phase 108 entry
- [ ] `make sync` clean

---

## Files to Modify

| File | Change |
|------|--------|
| `docs/security/pentest/SCOPE.md` | New |
| `docs/security/pentest/TEST_PLAN.md` | New |
| `docs/security/pentest/ATTACKER_PERSONAS.md` | New |
| `docs/security/pentest/THREAT_MODEL_CONSOLIDATED.md` | New (merges prior fragments) |
| `docs/security/pentest/FINDINGS_REGISTER.md` | New |
| `docs/security/pentest/EXTERNAL_ENGAGEMENT.md` | New |
| `docs/security/pentest/EXECUTIVE_SUMMARY_YYYY-MM.md` | New — written at close |
| `docs/security/pentest/findings/L1..L7-*.md` | New — one per finding |
| `docs/security/pentest/findings/L3_EVASION_MATRIX.md` | New |
| `docs/security/pentest/findings/L4_ASVS_COVERAGE.md` | New |
| `docs/security/pentest/findings/L6_SUPPLY_CHAIN.md` | New |
| `docs/security/pentest/findings/L7_OPERATIONAL.md` | New |
| `docs/security/pentest/purple/YYYYQN.md` | New — one per quarter |
| `docs/security/BUG_BOUNTY.md` | New |
| `SECURITY_CADENCE.md` | New |
| `ANNUAL_SECURITY_REPORT.md` | New — template |
| `tests/pentest/layer1..layer7/` | New directories + test scripts |
| `tests/pentest/dast/baseline.json` | New |
| `tests/fuzz/tls_corpus/` | Seed expansion |
| `tests/fuzz/regressions/` | New — crash reproducers directory |
| `tests/security/test_findings_register.py` | New |
| `tests/adversarial/test_proxy_protocol_pentest.go` | New |
| Fuzz targets in `internal/tls/`, `internal/config/`, `internal/security/`, `cmd/management/`, `internal/proxy/` | New |
| `.github/workflows/fuzz-ci.yml` | New — 5-min per-PR fuzz |
| `.github/workflows/fuzz-nightly.yml` | New — 4h matrix fuzz |
| `.github/workflows/dast.yml` | New — ZAP baseline + nightly full |
| `.github/workflows/docker-smoke.yml` | Add ZAP baseline step |
| `Makefile` | Add `pentest-layer1..7`, `pentest-ci`, `pentest-full`, `pentest-report`, `fuzz-ci`, `fuzz-coverage` targets |
| `SECURITY.md` | Link BUG_BOUNTY.md, FINDINGS_REGISTER.md |
| `.github/PULL_REQUEST_TEMPLATE.md` | Require finding-ID reference when applicable |
| `README.md` | Add pentest + bug-bounty links |
| `README.md` | Add executive summary link |
| `docs/compliance/CRA_CONFORMANCE.md` | Cite executive summary |
| `docs/security/RISK_REGISTER.md` | Add rows for deferred findings |
| `docs/phases/manifest.yaml` | Add Phase 108 entry; mark COMPLETE |
| `CHANGELOG.md` | Phase 108 entry |

---

## Sizing Summary

| Sub-phase | Size | Notes |
|-----------|------|-------|
| 108a — Scope + ROE + test plan | M | Foundation; blocks everything else |
| 108b — Personas + threat-model reconciliation | M | Synthesis of existing material |
| 108c — Layer 1 network / PROXY-protocol | M | Parser is small but dense |
| 108d — Layer 2 TLS and JA4 evasion | L | 108d.2 fingerprint-collision is hard |
| 108e — Layer 3 signal pipeline evasion (14 modules) | XL | Biggest single block |
| 108f — Layer 4 Management API + UI | XL | Chained-vuln + ASVS coverage |
| 108g — Layer 5 Redis + container + host | L | Scripted + manual mix |
| 108h — Layer 6 supply chain | L | Disposable repo copy needed |
| 108i — Layer 7 operational + insider | M | Runbook walkthrough heavy |
| 108j — Continuous fuzzing | L | 5 new fuzz targets + OSS-Fuzz |
| 108k — External engagement | L | Coordination heavy; vendor-time on top |
| 108l — Bug-bounty policy | S | Policy only; platform deferred |
| 108m — DAST + purple-team cadence | M | ZAP wiring + schedule |
| 108n — Findings management | M | Register + automation + reporting |

**Total effort:** EXTRA-LARGE. Realistic calendar ~2–3 months with a
dedicated engineer + part-time security review, assuming Wave 1/2/3
parallelism below.

### Suggested parallelism

- **Wave 1 — planning** (sequential, blocks everything): 108a, 108b.
- **Wave 2 — internal pentest** (parallel, 6 agents):
  108c, 108d, 108e, 108f, 108g, 108i. 108h also parallel but on a
  disposable repo copy. 108j can start in parallel once 108d is well
  underway (fuzz seeds overlap).
- **Wave 3 — findings pipeline**: 108n runs in parallel to Waves 2–4 as
  findings arrive; must be functional by end of Wave 2.
- **Wave 4 — external**: 108k begins only after Waves 1–3 have closed
  internal Criticals. Vendor report arrives during Wave 4; fixes land
  in Wave 5.
- **Wave 5 — continuous**: 108l, 108m, ongoing retests and quarterly
  purple-team.

One engineer full-time + 0.5 FTE security review: ~10 weeks internal,
~4 weeks vendor engagement on top (wall-clock, not effort-time).
Six-agent fan-out in Wave 2: ~3 weeks internal.

---

## Notes for Implementer

- **Don't start 108k before Criticals are closed.** An external vendor
  who finds five known-to-us Criticals is a waste of the budget and
  damages the executive-summary narrative.
- **"Pentest" doesn't mean "break everything".** The core asymmetry
  applies: false positives cost more than false negatives. A signal
  that's evadable in the lab but whose evasion requires capabilities
  an attacker doesn't have in practice is a known-and-accepted
  residual risk — document it in the risk register, do not over-fix.
- **Lab-only, always.** Every test in this phase runs against an
  isolated deployment. No pentest tool runs against a live production
  deployment, even for a "harmless" check. If it touches prod, it
  isn't a pentest, it's an incident.
- **Evidence hashing matters.** Every finding's reproducer must include
  the SHA of the binary under test. "Works on main" means nothing six
  months later. `git describe --dirty` in every finding row.
- **Regression test before fix.** A finding without a failing test is
  an anecdote. Write the test first, watch it fail, then fix. This is
  standard TDD but takes discipline on an active pentest workload.
- **OSS-Fuzz timeline is not in our control.** File the application
  early (start of Wave 1), track to acceptance as a parallel item;
  don't gate phase close on it.
- **Vendor selection caveat.** Beware "pentest firms" that are really
  just running Nessus + Burp and delivering the output. Ask for:
  (a) named lead consultant CV, (b) redacted sample report from a
  similar middlebox engagement, (c) statement that the lead is not
  on more than two concurrent engagements. Any pushback is a red flag.
- **Safe-harbour language**: the bug-bounty policy must use the
  disclose.io SAFE HARBOUR text verbatim (or vendored legal review
  equivalent); do not improvise.
- **Insider-threat tests require care.** 108i's log-tamper test must
  be run by someone other than the primary maintainer — there is a
  conflict-of-interest aspect built in. If this phase is run by a
  solo maintainer, document the limitation explicitly in the scope.
- **Relation to prior phases:** 108 tests the controls that 14, 18,
  20, 34, 62, 200–205, 107 put in place. Findings that invalidate
  prior-phase claims are a normal outcome — update the prior-phase
  notes and risk register, don't quietly fix.
- **Budget honesty.** If the external pentest budget isn't available,
  say so in `EXTERNAL_ENGAGEMENT.md` and mark 108k DEFERRED — do not
  fake a report. A deferred external pentest with a public note is
  honest; a pencil-whipped one is a much bigger problem.
- **Out of scope of Phase 108:** full formal verification (next
  decade's problem), FIPS 140-3 validation (requires a lab and is
  a ~$150k engagement), FedRAMP 3PAO assessment. These are separate
  phases if the project ever goes there.
