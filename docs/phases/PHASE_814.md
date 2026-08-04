---
phase: 814
title: "Full-Spectrum Penetration Testing Programme — First Cycle"
status: PROPOSED
size: XL
created: 2026-08-04
audience: [security, developer, operations]
---

# Full-Spectrum Penetration Testing Programme — First Cycle

> **Umbrella phase.** Defines all 19 sub-phases (`814a`–`814s`). Sub-phase
> documents (`docs/phases/PHASE_814x.md`) are written **just before that
> sub-phase runs** — several depend on earlier output (814d's test plan is
> written against 814b's generated inventory; the remediation sub-phases are
> written against actual findings). A sub-phase whose spec below is sufficient
> to execute needs no separate document; one needing a test matrix, a fix spec,
> or a decision record does.

> **The method lives elsewhere, on purpose.**
> [`docs/security/pentest/PROGRAMME.md`](../security/pentest/PROGRAMME.md) is
> the durable, repeatable process. **This document is the first cycle's plan.**
> Phase docs get archived to `docs/phases/complete/` when they close; a process
> meant to run again and again cannot live in one. Where this document and
> `PROGRAMME.md` overlap, **`PROGRAMME.md` wins** — it is maintained; this is a
> snapshot of one cycle.

## Where each thing lives

| Artefact | Home | Lifetime |
|---|---|---|
| **The method** — passes, roles, templates, gates, cadence | `docs/security/pentest/PROGRAMME.md` | Permanent, amended each cycle |
| Rules of engagement (bands, ladder, stop conditions) | `PROGRAMME.md` §5–§6, restated in `RULES_OF_ENGAGEMENT.md` for a cycle that narrows them | Permanent |
| **This cycle's scope, targets, sub-phases** | This file | Archived when 814 closes |
| Attack-surface inventory | `docs/security/ATTACK_SURFACE.md` (generated) | Regenerated, drift-checked |
| Threat model | `docs/security/threat-model.md` | Permanent; this cycle updates it |
| Findings | `docs/security/findings.yaml` + register views | Permanent |
| Evidence / PoC artefacts | `docs/security/pentest/evidence/<date>/` | Gitignored, 12 months, local |
| Verification scripts | `docs/security/pentest/verify/<ID>/` → regression corpus | Cycle artefact → permanent |
| Campaign report | `docs/reports/<date>_PENTEST_CAMPAIGN.md` | Permanent |
| Recurring-work timetable | `docs/reference/MAINTENANCE_CALENDAR.md` | Permanent |

## Goal (plain language)

Every security assessment this project has run has been a **campaign**: someone
attacked a slice of the system, wrote a dated report, findings went into the
register. 94 canonical findings, 92 fixed. Four structural weaknesses:

1. **Coverage is accidental.** Nobody can say what has *never* been pentested
   without reading twenty reports. The answer (§3) is about a third of the
   shipped surface.
2. **It is not repeatable.** No RoE, no test range, no methodology mapping.
3. **Findings are written for the finder, not the fixer.** "SSRF in
   `webhooks.py`" is a to-do for someone who already understands it; a junior
   handed that fixes one call site and misses four.
4. **"Fixed" is self-asserted** — and the register proves it (below).

This phase runs the first cycle of a method that closes all four.

## The finding that reorders the work

The register currently holds **92 findings at `FIXED`, 0 at `VERIFIED`, 0 at
`CLOSED`.**

The machinery to go further exists and always has: `CLOSURE_VERIFICATION.md`
describes the `VERIFIED` → `CLOSED` promotion, `findings_register.py` has a
`promote-verified` command, and `REMEDIATION_WAVES.md` defines wave completion
as "every canonical ID has `status ≥ VERIFIED`". By the project's own
definition, **no remediation wave has ever completed** — across four waves and
94 findings.

All 92 do carry a `regression_test` path, and `verify-findings-green` really
does execute them. But nothing has ever demonstrated that any of those tests
*fails on revert*, which is the entire difference between a regression test and
a decoration.

Consequence for this plan: **814c re-verifies history before 814d starts
hunting new bugs.** A believed-fixed CRITICAL that quietly came back outranks a
fresh MEDIUM, and the tests already exist, so it is cheap.

## The three-pass model

Full definition: `PROGRAMME.md` §2. Summary — every finding passes through
three parties:

| Pass | Who | Output |
|---|---|---|
| **1 Find** | Tester | Finding written as a **junior-executable fix specification** |
| **2 Fix** | Implementer (may be a junior) | Fix + verification script **proven to fail before / pass after** |
| **3 Audit** | Auditor (≠ tester, ≠ implementer; fresh context) | Re-runs the **original attack**, hunts what the fix broke and what sits beside it |

## What changed since the last full campaign (2026-04-16)

Scoping input — these deltas justify re-testing cleared ground:

| Change | Why it matters to an attacker |
|---|---|
| Python proxy (`proxy.py`) deleted; Go `cmd/ja4pd` is the sole runtime | Every prior finding in `proxy.py` is moot; every Go-side assumption it backstopped is now unbacked |
| Phase 500 full-codebase bug hunt (17 findings) | Fixes never faced an independent adversarial pass |
| Go TAP/SPAN sensor (316/334/335/336/244) | New privileged component (packet capture, capabilities, seccomp) |
| Management image rebase to a low-CVE base (801) | New base image, package set, user/uid semantics |
| Decision-cache rework, key `clientIP\|JA4` + asymmetric TTLs (515/516) | Cache-poisoning and cross-client-confusion surface changed shape |
| Hard-block + fail-open guards (520/521, findings 0093–0096) | Fail-open/fail-closed boundaries moved; boundary bugs cluster where boundaries move |
| Redis ACL authentication fix (813) | The auth path to the data store is new code |
| CI automation: `pull_request_target` autofix with `contents: write`, scheduled renewal workflow, Dependabot nudger (812) | **Net-new CI attack surface with write permissions — never pentested** |
| Image-list derivation + git history rewrite (810/811) | Supply-chain and provenance assumptions changed |
| Multi-agent development with commit access, reading instruction files every session | **An injection surface nobody has tested** — see 814g |
| Phase 522's "not fully audited" backlog (was to become 523, never written) | 5 named, still-unanswered adversarial questions |

**Phase 523 is absorbed here** (owner-approved): its five items map to 814e
(OIDC `aud`/`iss`, WebAuthn origin), 814j (tarpit bounds) and 814k (analytics
stream input validation, inter-container pub/sub HMAC). 523 is marked `CLOSED`
in the manifest — the status the roadmap generator defines as
"abandoned/superseded", and the only terminal-absorbed status
`scripts/lint-phases.py` permits (`CANCELLED` is in `sync-roadmap.py`'s map but
absent from that linter's `ALLOWED_STATUSES`, so it would red the gate) — with
a summary pointing here, so the references in `PHASE_521.md` / `PHASE_522.md`
resolve instead of dangling.

---

## 1. Rules of engagement

Defined in `PROGRAMME.md` §5–§7 and instantiated by 814a as
`docs/security/pentest/RULES_OF_ENGAGEMENT.md`. This cycle adopts them
unchanged. The load-bearing points, so nobody has to go looking:

- **Green / Amber / Red bands.** Destructive testing happens only on the
  isolated range and the fork. The upstream repo and anything live are Red —
  reasoned about statically, never touched.
- **No third-party service is ever a target.** Their clients in our code are in
  scope; their services are not.
- **The de-escalation ladder** (L0 static → L4 permission probe) governs
  anything whose blast radius we do not already know — chiefly 814f/814g.
  Stop at the lowest level that answers the question; ambiguity resolves to
  stop; owner checkpoints after L1 and before L3.
- **Every workstream is time-boxed**, and "attempted X, could not achieve it,
  here is why" is a valid and valuable result.
- **CRITICAL findings go to the owner immediately**, not at report time.
- Evidence is gitignored, retained 12 months locally, referenced by SHA-256.

---

## 2. Threat model

`docs/security/threat-model.md` is the permanent artefact; 814b reconciles it
with what this cycle learns. The test-design view:

### 2.1 Assets, in priority order

1. **Availability and correctness of protected customer websites.**
2. **The security decision** — its integrity (force ALLOW) and its inverse
   (force BLOCK *for someone else*).
3. **Non-public state** — client IPs, JA4 corpora, ban lists, feeds, JWTs,
   Redis credentials, TLS material.
4. **The control plane** — Management API, dial, lists, attack/offense routes.
5. **The build and release chain**, including the agent fleet that writes to it.
6. **The host and its neighbours** — escape, lateral movement, the TAP sensor's
   elevated capabilities.

### 2.2 The product-specific inversion — read before scoring anything

CLAUDE.md's core asymmetry (false positives cost far more than false negatives)
inverts the usual pentest value ordering. For most products the crown jewel is
"I bypassed the WAF". Here that is **second place**.

> **The crown-jewel attack against JA4proxy is inducing false positives at
> scale** — making the proxy block, tarpit or ban legitimate browser traffic.
> A customer-website outage *caused by the security product*, triggerable by a
> remote unauthenticated attacker. `SEVERITY_RUBRIC.md` encodes this as clause
> **C-4**; hunt it actively rather than accepting it when it turns up.

It constrains **fixes** too: any remediation that makes a path fail *closed* is
a candidate C-4 regression, and pass 3 must flag it (`PROGRAMME.md` §11 Q2).

### 2.3 Attacker personas

| # | Persona | Position | Goal | Sub-phases |
|---|---|---|---|---|
| P1 | Internet scanner/bot | Public → HAProxy | Bypass scoring, reach backend | d, h, i, j |
| P2 | Targeted evader | Public | Score benign, or frame others | d, h |
| P3 | DoS actor | Public | Exhaust resources, or induce mass FP | d, j |
| P4 | Unauthenticated control-plane prober | Reaches :8090 | Auth bypass, config read/write | e, l |
| P5 | Low-privilege insider | Valid `auditor`/`analyst` credential | Escalate to `operator`/`admin` | e |
| P6 | Co-located container | Compromised sidecar on the Docker network | Forge control-plane messages, read state | k, m |
| P7 | Supply-chain actor | Can open a PR, publish a package, influence a base image | Code into a shipped artefact; steal a token | f |
| **P10** | **Instruction-injection actor** | **Can get text in front of an agent — a PR, an issue, a file an agent reads** | **Aim an agent that holds commit rights** | **g** |
| P8 | Downstream-consumer pivot | Consumes our output in their SIEM | Injection into *their* system via our fields | n |
| P9 | Curious operator | Legitimate console access | Accidental self-inflicted outage | d, o |

P8, P9 and P10 are routinely omitted from pentests and all three are real here.

### 2.4 Trust boundaries

Internet→HAProxy · HAProxy→ja4pd (PROXY protocol) · ja4pd→backend ·
ja4pd↔Redis · Management API↔Redis · Management API↔browser · Management
API↔IdP (OIDC/SAML/WebAuthn) · analytics↔Redis stream · TAP↔host network ·
proxy↔outbound enrichment · proxy↔webhook receivers · CI↔repository↔registry ·
**instruction files↔agent↔commit rights** · operator↔CLI↔backup files.

---

## 3. Target inventory

Generated properly in 814b. Seed inventory:

| # | Component | Path | Exposure | Last adversarial pass |
|---|---|---|---|---|
| 1 | Go proxy hot path | `cmd/ja4pd/`, `internal/proxy/` | Public (via LB) | 500, 2026-04 campaign |
| 2 | TLS/ClientHello parser | `internal/tls/` | Public, pre-auth | 137, 500; fuzz target exists |
| 3 | Fingerprint/JA4 | `internal/fingerprint/` | Public, pre-auth | 500 |
| 4 | Scoring & signals | `internal/security/` | Public-influenced | Partial |
| 5 | Decision cache | `internal/cache/` | Public-influenced | 515/516 (fix, not pentest) |
| 6 | Redis client | `internal/redis/` | Internal | 813 (fix), 201 |
| 7 | Config + hot reload | `internal/config/` | Operator/file/pubsub | 0089 still OPEN |
| 8 | Metrics/health | `internal/metrics/`, `internal/health/` | Loopback-bound | 118 |
| 9 | Webhook egress | `internal/webhook/` | Outbound | Partial (0074 OPEN) |
| 10 | Cluster/multi-DC | `internal/cluster/` | Internal | **Never** |
| 11 | Backup/restore | `internal/backup/`, `cmd/ja4p/backup.go` | Operator/file | 40 |
| 12 | Compliance/GDPR | `internal/compliance/`, `management/compliance/` | Authenticated | 801 (found a DSAR bug) |
| 13 | Wizard / CLI | `internal/wizard/`, `internal/cli/`, `cmd/ja4p/` | Operator | **Never** |
| 14 | TAP/SPAN sensor | `internal/tap/`, `cmd/ja4-tap/` | Host NIC, privileged | 334/335/336 (review, not attack) |
| 15 | Management API | `management/api/` (28 route modules) | :8090 | 110 (deferred), 522 (partial) |
| 16 | Management UI | `management/templates/`, `management/static/` | :8090 | 115 (deferred) |
| 17 | Analytics node | `src/analytics/` | Internal | **Never (523 backlog)** |
| 18 | Tarpit server | `src/tarpit/` | Public-facing sink | Partial (118f) |
| 19 | Threat-intel ingest | `src/security/`, TI feeds | Outbound fetch | 85 + adversarial tests |
| 20 | Redis data layer | schema-wide | Internal | 813 |
| 21 | Containers/compose | `deploy/docker/` + root (8 files) | Host | 73/75/303/232c |
| 22 | Helm chart | `deploy/charts/ja4proxy` | K8s | Smoke test only |
| 23 | Terraform / provider / Ansible | `deploy/terraform*`, `deploy/ansible` | Deploy-time | **Never** |
| 24 | HAProxy/Caddy config | `deploy/haproxy`, `deploy/caddy` | Public edge | Partial (2026-04) |
| 25 | SIEM/SOAR integrations | `deploy/integrations/` | Egress to third parties | **Never** |
| 26 | Monitoring stack | `deploy/monitoring`, `deploy/prometheus` | Loopback | 810 (CVE scan only) |
| 27 | CI/CD | `.github/workflows/` (15 workflows) | GitHub | **Never — now includes `pull_request_target` + `contents: write`** |
| 28 | Supply chain | SBOM, SLSA, signing, pinning | Release | 61/131/134 (posture, not attack) |
| 29 | Secrets & bootstrap | `deploy/secrets/`, `template.env`, boot guards | Deploy | 522 (partial) |
| 30 | Public endpoints | EDL route, docs site | Public | **Never** |
| 31 | **Agent instruction surface** | `CLAUDE.md`, `AGENTS.md`, `docs/phases/`, PR/issue text | Any PR author | **Never** |

Rows marked **Never** are the honest headline: roughly a third of the shipped
surface has had no adversarial attention at all.

---

## 4. Methodology mapping

| Standard | Used for | Where |
|---|---|---|
| **PTES** | Programme spine, incl. post-exploitation | `PROGRAMME.md` §4; 814m |
| **NIST SP 800-115** | Technique taxonomy, evidence handling | 814a, 814b |
| **OWASP WSTG v4.2** | Management UI/API test cases | 814e |
| **OWASP ASVS 4.0 L2** | Pass/fail checklist — the *coverage* measure | 814e |
| **OWASP API Security Top 10 (2023)** | BOLA, BFLA, resource consumption, SSRF | 814e |
| **OWASP Top 10 CI/CD Security Risks** | Pipeline testing (CICD-SEC-1…10) | 814f |
| **OWASP LLM Top 10 (LLM01 prompt injection)** | Agent instruction surface | 814g |
| **MITRE ATT&CK** | Persona TTPs, purple-team validation | 814o |
| **CIS Docker / Kubernetes Benchmarks** | Container + orchestration review | 814m |
| **SLSA v1.0** | Build-integrity claim verification | 814f |
| **CWE** | Finding classification | 814s |
| **Project rubric** (`SEVERITY_RUBRIC.md`) | **Authoritative severity** — overrides CVSS | all |

---

## 5. Sub-phases, in execution order

Nineteen sub-phases in four stages. **Letters are the execution order.**

> **Renumbered from the first draft** (which had 17, `a`–`q`): the retrospective
> sweep and the agent-injection workstream were inserted at the points where
> they belong in the running order rather than appended, so letters continue to
> mean "do them in this order". Old `c`–`q` shift accordingly.

### Stage 0 — Foundation (sequential; blocks everything)

#### 814a — Charter, RoE, test range, and the finding/verification harness
**Size:** MEDIUM. **Depends on:** nothing.

1. `docs/security/pentest/RULES_OF_ENGAGEMENT.md` — this cycle's instantiation
   of `PROGRAMME.md` §5–§7.
2. **The test range** — `make pentest-range`: ja4pd + Redis + management API +
   analytics + tarpit + mock backend + attacker container, on a Docker network
   with **no route to the internet** (`internal: true`), seeded with synthetic
   data. Attacker tooling pinned by version/digest and scanned like any other
   image (`PROGRAMME.md` §5.7). Range prints the **provenance block** (git SHA,
   image digests, config hash) at start-up (`PROGRAMME.md` §13).
3. **The harness**, so every later sub-phase produces final-format output from
   day one: the fix-spec template + `scripts/check_finding_spec.py`;
   `docs/security/pentest/verify/` layout; `make verify-finding` /
   `make verify-findings-all`; `scripts/verify_revert.sh`.
4. **Register schema + CI gating:** add a `found_against` provenance field; and
   **wire `make verify-findings` into CI** — it exists as a Makefile target but
   no workflow runs it, so the register's integrity rules (including
   "`regression_test` required once ≥ `FIXED`") are enforced only when someone
   remembers.

**Done when:** cold `make pentest-range` works from a clean checkout with
verified-zero egress; `make verify-finding` runs end-to-end against a planted
sample finding; `verify-findings` is a required check; RoE owner-accepted.

#### 814b — Reconnaissance, attack-surface baseline, threat-model reconciliation
**Size:** MEDIUM. **Depends on:** 814a.

Enumerate: listening sockets per container (compose *and* rendered Helm); every
FastAPI route with its auth dependency and required role; Redis key patterns
actually written vs `REDIS_SCHEMA.md`; outbound destinations reachable from
code; workflow triggers/permissions/secrets; env vars vs `template.env`;
published artefacts; **and the agent instruction surface** (which files agents
are told to read, and who can write to them).

**Deliverables:** `scripts/surface_inventory.py`; generated
`docs/security/ATTACK_SURFACE.md`; a CI drift gate; and a reconciliation pass
over `docs/security/threat-model.md` so tests derive from a current model.

**Done when:** the inventory generates cleanly and every row maps to a
sub-phase or to explicitly recorded coverage debt.

#### 814c — Retrospective closure sweep (re-verify what we believe is fixed)
**Size:** MEDIUM. **Depends on:** 814a. **Runs before new-bug hunting.**

Applies `PROGRAMME.md` §10.4 to the existing register: 92 findings sit at
`FIXED`, none has ever been independently verified, and no regression test has
ever been shown to fail on revert.

Method: for each finding in scope, run `scripts/verify_revert.sh` — check out
the fix commit's parent in a worktree, run the recorded `regression_test`,
assert it fails there and passes on `main`. Time-boxed by sampling: **all 14
CRITICAL, all 20 HIGH, a sample of MEDIUM/LOW**, prioritising anything whose
component has changed since the fix landed.

Three possible outcomes per finding, all useful: the test fails on revert
(genuine — promote toward `VERIFIED`); it passes on both (decoration — register
a finding against the test, and re-attack the original); or it cannot run at
all (bit-rotted — same treatment). Any finding whose original PoC now
reproduces on `main` is a **live vulnerability believed fixed** and goes
straight to wave 1.

**Done when:** every sampled finding has a recorded two-state result, and
promotions to `VERIFIED` are pushed through `findings_register.py`.

---

### Stage 1 — Assessment (814d–814o; order is value ranking; mutually parallel-safe)

Each produces findings **in fix-spec format** (`PROGRAMME.md` §9) and fixes
nothing (except trivial fixes taken inline, which still need a spec, a
verification test and a register entry).

#### 814d — Decision-logic and false-positive weaponisation
**Size:** LARGE. **Personas:** P2, P3, P9. **Highest-value sub-phase; no true
precedent in prior campaigns.**

- **Mass FP induction.** Shared-state poisoning (HyperLogLog per /24 and /48,
  beaconing sorted sets, return-visitor hashes, connection counters) from a
  spoofable or shared source; ban expansion against a CGNAT/VPN egress;
  threat-intel feed poisoning (an entry naming a major CDN); any automated path
  that can put a common browser JA4 on a blocklist; RDAP/ASN mis-attribution.
- **Cache abuse.** Under the 515/516 `clientIP|JA4` key: can one client seed a
  decision another inherits? Can ALLOW entries be evicted cheaply? Can BLOCK
  entries be made sticky past their short TTL? Does "local cache wins over a
  Redis block" hold under reload, eviction and Redis flap?
- **Scorer manipulation.** Which single signal moves the score most for the
  least attacker cost? Which can be driven to its extreme by attacker input
  alone? Behaviour at each action's exact threshold boundary.
- **Fail-open inversion.** Kill DNS, AbuseIPDB, RDAP, Redis, the feed fetcher —
  individually and combined — and observe the *decision*, not the log. Any path
  that fails closed is a C-4 finding.
- **Bypass exposure.** With `alpn_browser_bypass` off by default (0004),
  *measure* real-browser FP exposure at dial=100 against the Tranco corpus.
- **Dial semantics.** Is dial=0 non-blocking on **every** path — bypass BLOCKs,
  the 0094 hard-block path, ban expiry? One path that blocks at dial=0 is a
  shipped-default outage.

**Deliverable:** an FP-induction suite extending `tests/fp_corpus/`, plus a
documented "attacker cost to induce one blocked legitimate user" per vector.

#### 814e — Management API and UI
**Size:** LARGE. **Personas:** P4, P5. **Highest likely yield. Absorbs 523
items 1–2.**

Generated matrix: every route × every principal (`auditor`, `analyst`,
`operator`, `admin`, unauthenticated, expired, revoked, malformed,
wrong-audience token) — BOLA/BFLA done properly, not spot checks.

Targets: OIDC `aud`/`iss` binding (*is a validly signed token minted for a
different client accepted?*); WebAuthn `origin`/`rpId` binding and single-use
challenges; TOTP replay and rate limits; SAML assertion tampering, signature
wrapping, `RelayState` nonce reuse (**real signature tests, not mocked
verification** — the Phase 801 lesson); session handling (cookie flags,
fixation, logout invalidation, bearer rotation/revocation via `mgmt:token:*`);
CSRF on *every* mutating route; SSRF (`webhooks.py`, `threat_intel.py`,
`edl.py`, OIDC discovery) incl. DNS rebinding and redirect following; injection
(template, log, header, path traversal in file-serving/backup/snapshot routes,
command injection in `config_ops.py` / `snapshots.py`); **`attack.py` /
`attack_mode.py` / `offense.py`** — active response is a self-DoS and
third-party-harm surface: who can trigger it, what can it target, can an
attacker *aim* it (treat "attacker makes our offense module attack a third
party" as CRITICAL-class); business logic (lower role reaching a
higher-privileged effect via snapshot restore, config import, canonical-list
edit; is `management:policy_audit` bypassable, forgeable, truncatable?);
client-side XSS in every field rendering attacker-controlled data (SNI, JA4,
UA, country), CSP, vendored JS CVEs (`make scan-js`). Verify the
CLAUDE.md-mandated `test_pages.py` and `test_container_config.py` actually
cover every route as it stands today.

#### 814f — Supply chain and CI/CD
**Size:** LARGE. **Persona:** P7. **Largest never-tested surface, and it grew
this month.** Fork-only, under the de-escalation ladder; L0 first.

- **`pull_request_target` (`pin-table-autofix.yml`, Phase 812-C).** Base-repo
  permissions, `contents: write`, writes to a PR branch. Can PR *content*
  (workflow files, the pin table, branch name, commit message) influence the
  script? Can the `dependabot[bot]` actor check be spoofed? Does the
  git-worktree read path ever *execute* anything from the PR (hooks,
  `.gitattributes` filters, `.gitmodules`)? Can the push be aimed at a ref it
  shouldn't reach? Its design doc argues it is safe — try to prove it wrong.
- `${{ }}` script injection of untrusted context into `run:` blocks, across all
  15 workflows.
- `GITHUB_TOKEN` permission audit per workflow; secret exposure to fork PRs;
  `actions/cache` key collisions; artifact/release upload permissions; what can
  auto-merge without a human.
- Action pinning integrity (`test_workflow_pinning.py` + the new autofix).
- **SLSA provenance verification against a deliberately tampered artefact** —
  `slsa-verify.yml` exists; does it actually fail? SBOM completeness vs image
  contents; signing and verification on pull; digest vs tag pinning.
- Dependency confusion / typosquat exposure across `requirements*.txt`,
  `go.mod`, in-tree `node_modules`, vendored UI JS.
- Release path: can an unauthorised actor publish a release, chart or binary?

#### 814g — Agent instruction surface (prompt injection into the development pipeline)
**Size:** MEDIUM. **Persona:** P10. **Novel, untested, and specific to how this
project is built.** Fork-only, same ladder as 814f.

This repository is developed by an autonomous multi-agent fleet **with commit
access**, alongside a `pull_request_target` workflow holding `contents: write`.
Agents are *instructed* to read `CLAUDE.md`, `AGENTS.md`, `docs/phases/*` and
the findings register every session, and they encounter PR titles, issue
bodies, commit messages and code comments in the course of working. That makes
those files an **injection surface**: 814f asks whether a PR can influence the
*script*; this asks whether a PR can influence the *agent*.

Attacker questions:
- Can a PR that edits `AGENTS.md` / `CLAUDE.md` / a phase doc change the
  behaviour of a later agent session — and would review catch it? (Test the
  human/CI review path as seriously as the payload.)
- Can instructions planted in a file an agent is likely to read (a test fixture,
  a doc, a code comment, a `notes` field in `findings.yaml`) redirect it —
  toward exfiltrating a secret, weakening a check, or approving its own work?
- Does any agent-invoked automation consume untrusted text (PR body, issue text,
  commit message) as *instruction* rather than *data*?
- What is the actual blast radius: which credentials and permissions does an
  agent session hold, and what is the smallest change that would matter?
- Are there guardrails at all — and if a hostile instruction lands, is there any
  audit trail that would show it afterwards?

**Deliverable:** a written model of the agent trust boundary, findings for any
path where untrusted text reaches instruction context, and concrete
recommendations (provenance rules for instruction files, review requirements,
least-privilege for agent credentials). Maps to OWASP LLM01.

#### 814h — TLS/JA4 parser and protocol fuzzing
**Size:** LARGE. **Persona:** P2.

Record fragmentation across TCP segments and TLS records; malformed extension
lengths; duplicate extensions; GREASE; ECH; SNI edge cases (empty, IDN/punycode,
embedded NUL, over-long, mixed case); zero-RTT and resumption; reassembly-cap
envelope; the `unsafe.String` zero-copy in `internal/tls/parser.go` (F-400-01,
accepted risk — prove or disprove). **Feeds 814d:** JA4 canonicalisation
collisions — can two different clients be made to share a fingerprint, so
blocking one blocks the other? That is an FP weapon.

Tools: extend `internal/tls/fuzz_test.go` and `cmd/ja4pd/fuzz_test.go` with
structure-aware corpora and long runs; differential testing against a reference
TLS library. Crash inputs → gitignored evidence + minimised verification test.

#### 814i — Network and DMZ edge
**Size:** MEDIUM. **Personas:** P1, P2. Re-tests against Go what the 2026-04-16
campaign found in the Python era (PROXY smuggling L1-018, fragmentation bypass
L1-019).

Direct-to-ja4pd reachability bypassing HAProxy; PROXY header spoofing,
doubling, smuggling with an internal `dst`; XFF vs PROXY precedence;
trusted-CIDR correctness for IPv6, IPv4-mapped-IPv6, zone-scoped addresses; DMZ
scanning via the backend; RST/timeout oracles distinguishing blocked from
backend-down; and whether **any** path reaches the backend without a scoring
decision.

#### 814j — Resource exhaustion and availability
**Size:** MEDIUM. **Persona:** P3. Green band only. **Absorbs 523 item 4.**

Connection-slot and goroutine exhaustion attacked *around* the existing
regression tests; accept-loop semaphore; workChan saturation and its 0094
hard-block interaction; tarpit slots and per-IP caps; slowloris pre-handshake
holds vs read timeouts; reassembly buffer memory under many partial handshakes;
Redis backpressure and XADD with a dead consumer; unbounded growth in any Redis
structure; log-volume amplification; **Prometheus metrics cardinality explosion
via attacker-controlled label values**. Record resource curves, not pass/fail.

#### 814k — Data layer: Redis, analytics stream, backup/restore
**Size:** MEDIUM. **Persona:** P6. **Absorbs 523 items 3 and 5.**

Post-813, is Redis auth enforced for *every* client (proxy, management,
analytics, TAP, exporters, CLI)? Per-client least-privilege ACLs, or is
everyone effectively admin? Is Redis TLS negotiated *and verified*? **Can a
co-located container forge control-plane pub/sub** (dial change, list edit) —
is `pubsub_hmac_secret` required rather than optional (cross-ref 0080; 0074,
still OPEN, logs the signed payload)? Redis key-name injection via
attacker-controlled data (an SNI containing `:` or a newline) colliding
namespaces. Does the analytics stream consumer size-bound and type-check every
field? Are backups encrypted and integrity-checked, and is restore safe against
a tampered archive (in-archive path traversal, resource bomb, injected keys)?
Does GDPR purge/DSAR remove data everywhere it lives — stream, HLL, backups?

#### 814l — Cryptography and secrets
**Size:** MEDIUM.

JWT: algorithm confusion, `none`, key confusion, `kid` traversal, expiry
(verify the 0095 fix), clock skew, secret strength and the 0096 boot guard
(verify it cannot be bypassed by any `ENVIRONMENT` value). HMAC: constant-time
comparison everywhere (webhook, pub/sub, EDL), replay windows, nonce reuse.
TLS: management-listener and Redis TLS cipher/version lockdown, plus
re-verifying that the proxy path is pure passthrough with no TLS config of its
own. CSPRNG sourcing for every token/challenge/nonce. Secret exposure via logs,
metrics labels, error pages, crash dumps, the audit list; rotation story per
secret; and the **systemic committed-default sweep across all compose/env
templates** that Phase 522's self-audit flagged and never finished.

#### 814m — Container, host, orchestration, and assume-breach
**Size:** MEDIUM. **Persona:** P6.

CIS Docker Benchmark across all 8 compose files (they drift — Phase 810 proved
images had gone unscanned for months); per-container capability audit focused
on the privileged **TAP sensor** (`cap_drop: ALL` + explicit adds; seccomp
profile actually loaded rather than still the F-400-02 / JA4PROXY-2026-0081
placeholder from issue #244; `no-new-privileges`; read-only rootfs);
`docker-socket-proxy` allowlist tightness (a loose allowlist is root-equivalent
escape); Helm defaults against the CIS Kubernetes Benchmark; host port exposure
across every compose file (Phase 303 fixed this once — verify it stayed fixed).

**Explicit assume-breach exercise** (PTES post-exploitation, never done here):
start with a shell in each container in turn and measure how far you get —
which other services answer, which credentials are readable, what the blast
radius of one compromised sidecar actually is. Segmentation must be *proven*,
not assumed from the compose file.

#### 814n — IaC, deployment, and downstream-consumer egress
**Size:** MEDIUM. **Persona:** P8.

`checkov`/`tfsec`-class review of `deploy/terraform*` and the in-repo provider;
Ansible secret handling, `become`, remote-fetch trust; HAProxy and Caddy TLS,
header handling, PROXY emission, stats-page exposure; **downstream injection** —
every field JA4proxy emits (SNI, JA4, country, ASN, reason strings) tested
against each output format under `deploy/integrations/` (Splunk TA, Splunk SOAR,
QRadar, Sentinel, XSOAR, ServiceNow, Elastic — CEF/LEEF/JSON/CSV delimiter,
newline, quote and CSV formula injection), plus Loki/Promtail log injection, the
EDL endpoint's output, and webhook egress SSRF and receiver spoofing.

This is the sub-phase that protects *our users' other systems from us*. Never
done; its findings are ours to fix even though the impact lands elsewhere.

#### 814o — Purple team: detection and response validation
**Size:** MEDIUM. **Depends on:** 814d–814n.

Every attack executed in Stage 1 is also a detection test: did the proxy score
it, did a metric move, did an alert fire, did the runbook exist and work?
Deliverables: a TTP coverage matrix against `docs/security/ATTACK_MAPPING.md`
that validates or **downgrades each confidence label with evidence** (currently
self-assessed, labelled DRAFT); detection gaps filed as *detection* findings,
tracked separately from vulnerabilities; measured MTTR for one simulated
incident via `make measure-mttr`; runbook corrections.

---

### Stage 2 — Remediation (wave-triggered, not stage-gated)

#### 814p — Remediation wave 1–2 (CRITICAL + HIGH)
**Size:** LARGE. **Depends on:** findings existing — starts the moment 814c or
814d produces its first CRITICAL, without waiting for Stage 1 to end.

Executes the fix specifications. Each fix ships its verification script proven
**failing pre-fix, passing post-fix**, and stays within its hot-path benchmark
budget where applicable. Deliberately executable by an implementer who did not
find the bug — that is the test of whether the spec was written properly. Every
fix then enters 814r.

#### 814q — Remediation wave 3–4 (MEDIUM + LOW)
**Size:** MEDIUM. Same discipline. Also resolves the two currently-OPEN
findings — 0074 (LOW, pub/sub debug log includes the full HMAC-signed payload)
and 0089 (MEDIUM, hot config reload orphans async enrichment workers) — each
either fixed or formally accepted per `PROGRAMME.md` §12 (owner sign-off,
expiry date, re-review on the maintenance calendar).

---

### Stage 3 — Assurance and closure

#### 814r — Independent fix-audit and adjacent-bug hunt (pass 3)
**Size:** LARGE. **Depends on:** 814p / 814q, **per wave**, not once at the end.
Method: `PROGRAMME.md` §11.

Auditor is neither tester nor implementer (fresh session for agent runs). Four
questions per fix, answered in writing: **Q1** re-run the *original attack*,
then vary it one step; **Q2** did the fix break something — new error paths, nil
derefs, lock ordering, hot-path allocation (**run the benchmark**), changed
TTL/timeout/defaults, and above all **any new fail-closed behaviour** (candidate
C-4 regression); **Q3** is the same bug elsewhere (grep the class, record the
actual command *and its output*, cross-language); **Q4** is there a bug beside
it (callers, callees, sibling branches, same lifecycle stage elsewhere).

Q3/Q4 findings get their own canonical IDs and re-enter at Stage 2. **Two
re-audit iterations maximum** per finding, then owner escalation and a formal
accept-or-redesign decision.

#### 814s — Report, register closure, KPIs, cadence handover
**Size:** MEDIUM. **Depends on:** everything.

`docs/reports/<date>_PENTEST_CAMPAIGN.md` in the established format **plus a
coverage appendix** — what was tested, what was attempted and could not be
achieved (that is the assurance evidence and it is valuable), and what was not
reached. Regenerate `REMEDIATION_WAVES.md`; follow `CLOSURE_VERIFICATION.md`;
record KPIs as the next cycle's baseline (including audit escape rate and
adjacent-bug yield); confirm external-report intake routes into this lifecycle
(`INTAKE_RUNBOOK.md` → `PROGRAMME.md` §5.6); hand cadence to
`MAINTENANCE_CALENDAR.md`; resolve the empty `tests/security/` and README-only
`tests/fuzz/` directories either way — an empty security test directory implies
coverage that does not exist.

**And a retrospective on the method itself** (`PROGRAMME.md` §16): what did the
process miss, what cost more than it was worth, what was done informally that
should be written down. Amendments land in `PROGRAMME.md`'s change log.

---

## 6. Sequencing summary

| Sub-phase | Stage | Size | Depends on |
|---|---|---|---|
| 814a Charter/RoE/range/harness | 0 | MEDIUM | — |
| 814b Recon/inventory/threat model | 0 | MEDIUM | a |
| 814c **Retrospective closure sweep** | 0 | MEDIUM | a |
| 814d Decision-logic / FP weapon | 1 | **LARGE** | b |
| 814e Management API/UI | 1 | **LARGE** | b |
| 814f Supply chain / CI-CD | 1 | **LARGE** | b |
| 814g **Agent instruction surface** | 1 | MEDIUM | b |
| 814h TLS/parser fuzz | 1 | LARGE | b |
| 814i Network/DMZ | 1 | MEDIUM | b |
| 814j Resource exhaustion | 1 | MEDIUM | b |
| 814k Data layer | 1 | MEDIUM | b |
| 814l Crypto/secrets | 1 | MEDIUM | b |
| 814m Container/orchestration/assume-breach | 1 | MEDIUM | b |
| 814n IaC/integrations egress | 1 | MEDIUM | b |
| 814o Purple team | 1 | MEDIUM | d–n |
| 814p Remediation W1–2 | 2 | LARGE | first CRITICAL/HIGH |
| 814q Remediation W3–4 | 2 | MEDIUM | first MEDIUM/LOW |
| 814r Fix-audit (pass 3) | 3 | LARGE | p / q, per wave |
| 814s Report/closure/KPIs/retro | 3 | MEDIUM | all |

**Minimum viable first cycle**, if time is bounded: **814a, 814b, 814c, 814d,
814e, 814f**, plus **814p / 814r / 814s** for whatever they find. Charter +
inventory + re-verifying what we believe is already fixed + the crown-jewel FP
attack + the richest app surface + the largest untested surface, with the full
find-fix-audit loop closed. Everything else runs as quarterly deltas under the
same charter. This cut line is pre-agreed so scope creep cannot eat it.

---

## 7. Acceptance criteria

- [ ] RoE and runbook exist, owner-accepted; `PROGRAMME.md` is the referenced
      method.
- [ ] `make pentest-range` builds an isolated, egress-free target stack from a
      clean checkout and prints the provenance block.
- [ ] `make verify-findings` runs in CI as a required check.
- [ ] `docs/security/ATTACK_SURFACE.md` is generated, committed, drift-checked;
      every row maps to a sub-phase or recorded coverage debt.
- [ ] `docs/security/threat-model.md` reconciled with what this cycle found.
- [ ] **814c complete:** every sampled historical finding has a recorded
      two-state result; anything that fails is registered and remediated.
- [ ] Each executed sub-phase produces a written result — including "attempted
      X, could not achieve it, here is why".
- [ ] **Every finding has a complete fix specification**;
      `check_finding_spec.py` passes with zero exemptions.
- [ ] **Every fix has a verification script with the two-state proof recorded**,
      machine-checked by `scripts/verify_revert.sh`.
- [ ] **Every fix has been through pass 3** with all four questions answered in
      writing, by someone who neither found nor fixed it.
- [ ] Q3/Q4 findings registered as their own canonical IDs, same lifecycle.
- [ ] No finding exceeded the two-iteration audit limit without owner
      escalation and a recorded decision.
- [ ] Anything not fixed has an `EXCEPTIONS.md` entry with sign-off, expiry and
      a re-review date on the maintenance calendar.
- [ ] Every verified finding's test lives in the permanent regression corpus and
      runs in CI.
- [ ] The Phase 522 backlog (OIDC `aud`/`iss`, WebAuthn origin, analytics input
      validation, tarpit bounds, inter-container pub/sub HMAC) is answered.
- [ ] Both currently-OPEN findings (0074, 0089) resolved or formally accepted.
- [ ] The `pull_request_target` workflow and the agent instruction surface have
      each been assessed under the de-escalation ladder, with the level reached
      and the reason for stopping recorded either way.
- [ ] `ATTACK_MAPPING.md` confidence labels evidence-backed or downgraded.
- [ ] Campaign report published with a coverage appendix; KPIs recorded as the
      baseline; cadence live in `MAINTENANCE_CALENDAR.md`.
- [ ] **Method retrospective done and `PROGRAMME.md` amended** (or explicitly
      confirmed unchanged, with reasoning).
- [ ] `make test`, `make lint`, `make scan` green with zero warnings.
- [ ] No PoC artefact, crash corpus, credential or real client IP committed.
- [ ] Phase 523 marked `CLOSED` with a summary pointing here.

---

## 8. Risks and safeguards

| Risk | Safeguard |
|---|---|
| Testing takes down the dev host | Destructive work is Green-band only; Amber forbids exhaustion runs |
| A fuzzer reaches the internet | Range network `internal: true`; egress verified as an 814a done-criterion |
| Exploit material leaks via the repo | Evidence gitignored; only minimised, reviewed tests committed (Phase 811 precedent) |
| CI/agent testing damages upstream or burns secrets | Fork only; upstream is Red band; de-escalation ladder with owner checkpoints and a one-click kill switch |
| Escalating faster than understanding | Stop at the lowest level that answers the question; ambiguity resolves to stop; three-attempt time-box per level |
| A finding affects released artefacts | Stop condition → `CVD_POLICY.md`; explicit advisory decision recorded either way |
| Junior implementer half-fixes a finding | Spec mandates the complete ripple file list; pass 3 Q3 catches missed instances |
| A fix introduces a worse bug | Pass 3 Q2, with new fail-closed behaviour called out as a C-4 candidate and the benchmark run for hot-path fixes |
| Fix-audit loop never terminates | Two-iteration limit, then owner escalation and a formal accept-or-redesign decision |
| Self-verification bias | Auditor ≠ tester ≠ implementer; fresh session for agent runs; pass 3 re-runs the attack, not the fix's own test |
| Register pollution from over-eager reporting | Triage gate before an ID is allocated (`PROGRAMME.md` §8) |
| Accepted risks quietly become permanent | Expiry dates + monthly review row on the maintenance calendar |
| The programme becomes shelfware | KPIs, cadence, drift-checked inventory, and the method's own change log |
| Scope inflation swallows the schedule | The six-sub-phase minimum cycle in §6 is a pre-agreed cut line |

---

## 9. Out of scope

- **Any third-party service**: AbuseIPDB, MaxMind, Spamhaus, RDAP registries,
  PyPI, Docker Hub, GitHub's own infrastructure, and every SIEM/SOAR vendor
  product under `deploy/integrations/`. Their client code is in scope; their
  services are never targets.
- **Social engineering, phishing, physical security, wireless** — no
  organisation, office or staff to test, and no authorisation to test any.
- **Any live deployment carrying real traffic**, and any customer environment.
- **Denial-of-service against shared or hosted infrastructure**, including
  GitHub Actions. Exhaustion testing is range-only.
- **Pre-existing tech debt unrelated to a finding.** Remediation of *this
  cycle's* findings is in scope (814p/814q); a general refactor is not. "This
  subsystem needs redesigning" becomes a proposed phase.
- **Re-auditing already-closed findings whose component has not changed** — the
  "What changed" delta list is the scoping filter. (Distinct from 814c, which
  re-verifies the *test*, not the finding.)
- **New security features.** A recommendation to build X becomes a proposed
  phase.
- **Formal certification** (SOC 2, ISO 27001, CREST-equivalent). This is an
  internal programme; it produces evidence such an effort could use, and makes
  no certification claim.

---

## 10. Decisions (resolved 2026-08-04)

| # | Decision | Outcome |
|---|---|---|
| 1 | Full cycle vs minimum | **Full programme**, 19 ordered sub-phases; six-sub-phase minimum in §6 as the pre-agreed cut line |
| 2 | Phase 523 | **Subsumed** — `CLOSED` in the manifest, items mapped to 814e/814j/814k |
| 3 | Fork-based CI testing | **Approved** under the de-escalation ladder: L0 first, stop at the lowest level that answers the question, owner checkpoints after L1 and before L3, one-click kill switch |
| 4 | Evidence retention | 12 months, gitignored, local-only, referenced by SHA-256 |
| 5 | Phase number | **814**, sub-phases `814a`–`814s` in execution order |
| 6 | Findings must be junior-implementable | `PROGRAMME.md` §9 — fix-specification template with a completeness gate |
| 7 | Fixes must be provably fixed | `PROGRAMME.md` §10 — two-state proof, machine-checked against the fix commit's parent |
| 8 | Independent re-check for regressions and adjacent bugs | `PROGRAMME.md` §11 — pass 3, four questions, two-iteration limit |
| 9 | The method must be repeatable and improvable | Split out to `docs/security/pentest/PROGRAMME.md` with its own change log and a mandatory per-cycle retrospective (§16) |
| 10 | Recurring work needs a visible timetable | `docs/reference/MAINTENANCE_CALENDAR.md` — project maintenance + deployment operations, with "what breaks if skipped" per row |
| 11 | Historical findings need re-verification | **814c**, run before new-bug hunting: 92 `FIXED`, 0 ever `VERIFIED` |
| 12 | The agent pipeline is an attack surface | **814g** — new workstream, persona P10, OWASP LLM01 |
