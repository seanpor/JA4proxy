---
phase: 814
title: "Full-Spectrum Penetration Testing Programme"
status: PROPOSED
size: XL
created: 2026-08-04
audience: [security, developer, operations]
---

# Full-Spectrum Penetration Testing Programme

> **Umbrella phase.** This document is the programme charter and the definition
> of all 17 sub-phases (`814a`–`814q`). Sub-phase documents
> (`docs/phases/PHASE_814x.md`) are written **just before that sub-phase runs**,
> not up front — several of them depend on the output of earlier ones (814c's
> test plan is written against 814b's generated inventory, and the remediation
> sub-phases are written against actual findings). A sub-phase whose spec below
> is already sufficient to execute does not need its own document; one that
> needs a test matrix, a fix spec, or a decision record does.

## Goal (plain language)

Every security assessment this project has run so far has been a **campaign**:
someone attacked a slice of the system for a while, wrote a dated report, and
the findings were folded into `docs/security/findings.yaml`. That worked — 94
canonical findings, 92 fixed — but it has four structural weaknesses:

1. **Coverage is accidental, not designed.** Nobody can currently answer "what
   parts of this system have *never* been pentested?" without reading twenty
   reports. (The answer, from §3: about a third of the shipped surface.)
2. **It is not repeatable.** No rules of engagement, no standing test range, no
   methodology mapping. A new auditor starts from a blank page every time.
3. **Findings are written for the finder, not the fixer.** A report that says
   "SSRF in `webhooks.py`" is a to-do for the person who already understands
   it. A junior engineer handed that will fix one call site and miss four.
4. **"Fixed" is self-asserted.** The fixer writes the test that proves their
   own fix works. Nobody independently re-runs the original attack, and nobody
   checks whether the fix opened a new hole or whether the same bug lives three
   functions away.

This phase establishes a **programme** that closes all four: designed coverage,
a repeatable methodology, findings written as junior-proof fix specifications,
and a mandatory independent third pass before anything is called closed.

## The three-pass model (the spine of this programme)

Every finding moves through three passes, executed by **three different
parties** (different agents, or different sessions with no inherited context):

| Pass | Who | Question | Output |
|---|---|---|---|
| **1 — Find** | Tester | Can I break it? | Finding + reproduction + **junior-proof fix specification** (§8) |
| **2 — Fix** | Implementer (may be a junior) | Did I make the specified change everywhere? | Fix + **verification script proven to fail before / pass after** (§9) |
| **3 — Audit** | Auditor (≠ tester, ≠ implementer) | Is it *really* fixed, did the fix break anything, and is the same or a similar bug next door? | PASS → VERIFIED, or new findings that re-enter at pass 2 (§10) |

Pass 3 is the part most programmes skip and the part the owner explicitly asked
for. It is not a re-run of the fixer's test — that test encodes the *fixer's*
understanding of the bug. Pass 3 re-runs the **original attack**, then goes
looking for what the fix disturbed.

## Programme vs campaign — what this phase adds

| | Campaign (what we have) | Programme (what this adds) |
|---|---|---|
| Scope | Implicit, per-report | Written RoE + generated asset inventory, drift-checked |
| Methodology | Auditor's judgement | PTES / NIST 800-115 / OWASP WSTG+ASVS / ATT&CK |
| Coverage | Unknown | Surface-to-sub-phase matrix; gaps visible, not invisible |
| Environment | Ad hoc | Isolated test range with a build recipe (`make pentest-range`) |
| Finding quality | Prose describing a bug | Fix specification a junior can execute without asking questions |
| "Fixed" | Fixer's own test passes | Two-state proof + independent re-attack + adjacent-bug hunt |
| Repeatability | None | Cadence, runbook, KPIs |

The existing apparatus is **kept and reused** — `findings.yaml`,
`FINDINGS_REGISTER.md`, `SEVERITY_RUBRIC.md`, `REMEDIATION_WAVES.md`,
`CLOSURE_VERIFICATION.md` and `scripts/findings_register.py` are all
load-bearing and good. This phase wraps process around them.

## What changed since the last full campaign (2026-04-16)

Scoping input, not decoration — these deltas justify re-testing cleared ground:

| Change | Why it matters to an attacker |
|---|---|
| Python proxy (`proxy.py`) deleted; Go `cmd/ja4pd` is the sole runtime | Every prior finding located in `proxy.py` is moot; every Go-side assumption it backstopped is now unbacked |
| Phase 500 full-codebase bug hunt (17 findings) | Fixes never faced an independent adversarial pass |
| Go TAP/SPAN sensor (316/334/335/336/244) | New privileged component (packet capture, capabilities, seccomp) |
| Management image rebase to a low-CVE base (801) | New base image, package set, user/uid semantics |
| Decision-cache rework, key `clientIP\|JA4` + asymmetric TTLs (515/516) | Cache-poisoning and cross-client-confusion surface changed shape |
| Hard-block + fail-open guards (520/521, findings 0093–0096) | Fail-open/fail-closed boundaries moved; boundary bugs cluster where boundaries move |
| Redis ACL authentication fix (813) | The auth path to the data store is new code |
| CI automation: `pull_request_target` autofix with `contents: write`, scheduled renewal workflow, Dependabot nudger (812) | **Net-new CI attack surface with write permissions — never pentested** |
| Image-list derivation + git history rewrite (810/811) | Supply-chain and provenance assumptions changed |
| Phase 522's honest "not fully audited" backlog (was to become 523, never written) | 5 named, still-unanswered adversarial questions |

**Phase 523 is absorbed into this programme** (owner-approved): its five items
map to 814d (OIDC `aud`/`iss`, WebAuthn origin), 814h (tarpit bounds) and 814i
(analytics stream input validation, inter-container pub/sub HMAC). 523 will be
marked `CLOSED` in the manifest — the status the roadmap generator defines as
"abandoned/superseded", and the only terminal-absorbed status that
`scripts/lint-phases.py` actually permits (`CANCELLED` is in
`sync-roadmap.py`'s map but absent from that linter's `ALLOWED_STATUSES`, so
using it would red the gate) — with a summary pointing here, so the references
in `PHASE_521.md` / `PHASE_522.md` resolve instead of dangling.

---

## 1. Rules of engagement (RoE)

First deliverable of 814a: `docs/security/pentest/RULES_OF_ENGAGEMENT.md`.
Content decided here.

### 1.1 Authorisation

- Testing is authorised by the project owner (Seán Ó Ríordáin) against
  **infrastructure the project owns**: the local dev host, the isolated test
  range built in 814a, and **a fork of this repository** (owner-approved) for
  CI testing.
- **No third-party system is ever a target.** AbuseIPDB, MaxMind, Spamhaus,
  IANA RDAP, PyPI, Docker Hub, GitHub's own infrastructure, and every SIEM
  vendor product under `deploy/integrations/` are out of bounds. Their
  *clients* in our code are in scope; their *services* are not. Tests exercise
  them through `tests/mocks/`, per CLAUDE.md's rule that no test calls a real
  external API.
- No testing against any deployment carrying real user traffic.

### 1.2 Target bands

| Band | Targets | Permitted |
|---|---|---|
| **Green** — isolated range | Test-range containers (814a), the fork's own Actions | Everything: crash, exhaust, corrupt, escape attempts, destructive fuzzing |
| **Amber** — local dev stack | `docker-compose.poc.yml` on the dev host | Non-destructive only: recon, auth testing, config review. No exhaustion runs |
| **Red** — everything else | Any live deployment, any third-party service, the upstream repo and its CI | **No testing.** Reasoned about statically only |

### 1.3 The de-escalation ladder — "foot off the pedal early"

Applies to any testing where **we do not already know what the blast radius
is** — chiefly 814e (CI/CD, fork-based) but also first-time container-escape
and exhaustion work. The owner's instruction is the governing principle:
*ascend only as far as needed, and stop early rather than late.*

| Level | What it is | Precondition to enter |
|---|---|---|
| **L0** | Static review only. Read the workflows/configs; reason about the attack; write it up. No execution. | Always start here |
| **L1** | Fork created with **Actions disabled** and secrets scrubbed. Inventory what *would* run. Verify the fork is inert. | L0 complete; fork confirmed inert |
| **L2** | Actions enabled in the fork with **dummy secrets only**. Benign PR from a fork-internal branch. Observe normal behaviour. | L1 checkpoint reported to owner |
| **L3** | Adversarial *content* in a fork PR: crafted branch name, workflow file, pin-table entry, commit message. The actual test. | **Owner checkpoint required before entering** |
| **L4** | Push/permission probe — only if L3 demonstrates a plausible path that cannot be confirmed any other way. | Owner explicit go-ahead, per instance |

**Governing rules:**

- **Stop at the lowest level that answers the question.** The realistic
  expectation is that most questions die at L0/L1 — a workflow that
  demonstrably never interpolates untrusted context into a `run:` block does
  not need an L3 experiment to prove it.
- **Abort triggers — any one of these means stop, tear down, report:** any
  observable effect on the upstream repository; any GitHub rate-limit or abuse
  warning; any workflow run triggered in the upstream org; any real secret
  appearing anywhere; anything that would create noise for another maintainer;
  **anything ambiguous.** Ambiguity resolves to stop, not to "probably fine".
- **Kill switch:** Actions can be disabled in the fork in one click; the fork
  is deleted when 814e completes. The owner holds the same switch.
- **Checkpoints:** report to the owner after L1, and again before entering L3.
  No unattended escalation past L2.
- **Time-box:** if a level needs more than three attempts to produce a clear
  answer, that is a signal to descend and reason statically instead of
  escalating.
- **Never test GitHub's own infrastructure** — only our own workflow logic
  running on it.

### 1.4 Stop conditions (whole programme)

Halt and escalate to the owner on any of:

- Evidence of **pre-existing compromise** (unexpected process, unexplained
  outbound connection, tampered artefact) — that is incident response, not
  pentesting; preserve the range rather than resetting it.
- A finding affecting **users of released artefacts** (a shipped image,
  published chart, CLI release) rather than only this repo — triggers
  `docs/security/CVD_POLICY.md`, not the ordinary register flow.
- Any test that would reach outside Green/Amber, including accidentally (a
  fuzzer that starts resolving real domains).

### 1.5 Evidence and data handling

- PoC artefacts (packet captures, crash inputs, request logs) live under
  `docs/security/pentest/evidence/<campaign-date>/` — **gitignored**, retained
  locally **12 months**, referenced from findings by filename + SHA-256, never
  committed. A committed crash corpus is a ready-made exploit kit for a repo
  that ships a security product, and Phase 811 already had to rewrite history
  once to purge a binary.
- Minimised reproducers **are** committed — as verification tests (§9), the
  sanitised and reviewed form of the same information.
- No real client IPs, no fingerprint corpora from live traffic, no credentials
  in any report. Synthetic data only; `tests/fixtures/` and `fixtures/` are the
  source.

### 1.6 Reporting channel

Findings enter `docs/security/findings.yaml` via
`scripts/findings_register.py add` (which opens a GitHub issue), scored per
`SEVERITY_RUBRIC.md`. **Timelines in that rubric are internal best-effort
prioritisation targets, not SLAs** — consistent with `CVD_POLICY.md`, this
programme creates no external commitment on acknowledgement, triage or fix
times, and nothing in this document may be written as one.

---

## 2. Threat model

### 2.1 Assets, in priority order

1. **Availability and correctness of protected customer websites.** The worst
   outcome this product can produce is blocking real users at scale.
2. **The security decision** — its integrity (can an attacker force ALLOW?)
   and its inverse (can an attacker force BLOCK *for someone else*?).
3. **Non-public state** — client IPs, JA4 corpora, ban lists, threat-intel
   feeds, JWTs, Redis credentials, TLS material.
4. **The control plane** — Management API, dial, black/whitelists,
   attack-mode/offense routes.
5. **The build and release chain** — anything letting a third party get code
   into a shipped image.
6. **The host and its neighbours** — container escape, lateral movement, the
   TAP sensor's elevated capabilities.

### 2.2 The product-specific inversion — read before scoring anything

CLAUDE.md's core asymmetry (false positives cost far more than false negatives)
inverts the usual pentest value ordering. For most products the crown jewel is
"I bypassed the WAF". Here that is **second place**.

> **The crown-jewel attack against JA4proxy is inducing false positives at
> scale** — making the proxy block, tarpit or ban legitimate browser traffic.
> That is a customer-website outage *caused by the security product*,
> triggerable by a remote unauthenticated attacker. `SEVERITY_RUBRIC.md`
> already encodes this as clause **C-4**; the programme must hunt it actively,
> not merely accept it when it turns up.

This also constrains **fixes**: any remediation that makes a path fail *closed*
is a candidate C-4 regression and must be flagged in pass 3 (§10, Q2).

### 2.3 Attacker personas

| # | Persona | Position | Capability | Goal | Sub-phases |
|---|---|---|---|---|---|
| P1 | Internet scanner/bot | Public → HAProxy | Arbitrary TCP/TLS, high volume | Bypass scoring, reach backend | c, f, g, h |
| P2 | Targeted evader | Public | Crafts ClientHellos; reads our published signal docs | Score benign, or frame others | c, f |
| P3 | DoS actor | Public | Moderate resources | Exhaust resources, or induce mass FP | c, h |
| P4 | Unauthenticated control-plane prober | Reaches :8090 via misconfig/SSRF/foothold | HTTP | Auth bypass, config read/write | d, j |
| P5 | Low-privilege insider | Valid `auditor`/`analyst` credential | Authenticated API | Escalate to `operator`/`admin` | d |
| P6 | Co-located container | Compromised sidecar on the Docker network | Redis + pub/sub reachable | Forge control-plane messages, read state | i, k |
| P7 | Supply-chain actor | Can open a PR, publish a package, influence a base image | CI-triggerable | Code into a shipped artefact; steal a token | e |
| P8 | Downstream-consumer pivot | Cannot reach us; consumes our output | Reads our logs/webhooks/EDL in their SIEM | Injection into *their* system via our fields | l |
| P9 | Curious operator | Legitimate console access | Everything the UI allows | Accidental self-inflicted outage | c, m |

P8 and P9 are routinely omitted and both are real here: we ship SIEM
integrations carrying attacker-controlled strings (SNI, JA4) into other
people's systems, and we ship a dial an operator can turn to 100 on a bad
afternoon.

### 2.4 Trust boundaries to enumerate and test

Internet→HAProxy · HAProxy→ja4pd (PROXY protocol) · ja4pd→backend ·
ja4pd↔Redis · Management API↔Redis · Management API↔browser · Management
API↔IdP (OIDC/SAML/WebAuthn) · analytics↔Redis stream · TAP↔host network
stack · proxy↔outbound enrichment (DNS/AbuseIPDB/RDAP/feeds) · proxy↔webhook
receivers · CI↔repository↔registry · operator↔CLI (`ja4p`)↔backup files.

---

## 3. Target inventory (attack-surface enumeration)

Generated properly in 814b. Seed inventory from reading the tree:

| # | Component | Path | Exposure | Auth | Last adversarial pass |
|---|---|---|---|---|---|
| 1 | Go proxy hot path | `cmd/ja4pd/`, `internal/proxy/` | Public (via LB) | None by design | 500, 2026-04 campaign |
| 2 | TLS/ClientHello parser | `internal/tls/` | Public, pre-auth | None | 137, 500; fuzz target exists |
| 3 | Fingerprint/JA4 | `internal/fingerprint/` | Public, pre-auth | None | 500 |
| 4 | Scoring & signals | `internal/security/` | Public-influenced | n/a | Partial |
| 5 | Decision cache | `internal/cache/` | Public-influenced | n/a | 515/516 (fix, not pentest) |
| 6 | Redis client | `internal/redis/` | Internal | ACL+TLS | 813 (fix), 201 |
| 7 | Config + hot reload | `internal/config/` | Operator/file/pubsub | Mixed | 0089 still OPEN |
| 8 | Metrics/health | `internal/metrics/`, `internal/health/` | Loopback-bound | Token | 118 |
| 9 | Webhook egress | `internal/webhook/` | Outbound | HMAC | Partial (0074 OPEN) |
| 10 | Cluster/multi-DC | `internal/cluster/` | Internal | ? | **Never** |
| 11 | Backup/restore | `internal/backup/`, `cmd/ja4p/backup.go` | Operator/file | File perms | 40 |
| 12 | Compliance/GDPR | `internal/compliance/`, `management/compliance/` | Authenticated | RBAC | 801 (found a DSAR bug) |
| 13 | Wizard / CLI | `internal/wizard/`, `internal/cli/`, `cmd/ja4p/` | Operator | Local | **Never** |
| 14 | TAP/SPAN sensor | `internal/tap/`, `cmd/ja4-tap/` | Host NIC, privileged | n/a | 334/335/336 (review, not attack) |
| 15 | Management API | `management/api/` (28 route modules) | :8090 | JWT/OIDC/SAML/WebAuthn/TOTP/bearer | 110 (deferred), 522 (partial) |
| 16 | Management UI | `management/templates/`, `management/static/` | :8090 | Session+CSRF | 115 (deferred) |
| 17 | Analytics node | `src/analytics/` | Internal | n/a | **Never (523 backlog)** |
| 18 | Tarpit server | `src/tarpit/` | Public-facing sink | None | Partial (118f) |
| 19 | Threat-intel ingest | `src/security/`, TI feeds | Outbound fetch | Feed-dependent | 85 + adversarial tests |
| 20 | Redis data layer | schema-wide | Internal | ACL | 813 |
| 21 | Containers/compose | `deploy/docker/` + root (8 compose files) | Host | n/a | 73/75/303/232c |
| 22 | Helm chart | `deploy/charts/ja4proxy` | K8s | n/a | Smoke test only |
| 23 | Terraform / provider / Ansible | `deploy/terraform*`, `deploy/ansible` | Deploy-time | n/a | **Never** |
| 24 | HAProxy/Caddy config | `deploy/haproxy`, `deploy/caddy` | Public edge | n/a | Partial (2026-04) |
| 25 | SIEM/SOAR integrations | `deploy/integrations/` | Egress to third parties | Vendor | **Never** |
| 26 | Monitoring stack | `deploy/monitoring`, `deploy/prometheus` | Loopback | Mixed | 810 (CVE scan only) |
| 27 | CI/CD | `.github/workflows/` (15 workflows) | GitHub | `GITHUB_TOKEN` | **Never — now includes `pull_request_target` + `contents: write`** |
| 28 | Supply chain | SBOM, SLSA, signing, pinning | Release | n/a | 61/131/134 (posture, not attack) |
| 29 | Secrets & bootstrap | `deploy/secrets/`, `template.env`, boot guards | Deploy | n/a | 522 (0096, partial) |
| 30 | Public endpoints | EDL route, docs site | Public | Varies | **Never** |

Rows marked **Never** are the honest headline: roughly a third of the shipped
surface has had no adversarial attention at all.

---

## 4. Methodology and standards mapping

| Standard | Used for | Where |
|---|---|---|
| **PTES** | Overall programme spine | §1, §5, §11 |
| **NIST SP 800-115** | Assessment technique taxonomy, evidence handling | 814a, 814b |
| **OWASP WSTG v4.2** | Management UI/API test cases | 814d |
| **OWASP ASVS 4.0 L2** | Pass/fail checklist for the management app — the *coverage* measure | 814d |
| **OWASP API Security Top 10 (2023)** | BOLA, BFLA, unrestricted resource consumption, SSRF | 814d |
| **OWASP Top 10 CI/CD Security Risks** | Pipeline testing (CICD-SEC-1…10) | 814e |
| **MITRE ATT&CK** | Persona TTPs + purple-team validation of `ATTACK_MAPPING.md` | 814m |
| **CIS Docker / Kubernetes Benchmarks** | Container + orchestration config review | 814k |
| **SLSA v1.0** | Build-integrity claim verification | 814e |
| **CWE** | Finding classification (already used by `findings.yaml`) | 814q |
| **Project rubric** (`SEVERITY_RUBRIC.md`) | **Authoritative severity** — overrides CVSS, which does not know about the FP asymmetry | all |

---

## 5. Sub-phases, in recommended execution order

Seventeen sub-phases in four stages. **Letters are the execution order** —
"do them alphabetically" is a rule nobody can misread.

### Stage 0 — Foundation (sequential; blocks everything)

#### 814a — Charter, rules of engagement, test range, and the finding/verification harness
**Size:** M. **Depends on:** nothing.

Builds the machinery every later sub-phase depends on. Four deliverables:

1. `docs/security/pentest/RULES_OF_ENGAGEMENT.md` — §1 content, including the
   de-escalation ladder.
2. `docs/security/pentest/PROGRAMME.md` — standing charter: roles, cadence,
   bands, escalation, KPIs, how to run a cycle.
3. **The test range** — `make pentest-range` brings up an isolated stack
   (ja4pd + Redis + management API + analytics + tarpit + mock backend +
   an attacker container) on a Docker network with **no route to the internet**
   (`internal: true`), seeded with synthetic data. Container-strict per
   `AGENTS.md`: Python runs in the pinned tools image, never on the host.
4. **The finding + verification harness** (§8, §9): the fix-spec template, the
   `scripts/check_finding_spec.py` completeness gate, the
   `docs/security/pentest/verify/` layout, `make verify-finding`, and
   `scripts/verify_revert.sh`. **This lands in 814a, not at the end** — every
   assessment sub-phase must produce specs in the final format from day one,
   or they get retrofitted badly later.

**Done when:** a cold `make pentest-range` on a clean checkout produces a
working target stack with verified-zero egress; `make verify-finding` runs
end-to-end against a deliberately planted sample finding; RoE accepted by owner.

#### 814b — Reconnaissance and attack-surface baseline
**Size:** M. **Depends on:** 814a.

Replaces §3's hand-written table with a generated one, so surface drift is a
visible diff rather than a discovery three campaigns later.

Enumerate: listening sockets per container (compose *and* rendered Helm); every
FastAPI route with its declared auth dependency and required role; every Redis
key pattern actually written vs `REDIS_SCHEMA.md`; every outbound destination
reachable from code; every workflow's triggers/permissions/secrets; every env
var consumed vs `template.env`; every published artefact.

**Deliverables:** `scripts/surface_inventory.py`, generated
`docs/security/ATTACK_SURFACE.md`, and a lint target failing on drift between
generated and committed (same discipline `check_manifest.py` uses).

**Done when:** inventory generates cleanly; every row maps to a sub-phase or to
explicitly recorded coverage debt.

---

### Stage 1 — Assessment (814c–814m; order is value ranking, mutually parallel-safe)

Each assessment sub-phase produces findings **in fix-spec format** (§8). None
of them fixes anything (except trivial fixes taken inline, which still need a
spec, a verification test and a register entry).

#### 814c — Decision-logic and false-positive weaponisation
**Size:** L. **Personas:** P2, P3, P9. **This is the highest-value sub-phase in
the programme** and has no true precedent in prior campaigns.

Attacker questions:
- **Mass FP induction.** Shared-state poisoning (HyperLogLog per /24 and /48,
  beaconing sorted sets, return-visitor hashes, concurrent-connection
  counters) from a spoofable or shared source; automatic ban expansion against
  a CGNAT/VPN egress; threat-intel feed poisoning (a feed entry naming a major
  CDN); any automated path that can place a common browser JA4 on a blocklist;
  RDAP/ASN mis-attribution.
- **Cache abuse.** With the 515/516 key `clientIP|JA4`: can one client seed a
  decision another inherits? Can ALLOW entries be evicted cheaply (making the
  cache useless under load)? Can BLOCK entries be made sticky past their short
  TTL? Does "local cache wins over a Redis block" hold under reload, eviction
  and Redis flap?
- **Scorer manipulation.** Which single signal moves the score most for the
  least attacker cost? Which can be driven to its extreme by attacker input
  alone? Behaviour at the exact threshold boundary of each action
  (flag/rate_limit/tarpit/block/ban).
- **Fail-open inversion.** Kill DNS, AbuseIPDB, RDAP, Redis and the feed
  fetcher — individually and in combination — and observe the *decision*, not
  the log. Any path that fails closed is a C-4 finding.
- **Bypass exposure.** With `alpn_browser_bypass` off by default (0004),
  *measure* real-browser FP exposure at dial=100 against the Tranco corpus
  rather than asserting it.
- **Dial semantics.** Is dial=0 genuinely non-blocking on **every** path,
  including bypass BLOCKs, the hard-block path (0094) and ban expiry? One path
  that blocks at dial=0 is a shipped-default outage.

**Deliverable:** FP-induction suite extending `tests/fp_corpus/`, plus a
documented "attacker cost to induce one blocked legitimate user" per vector.

#### 814d — Management API and UI
**Size:** L. **Personas:** P4, P5. **Highest likely finding yield.**
**Absorbs 523 items 1 and 2.**

Systematic pass: every route × every principal (`auditor`, `analyst`,
`operator`, `admin`, unauthenticated, expired, revoked, malformed,
wrong-audience token) as a **generated matrix**, not spot checks — this is
BOLA/BFLA done properly.

Specific targets: OIDC `aud`/`iss` binding (*is a validly signed token minted
for a different client accepted?*); WebAuthn `origin`/`rpId` binding and
single-use challenges; TOTP replay and rate limits; SAML assertion tampering,
signature wrapping and `RelayState` nonce reuse (**real signature tests, not
mocked verification** — the Phase 801 lesson); session handling (cookie flags,
fixation, logout invalidation, bearer rotation/revocation via `mgmt:token:*`);
CSRF coverage of *every* mutating route; SSRF (`webhooks.py`,
`threat_intel.py`, `edl.py`, OIDC discovery URL) including DNS rebinding and
redirect following; injection (template, log, header, path traversal in
file-serving/backup/snapshot routes, command injection in `config_ops.py` /
`snapshots.py`); **`attack.py` / `attack_mode.py` / `offense.py`** — active
response is a self-DoS and third-party-harm surface: who can trigger it, what
can it target, can an attacker *aim* it (treat "attacker makes our offense
module attack a third party" as CRITICAL-class); business logic (can a lower
role reach a higher-privileged effect via snapshot restore, config import or
canonical-list edit? is `management:policy_audit` bypassable, forgeable or
truncatable?); client-side XSS in every field rendering attacker-controlled
data (SNI, JA4, UA, country), CSP correctness, vendored JS CVEs
(`make scan-js`). Verify the CLAUDE.md-mandated `test_pages.py` and
`test_container_config.py` actually cover every route as it stands today.

#### 814e — Supply chain and CI/CD
**Size:** L. **Persona:** P7. **Largest never-tested surface, and it grew this
month.** Runs under the §1.3 de-escalation ladder; fork-only; L0 first.

Attacker questions:
- **`pull_request_target` (`pin-table-autofix.yml`, Phase 812-C).** Runs with
  base-repo permissions and `contents: write`, writes to a PR branch. Can PR
  *content* (workflow files, the pin table, branch name, commit message)
  influence the script? Can the `dependabot[bot]` actor check be spoofed (fork
  PR, renamed branch, impersonating account)? Does the git-worktree read path
  ever *execute* anything from the PR (hooks, `.gitattributes` filters,
  `.gitmodules`)? Can the push be aimed at a ref it shouldn't reach? Its design
  doc argues it is safe — this sub-phase's job is to try to prove it wrong.
- Script injection via `${{ }}` interpolation of untrusted context (PR title,
  branch name, issue body) into `run:` blocks — across all 15 workflows.
- `GITHUB_TOKEN` permission audit per workflow; secret exposure to fork PRs;
  `actions/cache` key collisions (cache poisoning); artifact/release upload
  permissions; what exactly can auto-merge without a human
  (`dependabot-automerge.yml`).
- Action pinning integrity (`test_workflow_pinning.py` + the new autofix) — can
  a wrong SHA be smuggled in?
- **SLSA provenance verification with a deliberately tampered artefact** —
  `slsa-verify.yml` exists; does it actually fail? SBOM completeness vs image
  contents; image signing and verification on pull; base images pinned by
  digest vs tag.
- Dependency confusion / typosquat exposure for `requirements*.txt`, `go.mod`,
  in-tree `node_modules` and the vendored UI JS.
- Release path: can an unauthorised actor publish a release, chart or CLI
  binary?

#### 814f — TLS/JA4 parser and protocol fuzzing
**Size:** L. **Persona:** P2.

Record fragmentation across TCP segments and TLS records; oversized/undersized
extension lengths; duplicate extensions; GREASE; ECH; SNI edge cases (empty,
IDN/punycode, embedded NUL, over-long, mixed case); zero-RTT and resumption
paths; reassembly cap boundaries (`pentest_reassembly_cap_test.go` covers the
fixed case — attack its envelope); the `unsafe.String` zero-copy in
`internal/tls/parser.go` (F-400-01, accepted risk — prove or disprove);
**JA4 canonicalisation collisions** (can two different clients be made to share
a fingerprint, so blocking one blocks the other? — an FP weapon, feeds 814c).

Tools: extend `internal/tls/fuzz_test.go` and `cmd/ja4pd/fuzz_test.go` with
structure-aware corpora and long runs against the range; differential testing
against a reference TLS library; `tlsfuzzer`-style scripted handshakes. Crash
inputs → gitignored evidence dir + minimised verification test.

#### 814g — Network and DMZ edge
**Size:** M. **Personas:** P1, P2. Prior art: the 2026-04-16 campaign found
PROXY smuggling (L1-018) and fragmentation bypass (L1-019) here, both fixed in
the Python era. Re-test from scratch against Go.

Can a client reach ja4pd directly, bypassing HAProxy? Can PROXY headers be
spoofed, doubled, or smuggled through to the backend with an internal `dst`?
Does XFF/PROXY precedence resolve to the true client? Is the trusted-CIDR check
correct for IPv6, IPv4-mapped-IPv6 and zone-scoped addresses? Can the backend be
used to scan the DMZ? Does any RST/timeout pattern distinguish "blocked" from
"backend down" (an oracle for tuning evasion)? Is there **any** path reaching
the backend without a scoring decision?

#### 814h — Resource exhaustion and availability
**Size:** M. **Persona:** P3. Green band only. **Absorbs 523 item 4 (tarpit
bounds).**

Connection-slot and goroutine exhaustion (regression tests exist — attack
*around* them); accept-loop semaphore; work-channel saturation and its
hard-block interaction (0094); tarpit slot exhaustion and per-IP caps;
slowloris-style pre-handshake holds vs read timeouts; reassembly buffer memory
under many partial handshakes; Redis backpressure and XADD behaviour when the
stream consumer is dead (`pentest_xadd_backpressure_regression_test.go` covers
the fixed case — attack the envelope); unbounded growth in any Redis structure
(bans, beaconing sets, audit list); log-volume amplification (one cheap request
→ many expensive log lines or webhooks); **metrics cardinality explosion via
attacker-controlled label values** — a classic, rarely tested Prometheus DoS.
Record resource curves, not just pass/fail.

#### 814i — Data layer: Redis, analytics stream, backup/restore
**Size:** M. **Persona:** P6. **Absorbs 523 items 3 and 5.**

Post-813, is Redis auth enforced for *every* client (proxy, management,
analytics, TAP, exporters, CLI)? Are ACL rules least-privilege per client or is
everyone effectively admin? Is Redis TLS actually negotiated *and verified*
where configured? **Can a co-located container forge control-plane pub/sub**
(dial change, list edit) — is `pubsub_hmac_secret` required rather than
optional (cross-reference 0080; and 0074, still OPEN, logs the signed payload)?
Can key names be injected via attacker-controlled data (an SNI containing `:`
or a newline) to collide with another namespace? Does the analytics stream
consumer size-bound and type-check every field it reads? Are backups encrypted
and integrity-checked, and is restore safe against a tampered archive (path
traversal inside the archive, resource bomb, injected keys)? Does GDPR
purge/DSAR actually remove data everywhere it lives — stream, HLL, backups
included?

#### 814j — Cryptography and secrets
**Size:** M.

JWT: algorithm confusion, `none`, key confusion, `kid` traversal, expiry
handling (0095 fixed malformed-expiry — verify), clock skew, secret strength
and the boot guard (0096 — verify it cannot be bypassed by any `ENVIRONMENT`
value). HMAC: constant-time comparison everywhere (webhook, pub/sub, EDL
tokens), replay windows, nonce reuse. TLS: cipher/version lockdown on the
*management* listener and Redis TLS (the proxy path is passthrough and has no
TLS config of its own — verify that claim still holds). Randomness: every
token/challenge/nonce from a CSPRNG. Secrets: `deploy/secrets/` permissions,
`.env` handling, whether any secret can reach logs, metrics labels, error
pages, crash dumps or the audit list; rotation story for each; and
**committed-default detection across all compose/env templates** — Phase 522's
self-audit flagged this as systemic and it was never completed.

#### 814k — Container, host and orchestration
**Size:** M. **Persona:** P6.

CIS Docker Benchmark pass over all 8 compose files (they drift — Phase 810
proved images had drifted for months); capability audit per container with
focus on the **TAP sensor** (packet capture needs real privilege: verify
`cap_drop: ALL` + explicit adds, that the seccomp profile is actually loaded
and not still a placeholder — F-400-02 / JA4PROXY-2026-0081, issue #244 —
`no-new-privileges`, read-only rootfs); the `docker-socket-proxy` allowlist (a
loose allowlist is root-equivalent escape); network segmentation — *prove* the
analytics/management/monitoring networks cannot reach what they shouldn't;
escape attempts from each container in the Green band; Helm chart defaults
against the CIS Kubernetes Benchmark (securityContext, network policies, RBAC,
secrets as env vs mounted); host port exposure across every compose file (Phase
303 fixed this once — verify it stayed fixed).

#### 814l — IaC, deployment and downstream-consumer egress
**Size:** M. **Persona:** P8.

`checkov`/`tfsec`-class review of `deploy/terraform*` and the in-repo provider;
Ansible playbook review (secret handling, `become`, remote-fetch trust);
HAProxy and Caddy config review (TLS config, header handling, PROXY protocol
emission, stats page exposure); **downstream injection** — take every field
JA4proxy emits (SNI, JA4, country, ASN, reason strings) and test it against
each output format under `deploy/integrations/` (Splunk TA, Splunk SOAR,
QRadar, Sentinel, XSOAR, ServiceNow, Elastic — CEF/LEEF/JSON/CSV: unescaped
delimiters, newlines, `=`, quotes, CSV formula injection), plus log injection
into Loki/Promtail and the EDL endpoint's output; webhook egress SSRF and
receiver spoofing.

This is the sub-phase that protects *our users' other systems from us*. It has
never been done, and its findings are ours to fix even though the impact lands
elsewhere.

#### 814m — Purple team: detection and response validation
**Size:** M. **Depends on:** 814c–814l (it validates their attacks).

Every attack executed in Stage 1 is also a detection test. For each: did the
proxy score it? Did a metric move? Did an alert fire? Did the runbook exist and
work? Deliverables: a coverage matrix mapping executed TTPs to
`docs/security/ATTACK_MAPPING.md`, validating or **downgrading each confidence
label with evidence** (that mapping is currently self-assessed and labelled
DRAFT); detection gaps filed as *detection* findings, tracked separately from
vulnerabilities; a measured MTTR for one simulated incident via the existing
`make measure-mttr` harness; runbook corrections.

---

### Stage 2 — Remediation (wave-triggered, not stage-gated)

814n may start the moment 814c produces its first CRITICAL. It does **not**
wait for Stage 1 to finish.

#### 814n — Remediation Wave 1–2 (CRITICAL + HIGH)
**Size:** L. **Depends on:** findings existing, not on all assessment ending.

Executes the fix specs from §8. Each fix ships with its verification script
(§9) proven **failing before / passing after**. Explicitly designed to be
executable by an implementer who did not find the bug — that is the test of
whether the spec was written properly. Every fix then enters 814p.

#### 814o — Remediation Wave 3–4 (MEDIUM + LOW)
**Size:** M. Same discipline, lower priority. Also re-examines the two
currently-OPEN findings (0074 LOW, 0089 MEDIUM) — fix or re-justify as accepted.

---

### Stage 3 — Assurance and closure

#### 814p — Independent fix-audit and adjacent-bug hunt (the third pass)
**Size:** L. **Depends on:** 814n / 814o output. Runs **per wave**, not once at
the end. Full method in §10.

Auditor must be neither the tester nor the implementer. Four questions per fix
(is it really fixed / did the fix break something / is the same bug elsewhere /
is there a bug beside it). Output is either promotion to `VERIFIED` or new
findings that re-enter at Stage 2.

#### 814q — Report, register closure, KPIs, cadence handover
**Size:** M. **Depends on:** everything.

`docs/reports/<date>_PENTEST_CAMPAIGN.md` in the established format (Executive
Summary; per-finding Severity/Description/Impact/Location/PoC/Remediation; CVSS
recorded, rubric clause authoritative), **plus a coverage appendix** stating
what was tested, what was attempted and failed (that is the assurance evidence,
and it is valuable), and what was not reached. `REMEDIATION_WAVES.md`
regenerated; `CLOSURE_VERIFICATION.md` followed; KPIs (§11) recorded as the
baseline for the next cycle; cadence handed to the schedule in §12.

---

## 6. Sequencing summary

| Sub-phase | Stage | Size | Depends on | Parallel-safe with |
|---|---|---|---|---|
| 814a Charter/RoE/range/harness | 0 | M | — | — (first) |
| 814b Recon/inventory | 0 | M | a | — (second) |
| 814c Decision-logic / FP weapon | 1 | **L** | b | d–l |
| 814d Management API/UI | 1 | **L** | b | c, e–l |
| 814e Supply chain / CI-CD | 1 | **L** | b | c, d, f–l |
| 814f TLS/parser fuzz | 1 | L | b | c–e, g–l |
| 814g Network/DMZ | 1 | M | b | c–f, h–l |
| 814h Resource exhaustion | 1 | M | b | c–g, i–l |
| 814i Data layer | 1 | M | b | c–h, j–l |
| 814j Crypto/secrets | 1 | M | b | c–i, k, l |
| 814k Container/orchestration | 1 | M | b | c–j, l |
| 814l IaC/integrations egress | 1 | M | b | c–k |
| 814m Purple team | 1 | M | c–l | — |
| 814n Remediation W1–2 | 2 | L | first CRITICAL/HIGH finding | o |
| 814o Remediation W3–4 | 2 | M | first MEDIUM/LOW finding | n |
| 814p Fix-audit (third pass) | 3 | L | n / o, per wave | — |
| 814q Report/closure/KPIs | 3 | M | all | — |

**Minimum viable first cycle**, if time is bounded: **814a, 814b, 814c, 814d,
814e**, plus **814n / 814p / 814q** for whatever they find. That is charter +
inventory + the crown-jewel FP attack + the richest app surface + the largest
untested surface, with the full fix-verify-audit loop closed. The remaining
assessment sub-phases then run as quarterly deltas under the same charter.
This cut line is pre-agreed so scope creep cannot eat it.

---

## 7. Per-finding lifecycle

```
DISCOVERED ──▶ SPEC'D ──▶ REGISTERED ──▶ FIXED ──▶ SCRIPT-VERIFIED ──▶ AUDITED ──▶ CLOSED
   814c–m       §8         findings.yaml   814n/o        §9              814p       §10.5
                                              ▲                             │
                                              └───── new/adjacent finding ──┘
                                                     (max 2 iterations, then
                                                      escalate to owner)
```

A finding may not skip a state. `SCRIPT-VERIFIED` without `AUDITED` is exactly
the weakness this programme exists to remove.

---

## 8. Finding write-up standard — the junior-proof fix specification

**The requirement:** an implementer with little codebase knowledge must be able
to execute the fix correctly, completely, and without asking a question. Prose
describing a vulnerability does not meet that bar. Every finding is written to
this template, and `scripts/check_finding_spec.py` (814a) fails the gate if any
section is missing or empty.

Model to follow: the Phase 522 phase doc, which passed exactly this test — it
gave exact files, the buggy lines inline, the rule being enforced, a
step-by-step fix, the test with fixtures named, and a revert check.

```markdown
## <CANONICAL-ID> — <title>

**Severity:** <LEVEL> (rubric clause <C-n/H-n/M-n/L-n>)  **CWE:** <id>
**CVSS v3.1:** <vector>   **Lane:** <go-proxy|python-management|infrastructure>
**Discovered:** <date>  **Persona:** <Pn>  **Sub-phase:** <814x>

### 1. Where it is
`path/to/file.go:120-134` — current code, pasted verbatim:
    <the actual code as it exists today>

### 2. What is wrong
<Three sentences maximum. Plain language. No security jargon, no acronym
without expansion. The implementer must understand the bug, not just its name.>

### 3. Why it matters here
<Impact in THIS product's terms — which asset (§2.1), which persona reaches it,
and whether it is a false-positive risk (the expensive kind) or a bypass.>

### 4. Reproduce it
    <copy-pasteable commands against `make pentest-range`>
Expected output on the VULNERABLE build:
    <exact observable — the line, the status code, the timing, the metric>

### 5. The fix
Before / after:
    <the exact change, as a diff or before-and-after blocks>

**The invariant this restores:** <one sentence — e.g. "an unauthenticated
request must never reach the branch that reads Redis credentials">

**Copy this existing pattern:** `path/to/good_example.go:88` already does it
correctly — follow that shape rather than inventing a new one.

### 6. Every file that must change
<COMPLETE list. Stopping at the first file is THE most common failure mode.
Include the ripple: callers, test fixtures, config keys, REDIS_SCHEMA.md,
docs, the CHANGELOG fragment. Phase 522's role-default fix rippled through
~40 test call sites; that is the scale of ripple that must be pre-stated.>

| File | Change | Why it ripples |
|---|---|---|

### 7. Do NOT do this
<Enumerated wrong fixes that will look tempting. MANDATORY entry whenever
relevant: any fix that makes a path fail CLOSED violates the core asymmetry
(§2.2) and creates a C-4 regression. Say so explicitly and give the fail-open
alternative.>

### 8. Anticipated questions
<The "you might think X, but…" list. Pre-empt the three questions the
implementer will actually hit. Phase 522's self-audit section is the model.>

### 9. Verification (see §9)
- Test to create: `<exact path>`
- Command: `make verify-finding FINDING=<CANONICAL-ID>`
- Expected on unfixed build: FAIL (<exact assertion that fires>)
- Expected on fixed build: PASS
- Permanent home once verified: `<regression corpus path>`

### 10. Blast radius and rollback
<What breaks if the fix is wrong; how to back it out; whether it is
hot-reloadable or needs a restart; whether it changes any default.>

### 11. Definition of done
- [ ] Every file in §6 changed
- [ ] Verification script fails on the pre-fix commit and passes on the fix
- [ ] No new fail-closed path introduced (§7)
- [ ] Test moved into the permanent regression corpus
- [ ] `make test` and `make lint` green, zero warnings
- [ ] Register entry updated with `regression_test` path
```

**Gate:** a finding without a complete spec cannot leave the assessment
sub-phase. "The tester knew what they meant" is not a deliverable.

---

## 9. Verification scripts — the two-state proof

**The requirement:** every fix ships with an executable script that proves the
bug is gone. Not prose, not "the existing tests still pass".

### 9.1 Layout

```
docs/security/pentest/verify/<CANONICAL-ID>/
    README.md      # what this proves, and the two-state evidence
    test.go | test_*.py    # the assertion, where a unit test can express it
    verify.sh              # drives `make pentest-range`, where it cannot
```

### 9.2 Runner

- `make verify-finding FINDING=JA4PROXY-2026-XXXX` — runs one.
- `make verify-findings-all` — runs the campaign's whole set.
- Container-strict: Python inside the pinned tools image, Go natively, per
  `AGENTS.md`.

### 9.3 The two-state proof is mandatory

A verification script must be demonstrated to:

1. **FAIL** against the pre-fix build, and
2. **PASS** against the post-fix build.

Both outputs are pasted into the finding's §9 section. **A test that passes in
both states proves nothing** — and it is the single most common way regression
tests become decoration. `scripts/verify_revert.sh <finding-id>` (814a)
automates this: it checks out the fix commit's parent into a git worktree, runs
the verification script there, and asserts failure. This is the machine-checked
version of the house rule already used in Phase 522 ("both verified to fail on
revert").

### 9.4 Permanent home

The `verify/` directory is a **campaign-time artefact**. Once a finding reaches
`AUDITED`, its test moves into the standing regression corpus so CI keeps it
fixed forever:

- **Go:** `cmd/ja4pd/pentest_<slug>_regression_test.go` — 19 such files already
  exist and are the model; or `internal/<pkg>/..._test.go` for package-local
  issues.
- **Python:** `management/tests/test_<slug>.py`; `tests/adversarial/` for
  injection/SSRF/traversal classes (the `test_ti_feeds_*.py` files are the
  model).
- Fuzz seeds: minimised and sanitised into `testdata/`; raw crash corpora stay
  in the gitignored evidence directory.

Note `tests/security/` is currently **empty** and `tests/fuzz/` is README-only.
814q either populates them or deletes them — an empty security test directory
is worse than none, because it implies coverage that does not exist.

---

## 10. The third pass — independent fix-audit and adjacent-bug hunt (814p)

**The requirement, in the owner's words:** *another pass to ensure that it
really is fixed and that there isn't another issue opened by the fix, or just
beside it.*

### 10.1 Independence

The auditor is **neither the tester nor the implementer**, and for agent-run
work means a **fresh session with no inherited context** — an agent that
reviews its own fix will rationalise it. The auditor gets three inputs only:
the original finding spec, the fix diff, and the verification script.

### 10.2 The four questions (all four, every fix, answered in writing)

**Q1 — Is it actually fixed?**
Re-execute the **original attack from §4 of the spec**, not the verification
test. The test encodes the fixer's understanding of the bug; the PoC encodes
the attacker's. Then vary it: same attack one step to the left (different
encoding, different order, different field, different protocol version). A fix
that only stops the literal PoC is not a fix.

**Q2 — Did the fix break something?**
Adversarial review of the diff itself, looking specifically for: new error
paths that swallow or propagate wrongly; new nil dereference or unchecked type
assertion; new lock or lock-ordering (deadlock risk); new allocation or I/O on
the hot path; changed timeout, TTL or cache semantics; changed default; and —
**highest priority for this product** — **any new fail-closed behaviour**, which
is a candidate C-4 regression under §2.2 and must be registered as a new finding
rather than waved through.

**Q3 — Is the same bug somewhere else?**
Systemic-pattern search: grep for the *class*, not the instance. The Phase 522
model is the standard — after fixing one insecure role default, it grepped
every role fallback in `management/`. The audit must record **the actual
command run and its actual output**, not a claim that a search was done.
Cross-language too: a Go fix should prompt "does the Python side have this?"

**Q4 — Is there a bug beside it?**
Neighbourhood audit: the function's callers and callees; the sibling branches
of the same switch/if-chain; the other handlers in the same file; the same
lifecycle stage elsewhere (if the bug was in reload, check startup and
shutdown). Bugs cluster — the code around a defect was written by the same
person, at the same time, under the same misunderstanding.

### 10.3 Output

Per fix: **PASS** (promote to `VERIFIED`) or **FAIL** with new findings
registered via `findings_register.py`, which re-enter the lifecycle at Stage 2.
Q3/Q4 findings are registered as their own canonical IDs — never appended to
the original as an afterthought, or they lose their own verification and audit.

### 10.4 Loop limit

**Maximum two re-audit iterations per finding.** A third failure means the
problem is a design flaw rather than a bug: stop fixing, escalate to the owner
with the three attempts documented, and decide whether the design changes or
the risk is formally accepted in `docs/security/EXCEPTIONS.md`. This bound
exists so the fix-audit loop cannot become an infinite grind.

### 10.5 Closure

Only after `AUDITED` does the existing `CLOSURE_VERIFICATION.md` process apply
(`VERIFIED` → `CLOSED` after the 14-day cool-off). This programme adds a pass
*before* the existing closure machinery; it does not replace it.

---

## 11. Programme KPIs

Recorded in 814q, compared cycle over cycle:

| KPI | Definition | First-cycle target |
|---|---|---|
| Surface coverage | Inventory rows with ≥1 executed test / total | ≥ 80% |
| Never-tested rows | Rows still marked **Never** | 0 (tested, or explicit accepted debt) |
| Findings by severity | Count per rubric level | Baseline |
| Spec completeness | Findings passing `check_finding_spec.py` | 100% |
| Two-state proof rate | Fixes with a verification script proven to fail pre-fix | 100% |
| Audit escape rate | Fixes failing Q1 at pass 3 (were called fixed, weren't) | Baseline — this number is the programme's honesty check |
| Adjacent-bug yield | New findings raised by Q2/Q3/Q4 | Baseline (a high number early is a *good* sign) |
| Regression coverage | Findings ≥ FIXED with a test in the permanent corpus | 100% |
| Time-to-verified | Median days discovered → VERIFIED (internal target, **not an SLA**) | Baseline |
| Detection coverage | Executed TTPs producing a signal or alert (814m) | Baseline |

---

## 12. Programme governance

### 12.1 Cadence

| Rhythm | What runs | Trigger |
|---|---|---|
| **Continuous** | `make scan`, `make lint-sast`, `make lint-secrets`, fuzz smoke, the `pentest_*` corpus | Every PR (already in CI) |
| **Weekly** | Extended fuzz run against the range; surface-inventory drift check | Scheduled workflow |
| **Quarterly** | Delta assessment: sub-phases touching whatever changed that quarter | Scheduled + phase-close trigger |
| **Annual** | Full cycle, all sub-phases | Calendar |
| **Event-driven** | Targeted sub-phase re-run | New component, new trust boundary, new external interface, or a CRITICAL elsewhere in its class |

Cadence is a project *intention*, not a commitment to anyone outside the
project — per `CVD_POLICY.md` this document creates no external obligation.

### 12.2 Roles (hats, not headcount)

**Tester** (executes an assessment sub-phase, writes specs) · **Implementer**
(executes fixes; may be a junior — that is the design target) · **Auditor**
(pass 3; must be neither of the above) · **Owner** (accepts risk, approves RoE
and de-escalation levels, decides fix-vs-accept).

The independence rule is load-bearing: this repo's history shows agent-written
fixes being agent-verified, and Phase 801 found real bugs precisely because a
different pass looked again.

### 12.3 Coverage debt

Anything untested is recorded in `docs/security/ATTACK_SURFACE.md` as explicit
debt with a reason. **Unknown coverage is the failure mode this programme
exists to eliminate** — an honest "not tested" row is a success.

---

## 13. Acceptance criteria

- [ ] RoE (incl. de-escalation ladder), charter and runbook exist and are
      owner-accepted.
- [ ] `make pentest-range` builds an isolated, egress-free target stack from a
      clean checkout.
- [ ] `docs/security/ATTACK_SURFACE.md` is generated, committed, drift-checked
      in CI; every row maps to a sub-phase or to recorded coverage debt.
- [ ] Each executed sub-phase produces a written result — including "attempted
      X, could not achieve it, here is why", which is assurance evidence, not a
      blank.
- [ ] **Every finding has a complete fix specification (§8)**;
      `check_finding_spec.py` passes with zero exemptions.
- [ ] **Every fix has a verification script with the two-state proof recorded**
      (fails pre-fix, passes post-fix), machine-checked by
      `scripts/verify_revert.sh`.
- [ ] **Every fix has been through pass 3 (§10)** with all four questions
      answered in writing, by someone who neither found nor fixed it.
- [ ] Q3/Q4 findings are registered as their own canonical IDs and completed
      the same lifecycle.
- [ ] No finding exceeded the two-iteration audit limit without owner
      escalation and a recorded decision.
- [ ] Every verified finding's test lives in the permanent regression corpus
      and runs in CI.
- [ ] The Phase 522 backlog (OIDC `aud`/`iss`, WebAuthn origin, analytics input
      validation, tarpit bounds, inter-container pub/sub HMAC) is answered —
      each either "verified correct, here is the test" or a registered finding.
- [ ] Both currently-OPEN findings (0074, 0089) are resolved or re-justified.
- [ ] The `pull_request_target` autofix workflow has been assessed under the
      de-escalation ladder, with the level reached and the reason for stopping
      recorded either way.
- [ ] `ATTACK_MAPPING.md` confidence labels are evidence-backed or downgraded.
- [ ] Campaign report published with a coverage appendix; KPIs recorded as the
      baseline; cadence handed over.
- [ ] `make test`, `make lint`, `make scan` green with zero warnings.
- [ ] No PoC artefact, crash corpus, credential or real client IP committed.
- [ ] Phase 523 marked `CLOSED` in the manifest with a summary pointing here.

---

## 14. Risks and safeguards

| Risk | Safeguard |
|---|---|
| Testing takes down the dev host | Destructive work is Green-band only; Amber forbids exhaustion runs |
| A fuzzer reaches the internet | Range network `internal: true`; egress verified as an 814a done-criterion |
| Exploit material leaks via the repo | Evidence dir gitignored; only minimised, reviewed tests committed (Phase 811 precedent) |
| CI testing damages upstream or burns secrets | Fork only; upstream is Red band; de-escalation ladder with owner checkpoints and a one-click kill switch (§1.3) |
| Escalating faster than understanding | "Stop at the lowest level that answers the question"; ambiguity resolves to stop; three-attempt time-box per level |
| A finding affects released artefacts | RoE stop condition → `CVD_POLICY.md`, not the ordinary flow |
| Junior implementer half-fixes a finding | §8 mandates the complete file list and the ripple; §10 Q3 catches the missed instances |
| A fix introduces a worse bug | §10 Q2, with new fail-closed behaviour called out as a C-4 candidate |
| Fix-audit loop never terminates | Two-iteration limit, then owner escalation and a formal accept-or-redesign decision |
| Self-verification bias | Auditor ≠ tester ≠ implementer; fresh session for agent runs; pass 3 re-runs the attack, not the fix's own test |
| Programme becomes shelfware | KPIs + cadence + drift-checked inventory; "never tested" is a visible number |
| Scope inflation swallows the schedule | The five-sub-phase minimum cycle in §6 is a pre-agreed cut line |

---

## 15. Out of scope

- **Any third-party service**: AbuseIPDB, MaxMind, Spamhaus, RDAP registries,
  PyPI, Docker Hub, GitHub's own infrastructure, and every SIEM/SOAR vendor
  product under `deploy/integrations/`. Their client code is in scope; their
  services are never targets.
- **Social engineering, phishing, physical security, wireless** — no
  organisation, office or staff to test, and no authorisation to test any.
- **Any live deployment carrying real traffic**, and any customer environment.
- **Denial-of-service against shared or hosted infrastructure** (including
  GitHub Actions). Exhaustion testing is range-only.
- **Pre-existing tech debt unrelated to a finding.** Remediation of *this
  campaign's* findings is in scope (814n/814o); a general refactor is not. If a
  sub-phase concludes "this subsystem needs redesigning", that becomes a
  proposed phase, not scope creep here.
- **Re-auditing already-closed findings** whose component has not changed since
  closure — the "What changed" delta list is the scoping filter.
- **New security features.** A recommendation to build X becomes a proposed
  phase.
- **Formal certification** (SOC 2, ISO 27001, CREST-equivalent) — this is an
  internal programme. It produces evidence such an effort could use; it makes
  no certification claim.

---

## 16. Decisions (resolved 2026-08-04)

| # | Decision | Outcome |
|---|---|---|
| 1 | Full cycle vs minimum first cycle | **Full programme**, broken into 17 ordered sub-phases; the five-sub-phase minimum in §6 stands as the pre-agreed cut line if time runs short |
| 2 | Phase 523 | **Subsumed** — mark `CLOSED` in the manifest, summary pointing here; items mapped to 814d/814h/814i |
| 3 | Fork-based CI testing | **Approved**, with the de-escalation ladder of §1.3: L0 first, stop at the lowest level that answers the question, owner checkpoints after L1 and before L3, one-click kill switch |
| 4 | Evidence retention | 12 months, gitignored, local-only, referenced by SHA-256 |
| 5 | Phase number | **814**, sub-phases `814a`–`814q` in execution order |
| 6 | Findings must be junior-implementable | **§8** — mandatory fix-specification template with a completeness gate |
| 7 | Fixes must be provably fixed | **§9** — verification script with a mandatory two-state proof, machine-checked against the pre-fix commit |
| 8 | Independent re-check for regressions and adjacent bugs | **§10** — pass 3, independent auditor, four questions, two-iteration limit |
