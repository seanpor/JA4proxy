<!--
title: External Reviewer Panel — Scoping & Engagement Brief
audience: Security Leadership, Engineering Leadership, Procurement
last_reviewed: 2026-04-09
reviewer: Independent technical & cyber risk
companion_to: CYBER_RISK_REVIEW_2026-04-09.md
-->

# JA4proxy — External Reviewer Panel: Scoping & Engagement Brief

**Date:** 2026-04-09
**Author:** Independent technical & cyber risk (companion document to `CYBER_RISK_REVIEW_2026-04-09.md`)
**Purpose:** Define the external expert panel needed to take JA4proxy from "feature complete" to "external-audit ready and externally validated." For each recommended reviewer this document specifies *who* to engage, *what* to give them, *what* to ask them, *what they must produce*, *how to know they did the job*, and *what it should cost in time*.

---

## 0. Why an external panel at all

The internal cyber risk review (`CYBER_RISK_REVIEW_2026-04-09.md`) found JA4proxy to be architecturally disciplined and runtime-hardened, with the dominant residual risks sitting in the **build/operate/assure** layer rather than the data plane. That class of risk cannot be closed by the team that built the system, for three reasons:

1. **Implementer bias.** Compliance mappings, threat models, and "we tested this" claims always pass the implementer's own review. External reviewers exist to apply the *unfamiliar reader* test.
2. **Specialist depth.** Some surfaces (eBPF/XDP, cryptographic primitives, SLSA toolchains, GDPR case law) require people who do only that for a living. No engineering team carries that depth across all of them.
3. **Evidentiary weight.** A finding written by an independent third party is worth materially more to a procurement officer, an enterprise customer's CISO, or a regulator than the same finding written by the vendor.

The panel below is sequenced and tiered. **You do not need all thirteen reviewers.** The goal of this document is to let leadership make a budget-shaped decision: a Tier-1-only engagement is enough to materially de-risk the next release; a Tier-1 + Tier-2 engagement is enough to take the product to enterprise GA; Tier 3 is for sustaining and growth-phase concerns.

A guiding principle throughout: **engage reviewers with a question, not a scope.** "Audit our TLS parser" produces a checklist. "Can you make our TLS parser allow a connection it should block, or block one it should allow?" produces findings. Every brief below is written in that shape.

---

## Tier 1 — Engage First (release-blocking)

These four engagements close the four highest residual risks identified in the cyber risk review (F-1 through F-4) and cover both halves of the picture: data-plane adversarial assurance and operational/build assurance. They are independent and can run in parallel.

---

### Reviewer 1 — Independent network/TLS penetration tester

**Why this reviewer.** JA4proxy's entire trust model rests on parsing attacker-controlled bytes (the TLS ClientHello and the PROXY protocol header) before the handshake completes, then making an irreversible allow/block decision in single-digit milliseconds. The class of bug that breaks this product is *not* a memory-safety bug in Go — it is a **semantic** bug: a crafted handshake that produces the wrong JA4 string, a bypass-ladder confusion that lets a malicious client claim ALPN `h2` and skip scoring, or a PROXY-protocol header that lets the client spoof its source IP past the trusted-CIDR check. These bugs are invisible to fuzzing and to unit tests because the *individual* operations are correct; it is the *composition* that fails.

This reviewer must have personally broken a TLS-aware middlebox before. Cloudflare, Akamai, F5, Netscaler, Imperva, Sangfor, and Palo Alto have all shipped CVEs in this exact class within the last five years. You want someone who has hunted those.

**Who to engage.** A CREST-certified or equivalent penetration testing firm with a named TLS/network-protocol practice. Strong candidates: NCC Group's Cryptography Services, Trail of Bits' AppSec practice, Doyensec, Cure53, or an independent consultant with published CVEs against TLS middleboxes. **Avoid** generalist pentest shops whose deliverable will be a Burp Suite report against the management UI — that is the wrong target.

**What to give them (evidence pack).**
- A reference deployment built from `deploy/docker/docker-compose.poc.yml` with a clean Redis, all 14 signal modules enabled, and dial set to 100.
- The current `internal/security/pipeline.go` and `internal/tls/` source for whitebox review.
- The bypass ladder documentation from `CLAUDE.md` — explicitly highlight the ALPN browser bypass, the JA4 whitelist bypass, the mTLS bypass, and the country/Spamhaus blocks.
- The PROXY-protocol parser at `internal/proxy/proxy_protocol.go` and the trusted-CIDR configuration shape.
- The Phase 27 pentest report and remediation log, so the team is not paid to re-find known issues.
- A scoped break-glass account on the management UI for testing the control plane.
- Explicit rules of engagement: targets, allowed techniques, blackout windows, contact list, evidence-handling requirements.

**The questions they must answer.** Give them these as numbered prompts, not as a scope statement.

1. Can you cause the proxy to compute a JA4 string that does not match the actual handshake? (Test JA4/JA4S/JA4H/JA4X.)
2. Can you cause the proxy to ALLOW a connection that should have been BLOCKED at dial=100, by exploiting bypass-ladder ordering, ALPN advertisement, SNI manipulation, mTLS, or whitelist matching?
3. Can you cause the proxy to BLOCK a connection that should have been ALLOWED — i.e. force a false positive against a benign browser? (This is the asymmetric cost direction — far more important than the inverse.)
4. Given a trusted upstream CIDR, can a non-trusted client convince the proxy that it has a different source IP? Can you smuggle a second PROXY-protocol header? Can you exploit IPv6 normalisation differences (`::ffff:1.2.3.4` vs `1.2.3.4`)?
5. What happens with a maximally malformed ClientHello — oversized extensions, duplicate extensions, GREASE values, zero-length cipher suites, fragmented TLS records, TLS-in-TLS (proxy chains), QUIC initial packets misrouted to the TCP listener?
6. What happens if you send 10,000 connections that *each* take 30 seconds to send their ClientHello? (Slowloris against the handshake.)
7. Can you exhaust any in-process map, ranger, or HyperLogLog by crafting input?
8. Can you cause the analytics stream consumer to lose, duplicate, or misorder events by manipulating handshake timing?
9. Can you reach Redis, the analytics node, or the management UI from a position you should not be able to reach them from? (This tests Phases 71–75 zone isolation.)
10. Does the management UI have any of: IDOR on bypass list edits, CSRF on dial change, stored XSS in audit log fields, missing rate limit on login, weak session handling post-SSO, auth bypass via header injection?
11. Are there any timing oracles in the bypass ladder that let an external observer infer the contents of the JA4 whitelist or the country blocklist?
12. Can you exfiltrate the AbuseIPDB API key, the MaxMind licence, the Ed25519 signing key, or the Redis password from any reachable surface (logs, metrics, error messages, debug endpoints, container labels, environment dumps)?

**Deliverables they must produce.**
- Findings report with CVSS 3.1 vectors *and* the project-specific severity (a finding that causes a false positive on browsers is High regardless of CVSS, because it violates the project's central design invariant).
- Proof-of-concept artefacts (PCAP files, repro scripts) for every finding, runnable against a clean reference deployment.
- A narrative section: "Things I tried that didn't work" — this is *more* valuable than the findings list, because it tells you which attack surfaces have been actively probed versus merely untested.
- A short "what I would do next with another week" addendum — feeds your next engagement scope.

**How to know they did the job.**
- They tested both directions of the asymmetry (false positive *and* false negative), not just "can I block stuff."
- They engaged the bypass ladder, not just the scorer.
- They produced at least one finding that the existing test suite did not catch *and* one observation about an attack surface they could not break — both are signs of genuine effort.
- Their report references specific files and line numbers, not just "the TLS parser."

**Effort.** 3–4 person-weeks elapsed, ~10–15 working days of tester time. Budget for a retest pass after fixes.

---

### Reviewer 2 — Site Reliability / Production Readiness Reviewer (PRR)

**Why this reviewer.** Findings F-2 (no SLOs wired), F-3 (no DR drill), and F-9 (no production-grade health story for fail-open externals) are not security findings — they are operational findings — but they will produce the first customer-visible incident if not closed. The PRR exists to walk in cold and ask the questions an SRE on a 03:00 page deck will ask. The Google SRE book formalised this practice as "Production Readiness Review" and most mature organisations now run it as a gate before any service can serve real traffic.

The PRR is a uniquely high-leverage engagement because the reviewer's *deliverable is mostly questions*, not findings. The questions force the team to either produce the runbook or admit it doesn't exist — either outcome is progress.

**Who to engage.** An SRE with at least seven years in production traffic-tier services (CDN, WAF, load balancer, reverse proxy backgrounds are ideal). Ex-Google SRE, ex-Cloudflare, ex-Fastly, ex-AWS Frontend, ex-Stripe Foundation. This is a single-person engagement; do not hire a "consultancy" for this — you want one experienced human, not a deck.

**What to give them.**
- Read access to the entire repo.
- The current state of `docs/runbooks/`, `docs/PROJECT_STATUS.md`, the Phase 63 and 64 plans.
- The Prometheus metric list as currently emitted (`curl /metrics` from a running instance).
- The current Grafana dashboard JSON if any.
- Whatever incident history exists, even if it's "we have not had one yet" — that itself is a signal.
- An honest answer to "what do you think will break first?"

**The questions they must answer.** This list is deliberately uncomfortable.

1. **Show me the on-call rotation.** Who is paged? Through what tool? With what runbook link in the alert? If the answer is "we don't have one yet," that is finding #1.
2. **Show me the SLO error budget policy.** What happens to feature work when the budget is exhausted? Who decides? If there is no policy, the SLO is decorative.
3. **Show me the four most recent alerts that fired and what the responder did.** If there are no alerts, the system is either perfect or unobserved — it is always the second.
4. **Walk me through a Redis total loss.** What does the proxy do at minute 1, minute 10, hour 1, hour 6? Where is the runbook? Has anyone done this drill? When?
5. **Walk me through a single proxy instance OOM.** Does HAProxy notice within the SLO budget? Do existing connections terminate cleanly? Does state recover when it restarts?
6. **Walk me through a config push that contains a syntax error.** Does it roll back? Does it fail safe (refuse the bad config) or fail open (load nothing and revert to defaults)? Is the difference documented?
7. **Walk me through a config push that contains a *semantic* error** — e.g. someone whitelists `*` by accident. Does anything notice? How fast?
8. **Show me the capacity model.** What is the headroom at current peak? What QPS triggers the first alert? Has anyone load-tested to that number recently?
9. **Show me how a new operator gets read-only access.** How is offboarding done? Where is the audit log of access grants? (This is Phase 79 territory but should be exercised end-to-end.)
10. **Show me the dependency upgrade cadence.** When was the last MaxMind database refresh? When was the last threat-intel feed schema check? Who notices when AbuseIPDB changes a field name?
11. **Show me a single TLS certificate rotation, end to end, in a non-production environment.** Time it. That is your rotation MTTR.
12. **Show me what happens when the dial is changed from 0 to 100 in production for the first time.** What is the rollback path? What is the smallest reversible step? Is there a "10% traffic" mode?
13. **Show me the false-positive feedback loop.** When a customer complains "I was blocked," how does that complaint reach the team? How is it adjudicated? How is the resulting JA4 added to the whitelist? How is the change audited? How long does the loop take?
14. **What is the meaning of the Phase 63 FP-rate SLI in concrete numbers?** "FP rate < 2%" — 2% of what? Counted how? Over what window? If you cannot answer, the SLI is undefined.
15. **Where is the postmortem template?** Have you written a postmortem for an incident that did not happen, as a dry run? (This is a real SRE practice.)

**Deliverables.**
- A "go / no-go / conditional-go" recommendation for production at three deployment scales: pilot (single tenant, monitor mode), enterprise GA (multiple tenants, dial > 0), and high-traffic (>100k req/s).
- A prioritised gap list with effort estimates.
- A draft on-call runbook skeleton if one does not exist.
- A draft error budget policy.
- A specific recommendation on the Phase 63 metric rename: should it be done in one shot, or staged with dual emission?

**How to know they did the job.**
- They asked at least three questions you could not answer.
- Their report includes specific numeric targets (e.g. "TLS rotation MTTR must be < 15 minutes"), not adjectives.
- They identified at least one alert that should exist but does not.
- They challenged at least one assumption in the existing threat model with operational reasoning.

**Effort.** 2 weeks elapsed, ~6–8 working days. This is the cheapest high-impact engagement on the list.

---

### Reviewer 3 — Supply-Chain & Build-Integrity Specialist (SLSA practitioner)

**Why this reviewer.** Finding F-1 (Phase 61 PROPOSED) is the highest-severity open item. For an inline traffic security control, the integrity of the build pipeline is part of the trust boundary: the binary makes block/allow decisions on every TLS connection, so any compromise of the toolchain is equivalent to a compromise of every deployed instance, simultaneously. The SolarWinds, 3CX, XZ-Utils, and Codecov incidents are the threat model — and all four were undetectable from inside the affected organisation until well after the fact.

Engage this reviewer **before** Phase 61 starts coding, not after. The design choices in SLSA implementation (keyless vs. KMS Cosign, which transparency log, in-toto attestation predicate shape, SBOM tool, reproducible-build strategy for cgo dependencies) are very hard to reverse. A two-week design review here saves a six-month rework later.

**Who to engage.** Someone who has personally shipped SLSA Level 2 or higher in production, not someone who has read the spec. Strong sources: Chainguard staff or ex-staff, ex-Google Open Source Security Team, ex-GitHub Security Lab, the maintainers of `cosign`/`rekor`/`in-toto`, or a consultancy with named SLSA practice (Chainguard, Stacklok, Kusari). Avoid generalist DevSecOps consultancies — you will get a Snyk dashboard and a bill.

**What to give them.**
- The current build process: `Makefile`, `Dockerfile`s, `go.mod`/`go.sum`, `requirements.txt`, the way `bin/proxy` is currently produced, and any GitHub Actions or Jenkins pipelines that exist.
- The current artefact distribution story: where do images go, how do customers pull them, is there a current signing mechanism, what registry, what mirror story.
- The Phase 61 phase document.
- The dependency tree at the time of review (`go mod graph`, `pip-compile --output-file=- requirements.in`).
- An honest statement of the threat model: are you defending against an opportunistic attacker, a targeted attacker, or a nation-state? The answer changes the design.

**The questions they must answer.**

1. What is the right SLSA target level for this product, given its position in customer infrastructure? (My prior is L3, not L2, because the binary runs in the customer's traffic path.)
2. Cosign keyless (Sigstore + OIDC) versus Cosign with a hardware-backed KMS key — which fits the team's operational model? What happens when the OIDC provider is down on release day?
3. Which transparency log? Public Rekor, a private Rekor instance, both? Who monitors the log for unauthorised entries against your identity?
4. SBOM: CycloneDX or SPDX? At which build step is it generated? Is it generated *from* the build or *from* a separate scan (these produce different results)? How is the SBOM itself signed and distributed?
5. Reproducible builds: is `bin/proxy` reproducible byte-for-byte across two independent build hosts? If not, what is the smallest change that would make it so? (Go is unusually good here; this should be achievable.)
6. Action pinning: are all GitHub Actions pinned to commit SHA, or to tag? Who refreshes them? How is a malicious tag re-point detected?
7. Branch protection: required reviews, required status checks, required signed commits, required linear history, no force push, no admin override — which of these are configured, which are missing, and which are enforced cryptographically versus by policy?
8. Dependency pinning: `go.sum` is enforced by toolchain; `requirements.txt` should be enforced by hash. Is it? What about transitive Python dependencies?
9. Vendoring versus module proxy: is the Go build dependent on `proxy.golang.org` being up at release time? What is the fallback?
10. Secret material in the build pipeline: where do the Cosign key, the AbuseIPDB key, the registry credentials live? Are they scoped per workflow? Per environment? Audited?
11. What happens if a dependency is yanked between the developer's machine and CI? Between CI and the customer's pull?
12. The "XZ-Utils question": if a maintainer of one of your transitive Go dependencies were socially engineered into shipping a malicious release tomorrow, how long would it take you to notice, and what is your recall procedure?
13. The "Codecov question": if your CI's coverage upload tool were silently exfiltrating env vars for six months, how would you find out?
14. What is the minimum viable customer-side verification story? Can a customer write `cosign verify --certificate-identity-regexp=...` against your image and have it mean something?

**Deliverables.**
- A Phase 61 design review document, written *before* the team writes the workflow files.
- A specific Cosign / Rekor / SLSA toolchain recommendation with rationale.
- A draft GitHub Actions workflow (or equivalent for whatever CI you choose) that the team can adapt.
- A customer-facing verification snippet — the literal `cosign verify` command an enterprise customer should run before deploying.
- A list of dependencies that should be removed, replaced, or vendored on supply-chain-risk grounds.
- A recommendation on whether to maintain the Python prototype's separate build chain, or to gate it explicitly behind a "research only" build that does not produce signed artefacts.

**How to know they did the job.**
- The recommendation distinguishes between SLSA *levels*, not just "do SLSA."
- They challenged at least one default in the Sigstore stack with a reason.
- They examined the dependency graph, not just the build step.
- They produced something a customer can actually run on their side.

**Effort.** 2 weeks elapsed, ~8–10 working days. Plus 1–2 days of follow-up review after Phase 61 implementation.

---

### Reviewer 4 — Cryptography Reviewer

**Why this reviewer.** JA4proxy never terminates TLS, so it does not need a TLS-implementation review. But it *does* use cryptographic primitives in four places where bugs are subtle and consequences are forensic-grade:

1. **Ed25519 config signing** (Phase 35) — used to verify configuration integrity. A bug here means an attacker who reaches the config path can ship arbitrary policy.
2. **AES-256-GCM at-rest backup encryption** (Phase 40) — nonce reuse in GCM is catastrophic and almost always wrong on the first try.
3. **SHA-256 hash-chain audit log** (Phase 35) — provides forensic integrity for security-relevant events. Subject to truncation, rollback, and "anchoring" failure modes that are not obvious.
4. **HMAC signing on the Redis ACL path** (Phase 34) — protects against unauthorised Redis writes.

None of these are huge surfaces; each is a few hundred lines of code. The point of this engagement is that *each* of them, if subtly wrong, makes the security claims of the entire system meaningless — and they are exactly the surfaces an auditor will ask about and the team will not be able to answer with confidence without an external validation.

**Who to engage.** A named applied cryptographer, not a generalist security firm. NCC Group Cryptography Services, Trail of Bits' Cryptography practice, Cure53, ISARA, or an academic with publication record (e.g. someone in the lineage of Matthew Green, Thomas Pornin, Filippo Valsorda). The deliverable from a generalist firm here will be a list of TLS cipher suites and a billing surprise; do not engage one.

**What to give them.**
- The four call sites listed above, with file paths and a 1-paragraph description of *what each is meant to guarantee*.
- The Phase 34 and Phase 35 phase documents.
- The current key management story: where each key lives, how it is generated, how it is rotated, how it is destroyed, how it is recovered.
- The threat model assumptions about the adversary's position relative to each key.
- An honest statement: "we have not had this independently reviewed before, and we want a fresh read."

**The questions they must answer.**

1. **Ed25519 config signing.** Is the verification call site reachable before the signature is checked? Is there a path where the verification result is logged but ignored? Is the public key load path itself integrity-protected (or could it be swapped)? Is the signed payload canonicalised in a way that two semantically identical configs produce the same signature, *and* that an attacker cannot exploit non-canonicalisation to forge?
2. **AES-256-GCM at rest.** How is the nonce generated? Random, counter, derived? If random, what is the expected number of backups before nonce collision becomes non-negligible? Is the nonce stored alongside the ciphertext correctly? Is there a key derivation step (HKDF, Argon2) or is the user-supplied passphrase used directly? Is associated data (AAD) bound to file metadata?
3. **SHA-256 hash chain.** Is each entry's hash bound to the previous entry's hash *and* to a wall-clock or counter so that a truncation is detectable? Is the chain head published anywhere external, on any cadence, or is the chain entirely internal (and thus rewritable by anyone who can reach storage)? What happens at proxy restart — is the chain continuous or does it reset?
4. **Redis HMAC.** What key is used? Is it shared across all proxy instances? What is the rotation procedure? Is the HMAC computed over a canonicalised request, or over the raw bytes (and can an attacker exploit the difference)?
5. **Cross-cutting key management.** Where do these keys live in production? Filesystem, env var, KMS, HSM? Who can read them? How are they backed up — and is the backup itself encrypted with a different key (otherwise the chain is circular)?
6. **Random number generation.** Every primitive above depends on a CSPRNG. In Go this is `crypto/rand`. Is it used at every call site? Are there any uses of `math/rand` that should be `crypto/rand`?
7. **Constant-time comparison.** Anywhere a secret is compared, is `crypto/subtle.ConstantTimeCompare` used? Audit log entry equality, HMAC verification, signature verification, password/token comparison?
8. **Algorithm agility.** If Ed25519 is broken in five years (it won't be, but the question matters), how does the system migrate? Is there a versioned envelope around each signed/encrypted artefact?

**Deliverables.**
- A short report (10–20 pages) with one section per primitive, each section containing: the security goal as stated, the security goal as actually implemented, the gap, the recommendation.
- A specific yes/no on each primitive: "this is correctly implemented as of commit X" or "this has a finding of severity Y."
- A key management recommendation: where each key should live in a real customer deployment, with options for "small customer," "regulated customer," and "FedRAMP customer."

**How to know they did the job.**
- They referenced the actual byte layout of the on-disk artefacts, not just the API.
- They asked about the threat model, not just the algorithm.
- They distinguished "this is fine" from "this is fine but fragile."
- They produced at least one observation about a primitive *not* on the list above (they will find one).

**Effort.** 1.5–2 weeks elapsed, ~6–8 working days. This is a focused engagement; do not let it expand into a full code audit.

---

## Tier 2 — Engage Once Tier 1 Is Scheduled

These four reviewers cover specialist surfaces that matter for enterprise GA but are not release-blocking. They can be sequenced over the following quarter.

---

### Reviewer 5 — eBPF / XDP Specialist

**Why this reviewer.** Phase 35 introduced an XDP program for NIC-level blocking, plus a Redis-to-BPF sync sidecar. This is the **highest-privilege code in the system** — it runs in the kernel, in interrupt context, on every packet. Bugs in eBPF code are rare but catastrophic: a verifier-bypass means kernel RCE, a stuck loop means a hung interface, a map-fill means silently dropped traffic, and a sync race means stale block lists that either over-block (false positives, the worst outcome by the project's own asymmetry) or under-block (silent enforcement gap).

Most security firms cannot review eBPF properly. The kernel verifier rejects most bugs, which gives a false sense of safety; the bugs that *do* land are in the design, the maps, the sync semantics, and the failure modes.

**Who to engage.** Someone who has personally shipped XDP in production at scale. Cilium / Isovalent staff or alumni, Cloudflare's L4 team alumni, Meta's Katran contributors, or an independent consultant with public eBPF work (e.g. Quentin Monnet, Daniel Borkmann's lineage). For a one-off engagement, Isovalent's professional services group is the most direct route.

**What to give them.**
- The XDP program source.
- The Redis-to-BPF sidecar source.
- The map definitions (sizes, types, eviction policy).
- The Phase 35 design document.
- The graceful-fallback path and the conditions that trigger it.
- The Alertmanager rule for volumetric attack.

**The questions they must answer.**

1. Does the XDP program pass the verifier on the kernel versions you intend to support? On older LTS kernels? On hardened kernels (lockdown, SELinux enforcing)?
2. What is the worst-case CPU cost per packet? Have you measured under PPS attack?
3. What happens when the block-list map fills? Does it evict (and how — LRU, FIFO, random)? Does it refuse new entries? Does it fall through to the userspace path?
4. What is the consistency model between the Redis source of truth and the BPF map? How long is the sync lag under load? What happens during a sync sidecar restart? What happens during a Redis failover?
5. Can a malicious packet cause the XDP program to take an unusually slow path (cache miss, map miss, helper call) and thereby contribute to a DoS through XDP itself?
6. What is the failure mode if the XDP program is unloaded mid-connection? Mid-attack?
7. Is the program attached as `XDP_DRV`, `XDP_GENERIC`, or `XDP_OFFLOAD`? The choice changes both the performance and the safety story.
8. Are there any helper functions or kfuncs used that are gated behind specific kernel versions? How is that detected at load time?
9. Is there a userspace shadow of the BPF map that allows post-incident forensics? (You almost certainly want one.)
10. Can the program leak information through map contents readable by another process on the same host?
11. What is the test strategy? Unit test against `bpf_prog_test_run`? Integration against a veth pair? Production canary?

**Deliverables.** A focused report on the XDP program plus the sync sidecar. Specific recommendations on map sizing, sync cadence, fallback triggers, and observability of the BPF-layer enforcement decisions.

**Effort.** 1–1.5 weeks. ~5–7 working days.

---

### Reviewer 6 — Container & Linux Hardening Reviewer (adversarial)

**Why this reviewer.** Phases 34, 56, and 71–75 deliver an unusually disciplined container security model: seccomp, AppArmor, no-new-privileges, ephemeral filesystems, four-zone networks, non-root, cpuset pinning, no Docker socket. The team also ships `scripts/check-isolation.sh` to validate the model. This is genuinely strong on paper. The gap is that nobody has *adversarially* tried to escape it.

The container-hardening community has a small number of practitioners who do exactly this: try to escape from a constrained workload to the host, or from one zone to another. They will find things the team will not.

**Who to engage.** NCC Group's container security practice, or a named individual with container-escape research history: Brad Geesaman, Rory McCune, Felix Wilhelm (when available), Andrew Martin (Control Plane). For a smaller engagement, a senior consultant from a Kubernetes-focused security boutique (Control Plane, ARMO, Sysdig's professional services).

**What to give them.**
- A live reference deployment of `deploy/docker/docker-compose.poc.yml`.
- Root on the *host* (so they can verify what they are seeing from below, not just from inside the container).
- `check-isolation.sh` and the underlying expectations.
- The seccomp and AppArmor profiles.
- The network zone definitions.
- The Phase 71–75 phase documents.

**The questions they must answer.**

1. Can you escape from inside the proxy container to the host? To another container in the same zone? To another zone?
2. Can you reach Redis from a position you should not be able to reach it from?
3. Can you reach the management UI from the DMZ zone?
4. Is the Docker socket *actually* not mounted in any container? (`check-isolation.sh` claims this — verify it independently.)
5. Are the seccomp profiles minimal, or are they copies of the Docker default with a few additions? (The default is permissive enough that it is not really hardening.)
6. Does the AppArmor profile actually constrain anything that matters, or is it cosmetic?
7. Is the tmpfs /tmp / /var/run mount actually `noexec,nosuid,nodev`?
8. Is `read_only: true` actually preventing writes everywhere, including in places the application might want to write logs?
9. Can you cause the container to run as a different uid than 1000 by exploiting any entrypoint logic?
10. Is the cpuset pinning enforced by the kernel, or just by docker-compose declaration?
11. Are there any capabilities added back after `cap_drop: ALL`? Are they justified?
12. What happens when a container OOMs — does it restart cleanly? Does the restart re-apply all the hardening, or does some of it require a fresh `docker compose up`?
13. Is `check-isolation.sh` verifying the ground truth (kernel-visible state) or the configured intent (`docker inspect`)? These can diverge.
14. Are there any host-mounted volumes that allow a compromised container to write to host paths? (`geoip` is mentioned as a read-only mount — verify.)

**Deliverables.** A findings list with severity, plus a "things `check-isolation.sh` should also check" addendum that strengthens the team's own validation script.

**Effort.** 1 week. ~5 working days.

---

### Reviewer 7 — Privacy / GDPR Counsel (specialist, not generalist)

**Why this reviewer.** JA4proxy logs IP addresses, SNI strings, JA4 fingerprints, and decisions. **Every one of those is personal data under GDPR Article 4** when associated with a natural person, which they are by definition for non-bot traffic. The project has done good work on this — Phase 91 specifically remediated a long-standing broken `make gdpr-delete` and added an HLL-aware erasure path — but that history *itself* is a fact a regulator will care about, because it shows the erasure path was non-functional for an extended period.

This reviewer is **not** a security consultant. They are a lawyer or DPO with technical fluency. The engagement protects the team from a class of risk (regulatory action under GDPR Articles 5, 6, 17, 25, 32, and 33) that no amount of security testing addresses.

**Who to engage.** A privacy lawyer or DPO with hands-on GDPR experience and technical fluency, ideally someone who has handled an actual regulator interaction. Specialist firms: Hunton Andrews Kurth, Bird & Bird, Fieldfisher, Pinsent Masons. Independent DPOs with sector experience are also strong. **Avoid** general commercial counsel who will bill hours on Article 6 boilerplate without engaging the technical reality.

**What to give them.**
- `docs/compliance/GDPR_COMPLIANCE.md`.
- The actual schema of what is logged: which fields, where, with what retention, in which Redis structures, in which log streams, in which backups.
- The Phase 91 remediation history.
- The cross-border data flow story: where customers might deploy, where threat-intel feeds are based, where backups go.
- The current Data Processing Agreement (DPA) template, if one exists.
- An honest answer to: "what is the lawful basis you intend to rely on?"

**The questions they must answer.**

1. What is the lawful basis for processing IP addresses in the proxy's decision path? (Probably Article 6(1)(f) legitimate interest — but the legitimate interest assessment must be documented.)
2. Is the analytics stream's retention proportionate? What is the documented retention period? Is it enforced by the system, or by policy?
3. Is the Phase 91 erasure path sufficient under Article 17? Specifically: when an erasure request lands, does the team know everywhere that data lives — Redis (multiple data structures), backups, SIEM, analytics node, log aggregator, threat-intel feed providers? Does the erasure reach all of them?
4. The HyperLogLog erasure problem. HLL is a probabilistic structure; you cannot remove a specific element. Is the documented approach (presumably "rebuild from source after erasure") regulator-defensible?
5. Are the threat-intel feed providers (AbuseIPDB, GreyNoise, OTX, MISP, VirusTotal, ThreatFox) data processors or independent controllers under GDPR? Each has different contractual implications. Do you have DPAs with each?
6. Cross-border transfers: which feeds are non-EU? Standard Contractual Clauses in place? Schrems II transfer impact assessments?
7. Article 25 (privacy by design): is logging IP addresses actually necessary, or could the system function on a hashed/truncated IP for some signal modules? (Probably not, but the question must be asked and answered in writing.)
8. Article 32 (security of processing): does the current architecture meet the "appropriate technical and organisational measures" bar? (It almost certainly does — but the assessment must be on file.)
9. Article 33 (breach notification): is there a 72-hour notification runbook? Who triggers it? Who notifies whom?
10. Article 35 (DPIA): is a DPIA required for this product, given that it processes IP addresses at scale and makes automated decisions affecting natural persons? My prior is yes, and that the DPIA does not currently exist.
11. The "automated decision-making" question (Article 22): the proxy makes automated decisions that affect data subjects (it can block them). Article 22 has narrow exceptions and significant requirements. How does the team rely on which exception?
12. Customer-side responsibilities: which obligations are the customer's, which are the vendor's? Is this clear in the DPA template?

**Deliverables.**
- A privacy posture report with explicit Article-by-Article assessment.
- A DPIA template (or an actual DPIA) for the product.
- A list of contractual gaps with feed providers.
- A model DPA appendix that an enterprise customer can incorporate.
- A specific recommendation on the Article 22 question — this is the highest-leverage privacy risk for an automated-blocking product and is often missed.

**How to know they did the job.**
- They engaged with the *actual* logged fields, not the abstract.
- They produced something a customer's privacy team can use.
- They flagged the Article 22 question without prompting.

**Effort.** 2 weeks. ~5–7 working days of legal time. This is the most expensive hourly rate on the panel.

---

### Reviewer 8 — SOC 2 / ISO 27001 Pre-Audit Readiness Reviewer

**Why this reviewer.** The compliance mappings in `docs/compliance/iso27001-annex-a-mapping.md` and `docs/compliance/soc2-control-narrative.md` are unusually mature — but mappings written by the implementing team always pass the implementing team's review. Phase 84 is COMPLETE, Phase 101 (the second-review fixes) is PROPOSED, and the second-review delta itself is evidence that the mappings need an external eye. This engagement is **not** the actual SOC 2 / ISO 27001 audit. It is a *dry run* — cheaper to fail than the real one.

**Who to engage.** A pre-audit / readiness assessment practice from a recognised audit firm, run by people who *also* perform the real audits (so they know what their own colleagues will reject). Schellman, A-LIGN, Insight Assurance, Sensiba, Prescient Assurance, or a Big-4 risk advisory practice. The key qualifier: the firm must perform actual audits — pure consultancies will give you a checklist, not a regulator-shaped read.

**What to give them.**
- The full `docs/compliance/` tree.
- The phase manifest, with explicit pointers to which phases produced which control.
- The Phase 84 deliverables and the Phase 101 deferred items.
- A clear statement of which framework you intend to certify against first (SOC 2 Type 1, then Type 2? ISO 27001? Both? FedRAMP eventually?).

**The questions they must answer.**

1. For each control in the mapping, is the cited evidence *sufficient* — i.e. would it pass the auditor's evidence test, or is it cited but not actually demonstrable?
2. Are there controls in the framework that are *not* mapped at all? (There always are.)
3. Are there controls where the mapping is technically accurate but operationally hollow — e.g. "we have a policy" without "we have evidence the policy is followed"?
4. What is the right Trust Services Criteria scope for SOC 2 (Security only, or Security + Availability + Confidentiality + Processing Integrity + Privacy)?
5. What is the gap between "we have the control" and "we have a year of evidence the control was in place" — i.e. how long until a Type 2 attestation is achievable?
6. Which of the nine Phase 101 deferred items would block an audit, and which are cosmetic?
7. Are the CLOSED phases (24, 55) defensible to an auditor? "Closed without complete" is a flag.
8. Are the mappings consistent across frameworks? ISO 27001 and SOC 2 overlap heavily; if a control is described differently in the two documents, that is a finding.
9. Risk register: does one exist? Is it maintained? Is risk treatment documented?
10. Vendor management: do you have DPAs/DPIAs for the third-party services you depend on (Redis, MaxMind, AbuseIPDB, etc.)?
11. Change management: is the phase / branch / merge model auditable? Can you produce evidence of who approved each phase?
12. Access reviews: SOC 2 requires periodic access reviews. Do they happen? Are they evidenced?
13. Incident management: have any incidents occurred? If yes, were postmortems written, evidenced, and remediated?
14. Business continuity: does the BCP cover the scenarios SOC 2 expects? (See also Reviewer 2 and Phase 64.)

**Deliverables.**
- A gap assessment against the chosen framework(s), with each gap categorised as "blocking," "high," "medium," "cosmetic."
- A remediation roadmap with effort estimates and the order of operations.
- A specific recommendation on framework sequencing (SOC 2 first vs. ISO 27001 first vs. parallel).
- A draft of any policies that are missing entirely.

**How to know they did the job.**
- They produced findings the team did not already know about.
- They distinguished evidence that exists from evidence that is documented.
- They engaged with the actual control implementations, not just the mapping documents.

**Effort.** 3–4 weeks. ~10–15 working days.

---

## Tier 3 — Engage When Relevant

These five reviewers address sustaining-phase concerns. They do not block release; they make the difference between a product that ships and a product that thrives.

---

### Reviewer 9 — Threat-Intelligence Feed Specialist

**Why.** Phases 23, 53, 58, 59 integrate AbuseIPDB, GreyNoise, OTX, MISP, VirusTotal, ThreatFox. Each has different licence terms, different data quality characteristics, different failure modes, different false-positive histories, and different commercial-redistribution rules. The team has done well to wire them with circuit breakers and a health monitor — but the *content* of the feeds, and the legal shape of redistributing decisions derived from them, has not been independently reviewed.

**Who.** An independent TI specialist with vendor-side experience. Team Cymru alumni, Recorded Future alumni, or an independent like John Bambenek. Avoid the feed vendors themselves — they will recommend their own feed.

**What to give them.** The current feed configuration, the licence agreements, the way feed signals are weighted in the composite scorer, and the false-positive corpus from Phase 46.

**Questions.**
1. Are the licence terms compatible with redistributing decisions derived from the feeds in a commercial product?
2. Which feeds are known to have systematic false positives? Against which populations?
3. Which feeds have been observed to be poisoned in the past?
4. Is the weighting in the composite scorer defensible given the relative quality of the feeds?
5. Are there better feeds for specific signal categories that are missing from the integration list?
6. How fresh is each feed? What is the right refresh cadence?
7. Are there feeds that should be removed because they are noise?

**Deliverables.** A feed-by-feed scorecard, a licence compatibility matrix, and a recommendation on weights.

**Effort.** 1 week.

---

### Reviewer 10 — Anti-Bot / Fraud Domain Reviewer

**Why.** JA4 fingerprinting lives next door to the commercial anti-bot industry. The people who operate Akamai Bot Manager, Cloudflare Bot Management, DataDome, Kasada, hCaptcha, and Imperva Advanced Bot Protection know things the JA4 research community does not — specifically, which JA4 patterns the residential-proxy networks (Bright Data, Oxylabs, IPRoyal) have already learned to mimic, and which fingerprints are about to become useless. This is product validation, not security per se, but it directly affects the FP-rate SLI and the long-term value of the JA4 signal.

**Who.** A senior engineer or researcher from the anti-bot industry, preferably between roles. The community is small; one well-targeted introduction is worth more than a procurement search.

**What to give them.** The signal scoring weights, the JA4 whitelist policy, and the FP corpus.

**Questions.**
1. Which signal modules duplicate work the customer's upstream WAF or CDN already does?
2. Which JA4 patterns are residential-proxy-network mimicked today, and which are about to be?
3. Is the JA4X signal carrying its weight, or is it noise?
4. What is the realistic shelf-life of the current scoring before it needs retuning?
5. What signal would you add that JA4proxy is missing?
6. What is the right FP corpus size for a Tranco-top-10k regression test? (The current target is "Tranco top 10k"; 10k may be too small.)

**Deliverables.** A short memo. This is not a multi-week engagement.

**Effort.** 2–3 days.

---

### Reviewer 11 — FinOps / Capacity Reviewer

**Why.** Inline traffic devices have asymmetric cost models: every connection costs CPU, every signal costs an external API call, every analytics event costs Redis stream storage. Phase 86 (Observability & Capacity Planning) is PROPOSED. A FinOps reviewer can usually save more money than the engagement costs.

**Who.** A FinOps practitioner with infrastructure (not just cloud-bill) experience. The FinOps Foundation maintains a practitioner directory.

**Questions.**
1. What is the per-connection cost in CPU-seconds, Redis operations, external API calls, log bytes, and storage?
2. What is the AbuseIPDB quota economics — at what QPS do you hit the daily quota, and what happens then?
3. What is the MaxMind refresh strategy and its bandwidth cost?
4. What is the Redis memory growth model under sustained load?
5. What is the analytics stream retention cost?
6. Where would a 10× traffic growth break the cost model first?

**Deliverables.** A capacity model spreadsheet and a list of cost-shaped optimisation opportunities.

**Effort.** 1 week.

---

### Reviewer 12 — Open-Source Programme Office / Licence Reviewer

**Why.** With ~30+ Python deps, a Go module graph, MaxMind data, RedisBloom, pytricia, the threat-intel feed clients, and the project's own licence (LICENSE in repo root), there is a non-trivial licence compatibility surface. One pass from an OSPO-style reviewer is enough to surface anything strongly copyleft or commercially incompatible.

**Who.** Tidelift, FOSSA, Snyk Licence, or an OSPO-experienced consultant.

**Questions.**
1. Are any dependencies under licences incompatible with the project's distribution model?
2. Are any dependencies under licences that require source disclosure?
3. Are MaxMind GeoLite2 terms compatible with redistribution in customer deployments? (This is the most likely surprise.)
4. Are any dependencies unmaintained, and what is the replacement?

**Deliverables.** A licence matrix and a short list of replacements.

**Effort.** 2–3 days.

---

### Reviewer 13 — Human-Factors / UI Security Reviewer

**Why.** The Management UI is the place where a tired SOC operator at 03:00 will accidentally add `0.0.0.0/0` to a whitelist, or flip the dial to 0 across all instances during an unrelated incident. The damage from a UX failure on a security-critical control plane is asymmetrically large. The discipline that studies this — human-factors security — is rare but valuable.

**Who.** A UX-security researcher. The lineage of Lorrie Cranor's CMU group, Angela Sasse's UCL group, or commercial UX practices with security specialism (Nielsen Norman has touched this; Simply Secure is closer). For a smaller engagement, a senior security UX designer between roles.

**Questions.**
1. Are destructive actions (whitelist additions, dial changes, ban removals) protected by friction proportional to their blast radius?
2. Is there a "are you sure" pattern, or a typed-confirmation pattern, on the most consequential actions?
3. Is the audit log surfaced where the operator would notice, or only where the auditor would look?
4. Is there a "preview the effect of this change" pattern before it ships?
5. Does the UI distinguish read-only from write modes clearly enough that an operator does not accidentally edit while investigating?
6. Are the most dangerous actions reachable in fewer clicks than the most common actions? (They should not be.)
7. Does the SSO/MFA flow degrade gracefully, or does an auth-provider outage lock the team out during an incident? (This is the "break-glass" question.)

**Deliverables.** A short report with screenshots and specific recommendations. Recommendations should be actionable in a sprint, not architectural.

**Effort.** 1 week.

---

## What I Would Explicitly NOT Spend Money On

These engagements have surface appeal but low marginal value given what JA4proxy already has. Listing them explicitly so leadership can push back on vendor pitches.

- **A second general-purpose code audit.** The project has had Phase 14, Phase 18, Phase 27, the existing comprehensive security audit, plus 99% unit coverage from Phase 46. A second generalist audit will produce overlap, not new findings. Spend the budget on Reviewer 1 (focused TLS pentest) instead.
- **Compliance scan tool vendors.** Tools like Drata, Vanta, Secureframe are useful for *running* a compliance programme, not for *assessing* whether your implementation is sound. They produce evidence-collection automation, not findings. They are appropriate after Reviewer 8 has identified the gaps, not as a substitute for that engagement.
- **AI-security boutiques.** JA4proxy has no LLM surface, no model serving, no prompt injection vector. AI-security firms are rapidly multiplying and will pitch you regardless. Decline.
- **Blockchain / Web3 / "zero trust" boutiques.** None of these map to the actual threat surface. The product is a TLS-aware passthrough proxy; the threat model is well-defined and conventional.
- **A second pentest of the management UI alone.** Reviewer 1's brief covers this. A standalone web-app pentest will produce IDOR/CSRF/XSS findings of moderate value but will not engage the bypass-ladder semantics, which is the higher-value target.
- **Generic "DevSecOps maturity" assessments.** These are checklist exercises and produce no findings the team cannot self-identify. Skip.

---

## Sequencing & Budget Shapes

Three procurement-shaped options for leadership.

### Option A — Minimum viable de-risking (Tier 1 only)

**Engagements:** Reviewers 1, 2, 3, 4.
**Elapsed time:** ~6 weeks calendar, run mostly in parallel.
**Effort:** ~30–40 reviewer-days total.
**Outcome:** F-1 (supply chain), F-2 (SLOs), F-3 (DR), F-4 (fuzz), and the cryptographic primitives are externally validated. The product is materially de-risked for pilot deployment. SOC 2 / ISO 27001 / privacy / specialist surfaces are still open.
**Recommendation:** This is the smallest engagement I would consider responsible before any external pilot.

### Option B — Enterprise-GA readiness (Tier 1 + Tier 2)

**Engagements:** Reviewers 1–8.
**Elapsed time:** ~3 months calendar.
**Effort:** ~75–100 reviewer-days total.
**Outcome:** Everything in Option A, plus eBPF validated, container hardening adversarially tested, GDPR position established, and SOC 2 / ISO 27001 readiness assessed. The product is ready for enterprise customer security questionnaires. This is the realistic target before charging an enterprise customer.
**Recommendation:** This is the procurement decision that matches the "enterprise GA" stage of the product.

### Option C — Sustaining and growth (Tier 1 + Tier 2 + selected Tier 3)

**Engagements:** Add Reviewers 9, 10, 13 from Tier 3 (skip 11 and 12 if budget is constrained — they can come later).
**Elapsed time:** 4–5 months calendar.
**Outcome:** Feed quality independently reviewed, signal model challenged by anti-bot domain experts, UI safety reviewed.
**Recommendation:** Appropriate once the product is in the field and the question shifts from "is it safe?" to "is it durable?"

**Phasing note.** Within any option, the *order* matters. Engage Reviewer 3 (supply chain) **before** Phase 61 starts implementation, not after. Engage Reviewer 2 (SRE) **early**, because the deliverable is mostly questions that the team will need time to answer. Engage Reviewer 1 (TLS pentest) **after** the most recent significant change to the bypass ladder or the TLS parser, so the test is against the version you intend to ship. Engage Reviewer 4 (cryptography) **whenever** — the surfaces are stable.

---

## Cross-Cutting Recommendations for Managing the Panel

A few practices that materially raise the value of any external engagement:

1. **One internal owner per reviewer.** Not a committee. The owner is responsible for the evidence pack, the kickoff call, the question list, the mid-engagement check-in, and the findings response. Without a single owner, external engagements drift.
2. **Pre-write the kickoff brief.** Each reviewer should arrive with a 1-page brief specific to JA4proxy, not a generic engagement letter. The briefs in this document are the starting point.
3. **Demand a kickoff call and a mid-engagement check-in.** Reviewers who write the report at the end without checking their understanding mid-way produce weaker work. Two short calls cost nothing and improve the deliverable.
4. **Insist on findings *and* non-findings.** "Things I tried that didn't work" is more valuable than the findings list. Require it in the statement of work.
5. **Read the report as a team, not individually.** A 30-minute walk-through with the reviewer is worth more than ten people reading the PDF in isolation. Schedule it.
6. **Track findings to closure in the same system you track engineering work.** Findings that live only in PDFs do not get fixed. Open issues for each one with the reviewer's name attached.
7. **Pay for retest.** Budget for a one-day retest pass after fixes for at least Reviewers 1, 5, 6. The retest is the moment the finding becomes evidence.
8. **Publish the response, not the report.** External findings are sensitive; the *team's response* to them is publishable and demonstrates security maturity to customers. SOC 2 reports are precedent for this pattern.
9. **Do not negotiate findings.** Negotiate the *severity* if you disagree, with reasoning. Never negotiate the existence of a finding.
10. **Keep the reviewer's contact for the next engagement.** Reviewers who already understand the codebase produce 2–3× the value on a follow-up engagement. The relationship is the asset.

---

## Closing Note for Leadership

The single most expensive mistake leadership can make with this panel is to treat external review as a checkbox — to engage reviewers, receive reports, and shelve them. Every reviewer above is selected because they will produce *uncomfortable* findings. The value of the panel is exactly the discomfort: it is the mechanism by which the project's blind spots become visible.

The second most expensive mistake is to engage all thirteen reviewers at once. They will overwhelm the team's response capacity, the findings will pile up, and the engagement will fail in the response phase even if every individual reviewer succeeds. The Tier 1 / Tier 2 / Tier 3 sequencing exists specifically to prevent this.

The third mistake is to engage *none* of them and rely on the internal review (`CYBER_RISK_REVIEW_2026-04-09.md`) plus the team's own diligence. That is sufficient for development; it is not sufficient for the moment a customer's CISO opens a security questionnaire and asks "who has independently tested this?" The right answer is a list of named firms with publishable findings and demonstrable remediation. That answer takes months of calendar time to build, which is why this document exists now.

JA4proxy is, on the evidence, a better-than-typical security product built by a disciplined team. That makes it *worth* the panel above. Products that are not worth external review are usually obvious; this one is not in that category. The recommended action is Option B (Tier 1 + Tier 2), sequenced over the next quarter, with Reviewer 3 (supply chain) and Reviewer 2 (SRE) starting first because they have the longest tail.

---

*Companion document to `CYBER_RISK_REVIEW_2026-04-09.md`. Cross-references: `docs/PROJECT_STATUS.md`, `docs/phases/manifest.yaml`, `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, `docs/security/threat-model.md`, `docs/compliance/`, `CLAUDE.md`.*
