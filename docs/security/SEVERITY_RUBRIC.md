# JA4proxy Severity Rubric

> **Sub-phase:** 121c. **Authority:** this document binds severity labels on
> every entry in `docs/security/findings.yaml`.
>
> **⚠ The day-figures below are internal best-effort prioritisation targets, not
> service-level agreements.** Per [`CVD_POLICY.md`](CVD_POLICY.md), JA4proxy
> makes **no SLA** on acknowledgement, triage, or fix timelines and has **no
> on-call rotation** — it is a self-funded open-source project responding as
> maintainer capacity allows. "SLA" / "past SLA" in this document means a missed
> *internal* target, never a breached external commitment.

## Why a project-specific rubric

External reports (red team audits, automated scanners, CVE feeds) score
findings with generic CVSS vectors that do not know the product's risk model.
JA4proxy's core asymmetry — **false positives cost far more than false
negatives** — means some findings that CVSS rates HIGH are actually MEDIUM
for this product (e.g. a signal module that over-scores during outage), and
some it rates MEDIUM are CRITICAL (e.g. anything that blocks legitimate
browsers at scale).

This rubric is the single source of truth. CVSS vectors are recorded in
`cvss_v3_1` for reference but are **not** the severity label.

Every register entry must populate `severity_rationale` with the clause ID
it was classified under. `make verify-findings` enforces non-empty
`severity_rationale`.

## Severity levels

### CRITICAL — 7 days to fix / 14 days to verified

Any of the following:

| Clause | Criterion |
|---|---|
| **C-1** | Unauthenticated remote code execution, container escape, or host compromise via the proxy path, management API, analytics node, or any support service exposed on a public network. |
| **C-2** | Full authentication bypass (any role) on the management API, or the ability to impersonate an authenticated user without a credential. |
| **C-3** | Unauthenticated data exfiltration of security posture, client IPs, fingerprint corpus, JWTs, Redis credentials, or other material non-public state. |
| **C-4** | A bug that can cause the proxy to block legitimate browser traffic at scale — violating the fail-open principle. Worst-case is an outage of customer websites behind the proxy. |
| **C-5** | Supply-chain compromise vector: unsigned or unverified code paths that a third-party can influence (e.g. unverified Docker base image, unvalidated webhook recipient that becomes a privileged pivot). |
| **C-6** | A demonstrable way to turn the proxy itself into an attack amplifier (SSRF to internal metadata, reflection abuse). |

**Worked examples (from the 108–120 corpus):**

- *PROXY protocol v2 spoofing from untrusted upstream* (L1-001): if exploited, an external attacker rewrites `src_ip` and bypasses all IP-based security decisions → **C-4** (blocks legitimate users wrongly *and* lets attackers pose as trusted). CVSS v3.1 ≈ 9.1; our label: **CRITICAL**.
- *Unauthenticated `/metrics` endpoint exposes client IPs and fingerprints* (RT-003 / 118h): **C-3**.
- *Redis fails open on auth error → signals silently drop, scorer returns 0* (119): **C-4** — could flip a dial-100 deployment to allow everything.

### HIGH — 30 days to verified

Any of:

| Clause | Criterion |
|---|---|
| **H-1** | Authenticated bypass for a privileged role (e.g. an analyst-level JWT can do admin-only mutations). |
| **H-2** | DoS of the proxy itself (crash, hang, memory exhaustion) achievable with moderate resources from an untrusted attacker. |
| **H-3** | Material false-positive risk: a bug that causes the proxy to block some legitimate traffic (not an outage, but measurable fallout). |
| **H-4** | Credential, secret, or signing-key leak with limited blast radius (e.g. logged only in debug builds, expired within 24h, limited to one tenant). |
| **H-5** | Persistent stored XSS, SSRF with limited reach, or log injection that pivots through a downstream consumer. |
| **H-6** | Missing authentication on a sensitive non-exfil endpoint (e.g. health check leaks version strings but not data). |

**Worked examples:**

- *JA4 fingerprint bypass via TLS record fragmentation* (L2-005 / 118b): **H-3** — attackers can craft client hellos that score differently than they should, causing mis-bucketing. Not an outage but measurable scoring error. CVSS v3.1 ≈ 7.5; our label: **HIGH**.
- *Goroutine leak on malformed connection close* (118): **H-2** — slow resource exhaustion.
- *Tarpit exhaustion without per-IP timeout* (R-006 / 118f): **H-2**.

### MEDIUM — 60 days to verified

Any of:

| Clause | Criterion |
|---|---|
| **M-1** | Info leak with no direct exploit path (e.g. version disclosure, directory listing on a non-public route). |
| **M-2** | Weakness exploitable only after a prior compromise (e.g. log injection exploitable only if an attacker already controls a log-writing process). |
| **M-3** | Hardening gap with compensating controls present (e.g. missing defence-in-depth header on a route that also has auth + CSRF). |
| **M-4** | DoS requiring high resources, or only affecting a non-critical subsystem (e.g. analytics node — not the proxy path). |
| **M-5** | Non-persistent, self-only XSS reachable only by admin tokens. |

**Worked examples:**

- *Audit log stored in Redis LIST instead of Stream (loss on restart)* (M): **M-3** — loss window is bounded by cron-driven snapshots.
- *IPv6 burst parser off-by-one* (119): **M-1** if the worst case is a dropped packet; would escalate to H-3 if it produces mis-scoring.

### LOW — 120 days to verified

Any of:

| Clause | Criterion |
|---|---|
| **L-1** | Cosmetic finding: documentation drift, incorrect comment, or similar. |
| **L-2** | Defence-in-depth improvement with no exploit path against the current threat model. |
| **L-3** | Best-practice deviation (e.g. missing security header on an admin-only route already behind mTLS). |
| **L-4** | Dependency hygiene finding where no known exploit exists (e.g. bumping to a newer release to get out of EOL). |

**Worked examples:**

- *Cookie missing `Secure` flag on management UI served only over HTTPS via HAProxy* (RT-011): **L-3** (but promote to M if served over HTTP in any realistic path).
- *Missing `X-Content-Type-Options` on admin HTML routes*: **L-3**.

## The asymmetry rule (project-specific)

> Any finding whose worst-case remediation could cause the proxy to block
> legitimate traffic must carry a **fail-open acceptance criterion**, regardless
> of severity.

Examples: a CRITICAL finding on Redis ACLs cannot be fixed by enabling
fail-closed Redis in all environments — the fix must preserve fail-open for
ALLOW decisions (per `CLAUDE.md`). A HIGH tarpit-exhaustion fix cannot set a
hard per-IP limit without an explicit carve-out for shared NAT ranges.

The acceptance criterion on the fix PR must state: "no code path reachable
from legitimate browser traffic can result in a BLOCK or RST as a consequence
of this change".

## Escalation

| Event | Escalation |
|---|---|
| CRITICAL finding past target | Escalated to the maintainers (there is no on-call rotation — see `CVD_POLICY.md`); reviewed until closed. |
| HIGH finding past SLA | Weekly security review; annotated in `findings.yaml` with `breach_acknowledged: true`. |
| MEDIUM/LOW past SLA | Tracked in `make findings-list --sla-breach` output; no page. |

`scripts/findings_register.py list --sla-breach` returns all breaches; run
weekly as part of security review.

## Interaction with CVSS

CVSS v3.1 scores continue to be recorded for each finding for external
compatibility (see `docs/decisions/ADR-121a-cvss-version.md`). When the CVSS
label and this rubric disagree, **this rubric wins** and the disagreement is
noted in `severity_rationale`, e.g.:

> `severity_rationale: "HIGH per clause H-3 (mis-scoring at scale). CVSS v3.1 rates this MEDIUM; elevated due to fail-open asymmetry."`

## Change control

This rubric is itself a finding-surface: a badly-written clause produces
misclassified findings, which produces wrong remediation priorities. Changes
to this document require the same review rigour as a CRITICAL fix and must
include a rescoring audit of any entries whose severity would change.
