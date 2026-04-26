# Coordinated Vulnerability Disclosure (CVD) Policy

> **Status:** Self-assessed policy. Aligned with ISO/IEC 29147:2018 and ISO/IEC 30111:2019.
> **Phase:** 107g
> **Alignment:** ISO/IEC 29147 (vulnerability disclosure) and ISO/IEC 30111 (vulnerability handling)

---

## 1. Scope

This policy applies to security vulnerabilities in the production JA4proxy
codebase and its officially distributed artefacts.

**In scope:**

- Go proxy core — `cmd/proxy/` and `internal/` (the production runtime).
- Command-line binary — `ja4proxy-cli`.
- Management API service — `src/management/`.
- The official container image distributed by the project.

**Out of scope:**

- The experimental Python prototype — `proxy.py` and the Python sources under
  `src/security/`. These are clearly labelled as a prototyping surface in
  `CLAUDE.md` and never ship in releases, container images, or Helm charts.
  Issues in the prototype should still be reported as ordinary GitHub issues,
  but the CVD process does not apply.
- Documentation typos, broken links, or unrendered Markdown.
- Social engineering of project maintainers.
- Vulnerabilities in third-party dependencies — please report those upstream
  to the dependency's own security contact. If the dependency vulnerability
  affects JA4proxy in a non-obvious way (e.g. our usage pattern is unsafe
  even though the dependency is fine), open a CVD report against this project
  and we will coordinate.

---

## 2. Reporting channels

**Primary channel: GitHub Security Advisories (private vulnerability reports).**

To submit a report, open a new draft advisory at:

```
https://github.com/<owner>/<repo>/security/advisories/new
```

(Replace `<owner>/<repo>` with the canonical project repository path. The
private-advisory mechanism keeps the report confidential between the reporter
and the maintainers until coordinated disclosure.)

**No secondary channel is committed at this time.** Specifically: there is no
project security email address, no PGP key is currently published, and there
is no telephone or chat-based intake. If GitHub Security Advisories is not a
viable channel for you (for example, you cannot create a GitHub account),
open a regular GitHub issue stating only that you have a security report and
need an alternative channel — do not include vulnerability details in a
public issue.

**Expected report contents:**

- Affected component (Go proxy, CLI, management API, container image).
- Affected version, commit hash, or release tag.
- Reproduction steps (a minimal, deterministic recipe is most useful).
- Observed behaviour and expected behaviour.
- Impact assessment from the reporter's perspective (optional but helpful).
- Any proposed mitigation or patch (optional).

---

## 3. Acknowledgement and triage

No service-level commitments are made on acknowledgement, triage, or fix
timelines. The project will respond on a best-effort basis as maintainer
capacity allows. Reporters who require a guaranteed response time should
arrange a commercial support agreement (none currently offered).

When a report is first reviewed, the maintainer will acknowledge receipt
through the GitHub Security Advisory thread, confirm the report is in scope,
and begin reproduction against the most recent stable release. Triage results
(severity classification per `docs/security/SEVERITY_RUBRIC.md`, assigned
maintainer, planned fix path) will be posted back to the same advisory
thread.

### Why no SLA

JA4proxy is a self-funded open-source project with no oncall rotation, no
commercial entity behind it, and no paid-support tier. Publishing a numerical
SLA — for example "2-day acknowledgement" or "30-day critical fix" — would
create an obligation that the project cannot reliably meet, and would mislead
reporters and downstream users about the response capacity that actually
exists. A fake SLA does more harm than no SLA: it converts an honest
best-effort posture into an implied promise that breaks the first time a
maintainer is on holiday. The project therefore commits only to best-effort
response and to transparent communication on the GitHub Security Advisory
thread when a report is being worked on.

---

## 4. Fix timelines by severity

No service-level commitments are made on acknowledgement, triage, or fix
timelines. The project will respond on a best-effort basis as maintainer
capacity allows. Reporters who require a guaranteed response time should
arrange a commercial support agreement (none currently offered).

Severity is assessed against `docs/security/SEVERITY_RUBRIC.md`. Higher
severities are prioritised over lower ones, and a fix for a CRITICAL or HIGH
issue will be worked ahead of unrelated feature work, but no specific
calendar duration is promised. Fix availability and the planned disclosure
window will be communicated through the GitHub Security Advisory thread as
the work progresses.

### Why no SLA

The same reasoning applies as in §3: a self-funded open-source project with
no oncall rotation cannot honestly publish per-severity fix SLAs (e.g.
"30 days for critical, 60 days for high"). Publishing such numbers would
imply a maintenance posture that does not exist. Reporters needing a
guaranteed turnaround should arrange a commercial support relationship; in
the absence of one, the project will work fixes in priority order and report
status on the advisory thread.

---

## 5. Disclosure and embargo

The project follows a **coordinated disclosure** model. The default embargo
window is **90 days** from the earlier of:

- the date the report is acknowledged on the GitHub Security Advisory, or
- the date a fix becomes available.

The embargo may be **extended by mutual agreement** between the reporter and
the maintainer — for example, when downstream redistributors need additional
time to ship the fix, or when the underlying issue requires a larger
architectural change. Extensions are documented on the advisory thread.

Once a fix is published, the project will publish a **GitHub Security
Advisory (GHSA)** describing the issue, the affected versions, the fix
version, and (where applicable) any mitigations available to operators who
cannot upgrade immediately. Pre-disclosure of the fix to specific
downstream redistributors is possible by request and is handled
case-by-case.

---

## 6. Credit and CVE assignment

**Researcher credit is opt-in.** The default is to name the reporter in the
published advisory. Reporters who prefer to remain anonymous should say so in
the initial report or before the advisory is published.

**CVE assignment** is requested through GitHub Security Advisories, which
acts as a CVE Numbering Authority (CNA) for advisories published in this
form. Each published advisory therefore carries a `GHSA-*` identifier and,
where the issue meets CVE-eligibility criteria, a `CVE-*` identifier as
well.

Reporters are credited by the name they provide. If the reporter is part of
an organisation and wishes the organisation to be acknowledged instead of or
alongside the individual, the advisory will reflect that.

---

## 7. Safe harbour

The following text is reproduced verbatim from the disclose.io Simple Safe
Harbor template.

<!-- Source: https://github.com/disclose/dioterms/blob/master/simple-safeharbor/simple-safe-harbor.md
     Reproduced verbatim. Do not paraphrase. -->

> # Simple Safe Harbor
>
> We will consider your security research to be authorized if you make a good faith effort to comply with this policy during your security research. If your activities violate certain restrictions in our Acceptable Use Policy, we will waive those restrictions for the limited purpose of allowing security research. We will not sue you for attempting to circumvent the technological safeguards we have put in place to protect the applications in scope. If a third party takes legal action against you for activities carried out in accordance with this policy, we will make this authorization known.
>
> For inadvertent, good-faith violations of this policy, we will not take civil action or file a report with law enforcement. Before doing anything that may be inconsistent with or unaddressed by this policy, please contact us by submitting a report.

---

## 8. Standards alignment

This policy is **self-assessed** as aligned with two ISO standards covering
the disclosure-and-handling lifecycle:

- **ISO/IEC 29147:2018** — *Information technology — Security techniques —
  Vulnerability disclosure.* Section 6 of that standard describes the
  external-facing disclosure process: receiving reports, acknowledging
  reporters, coordinating with stakeholders, and publishing advisories.
  Sections 1, 2, 5, and 7 of this policy map to those activities.
- **ISO/IEC 30111:2019** — *Information technology — Security techniques —
  Vulnerability handling processes.* Section 5 of that standard describes the
  internal handling lifecycle: receive, verify, remediate, publish. Sections
  3, 4, 5, and 6 of this policy describe how this project executes each of
  those phases (acknowledge → reproduce → fix → publish advisory + CVE).

No accredited body has audited this alignment; the assessment is the
maintainers' own. If a future third-party audit adds external attestation,
this section will be updated and the result linked here.

---

## Cross-references

- See also: [`../compliance/CRA_CONFORMANCE.md`](../compliance/CRA_CONFORMANCE.md) — CRA Annex II vulnerability-handling requirements
- See also: [`../compliance/SSDF_MAPPING.md`](../compliance/SSDF_MAPPING.md) — NIST SSDF RV practices
- Pointer from: [`../../SECURITY.md`](../../SECURITY.md)
- Intake runbook: [`./INTAKE_RUNBOOK.md`](INTAKE_RUNBOOK.md) — operational steps maintainers follow when a CVD report arrives
