# Security Policy

JA4proxy's full coordinated vulnerability disclosure policy is at:

**[`docs/security/CVD_POLICY.md`](docs/security/CVD_POLICY.md)**

## Quick reference

- **Reporting:** open a GitHub Security Advisory (private). See CVD_POLICY §2 for details.
- **Scope:** Go proxy core, CLI, management API, official container image. The Python prototype is out of scope.
- **Response:** best-effort; no service-level commitments. See CVD_POLICY §3-4.
- **Safe harbour:** disclose.io Simple Safe Harbor template applies. See CVD_POLICY §7.

## Historical credential exposure (resolved)

Commit `d67f4d6` (2026-03-06) inadvertently included a POC Redis password in
a now-deleted analysis doc. The password was rotated; current production
environments do not use that value. The historical commit remains visible
in git history; remove via [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
if compliance requires.
