---
phase: 308
title: Code-Scanning Remediation — CodeQL Triage Closeout & Scorecard Noise
status: COMPLETE
created: 2026-06-10
completed: 2026-06-10
audience: [developer, security]
---

# Code-Scanning Remediation — CodeQL Triage Closeout & Scorecard Noise

> Closes out the GitHub **code-scanning** backlog that built up after Phase 302
> enabled CodeQL + OpenSSF Scorecard. Follows the same discipline as
> [[PHASE_305]]: **triage before touching anything**, and *be very critical of
> any suppression* — every dismissal is backed by evidence read from the code,
> and anything genuinely fixable is fixed rather than dismissed.

## Starting point

The Security → Code scanning tab showed **60 open alerts**: **7 CodeQL** (real
code findings) and **53 Scorecard** (OpenSSF supply-chain *scores*). The headline
count is misleading — the two tools mean very different things, and most of the
53 are not vulnerabilities at all.

## CodeQL (7) — every one verified against the code

| # | Rule | Location | Disposition |
|---|------|----------|-------------|
| 89 | `py/url-redirection` | `oidc.py:507` | **Dismissed (FP)** — mitigated |
| 92 | `py/url-redirection` | `saml.py:323` | **Dismissed (FP)** — mitigated |
| 86 | `py/clear-text-logging` | `splunk .../ja4proxy_ban_action.py:38` | **Dismissed (FP)** |
| 77 | `py/bind-socket-all-network-interfaces` | `scripts/capture_server.py:35` | 🔧 **Fixed in code** |
| 79 | `py/insecure-protocol` | `scripts/test-bot.py` | **Dismissed (used in tests)** |
| 81 | `py/insecure-protocol` | `scripts/tls-traffic-generator.py` | **Dismissed (used in tests)** |
| 91 | `go/disabled-certificate-check` | `internal/test/bench/ja4bench.go` | **Dismissed (used in tests)** |

### Fixed in code
- **#77** — `capture_server.py` bound `0.0.0.0`. It is a fixture recorder driven
  entirely by local clients (`generate_fixtures.sh` connects to
  `127.0.0.1:9443-9446`), so it never needs off-host connections. Changed the
  bind to `127.0.0.1` — clears the alert *legitimately* (behaviour unchanged),
  rather than by dismissal. The stale `# nosemgrep` was removed.

### Dismissed — false positives (proven by reading the code)
- **#89 / #92** — the post-login redirect target is confined to a same-site
  relative path by `auth.safe_relative_redirect()` (applied at `oidc.py:431` and
  `saml.py:323`), with regression tests from [[PHASE_305]]. CodeQL flags them
  because it can't trace the custom sanitizer. *Mitigated, not exploitable.*
- **#86** — the splunk action's `api_token` is used **only** in the
  `Authorization: Bearer` header (line 146); it is never passed to `_log()`
  (whose arguments are IPs / HTTP status / response bodies / reasons). Verified
  every call site.

### Dismissed — used in tests (intentional, non-production)
- **#79 / #81** — these are TLS *generators* that deliberately set a legacy
  `minimum_version` (with `CERT_NONE`) to emit a spread of ClientHello
  fingerprints that exercise the proxy's JA4 detection. A TLS-1.2 floor would
  defeat the tool's entire purpose — there is no "fix" that preserves it.
- **#91** — a benchmark load generator (`internal/test/bench`) that connects to
  the self-signed mock backend, so `InsecureSkipVerify` is correct there; it is
  never deployed to production and already carried `#nosec G402`.

> All dismissals are per-alert with a code-backed justification recorded in the
> GitHub audit trail (reversible in one click). **No blanket rule suppression.**

## Scorecard (53) — supply-chain *scores*, not vulnerabilities

OpenSSF Scorecard rates repository posture across ~18 checks and produces a 0–10
score + badge. `scorecard.yml` was piping every check finding into the
code-scanning tab. On inspection the 53 are **not actionable** in any meaningful
way:

- **`PinnedDependenciesID ×45`** — the production Dockerfile **base images are
  already digest-pinned** (Phase 229). What remains flagged is `pip install` /
  `apt-get` *inside* Dockerfiles and tool downloads in shell scripts;
  hash-pinning those is high-churn, brittle, and low-value for a zero-user
  project.
- **`TokenPermissionsID ×3`** — all are **required `write`** (CodeQL SARIF
  upload, Dependabot auto-merge, metrics auto-commit), already job-scoped with
  `contents: read` at the top level. Reducing them breaks function.
- **`VulnerabilitiesID ×1`** — self-clears now that Dependabot alerts are at 0.
- **`BranchProtection / CodeReview / CII / SAST`** — solo-maintainer
  repo-process scores (e.g. CodeReview dings single-author merges, inherent to a
  one-person project).

### Decision: stop uploading Scorecard SARIF to code-scanning
The 53 entries were pure signal-to-noise cost — already-satisfied, required, or
self-clearing — drowning real CodeQL findings in the Security tab. We removed the
`"Upload to code-scanning"` step from `scorecard.yml` (and the now-unneeded
`security-events: write` permission). **Scorecard still runs** on schedule + push
and still publishes the score/badge via `publish_results: true`, and
`results.sarif` is still kept as a build artifact — only the noisy per-check
upload to the Security tab is gone. This suppresses no *analysis* and is a
one-step revert (restore the permission + the upload-sarif step).

## Verification
- `tests/test_workflow_pinning.py` — 7 passed (the removed `upload-sarif` line
  reduces the pinned-`uses:` set; nothing else changes).
- `scripts/capture_server.py` parses; the fixture clients already target
  `127.0.0.1`, so the loopback bind is behaviour-preserving.
- After the next default-branch CodeQL scan, the fixed-in-code #77 auto-closes;
  the six dismissed alerts are already cleared with justifications.

## Acceptance Criteria
1. Every CodeQL finding triaged to fixed / FP / used-in-tests, each with a
   written, code-backed justification; no blanket rule suppression.
2. The one genuinely-fixable finding (#77) is fixed in code, not dismissed.
3. Scorecard advisories no longer pollute the code-scanning tab, while the
   Scorecard run + score/badge are preserved (reversible).
4. Workflow-pinning and YAML tests stay green; manifest + CHANGELOG + `make
   sync` updated; landed via PR.

## Out of Scope (follow-ups)
- Raising the actual OpenSSF Scorecard *score* (pip hash-pinning, two-person
  review) — deliberately not pursued; disproportionate for a zero-user project.
- `python-jose` → PyJWT migration (carried from [[PHASE_304]]).
- Deleting/rewriting the dead `test_phase_122_security_review.py` tests
  (carried from [[PHASE_305]]).
