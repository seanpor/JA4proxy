---
phase: 304
title: Dependency Security Remediation (Management-API auth stack)
status: COMPLETE
size: SMALL
created: 2026-06-09
completed: 2026-06-09
audience: [developer, security]
---

# Dependency Security Remediation

> **Outcome (as executed, 2026-06-09).** Between writing this plan and running it,
> the **Phase 302 Dependabot auto-merge already landed two of the five** bumps on
> `main` — `authlib 1.4.0 → 1.6.12` and `python-multipart 0.0.12 → 0.0.32` (both
> minor/patch, so they auto-merged once the required checks passed; *both now
> exceed the fix versions named below*). That left exactly the two Dependabot
> *correctly held back* — `cryptography` (a **major** 45→46 bump, auto-merge skips
> majors) and `python-jose` — plus the Go `grpc` tooling bump. This phase did
> those three by hand:
> - `cryptography 45.0.0 → 46.0.5` (`management/requirements.txt` **and** root `requirements.txt` floor)
> - `python-jose 3.3.0 → 3.4.0` (`management/requirements.txt`)
> - `google.golang.org/grpc 1.76.0 → 1.79.3` (`deploy/terraform-provider/go.mod`, indirect, via `go get` + `go mod tidy`)
>
> **Verification:** management suite **614 passed / 3 skipped** against the upgraded
> stack; the **8 failures are pre-existing dead tests** (they import
> `src.tap.enforcement_bridge`, `src.security.health`, read `proxy.py` — all part
> of the legacy Python pruned in v2.0.0) and are unrelated to these bumps. Root Go
> build clean; terraform-provider builds clean; `test_workflow_pinning` green.
>
> The rest of the doc is the original plan, kept for the educational walk-through
> and the triage reasoning.

> **Audience note.** This doc is written for a junior engineer who has not done a
> CVE-remediation pass before. It explains *what* to change, *why each change
> matters*, and *how to be sure you didn't break anything*. Read it top to
> bottom once before touching a file.

## 0. Background — what triggered this phase

In Phase 302 we turned on GitHub's two free security scanners for the repo:

- **Dependabot** — reads our dependency manifests (`requirements.txt`, `go.mod`,
  `package.json`, …), looks each package up in the GitHub Advisory Database, and
  raises an **alert** when a version we depend on has a known published
  vulnerability (CVE). It can also open PRs that bump the bad version.
- **CodeQL** — a *static analysis* engine. It compiles our code into a queryable
  database and runs security queries over it (e.g. "is untrusted data ever
  logged in clear text?", "is a TLS certificate check disabled?"). Its results
  show up under **code scanning**.

The moment we switched them on, they reported the *entire historical backlog* at
once — **118 alerts**. That number is alarming but misleading. Most security
backlogs are like this: a big headline number that collapses to a small set of
things that actually matter once you triage. **Triage is the skill this phase is
really teaching.**

### The triage result

We sorted all 118 into four buckets:

| Bucket | Count (approx) | What to do |
|---|---|---|
| 🔴 **Real, production, fixable** | ~5 dependency CVEs | **This phase fixes them.** |
| 🟢 **Non-production / benign** | bench tool, deploy tooling | dismiss or low-priority |
| ⚪ **Scanner noise** | OpenSSF Scorecard advisories | filter, don't action |
| 🟡 **Needs human eyeballing** | a handful of CodeQL Python hits | follow-up, case-by-case |

The single most important finding: **the 🔴 bucket is concentrated entirely in
the Python Management-API authentication stack** — the OIDC / OAuth / JWT / TOTP
libraries. The **Go production proxy** (the thing that actually sits in the
traffic path — see the "Production runtime is Go" banner in `CLAUDE.md`) came
back essentially clean. So the blast radius of "118 scary alerts" is one Python
service's dependency list.

> **Why does the Management API count as production?** `CLAUDE.md` says the
> *proxy* is Go and the *Python proxy* is experimental — but it is explicit that
> "Python services that **are not the proxy** — Management API (FastAPI),
> analytics node, compliance reporting — remain Python and are production code."
> The auth stack we're fixing guards the operator login to that production API,
> so these CVEs are real exposure, not prototype noise.

## 1. Goal

Bump five dependencies to their first patched versions, eliminating the
**critical + high** Dependabot alerts in the production Python auth stack, and
clear the small amount of CodeQL/Scorecard noise that is inflating the count.

**Guiding principle (from the project owner, verbatim):** *be very critical of
any whitelisting or suppression of issues* — and *"I'd prefer to fix it with an
[upgrade] and be clear of the issue entirely."* So our default is **upgrade to
the fixed version**, never `.trivyignore` / dismiss, unless the finding is
provably not a real bug (which we justify in writing).

## 2. The five upgrades

Every one of these has a published fixed version — there are **no "no-fix"
situations** here, which is the easy case.

| Package | File | Current → Fix | Severity |
|---|---|---|---|
| **authlib** | `management/requirements.txt` | `1.4.0` → **`1.6.4`** | critical + high (×several) |
| **python-jose[cryptography]** | `management/requirements.txt` | `3.3.0` → **`3.4.0`** | critical |
| **python-multipart** | `management/requirements.txt` | `0.0.12` → **`0.0.18`** | high |
| **cryptography** | `management/requirements.txt` **and** `requirements.txt` | `45.0.0` → **`46.0.5`** | high |
| **google.golang.org/grpc** | `deploy/terraform-provider/go.mod` | → **`1.79.3`** | critical (but deploy tooling, not the proxy) |

> ⚠ **Pinning rule — read this before editing `management/requirements.txt`.**
> That file has a header comment (finding JA4PROXY-2026-0044) mandating **exact
> `==` pins** and forbidding floating versions. Honour it: change the version
> *number* on the `==` line, do **not** switch to `>=`. In the root
> `requirements.txt`, `cryptography` is already `>=45.0.0`, so bump the **floor**
> to `>=46.0.5` there (that file uses floors by convention — match the file
> you're editing).

### 2a. Why each one matters (the educational bit)

Understanding the *class* of each vulnerability is more useful than memorising
the CVE number — you'll meet these classes again.

- **authlib (OIDC/OAuth/JWT library).** Several issues, the scariest being a
  **signature-verification bypass** via JWS/JWK header injection, plus a
  *fail-open* crypto path. A signature bypass on a JWT library is close to
  worst-case: it can let an attacker forge a token the server accepts as valid,
  i.e. **authenticate as anyone**. There were also a JWE Bleichenbacher (a
  classic padding-oracle attack on RSA encryption) and a DoS. This is the single
  most important bump in the phase.

- **python-jose (JWT library).** A **critical algorithm-confusion** bug. The
  attack: a token says `alg: HS256` (symmetric — verified with a shared secret)
  but the server is configured for `RS256` (asymmetric — verified with a public
  key). If the library lets the *token* pick the algorithm, an attacker can sign
  an HS256 token using the server's **public** key (which is, by definition, not
  secret) and have it accepted. 3.4.0 fixes the specific CVE.
  - **Follow-up flagged, not done here:** `python-jose` is effectively
    unmaintained. The industry-standard replacement is **PyJWT**. Migrating is a
    code change (different API) and out of scope for this "just stop the
    bleeding" phase — but note it in the PR as a recommended follow-up.

- **python-multipart (FastAPI form/multipart parser).** A **DoS** (a malformed
  multipart body that makes the parser burn CPU) and an **arbitrary file write**.
  FastAPI uses this for every form/file upload, so it's directly reachable from
  the network on any endpoint that accepts form data.

- **cryptography (the primitives library).** A subgroup/confusion issue in a
  key-exchange path. We use `cryptography` for **Fernet** (symmetric encryption
  of stored TOTP secrets — see `# phase-79` comment). Lower practical risk for
  our usage than the JWT bugs, but it's a trivial bump and it's a transitive
  dependency of half the stack anyway.

- **google.golang.org/grpc.** A critical authorization bypass — but it lives in
  `deploy/terraform-provider/go.mod`, which is **infrastructure tooling we run at
  deploy time**, not code in the proxy's traffic path. Lower urgency, but it's a
  one-line `go.mod` bump + `go mod tidy`, so we do it in the same sweep.

## 3. Step-by-step

> Work on a branch — `phase-304-dep-security` — and land via PR (`main` is
> branch-protected; see `CLAUDE.md`). All 10 required checks must pass.

1. **Branch.**
   ```
   git checkout main && git pull
   git checkout -b phase-304-dep-security
   ```

2. **Edit `management/requirements.txt`** — change four version numbers
   (keep the `# phase-79` trailing comments):
   ```
   python-jose[cryptography]==3.4.0   # phase-79: OIDC ... (was 3.3.0, CVE alg-confusion)
   python-multipart==0.0.18           # (was 0.0.12, CVE DoS + arbitrary file write)
   cryptography==46.0.5               # phase-79: Fernet ... (was 45.0.0, CVE subgroup)
   authlib==1.6.4                     # phase-79: OIDC ... (was 1.4.0, CVE sig-verify bypass)
   ```

3. **Edit `requirements.txt`** (root) — bump the cryptography floor only:
   ```
   cryptography>=46.0.5
   ```

4. **Edit `deploy/terraform-provider/go.mod`** — set grpc to `v1.79.3`, then in
   that directory run `go mod tidy` (use the project's Go toolchain;
   per project memory: `GOROOT=/snap/go/current go ...`). Commit the resulting
   `go.sum` change too.

5. **Re-create the management virtualenv from the new pins and run its tests.**
   This is the step that catches breaking API changes (especially authlib, which
   jumped two minor versions — minor bumps *can* change APIs in pre-1.0-feeling
   libraries):
   ```
   cd management
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements.txt
   python3 -m pytest        # management API test suite
   deactivate && cd ..
   ```
   If a test fails with an `ImportError` / signature change, that's the upgrade
   surfacing a real API delta — fix the call site, don't pin back. Read the
   library's changelog for the breaking change.

6. **Run the full repo gate** (the rest of the suite must stay green — `make
   test` runs `test_workflow_pinning` and the docker-consistency checks too):
   ```
   make test
   ```

7. **CHANGELOG + manifest + sync** (the mandatory closing steps from `CLAUDE.md`):
   - Prepend a `### Security` entry under `## [Unreleased]` in `CHANGELOG.md`.
   - Add the Phase 304 entry to `docs/phases/manifest.yaml` and flip this doc's
     `status: PLANNED` → `COMPLETE` (add `completed:`), then move it to
     `docs/phases/complete/` if that's the convention the other complete phases
     follow.
   - Run `make sync` to regenerate `TODO.md` / `PROJECT_STATUS.md`.

8. **Commit, push, PR, auto-merge:**
   ```
   git push origin phase-304-dep-security
   gh pr create --base main
   gh pr merge --auto --squash --delete-branch
   ```

## 4. The CodeQL / Scorecard noise (decide, then move on)

These are *not* dependency bumps — they're the rest of the 118. Triage, don't grind:

- **Bench-tool disabled cert check** — `internal/test/bench/ja4bench.go:240`,
  `go/disabled-certificate-check` (one Go CodeQL "high"). This is
  `InsecureSkipVerify` in a **benchmark tool** that connects to our own
  self-signed mock backend. It is *correct* for it to skip verification there —
  there's no real peer to authenticate. It already carries a `// #nosec G402`
  annotation for gosec. **Action: dismiss the CodeQL alert as "used in tests" /
  won't-fix**, with that one-line justification. This is the rare, *justified*
  suppression — and we write down *why*, which is exactly the bar the owner set.

- **OpenSSF Scorecard advisories appearing as code-scanning "high"** —
  `TokenPermissionsID`, `BranchProtectionID`, `CodeReviewID`, shown with "no file
  associated". These are **supply-chain posture scores**, not code bugs that got
  uploaded into the code-scanning tab. **Action: leave them** (informational). If
  they're too noisy, they can be filtered in the code-scanning UI; they are not a
  code fix.

- **CodeQL Python findings that need a human** —
  `py/clear-text-logging-sensitive-data` (×4), `py/insecure-protocol` (×4),
  `py/reflective-xss` (×1). The logging/insecure-protocol ones are
  **false-positive-prone** (they frequently fire on test fixtures and mock TLS
  setups). The **`reflective-xss`** one is worth a genuine read. **Action: out of
  scope for this phase** — list them in the PR as a "review next" follow-up so
  they're not silently dropped. Don't bulk-dismiss them; that would be exactly
  the kind of blanket suppression we're avoiding.

## 5. Acceptance Criteria

1. `authlib`, `python-jose`, `python-multipart`, `cryptography` upgraded to the
   fixed versions in `management/requirements.txt` (exact `==` pins retained);
   `cryptography>=46.0.5` in root `requirements.txt`.
2. `google.golang.org/grpc` at `v1.79.3` in `deploy/terraform-provider/go.mod`
   with a tidied `go.sum`.
3. The management test suite passes against the upgraded pins (any API breakage
   fixed at the call site, **not** by pinning back).
4. `make test` is green end-to-end.
5. The corresponding Dependabot **critical + high** alerts for these packages are
   resolved (they auto-close once the fix is on `main`).
6. The bench-tool `go/disabled-certificate-check` CodeQL alert is dismissed with
   a written justification; Scorecard/other CodeQL items are documented as
   follow-ups, **not** bulk-suppressed.
7. CHANGELOG, manifest, and `make sync` updated; phase landed via PR.

## 6. Out of Scope (explicit follow-ups)

- **`python-jose` → `PyJWT` migration.** jose is unmaintained; PyJWT is the
  maintained standard. This is a code change (different API surface) and deserves
  its own phase.
- **`pip install --require-hashes` lockfile** (finding 0044) — the long-term fix
  that makes *every* future dependency change tamper-evident. Still roadmap.
- **The 9 CodeQL Python findings** (clear-text logging, insecure-protocol,
  reflective-xss) — review case-by-case in a later pass.
