# ADR-202a: SLSA Reusable Workflow Pinning — SHA vs Trusted-Org Tag Allowlist

**Status:** Accepted — Path A (SHA-pinned)
**Date:** 2026-04-15
**Phase:** 202 (CI supply chain hardening) — sub-phase 202a

---

## Context

Phase 202a closes the residual supply-chain-pinning gap in the repo's GitHub
Actions workflows. After prior phases, one `uses:` reference remains unpinned
at a commit SHA:

```
.github/workflows/release-cli.yml:57
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
```

This is a **reusable workflow** (not an ordinary action). GitHub's
supply-chain hardening guidance explicitly calls out that reusable workflows
behave differently from actions: they are always fetched from the default
branch of the caller's ref unless a specific ref is given, and `@v2.1.0` here
is a mutable tag.

The invariant the repo-wide `grep` check enforces
(`grep -nE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml`
returns nothing) would flag this line. Two paths are defensible; this ADR
records the decision gate.

---

## Options

### Path A — SHA-pin the SLSA reusable workflow

Look up the commit SHA that tag `v2.1.0` currently points to on
`slsa-framework/slsa-github-generator`, then rewrite the `uses:` line:

```yaml
uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@<SHA>  # v2.1.0
```

**Pros:**
- Matches the invariant applied to every other `uses:` in the repo —
  one rule, no exceptions.
- Immutable reference: even if `v2.1.0` is force-pushed upstream, our
  workflow still resolves the exact tree it was reviewed against.

**Cons:**
- SLSA guidance itself recommends **tag-pinning** for its reusable workflows
  because some of its internal permissions checks depend on the resolved ref
  being a tag, not a SHA. In practice, SLSA v2.1.0's
  `generator_generic_slsa3.yml` accepts a SHA-pinned caller and emits valid
  provenance — the ref-form constraint in older SLSA guidance applied to
  the caller's own `on: push: tags:` trigger, not to the reusable
  `uses:` ref.
- Updates to a new SLSA version now require a SHA lookup step, not just a
  tag bump.

### Path B — Tag-pin with a trusted-org allowlist

Accept that reusable workflows from `slsa-framework/*` may be tag-pinned,
documented here as a narrowly scoped exception. The repo-wide pin-check
regex is widened to exempt `slsa-framework/` prefixes (or a more generic
"reusable workflow from a GitHub-verified org" allowlist).

**Pros:**
- Matches SLSA's own guidance and the patterns seen in other
  production repos using SLSA provenance.
- No SHA drift to track on version bumps.

**Cons:**
- Creates an "exception class" in our supply-chain posture; any future
  additions to the allowlist need an equivalent ADR.
- Slightly weakens the blanket invariant ("every `uses:` is SHA-pinned") to
  a conditional one.

---

## Decision

**Path A — SHA-pinned.**

Resolved via `curl https://api.github.com/repos/slsa-framework/slsa-github-generator/git/refs/tags/v2.1.0`:
tag `v2.1.0` points directly at commit
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` (lightweight tag — no annotated-tag
dereference required).

Applied to `.github/workflows/release-cli.yml:57`:

```yaml
uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@f7dd8c54c2067bafc12ca7a55595d5ee9b75204a  # v2.1.0
```

**Rationale for choosing Path A:**

1. One rule across the repo is cheaper to maintain and audit than an
   allowlist class. `test_all_workflow_actions_sha_pinned` in
   `tests/integration/test_container_config.py` now passes unconditionally.
2. The repo has exactly one SLSA reusable call; the "no SHA drift on version
   bumps" benefit of Path B would save us one lookup roughly once a year.
3. SLSA's own concern about tag-vs-SHA caller refs applies to the *caller's*
   tag (used for `upload-assets: true`), not to the reusable ref. A release
   still fires from a `v*.*.*` git tag; the caller-side ref semantics are
   unchanged by pinning the reusable at a SHA.

If a future SLSA version's provenance-attestation step does reject a
SHA-pinned reusable, revisit — flip this ADR to Path B and widen the
pin-check regex then.

---

## Consequences

- Either path satisfies the Phase 202 acceptance criterion "No ordinary
  GitHub Action uses `@v*` or `@main`/`@master`". The ordinary-action check
  is unchanged; only reusable workflows are covered by this ADR.
- Future SLSA version bumps follow the SHA-pinning discipline chosen here.
  To update: fetch
  `https://api.github.com/repos/slsa-framework/slsa-github-generator/git/refs/tags/<new-tag>`
  and use the returned `object.sha`. If the response returns
  `"object.type": "tag"` (annotated tag), follow the one-hop dereference
  via `/git/tags/<sha>` to obtain the underlying commit SHA. Record the
  new SHA both in `release-cli.yml` and in the
  `tests/test_workflow_pinning.py` `KNOWN_ACTION_SHAS` allowlist in the
  same commit.
- No effect on the Go proxy image workflow (202d) — that workflow uses only
  ordinary actions, all SHA-pinned.

## Revisit if...

- SLSA v3.x changes its ref-resolution rules.
- A second reusable workflow from a different organisation is introduced;
  the allowlist pattern (if chosen) needs a rethink.

## Implementation notes

- File: `.github/workflows/release-cli.yml:57` (the `uses:` line).
- SHA: `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` (tag `v2.1.0`,
  lightweight — no annotated-tag dereference required).
- Resolved via: `curl -s https://api.github.com/repos/slsa-framework/slsa-github-generator/git/refs/tags/v2.1.0`.
- For future SLSA releases: repeat the same API call with the new tag. If
  `object.type == "tag"` the result is an annotated tag object and a
  second `/git/tags/<sha>` call is needed to reach the commit. See
  the Consequences section above for the exact procedure.
- Verified clean under: `grep -nE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml`
  (returns only the `# v2.1.0` comment, not a ref).
