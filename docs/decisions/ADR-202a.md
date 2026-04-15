# ADR-202a: SLSA Reusable Workflow Pinning — SHA vs Trusted-Org Tag Allowlist

**Status:** Proposed
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
  being a tag, not a SHA. <!-- TODO: verify after impl — confirm whether SLSA
  v2.1.0 requires tag-ref for provenance attestation to succeed. -->
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

**Deferred to the Coder who executes 202a**, based on the following gate:

1. **First**, attempt Path A. Resolve the SHA for
   `slsa-framework/slsa-github-generator` tag `v2.1.0`:
   ```
   gh api repos/slsa-framework/slsa-github-generator/git/ref/tags/v2.1.0 --jq '.object.sha'
   ```
   Pin the line; push a test branch; confirm the workflow still produces a
   valid SLSA provenance attestation on a no-op release.

2. **If Path A fails** (provenance attestation rejects a SHA-ref caller, or
   the SLSA docs for v2.1.0 explicitly require a tag ref), fall back to
   Path B: update this ADR to Accepted with Path B chosen, widen the
   pin-check regex in `Makefile`/`scripts/` to allowlist `slsa-framework/`,
   and record the exception in `docs/phases/PHASE_202a_notes.md`.

<!-- TODO: verify after impl — record which path was chosen, the SHA if
Path A, and the regex exemption if Path B. Update Status to Accepted. -->

---

## Consequences

- Either path satisfies the Phase 202 acceptance criterion "No ordinary
  GitHub Action uses `@v*` or `@main`/`@master`". The ordinary-action check
  is unchanged; only reusable workflows are covered by this ADR.
- Future SLSA version bumps follow whichever pinning discipline is chosen
  here, documented in `docs/runbooks/docker_image_updates.md` <!-- TODO:
  or a new dedicated runbook if CI pinning grows beyond one reusable. -->
- No effect on the Go proxy image workflow (202d) — that workflow uses only
  ordinary actions, all SHA-pinned.

## Revisit if...

- SLSA v3.x changes its ref-resolution rules.
- A second reusable workflow from a different organisation is introduced;
  the allowlist pattern (if chosen) needs a rethink.
