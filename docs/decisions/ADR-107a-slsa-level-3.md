# ADR-107a: Adopt SLSA Level 3 via `slsa-github-generator` Reusable Workflow

**Status:** Proposed
**Date:** 2026-04-26
**Phase:** 107 (Regulatory & Supply-Chain Conformance) — sub-phase 107c

---

## Context

Phase 202d shipped SBOM (CycloneDX, OCI-attached) plus keyless cosign
signing (Fulcio OIDC) for the Go proxy container image
(`.github/workflows/go-proxy-image.yml` →
`ghcr.io/anomalyco/ja4proxy-go`). That places JA4proxy at **SLSA Level 2**:
hosted, tamper-resistant build with signed artefacts.

**SLSA Level 3** adds three properties beyond L2:

1. **Hardened build platform.** The build runs on infrastructure the
   producer does not have administrative access to — so a compromised
   maintainer cannot inject build-time changes.
2. **Isolated build per artefact.** Each artefact is built in a fresh
   environment, so build N cannot influence build N+1.
3. **Non-falsifiable provenance.** A signed attestation cryptographically
   binds the build inputs (source revision, build parameters, builder
   identity) to the output artefact's digest. The attestation is generated
   by the build platform itself, not by code under the producer's control,
   so a compromised maintainer cannot forge it.

For a project hosted on GitHub Actions, the **reference implementation**
of L3 provenance is the `slsa-framework/slsa-github-generator` reusable
workflow family. It runs the provenance-emitting steps in a separate,
short-lived runner that the calling workflow cannot override or read,
satisfying property (3). GitHub-hosted runners satisfy properties (1)
and (2) by default for the OSS plan.

**Buyer expectations.** Enterprise buyers' supply-chain security
questionnaires increasingly ask "what SLSA level do you produce?" and
treat L3 as the threshold for production-criticality. The EU CRA Annex
II SBOM and vulnerability-handling requirements assume an L3-style
producer-signed provenance chain in the harmonised standards being
drafted by ETSI / CEN-CENELEC through 2026.

---

## Decision

**Adopt SLSA Level 3 by integrating `slsa-framework/slsa-github-generator`
reusable workflows into the existing build pipelines.** Specifically:

- **`go-proxy-image.yml`** — call
  `slsa-framework/slsa-github-generator/.github/workflows/generator-container-slsa3.yml@<SHA>`
  after the image push step, with the pushed image digest as input. The
  generator emits a SLSA v1.0 in-toto attestation and pushes it to the
  same OCI registry.
- **`release-cli.yml`** — call
  `slsa-framework/slsa-github-generator/.github/workflows/generator-generic-slsa3.yml@<SHA>`
  with the `ja4proxy-cli` binary's sha256 as input. The attestation is
  attached to the GitHub Release.
- **`slsa-verify.yml`** — net-new test workflow that pulls the published
  image + attestation from GHCR and runs `slsa-verifier verify-image`.
  Exit code 0 is the gate. Initially `workflow_dispatch`-only; promoted
  to a scheduled or push-triggered run after the first end-to-end
  verification succeeds.

**Not chosen:** in-toto custom attestation. `slsa-github-generator`
provides the attestation generation, signing (via keyless cosign Fulcio),
and verifier path as one tested, well-documented unit; rolling our own
attestation generator would duplicate work and lose the property-(3)
isolation guarantee that the reusable-workflow architecture provides.

---

## Rationale

**Why L3 and not L4.** L4 requires hermetic, reproducible builds —
the build inputs are fully enumerated and the same inputs produce
byte-identical outputs. The Go toolchain is close to reproducible but
the container-image build path (with timestamps, embedded metadata, and
non-deterministic layer ordering from `docker buildx`) is not. Achieving
L4 would require switching the image-build pipeline from `docker buildx`
to a reproducible-build-aware tool such as `ko` or Bazel, which is a
disproportionate investment for the marginal buyer-facing benefit over
L3. L4 is reserved for a future phase if a concrete buyer asks for it.

**Why `slsa-github-generator` and not in-toto.** The project's
distinguishing security property (3) — non-falsifiable provenance — is
exactly that the build code cannot influence the attestation. A custom
in-toto generator running in the same workflow as the build would not
satisfy this. The reusable-workflow architecture of
`slsa-github-generator` is what provides the property; switching to a
custom path would silently lose it while keeping the L3 label.

**Verifier-UX is the load-bearing UX.** The whole point of SLSA L3 is
that buyers can independently verify provenance. The verification
runbook ([`../ADR-107a-slsa-level-3.md`](ADR-107a-slsa-level-3.md))
must be copy-paste-runnable on a clean machine with only `cosign` and
`slsa-verifier` installed. A great attestation that nobody can verify is
worthless.

---

## Consequences

**Positive**

- Production-grade supply-chain provenance independently verifiable by
  any consumer.
- Aligns with the supply-chain provenance expectations baked into CRA
  harmonised standards.
- Closes one of the most-asked enterprise procurement questions
  ("what's your SLSA level?").
- No new long-lived secrets; reuses Phase 202d's keyless cosign + Fulcio
  OIDC setup.

**Negative — and the explicit landing risk**

- **`id-token: write` permission moves from the job to the workflow level.**
  The `slsa-github-generator` reusable workflow requires the OIDC token
  permission at the calling workflow's top level. This is a non-trivial
  rewrite of the existing `permissions:` block in `go-proxy-image.yml`
  and `release-cli.yml`, and changing those workflows is a production
  release-pipeline change.
- **Mitigation: land under `workflow_dispatch`-only first.** Sub-tasks
  107c.3 and 107c.4 will commit the SLSA generator wiring with the
  existing `push:` triggers temporarily commented out; manually verify
  the published artefact + attestation; then restore `push:` triggers in
  a follow-up commit. This makes a botched wiring revertible in
  isolation.
- **Sigstore public-good infrastructure dependency.** Generator runs and
  verifier runs both depend on Fulcio + Rekor reachability. Phase 202d's
  ADR-202d already documents and accepts this risk; SLSA L3 increases
  the surface (now both the signing and the attestation-generation steps
  depend on it) but does not change the failure mode.

---

## Verifier story (for downstream consumers)

End-user operators verify provenance with two commands:

```bash
# 1. Install the verifier (one-off; SHA-pin the release).
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@<SHA>

# 2. Verify the published image.
slsa-verifier verify-image \
  --source-uri github.com/anomalyco/JA4proxy \
  ghcr.io/anomalyco/ja4proxy-go:<TAG>
```

Exit code 0 = attestation is valid, was generated by the
`slsa-github-generator` reusable workflow on the named source repo, and
binds to the image digest the verifier resolved. Any other exit code
means **do not deploy**. The full procedure (with example output and
failure-mode triage) lives in
[`../ADR-107a-slsa-level-3.md`](ADR-107a-slsa-level-3.md).

---

## Implementation references

- Phase doc: [`../phases/complete/PHASE_107.md`](../phases/complete/PHASE_107.md) §107c
- Sub-task breakdown: [`../phases/complete/PHASE_107_review.md`](../phases/complete/PHASE_107_review.md) §"Phase 2 — Core content" sub-tasks 107c.2, 107c.3, 107c.4, 107c.5, 107c.6
- Existing keyless-cosign decision: [`ADR-202d.md`](ADR-202d.md)
- Verifier runbook: [`../ADR-107a-slsa-level-3.md`](ADR-107a-slsa-level-3.md) (created by 107c.5)
- Test workflow: [`../../.github/workflows/slsa-verify.yml`](../../.github/workflows/slsa-verify.yml) (created by 107c.2)

---

## Revisit if…

- A concrete buyer asks for SLSA L4 — re-evaluate the cost of switching
  to a reproducible-build pipeline.
- Sigstore public infrastructure has a multi-hour outage that blocks an
  L3 release — same recovery path as ADR-202d (release waits).
- GitHub deprecates the `slsa-github-generator` reusable workflows — the
  ADR needs revisiting against whichever SLSA-L3-equivalent tooling
  emerges.
