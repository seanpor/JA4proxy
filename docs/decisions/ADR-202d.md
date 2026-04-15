# ADR-202d: Keyless Cosign Signing for the Go Proxy Image

**Status:** Proposed
**Date:** 2026-04-15
**Phase:** 202 (CI supply chain hardening) — sub-phase 202d

---

## Context

Phase 202d introduces the first CI workflow that builds, scans, SBOMs,
signs, and pushes the Go proxy container image
(`.github/workflows/go-proxy-image.yml` → `ghcr.io/anomalyco/ja4proxy-go`).
A signing strategy must be chosen before the workflow is implemented so
that downstream consumers (Helm chart, `scripts/verify-image-signature.sh`,
any future admission controller) build against a stable verification model.

Two signing backends are viable for a `sigstore/cosign` workflow running in
GitHub Actions:

1. **Keyless (Fulcio OIDC).** cosign exchanges the workflow's OIDC token
   (issued by `token.actions.githubusercontent.com`) for a short-lived
   X.509 signing cert from Fulcio. The cert's subject encodes the
   GitHub repo, workflow ref, and SHA. The signature and cert are logged
   to the Rekor transparency log. **No long-lived signing key exists in
   the repo or in CI secrets.**

2. **Key-based (`COSIGN_PRIVATE_KEY`).** A long-lived cosign private key is
   generated once, encrypted with `COSIGN_PASSWORD`, and stored as two
   GitHub Actions secrets. The workflow uses them on every sign.

---

## Decision

**Use keyless cosign (Fulcio OIDC).**

Concrete implications baked into the workflow:

- `id-token: write` permission added to the `sign` job (required for
  OIDC token exchange).
- `cosign sign --yes ghcr.io/anomalyco/ja4proxy-go@${IMAGE_DIGEST}` — no
  `--key` flag, no `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` secrets.
- Verification regex used by `scripts/verify-image-signature.sh`:
  ```
  cosign verify "$image" \
    --certificate-identity-regexp "^https://github.com/anomalyco/JA4proxy/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  ```

---

## Rationale

**Keyless wins on operational grounds:**

- **No key rotation runbook needed.** The Fulcio-issued cert is valid for
  ~10 minutes; expiry is handled by the transparency-log record rather than
  by rotating a static key. We do not need a "rotate cosign key every 90
  days" entry in `credential_rotation.md`.
- **No long-lived secrets to leak.** The #1 operational failure mode of
  key-based signing is the static key being accidentally committed or
  leaked via a misconfigured CI job. Keyless removes the attack surface.
- **Identity-based verification is stronger.** Downstream consumers verify
  against the GitHub repo + workflow identity, not "did this key sign it."
  A leaked key can sign anywhere; a leaked OIDC token is scoped to one
  workflow run and expires in minutes.
- **Transparency log.** Every signature is publicly logged to Rekor. A
  surreptitious signing run is auditable.

**Tradeoffs accepted:**

- **Online verification.** Verification requires reaching the Rekor log
  and Fulcio CA (offline verification needs a signature bundle attached
  to the image; we DO attach one via `cosign sign --yes` which defaults
  to bundle-mode in cosign v2.x). Air-gapped consumers need the bundle
  format documented explicitly. <!-- TODO: verify after impl — document
  bundle-mode behaviour in scripts/verify-image-signature.sh header. -->
- **Dependency on Sigstore public-good infrastructure.** Fulcio/Rekor are
  run by the Sigstore project. Outage windows have occurred but are rare;
  we accept this risk. Operators needing stronger isolation can run a
  private Sigstore stack — out of scope for this ADR.

---

## SBOM handling (related, decided here)

- **Format:** CycloneDX JSON (via `anchore/sbom-action`).
- **Storage:** Attached to the image via the OCI referrers API
  (`cosign attach sbom` or the sbom-action's built-in attach step).
  <!-- TODO: verify after impl — confirm which tool writes the attachment
  and whether `cosign attest` is used in addition to `cosign sign`. -->
- **Discoverability:** `cosign download sbom ghcr.io/.../ja4proxy-go:TAG`
  retrieves it. No separate SBOM publication pipeline — the image IS the
  carrier.
- **Not done:** submitting SBOMs to third-party SBOM registries, SPDX
  format (added by request only).

---

## Who verifies

- **End-user operators:** `scripts/verify-image-signature.sh <image-ref>`
  (shipped in repo). Documented in
  `docs/runbooks/docker_image_updates.md` <!-- TODO: verify after impl --
  add a cross-link section here -->.
- **Helm chart users:** verify before `helm install`; documented in the
  chart README.
- **CI consumers:** PR workflows that pull `ghcr.io/anomalyco/ja4proxy-go`
  should call `verify-image-signature.sh` before `docker run`.

**Not yet enforced:** Kubernetes admission controller (Kyverno / Sigstore
policy-controller) verification at deploy time. Documented as future work
— once the signed-image pipeline has run cleanly for a few releases, a
follow-up phase can add a cluster admission policy. That work also needs
to decide whether to pin to a single workflow ref or allow any workflow
in the `anomalyco/JA4proxy` repo to sign, which affects the CI identity
regex above.

---

## Consequences

**Positive**
- Zero long-lived signing secrets in GitHub Actions; no rotation surface.
- Transparent-log-auditable supply chain.
- SBOM co-located with image for one-step retrieval.

**Negative**
- Online verification required (Fulcio/Rekor reachability).
- Build failures if Sigstore public infrastructure is down. Mitigation:
  push without signing as an emergency override, flagged by a manual
  `workflow_dispatch` input. <!-- TODO: verify after impl — decide whether
  to implement the override or accept "wait for Sigstore to come back". -->

## Revisit if...

- Sigstore public infrastructure has a multi-hour outage that blocks a
  release — re-evaluate running a private Sigstore or falling back to
  key-based for emergency releases.
- A downstream consumer requires offline-only verification with no
  initial Rekor fetch — the bundle-format story needs tightening.
- Admission-controller verification is prioritised — a follow-up ADR
  defines the policy (identity pinning, required annotations, etc.).

## Implementation notes

<!-- TODO: verify after impl — fill after 202d lands:
  - final action SHAs for cosign-installer, sbom-action, trivy-action
  - bundle format used (attached vs detached)
  - SBOM attachment verification command
  - sample output of scripts/verify-image-signature.sh on the first signed build
-->
