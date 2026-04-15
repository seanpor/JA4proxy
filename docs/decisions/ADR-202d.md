# ADR-202d: Keyless Cosign Signing for the Go Proxy Image

**Status:** Accepted
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
  format documented explicitly; the header of
  `scripts/verify-image-signature.sh` points at this ADR and the cosign
  v2 bundle-mode behaviour is the default path the script exercises.
- **Dependency on Sigstore public-good infrastructure.** Fulcio/Rekor are
  run by the Sigstore project. Outage windows have occurred but are rare;
  we accept this risk. Operators needing stronger isolation can run a
  private Sigstore stack — out of scope for this ADR.

---

## SBOM handling (related, decided here)

- **Format:** CycloneDX JSON (via `anchore/sbom-action`).
- **Storage:** Attached to the image via the OCI referrers API.
  The workflow calls `cosign attach sbom --sbom sbom.cdx.json --type cyclonedx "${tag}@${DIGEST}"`
  (see `.github/workflows/go-proxy-image.yml:146`). The SBOM is ALSO
  uploaded as a workflow artifact for CI-retention convenience. We do
  NOT use `cosign attest` in addition to `cosign sign` in this phase —
  `attach sbom` is sufficient for `cosign download sbom`
  discoverability; `attest` with in-toto predicates is reserved for a
  future phase if attestation-based policy becomes a requirement.
- **Discoverability:** `cosign download sbom ghcr.io/.../ja4proxy-go:TAG`
  retrieves it. No separate SBOM publication pipeline — the image IS the
  carrier.
- **Not done:** submitting SBOMs to third-party SBOM registries, SPDX
  format (added by request only).

---

## Who verifies

- **End-user operators:** `scripts/verify-image-signature.sh <image-ref>`
  (shipped in repo; mode 755). Cross-referenced from
  `docs/runbooks/deploy_credentials.md` "Setting in CI" and from the
  phase-202 close-out notes.
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
- Build failures if Sigstore public infrastructure is down. Decided:
  we **do not** implement an emergency unsigned-push override in this
  phase. If Fulcio/Rekor is unavailable the release simply waits. This
  keeps the invariant "every image in GHCR is signed" true without
  exception, which simplifies the downstream verification story.
  Revisit if a real outage produces a concrete release-blocking
  incident.

## Revisit if...

- Sigstore public infrastructure has a multi-hour outage that blocks a
  release — re-evaluate running a private Sigstore or falling back to
  key-based for emergency releases.
- A downstream consumer requires offline-only verification with no
  initial Rekor fetch — the bundle-format story needs tightening.
- Admission-controller verification is prioritised — a follow-up ADR
  defines the policy (identity pinning, required annotations, etc.).

## Implementation notes

- Workflow: `.github/workflows/go-proxy-image.yml`, two jobs
  (`test` → `build-scan-sign-push`).
- Top-level permissions: `contents: read`, `packages: write`,
  `id-token: write` (OIDC exchange for keyless cosign).
- Triggers: path-based push (`deploy/docker/Dockerfile.go-proxy`,
  `cmd/proxy/**`, `internal/**`, `go.mod`, `go.sum`),
  git tags matching `v*-go-proxy`, and `workflow_dispatch`.
- Action SHAs (pinned, recorded in `PHASE_202.md`):
  - `sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da  # v3.7.0`
    (`.github/workflows/go-proxy-image.yml:121`)
  - `anchore/sbom-action@55dc4ee22412511ee8c3142cbea40418e6cec693  # v0.17.8`
    (line 99)
  - `aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0  # v0.29.0`
  - `docker/setup-buildx-action@4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd  # v4.0.0`
  - `docker/metadata-action@030e881283bb7a6894de51c315a6bfe6a94e05cf  # v6.0.0`
- Signing call: `cosign sign --yes "${tag}@${DIGEST}"` (line 134). No
  `--key` argument; keyless path only.
- SBOM attach: `cosign attach sbom --sbom sbom.cdx.json --type cyclonedx "${tag}@${DIGEST}"`
  (line 146).
- Bundle format: cosign v2.x default (attached, bundle-mode). The
  signature and Fulcio cert travel with the image; Rekor is still
  consulted by the verifier for transparency-log proof.
- Verification command (shipped as `scripts/verify-image-signature.sh`,
  mode 755):
  ```bash
  cosign verify "$image" \
    --certificate-identity-regexp "^https://github.com/anomalyco/JA4proxy/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  ```
- SBOM retrieval for an end user:
  `cosign download sbom ghcr.io/anomalyco/ja4proxy-go:TAG > sbom.cdx.json`
- Live sample output from the first signed build is deferred until
  after merge (the workflow has not run on `main` yet). See
  `PHASE_202_notes.md` for the explicit deferral note.
