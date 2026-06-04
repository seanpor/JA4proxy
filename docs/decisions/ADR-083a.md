# ADR-083a: Release Tooling for `ja4proxy-cli`

**Status:** Accepted
**Date:** 2026-04-07
**Phase:** 83 (`ja4proxy-cli` Go Binary)

---

## Context

Phase 83 requires signed binary releases of `ja4proxy-cli` for standalone download
and container image distribution. The acceptance criteria specify:

- GPG signature (detached `.asc`) for every binary artifact
- SLSA level 2 provenance attestation (build on GitHub-hosted runner, provenance JSON
  uploaded to the GitHub release)
- `checksums.txt` with SHA-256 of every binary
- Multi-arch support: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64,
  windows/amd64

The release workflow lives at `.github/workflows/release-cli.yml`. The signing key
is stored as a GitHub Actions secret `GPG_SIGNING_KEY`.

Two options were evaluated for assembling this pipeline.

---

## Options

### Option A: Goreleaser

Goreleaser is a declarative release tool for Go projects. A single `.goreleaser.yml`
configuration file drives the entire release pipeline:

- Multi-arch cross-compilation using `GOARCH`/`GOOS` matrix defined in one place
- `checksums.txt` generated automatically from all built artifacts
- GPG signing via a `signs:` block — passes each artifact through `gpg --detach-sign`
  using the key exported from the `GPG_SIGNING_KEY` GitHub Actions secret
- Native integration with `slsa-github-generator` action for SLSA level 2 provenance
  attestation
- Docker image build and push via `dockers:` block (produces `FROM scratch` image)
- Single `goreleaser release` command in CI; `goreleaser release --snapshot --clean`
  for local testing without publishing

Goreleaser is the industry standard for Go project binary distribution. Its
integration with `slsa-github-generator` is well-documented and maintained by the
OpenSSF SLSA project.

**Complexity:** Low. One config file, one CI workflow step.
**Maintenance burden:** Minimal. `goreleaser` is a single versioned binary.

### Option B: Manual `go build` + shell scripts

Each platform binary built by hand with `GOOS`/`GOARCH` environment variables, driven
by a shell script or CI matrix. Signing performed with `gpg --detach-sign` in a manual
loop. `checksums.txt` assembled with `sha256sum`.

SLSA provenance requires a separate, manually configured workflow using
`slsa-github-generator`. The provenance upload step and the binary signing step must
be coordinated to avoid race conditions in parallel CI jobs.

**Complexity:** High. 200+ lines of CI YAML. Each new platform requires updating
multiple workflow sections.
**Maintenance burden:** High. GPG signing, checksum generation, provenance upload,
and Docker build are each maintained as separate scripts.

---

## Decision

**Option A (Goreleaser).**

Reasons:

1. A single `.goreleaser.yml` drives all platforms. Adding a new platform requires one
   line in the `builds:` matrix.
2. The `slsa-github-generator` integration is officially documented and well-tested for
   Goreleaser workflows. Using it with hand-rolled scripts requires more configuration
   and is more likely to produce incomplete provenance.
3. `checksums.txt` is generated automatically and signed as part of the same
   `signs:` block, so the checksum file itself is covered by the GPG signature.
4. `goreleaser release --snapshot --clean` allows full local testing of the release
   pipeline without publishing, which makes CI failures easier to reproduce and debug.
5. Goreleaser is proven in production at comparable scale (it is used by many
   open-source security tools with similar release requirements).

---

## Consequences

- `goreleaser` is added to the project as a tool dependency in `tools.go`
  (following Go tool dependency conventions):
  ```go
  //go:build tools
  package tools

  import _ "github.com/goreleaser/goreleaser/v2"
  ```
- `.goreleaser.yml` is added to the repository root. It configures builds for all
  five target platforms, GPG signing, checksum generation, SLSA provenance, and Docker
  image push to `ghcr.io/seanpor/ja4proxy-cli`.
- GitHub Actions secrets required: `GPG_SIGNING_KEY` (armored private key export),
  `GPG_FINGERPRINT` (used to select the key for signing).
- The release public key is committed at `docs/developer/ja4proxy-release.asc` so
  users can verify artifacts without a keyserver.
- One-time key generation and CI secret setup is documented in
  `docs/developer/RELEASE_PROCESS.md`.
- The release workflow (`.github/workflows/release-cli.yml`) triggers on `v*` tags
  pushed to `main`. It runs `go test ./...` before releasing to prevent publishing
  a broken binary.
