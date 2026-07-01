# Release Process — `ja4proxy-cli`

This runbook covers the end-to-end process for releasing a signed `ja4proxy-cli`
binary, from one-time key setup through to user verification of a downloaded artifact.

See ADR-083a for the rationale behind Goreleaser and GPG signing.

---

## Prerequisites

- Go 1.25 or later installed
- `goreleaser` installed:
  ```bash
  go install github.com/goreleaser/goreleaser/v2@latest
  ```
- GPG 2.x installed (`gpg --version`)
- Access to the GitHub repository secrets page (for initial setup only)

---

## Setting Up the GPG Release Key (one-time)

Generate a dedicated release key. Do not use a personal GPG key for releases.

```bash
# Generate a 4096-bit RSA key with a 2-year expiry, no passphrase (required for CI)
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: JA4proxy Release
Name-Email: releases@ja4proxy.io
Expire-Date: 2y
EOF
```

Export the private key for the GitHub Actions secret:

```bash
gpg --armor --export-secret-keys releases@ja4proxy.io
```

<!-- nosemgrep: generic.secrets.security.detected-pgp-private-key-block.detected-pgp-private-key-block -->
Copy the full output (including the PGP private key block header and
footer) and store it as the GitHub Actions secret `GPG_SIGNING_KEY`.

Find the key fingerprint:

```bash
gpg --list-keys --fingerprint releases@ja4proxy.io
```

Store the fingerprint (40-character hex string, no spaces) as the GitHub Actions
secret `GPG_FINGERPRINT`.

Export the public key for users to verify artifacts:

```bash
gpg --armor --export releases@ja4proxy.io > docs/developer/ja4proxy-release.asc
```

Commit `docs/developer/ja4proxy-release.asc` to the repository. This file is
referenced in the verification instructions below.

### Key Rotation

When the key expires or needs to be rotated:

1. Generate a new key pair following the steps above.
2. Update the `GPG_SIGNING_KEY` and `GPG_FINGERPRINT` GitHub Actions secrets.
3. Replace `docs/developer/ja4proxy-release.asc` with the new public key.
4. Commit the updated public key file.
5. Announce the key rotation in the release notes for the next version.

---

## Creating a Release

Tag the commit you want to release with a `v`-prefixed semantic version tag.
Use a signed tag (`-s`) to create a chain of trust from the tag to the binary.

```bash
git checkout main
git pull

# Tag the release (use -s for a GPG-signed tag)
git tag -s v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

The push triggers `.github/workflows/release-cli.yml`, which:

1. Runs `go test ./...` — the release aborts if any test fails
2. Builds binaries for all five platforms (linux/amd64, linux/arm64, darwin/amd64,
   darwin/arm64, windows/amd64) using Goreleaser
3. Signs each binary with a detached GPG signature (`.asc` file)
4. Generates `checksums.txt` (SHA-256 of every artifact) and signs it
5. Uploads SLSA level 2 provenance attestation via `slsa-github-generator`
6. Creates the GitHub release with all artifacts attached

The full release process takes approximately 5–10 minutes depending on GitHub Actions
runner load.

---

## Verifying a Release

These instructions are for operators and end users who want to verify the integrity of
a downloaded binary.

### Download Artifacts

```bash
VERSION=v1.0.0
BASE=https://github.com/seanpor/ja4proxy/releases/download/${VERSION}

curl -LO ${BASE}/ja4proxy-cli_linux_amd64.tar.gz
curl -LO ${BASE}/ja4proxy-cli_linux_amd64.tar.gz.asc
curl -LO ${BASE}/checksums.txt
curl -LO ${BASE}/checksums.txt.asc
```

### Import the Project Release Key

```bash
curl -s https://raw.githubusercontent.com/seanpor/ja4proxy/main/docs/developer/ja4proxy-release.asc \
  | gpg --import
```

### Verify the GPG Signature

```bash
# Verify the checksum file signature first
gpg --verify checksums.txt.asc checksums.txt

# Verify the binary archive signature
gpg --verify ja4proxy-cli_linux_amd64.tar.gz.asc ja4proxy-cli_linux_amd64.tar.gz
```

Both commands should output `Good signature from "JA4proxy Release <releases@ja4proxy.io>"`.

### Verify the SHA-256 Checksum

```bash
sha256sum --check checksums.txt --ignore-missing
```

Expected output: `ja4proxy-cli_linux_amd64.tar.gz: OK`

### Verify SLSA Provenance

SLSA provenance confirms that the binary was built by the expected GitHub Actions
workflow on a GitHub-hosted runner, not on a compromised machine.

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download the provenance file from the release
curl -LO ${BASE}/multiple.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/seanpor/ja4proxy \
  ja4proxy-cli_linux_amd64.tar.gz
```

Expected output: `PASSED: SLSA verification passed`

---

## Local Release Test (without publishing)

Run a full release build locally to verify the Goreleaser configuration before
pushing a tag:

```bash
goreleaser release --snapshot --clean
```

Artifacts appear in `dist/`. The `--snapshot` flag sets the version to a
timestamp-based string and skips publishing, signing, and provenance upload.

To test the full pipeline including signing (requires your local GPG key):

```bash
export GPG_FINGERPRINT="<your-test-key-fingerprint>"
goreleaser release --snapshot --clean
```

---

## Troubleshooting

### `gpg: signing failed: No secret key`

The `GPG_SIGNING_KEY` secret is not set, or was set incorrectly (missing the PEM
header/footer lines). Re-export the key with `--armor` and update the secret.

### Goreleaser build fails with `go: module lookup disabled`

The release environment is air-gapped. Set `GONOSUMCHECK=*` and `GOFLAGS=-mod=mod`
in the workflow environment, or pre-download all dependencies with `go mod download`
before the build step.

### SLSA provenance upload fails

The `slsa-github-generator` action requires that the workflow is triggered by a
`push` event on a `v*` tag. Manual workflow dispatch (`workflow_dispatch`) does not
produce valid SLSA provenance. Use a real version tag.

### Release tag already exists

If you need to re-release the same version (e.g., after fixing a broken artifact):

1. Delete the GitHub release (do not delete the tag if it has been announced).
2. Delete the tag locally and remotely: `git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0`.
3. Re-create the tag and push it.

Do not reuse a version tag for a different commit. Use a patch version bump instead.
