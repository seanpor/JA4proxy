# SLSA Level 3 Provenance Verification Runbook

> **Audience:** System Architects, Security Engineers, and Deployers  
> **Target Products:** `ghcr.io/seanpor/ja4proxy-go` (container image), `ja4proxy-cli` (binary)  
> **Assurance Level:** [SLSA Build Level 3](https://slsa.dev/spec/v1.0/levels) (non-falsifiable build provenance generated in isolated runners)

---

## 1. Overview & Security Guarantee

JA4proxy builds and signs all official production artifacts using cryptographic provenance via the OpenSSF [`slsa-framework/slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator).

Every production release produces a signed in-toto attestation (`https://slsa.dev/provenance/v1`) that binds:
1. **Source Repository & Commit SHA:** Cryptographic proof that the binary/image was built from `github.com/seanpor/JA4proxy` at a specific git commit.
2. **Builder Identity:** Confirmation that the build was executed by GitHub Actions using the hardened SLSA reusable workflows (`generator_container_slsa3.yml` or `generator_generic_slsa3.yml`).
3. **Immutability:** Protection against tampering during build or publication; the attestation cannot be generated or forged by repository maintainers outside the isolated runner environment.

---

## 2. Prerequisites

Verification requires [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) (version 2.6.0 or later).

### Option A: Install via Go (Host or Builder)
```bash
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.6.0
```

### Option B: Download Pre-built Binary
```bash
SLSA_VERIFIER_VERSION="v2.6.0"
SLSA_VERIFIER_SHA256="1c9c0d6a272063f3def6d233fa3372adbaff1f5a3480611a07c744e73246b62d"

curl --proto '=https' --tlsv1.2 -fsSL -o slsa-verifier \
  "https://github.com/slsa-framework/slsa-verifier/releases/download/${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-amd64"

echo "${SLSA_VERIFIER_SHA256}  slsa-verifier" | sha256sum -c -
chmod +x slsa-verifier
sudo mv slsa-verifier /usr/local/bin/
```

Verify the installation:
```bash
slsa-verifier version
```

---

## 3. Verifying Go Proxy Container Images

Official images are pushed to GitHub Packages Container Registry (`ghcr.io/seanpor/ja4proxy-go`). Provenance attestations are stored alongside the image in GHCR as OCI artifacts.

### Using the Helper Script
```bash
scripts/verify-slsa.sh image ghcr.io/seanpor/ja4proxy-go:<TAG_OR_DIGEST>
```

### Direct Verification via `slsa-verifier`
```bash
slsa-verifier verify-image ghcr.io/seanpor/ja4proxy-go:<TAG_OR_DIGEST> \
  --source-uri github.com/seanpor/JA4proxy
```

To verify against an exact git release tag (e.g., `v2.0.0-go-proxy`):
```bash
slsa-verifier verify-image ghcr.io/seanpor/ja4proxy-go:v2.0.0-go-proxy \
  --source-uri github.com/seanpor/JA4proxy \
  --source-tag v2.0.0-go-proxy
```

### Expected Output
```text
Verifying image ghcr.io/seanpor/ja4proxy-go:v2.0.0-go-proxy...
PASSED: Verified SLSA provenance
  Generator: https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@...
  Source: github.com/seanpor/JA4proxy
  Source Commit: 8fa2...
```

---

## 4. Verifying CLI Binaries

Each GitHub release of `ja4proxy-cli` includes release archives, checksums, and an accompanying provenance file `attestation.intoto.jsonl` (or `multiple.intoto.jsonl`).

### Using the Helper Script
```bash
scripts/verify-slsa.sh artifact ./ja4proxy-cli \
  --provenance-path ./attestation.intoto.jsonl
```

### Direct Verification via `slsa-verifier`
```bash
slsa-verifier verify-artifact ./ja4proxy-cli \
  --provenance-path ./attestation.intoto.jsonl \
  --source-uri github.com/seanpor/JA4proxy \
  --source-tag v2.0.0
```

---

## 5. Automated CI Verification (`slsa-verify.yml`)

The repository includes a verification workflow in [`.github/workflows/slsa-verify.yml`](../../.github/workflows/slsa-verify.yml).

To trigger an on-demand verification against any published image tag:
```bash
gh workflow run slsa-verify.yml -f image_ref=ghcr.io/seanpor/ja4proxy-go:latest
```

---

## 6. Failure Modes & Triage

| Failure Message | Cause | Resolution |
|---|---|---|
| `no attestation found` | The image/binary was pushed without running the SLSA generator workflow. | Do not deploy into production. Check if image tag is a development build or was built before SLSA L3 pipeline was enabled. |
| `source repository mismatch` | The image was built from a fork or untrusted repository. | Do not deploy. Only artifacts built from `github.com/seanpor/JA4proxy` are authentic. |
| `tag mismatch` | The artifact was not built from the claimed release tag. | Verify if tag was moved or if the build was triggered from an un-tagged commit. |
| `certificate verification failed` | Sigstore Fulcio / Rekor transparency log issue or untrusted certificate issuer. | Check network connectivity to Sigstore services (`sigstore.dev`) and ensure system clocks are synchronized. |

