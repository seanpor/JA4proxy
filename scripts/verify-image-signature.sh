#!/usr/bin/env bash
# Usage: scripts/verify-image-signature.sh <image-ref>
#
# Verifies a keyless cosign signature for a JA4proxy container image.
# The certificate must chain to the Fulcio root and be issued to a workflow
# running from this repo under the github-actions OIDC issuer.
#
# See docs/decisions/ADR-202d.md.

set -euo pipefail

image="${1:?image-ref required (e.g. ghcr.io/seanpor/ja4proxy-go:sha-abc123)}"

cosign verify "$image" \
  --certificate-identity-regexp "^https://github.com/seanpor/JA4proxy/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
