#!/usr/bin/env bash
# scripts/verify-slsa.sh — Verify SLSA Level 3 provenance for JA4proxy artifacts.
#
# Phase 601 (SLSA Level 3 Release Pipeline).
#
# Verifies SLSA v1.0 provenance attestations cryptographically bound to
# JA4proxy container images (via GHCR / OCI) or binaries (via GitHub releases).
#
# Usage:
#   scripts/verify-slsa.sh image <image-ref> [source-uri]
#   scripts/verify-slsa.sh artifact <binary-path> --provenance-path <provenance-path> [source-uri]
#
# Examples:
#   scripts/verify-slsa.sh image ghcr.io/seanpor/ja4proxy-go:latest
#   scripts/verify-slsa.sh image ghcr.io/seanpor/ja4proxy-go@sha256:abc...
#   scripts/verify-slsa.sh artifact ./ja4proxy-cli --provenance-path ./multiple.intoto.jsonl
#
# Requirements:
#   - slsa-verifier (https://github.com/slsa-framework/slsa-verifier) installed in PATH
#
# Exit codes:
#   0 - Provenance successfully verified
#   1 - Verification failed or bad usage

set -euo pipefail

DEFAULT_SOURCE_URI="github.com/seanpor/JA4proxy"

command -v slsa-verifier >/dev/null 2>&1 || {
  echo "::error::slsa-verifier not found in PATH." >&2
  echo "Install it via: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.6.0" >&2
  echo "or download a pre-built binary from https://github.com/slsa-framework/slsa-verifier/releases" >&2
  exit 1
}

MODE="${1:-}"

case "${MODE}" in
  image)
    IMAGE_REF="${2:?Error: image-ref required (e.g. ghcr.io/seanpor/ja4proxy-go:latest)}"
    SOURCE_URI="${3:-${DEFAULT_SOURCE_URI}}"
    echo "==> Verifying SLSA provenance for container image: ${IMAGE_REF}"
    echo "    Expected source URI: ${SOURCE_URI}"
    slsa-verifier verify-image "${IMAGE_REF}" \
      --source-uri "${SOURCE_URI}"
    echo "✓ SLSA Level 3 provenance verification PASSED for ${IMAGE_REF}"
    ;;

  artifact)
    ARTIFACT_PATH="${2:?Error: binary/artifact path required}"
    shift 2
    PROVENANCE_PATH=""
    SOURCE_URI="${DEFAULT_SOURCE_URI}"

    while [ $# -gt 0 ]; do
      case "$1" in
        --provenance-path)
          PROVENANCE_PATH="${2:?Error: --provenance-path requires an argument}"
          shift 2
          ;;
        *)
          SOURCE_URI="$1"
          shift
          ;;
      esac
    done

    [ -n "${PROVENANCE_PATH}" ] || {
      echo "Error: --provenance-path <path-to-intoto.jsonl> is required for artifact verification" >&2
      exit 1
    }

    [ -f "${ARTIFACT_PATH}" ] || {
      echo "Error: artifact file '${ARTIFACT_PATH}' does not exist" >&2
      exit 1
    }

    [ -f "${PROVENANCE_PATH}" ] || {
      echo "Error: provenance file '${PROVENANCE_PATH}' does not exist" >&2
      exit 1
    }

    echo "==> Verifying SLSA provenance for artifact: ${ARTIFACT_PATH}"
    echo "    Provenance:          ${PROVENANCE_PATH}"
    echo "    Expected source URI: ${SOURCE_URI}"
    slsa-verifier verify-artifact "${ARTIFACT_PATH}" \
      --provenance-path "${PROVENANCE_PATH}" \
      --source-uri "${SOURCE_URI}"
    echo "✓ SLSA Level 3 provenance verification PASSED for ${ARTIFACT_PATH}"
    ;;

  *)
    echo "Usage:" >&2
    echo "  $0 image <image-ref> [source-uri]" >&2
    echo "  $0 artifact <artifact-path> --provenance-path <path> [source-uri]" >&2
    exit 1
    ;;
esac
