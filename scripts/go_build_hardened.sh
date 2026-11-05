#!/usr/bin/env sh
# Single-source build script for hardened Go binaries (Phase 863)
# Enforces PIE, BIND_NOW, GNU_RELRO, -trimpath, -buildid=, and netgo/osusergo resolvers.
set -eu

OUTPUT="${1:?Usage: $0 <output-path> <package-path> [extra-tags]}"
PKG="${2:?Usage: $0 <output-path> <package-path> [extra-tags]}"
EXTRA_TAGS="${3:-}"

TAGS="netgo,osusergo"
if [ -n "$EXTRA_TAGS" ]; then
    TAGS="${TAGS},${EXTRA_TAGS}"
fi

VERSION="${VERSION:-2.0}"
GIT_COMMIT="${GIT_COMMIT:-unknown}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

LDFLAGS="-s -w -buildid= -linkmode external -extldflags \"-static -z relro -z now\" \
  -X github.com/seanpor/ja4proxy/internal/config.Version=${VERSION} \
  -X github.com/seanpor/ja4proxy/internal/config.GitCommit=${GIT_COMMIT} \
  -X github.com/seanpor/ja4proxy/internal/config.BuildDate=${BUILD_DATE}"

CGO_ENABLED=1 GOOS=linux go build \
    -buildmode=pie \
    -trimpath \
    -tags "${TAGS}" \
    -ldflags="${LDFLAGS}" \
    -o "${OUTPUT}" \
    "${PKG}"
