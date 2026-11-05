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

if command -v go >/dev/null 2>&1; then
    GO_CMD="go"
elif [ -x /snap/go/current/bin/go ]; then
    export GOROOT=/snap/go/current
    GO_CMD="/snap/go/current/bin/go"
elif command -v docker >/dev/null 2>&1; then
    echo "Host 'go' not found — executing build in golang:1.27.3-alpine container"
    OUTPUT_DIR="$(dirname "${OUTPUT}")"
    mkdir -p "${OUTPUT_DIR}"
    exec docker run --rm -v "${PWD}:/src" -w /src \
        -e VERSION="${VERSION}" -e GIT_COMMIT="${GIT_COMMIT}" -e BUILD_DATE="${BUILD_DATE}" \
        golang:1.27.3-alpine sh -c "
            apk add --no-cache gcc musl-dev >/dev/null 2>&1
            CGO_ENABLED=1 GOOS=linux go build \
                -buildmode=pie \
                -trimpath \
                -tags '${TAGS}' \
                -ldflags='${LDFLAGS}' \
                -o '${OUTPUT}' \
                '${PKG}'
        "
else
    echo "Error: neither 'go' nor 'docker' is available to build Go binaries" >&2
    exit 1
fi

CGO_ENABLED=1 GOOS=linux ${GO_CMD} build \
    -buildmode=pie \
    -trimpath \
    -tags "${TAGS}" \
    -ldflags="${LDFLAGS}" \
    -o "${OUTPUT}" \
    "${PKG}"
