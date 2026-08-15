# Phase 229: aligned to the single pinned Go base used everywhere else
# (was golang:1.25.10-alpine — a drifted, unpinned version).
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df

RUN apk add --no-cache git && \
    addgroup -g 1001 -S scanner && adduser -u 1001 -S -G scanner scanner

RUN go install golang.org/x/vuln/cmd/govulncheck@latest &&     go install github.com/securego/gosec/v2/cmd/gosec@latest

WORKDIR /app

HEALTHCHECK NONE

USER scanner

# The user will mount the project root to /app
ENTRYPOINT ["/bin/sh", "-c"]
