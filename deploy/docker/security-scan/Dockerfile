# Phase 229: aligned to the single pinned Go base used everywhere else
# (was golang:1.25.10-alpine — a drifted, unpinned version).
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba

RUN apk add --no-cache git && \
    addgroup -g 1001 -S scanner && adduser -u 1001 -S -G scanner scanner

RUN go install golang.org/x/vuln/cmd/govulncheck@latest &&     go install github.com/securego/gosec/v2/cmd/gosec@latest

WORKDIR /app

HEALTHCHECK NONE

USER scanner

# The user will mount the project root to /app
ENTRYPOINT ["/bin/sh", "-c"]
