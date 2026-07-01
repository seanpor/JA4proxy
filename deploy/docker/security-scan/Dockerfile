# Phase 229: aligned to the single pinned Go base used everywhere else
# (was golang:1.25.10-alpine — a drifted, unpinned version).
FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f

RUN apk add --no-cache git && \
    addgroup -g 1001 -S scanner && adduser -u 1001 -S -G scanner scanner

RUN go install golang.org/x/vuln/cmd/govulncheck@latest &&     go install github.com/securego/gosec/v2/cmd/gosec@latest

WORKDIR /app

HEALTHCHECK NONE

USER scanner

# The user will mount the project root to /app
ENTRYPOINT ["/bin/sh", "-c"]
