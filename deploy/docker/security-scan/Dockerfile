# Phase 229: aligned to the single pinned Go base used everywhere else
# (was golang:1.25.10-alpine — a drifted, unpinned version).
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2

RUN apk add --no-cache git && \
    addgroup -g 1001 -S scanner && adduser -u 1001 -S -G scanner scanner

RUN go install golang.org/x/vuln/cmd/govulncheck@latest &&     go install github.com/securego/gosec/v2/cmd/gosec@latest

WORKDIR /app

HEALTHCHECK NONE

USER scanner

# The user will mount the project root to /app
ENTRYPOINT ["/bin/sh", "-c"]
