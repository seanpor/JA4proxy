FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS go-base

FROM python:3.15.2-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd

# Install Go from the base image
COPY --from=go-base /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOCACHE=/tmp/gocache \
    GOPATH=/tmp/gopath \
    PIP_CACHE_DIR=/tmp/pip-cache \
    PYTHONUSERBASE=/tmp/pyuser

# Install Node.js and other tools, and prepare writable cache dirs for non-root user
RUN apk add --no-cache nodejs npm git && \
    addgroup -S checker && adduser -S -G checker checker && \
    mkdir -p /tmp/gocache /tmp/gopath /tmp/pip-cache /tmp/pyuser && \
    chmod 1777 /tmp/gocache /tmp/gopath /tmp/pip-cache /tmp/pyuser

WORKDIR /app

HEALTHCHECK NONE

USER checker

# The user will mount the project root to /app
ENTRYPOINT ["python3", "scripts/check_updates.py"]
