FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS go-base

FROM python:3.15.2-alpine3.24@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

# Install Go from the base image
COPY --from=go-base /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Node.js and other tools
RUN apk add --no-cache nodejs npm git && \
    addgroup -S checker && adduser -S -G checker checker

WORKDIR /app

HEALTHCHECK NONE

USER checker

# The user will mount the project root to /app
ENTRYPOINT ["python3", "scripts/check_updates.py"]
