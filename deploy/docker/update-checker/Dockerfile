FROM golang:1.25.10-alpine AS go-base

FROM python:3.14-alpine

# Install Go from the base image
COPY --from=go-base /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Node.js and other tools
RUN apk add --no-cache nodejs npm git

WORKDIR /app

# The user will mount the project root to /app
ENTRYPOINT ["python3", "scripts/check_updates.py"]
