FROM golang:1.25.10-alpine

RUN apk add --no-cache git

RUN go install golang.org/x/vuln/cmd/govulncheck@latest &&     go install github.com/securego/gosec/v2/cmd/gosec@latest

WORKDIR /app

# The user will mount the project root to /app
ENTRYPOINT ["/bin/sh", "-c"]
