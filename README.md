# JA4proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/downloads/)
[![Go 1.26.4](https://img.shields.io/badge/go-1.26.4-00ADD8.svg)](https://go.dev/)
![CI](https://github.com/seanpor/JA4proxy/actions/workflows/ci.yml/badge.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seanpor/JA4proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/seanpor/JA4proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/seanpor/JA4proxy)](https://goreportcard.com/report/github.com/seanpor/JA4proxy)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/seanpor/JA4proxy.svg)](https://pkg.go.dev/github.com/seanpor/JA4proxy)
[![Coverage](https://img.shields.io/badge/coverage-verified-brightgreen)](#-go-test-coverage)
[![GitHub release (latest by mature)](https://img.shields.io/github/v/release/seanpor/JA4proxy)](https://github.com/seanpor/JA4proxy/releases)

> **Enterprise-Grade Go Runtime**: JA4proxy is a high-performance, strictly typed Go application built for sub-millisecond latency. All legacy Python prototyping components have been archived. The ecosystem includes a robust Python Management API and Analytics worker.

JA4proxy is a TLS-aware passthrough security proxy that sits in front of web server infrastructure. It makes allow/block/tarpit decisions from the plaintext metadata visible before and during the TLS handshake — JA4 fingerprint, SNI, ALPN, ASN, reputation feeds, behavioural signals — and forwards allowed connections byte-for-byte unchanged. It never decrypts traffic and never holds TLS keys.

## Security Posture (Trust but Verify)

Our governance model aligns with **OpenSSF** and **SLSA** best practices to ensure a hardened supply chain:
- **Immutable Dependencies**: All Docker base images are pinned to SHA256 digests.
- **SBOM Generation**: Full CycloneDX Software Bill of Materials via `make sbom`.
- **Automated Auditing**: Continuous OpenSSF Scorecard auditing on the `main` branch.
- **Least Privilege**: Strict GitHub Action token permissions (`read-all` default).
- **Control Plane Integrity**: Tamper-proof, signed enforcement updates via Redis.

## Start by role

| You are a… | Start here |
|------------|------------|
| **Website owner / CISO** evaluating fit | [`docs/WHY_JA4PROXY.md`](docs/WHY_JA4PROXY.md) |
| **Security architect** designing integration | [`docs/security/ARCHITECTURE.md`](docs/security/ARCHITECTURE.md) |
| **Operator** running it day-to-day | [`docs/OPERATIONS.md`](docs/OPERATIONS.md) |
| **Compliance / audit** | [`docs/compliance/`](docs/compliance/) |
| **Developer / contributor** | [`docs/developer/`](docs/developer/) |

## PDFs (offline reading)

| Audience | PDF | Source |
|----------|-----|--------|
| Business / commercial | [brochure](docs/pdf/brochure/brochure.pdf) | `docs/pdf/brochure/` |
| Operator | [user guide](docs/pdf/user-guide/user-guide.pdf) | `docs/pdf/user-guide/` |
| Architect | [reference manual](docs/pdf/reference-manual/reference-manual.pdf) | `docs/pdf/reference-manual/` |

## Quick verification (developers)

A fresh clone should build cleanly and pass the full test suite:

```bash
git clone https://github.com/seanpor/JA4proxy && cd JA4proxy
cp .env.example .env
make build
make test-go test-unit
```

## Architecture (one-paragraph)

The proxy sits between a TLS-passthrough load balancer and the backend. Every connection is parsed for ClientHello metadata, run through strict hard-block checks (Blacklists, GeoIP), then scored by parallel signal modules (Malformed SNI, TLS version mismatch). The result is mapped to an action by a configurable, signed dial. The backend completes TLS itself — JA4proxy never decrypts the payload.

```
Internet ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                      :443                  :8080               :443
                                              │  ▲
                           write events       │  │  signed dial & lists
                           (Redis Stream)     ▼  │  (Redis pub/sub)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  FastAPI
                                         │     API      │
                                         └──────────────┘
```