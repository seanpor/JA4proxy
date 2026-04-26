# JA4proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![Go 1.25.9](https://img.shields.io/badge/go-1.25.9-00ADD8.svg)](https://go.dev/) ![CI](https://github.com/seanpor/JA4proxy/actions/workflows/ci.yml/badge.svg) [![7166 Tests](https://img.shields.io/badge/tests-7166-brightgreen.svg)](Makefile) [![Docker Ready](https://img.shields.io/badge/docker-compose-ready-2496ED.svg?logo=docker)](deploy/docker/docker-compose.poc.yml)

> **Production runtime is the Go proxy** (`cmd/proxy/`, `internal/`, built to
> `bin/proxy`). The Python proxy (`proxy.py`, `src/security/`) is an
> **experimental prototyping surface** for new signal modules and is not
> shipped to production. Default to the Go side. Touch the Python side only
> when prototyping a new signal or fixing the Python prototype itself.

JA4proxy is a TLS-aware passthrough security proxy that sits in front of web
server infrastructure. It makes allow/block/tarpit decisions from the
plaintext metadata visible before and during the TLS handshake — JA4
fingerprint, SNI, ALPN, ASN, reputation feeds, behavioural signals — and
forwards allowed connections byte-for-byte unchanged. It never decrypts
traffic and never holds TLS keys.

## Start by role

| You are a… | Start here |
|------------|------------|
| **Website owner / CISO** evaluating fit | [`docs/for-website-owners/`](docs/for-website-owners/README.md) |
| **Security architect** designing integration | [`docs/for-architects/`](docs/for-architects/README.md) |
| **Operator** running it day-to-day | [`docs/for-operators/`](docs/for-operators/README.md) |
| **Compliance / audit** | [`docs/for-compliance/`](docs/for-compliance/README.md) |
| **Developer / contributor** | [`docs/for-developers/`](docs/for-developers/README.md) |

## PDFs (offline reading)

| Audience | PDF | Source |
|----------|-----|--------|
| Business / commercial | [brochure](docs/pdf/brochure/brochure.pdf) | `docs/pdf/brochure/` |
| Operator | [user guide](docs/pdf/user-guide/user-guide.pdf) | `docs/pdf/user-guide/` |
| Architect | [reference manual](docs/pdf/reference-manual/reference-manual.pdf) | `docs/pdf/reference-manual/` |

## Quick verification (developers)

A fresh clone should build and test cleanly:

```bash
git clone https://github.com/seanpor/JA4proxy && cd JA4proxy
cp .env.example .env
pip install -r requirements.txt
GOROOT=/snap/go/current go build ./cmd/proxy
make test
```

For the full developer flow — branch strategy, test categories, signal
porting, Go/Python parity — see [`docs/for-developers/`](docs/for-developers/README.md).

## Architecture (one-paragraph)

The proxy sits between a TLS-passthrough load balancer and the backend.
Every connection is parsed for ClientHello metadata, run through bypass
checks (ALPN, JA4 lists, mTLS, Spamhaus), then scored by parallel signal
modules; the result is mapped to an action by the configurable dial. The
backend completes TLS itself — JA4proxy never decrypts payload.

```
Internet ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                      :443                  :8080               :443
                                              │  ▲
                           write events       │  │  write findings
                           (Redis Stream)     ▼  │  (Redis keys)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  FastAPI + React
                                         │     UI       │  :8090
                                         └──────────────┘
```

Architecture deep-dives, trust boundaries, ADRs, and DMZ readiness live in
[`docs/for-architects/`](docs/for-architects/README.md).

## Project status & manifest

- Live phase manifest: [`docs/phases/manifest.yaml`](docs/phases/manifest.yaml)
- Project status: [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md)
- Engineering method: [`docs/engineering-method/`](docs/engineering-method/README.md)
- Documentation index: [`docs/INDEX.md`](docs/INDEX.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE).
