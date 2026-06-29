# JA4proxy — Open-Source Bot Protection

> **Under attack right now?** Jump to [Emergency Deploy](#emergency-deploy) — 3 commands, 5 minutes, no config files.
>
> **Already running?** &rarr; [Incident response](docs/operations/INCIDENT_RESPONSE.md) (block a fingerprint in 30 seconds)

## What is this?

If bots are filling out your forms, scraping your content, stuffing credentials
into your login page, or hammering your checkout — JA4proxy stops them.

It sits in front of your website and identifies automated tools by *how their
software connects*, not by what they send. Every piece of software — browsers,
bots, scrapers, curl, Python requests — creates a unique fingerprint when it
opens a connection. Real browsers look structurally different from everything
else. JA4proxy sees that difference on the very first connection, before the
bot even sends a request, and blocks it.

**Think of it like a bouncer who can tell a real ID from a fake one by the paper
it's printed on — before reading the name.**

You don't need to change your website, add CAPTCHAs, or modify any code. The
proxy forwards legitimate traffic byte-for-byte unchanged. It never decrypts
your traffic and never touches your TLS keys.

## Will this break my site?

**No.** Three guarantees make this safe to deploy:

1. **Monitor mode by default.** On first deploy, JA4proxy scores every
   connection but blocks nothing. You see exactly what *would* be blocked
   before you turn on enforcement. Go at your own pace.

2. **Real browsers can't be blocked.** Modern browsers identify themselves
   during the connection handshake in a way bots can't fake. These connections
   bypass all scoring — they cannot be blocked by any rule, threshold, or
   misconfiguration. This is an architectural guarantee, not a heuristic.

3. **Fail open, always.** If anything goes wrong — a lookup service is slow,
   Redis is down, a signal module crashes — the proxy lets the connection
   through and logs the problem. A missed bad request is recoverable. A blocked
   customer is not.

## Emergency Deploy

Get protection running in under 5 minutes. You need Docker and your backend's
hostname.

```bash
git clone https://github.com/seanpor/JA4proxy.git && cd JA4proxy
export BACKEND_HOST=your-server.com
docker compose up -d
```

JA4proxy is now scoring connections on port **8443**.

**If you're on this machine:** open `http://127.0.0.1:8090` or `https://127.0.0.1:8444`
for the dashboard.

**If you're working remotely** (the normal case — the server is in a datacentre and
you're at home or on a different network):

```bash
# SSH tunnel — works through corporate VPN, bastion hosts, and firewalls
# Replace bastion.example.com and dmz-host with your actual hostnames
ssh -J you@bastion.example.com you@dmz-host \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N
# Then open: https://127.0.0.1:8444  (or http://127.0.0.1:8090)
```

See [Dashboard Access](docs/runbooks/dashboard_access.md) for the full guide including
corporate proxy bypass, two-datacentre setups, and the emergency change procedure.

To verify traffic is flowing through the proxy (from the server itself):

```bash
curl -kv https://127.0.0.1:8443/
```

For the full emergency deployment guide with port 443 setup, traffic insertion, and
blocking instructions, see [Emergency Deploy](docs/operations/EMERGENCY_DEPLOY.md).

### First 5 minutes after deploy

1. **Open the dashboard** — see the SSH tunnel command above if working remotely.
   You'll see connections arriving with fingerprints and risk scores.
2. **Watch for a few minutes.** The proxy is in monitor mode (dial=0) — scoring
   everything, blocking nothing.
3. **Look at the top fingerprints.** Bots cluster on a small number of
   signatures. Real browsers are labelled and bypassed automatically.
4. **Block a bad fingerprint.** Click the block button next to a bot signature,
   or from the CLI: `./scripts/ja4-admin.sh block-ja4 <fingerprint>`
5. **Raise the dial.** When you're comfortable, raise the enforcement dial from
   0 toward 100. At 25, the proxy starts auto-blocking the worst offenders.
   At 0, it goes back to monitor mode instantly.

**Accidentally blocked everything?** Set the dial back to 0 — all traffic is
immediately allowed through. No restart needed.

## How do I point my traffic here?

JA4proxy sits between your users and your backend. How you route traffic
depends on your setup:

| Your setup | What to do | Full guide |
|------------|-----------|------------|
| **No load balancer** (direct) | Point DNS at the JA4proxy host, map port 443→8443 | [Direct mode](docs/operations/DEPLOYMENT_MODES.md#direct-mode-default) |
| **nginx** | Add a `stream` block forwarding to JA4proxy with PROXY protocol | [nginx setup](docs/operations/DEPLOYMENT_MODES.md#behind-nginx) |
| **AWS** | Create a TCP NLB target group with PROXY protocol v2 | [AWS NLB setup](docs/operations/DEPLOYMENT_MODES.md#behind-aws-nlb) |
| **Cloudflare** | Use Spectrum (Enterprise) or DNS-only mode (grey cloud) | [Cloudflare setup](docs/operations/DEPLOYMENT_MODES.md#behind-cloudflare) |

## Start by role

| You are a… | Start here |
|------------|------------|
| **Website owner** under attack | [Emergency Deploy](#emergency-deploy) above, then [Incident Response](docs/operations/INCIDENT_RESPONSE.md) |
| **Website owner / CISO** evaluating fit | [`docs/product/WHY_JA4PROXY.md`](docs/product/WHY_JA4PROXY.md) — plain-language business case |
| **Security architect** designing integration | [`docs/security/ARCHITECTURE.md`](docs/security/ARCHITECTURE.md) |
| **Operator** running it day-to-day | [`docs/operations/OPERATIONS_GUIDE.md`](docs/operations/OPERATIONS_GUIDE.md) |
| **Compliance / audit** | [`docs/compliance/`](docs/compliance/) |
| **Developer / contributor** | [`docs/developer/`](docs/developer/) |

## Full Setup (Production)

For a complete production deployment with monitoring, analytics, and the
management API:

```bash
git clone https://github.com/seanpor/JA4proxy && cd JA4proxy
make init          # guided setup wizard — secrets, env vars, dependency checks
make build         # build the Go proxy and CLI
```

See the [Operations Guide](docs/operations/OPERATIONS_GUIDE.md) for day-2
operations, scaling, and maintenance.

### PDFs (offline reading)

| Audience | PDF |
|----------|-----|
| Business / commercial | [brochure](docs/pdf/brochure/brochure.pdf) |
| Operator | [user guide](docs/pdf/user-guide/user-guide.pdf) |
| Architect | [reference manual](docs/pdf/reference-manual/reference-manual.pdf) |

---

## How it works (technical)

JA4proxy is a TLS-aware passthrough proxy. It reads the plaintext metadata
visible *before and during* the TLS handshake — JA4 fingerprint, SNI, ALPN,
ASN, IP reputation, behavioural signals — and makes allow/block/tarpit
decisions without ever decrypting the traffic.

```
Internet ──TLS──▶ Load Balancer ──TCP──▶ JA4proxy ×N ──TLS──▶ Your Server
                      :443                  :8443               :443
                                              │  ▲
                           write events       │  │  signed dial & lists
                           (Redis Stream)     ▼  │  (Redis pub/sub)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  Dashboard :8090
                                         │     UI       │
                                         └──────────────┘
```

The proxy is a high-performance Go application built for sub-millisecond
latency. The ecosystem includes a Python management API, analytics worker,
and CLI tooling.

## Security & Supply Chain

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26.4](https://img.shields.io/badge/go-1.26.4-00ADD8.svg)](https://go.dev/)
![CI](https://github.com/seanpor/JA4proxy/actions/workflows/ci.yml/badge.svg)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/seanpor/JA4proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/seanpor/JA4proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/seanpor/JA4proxy)](https://goreportcard.com/report/github.com/seanpor/JA4proxy)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Coverage](https://img.shields.io/badge/coverage-verified-brightgreen)](#)
[![GitHub release](https://img.shields.io/github/v/release/seanpor/JA4proxy)](https://github.com/seanpor/JA4proxy/releases)

- **Immutable Dependencies**: Docker base images pinned to SHA256 digests
- **SBOM Generation**: Full CycloneDX Software Bill of Materials via `make sbom`
- **OpenSSF Scorecard**: Continuous auditing on the `main` branch
- **SLSA Level 3**: Hardened build provenance
- **Control Plane Integrity**: Tamper-proof, signed enforcement updates via Redis
