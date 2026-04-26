<!--
title: "JA4proxy for Website Owners"
audience: website-owners
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy — for Website Owners and CISOs

If you run a website with logins, signups, checkouts, or any
public-facing form, a non-trivial slice of the traffic you serve is
not human. Credential-stuffing tools, inventory scrapers, bulk
signup bots, and carding bots produce HTTP requests that look
syntactically correct, ship plausible user-agent strings, and pass
your WAF — yet the cost shows up downstream in stolen accounts,
inflated cloud bills, checkout fraud, and customer-support tickets.
JA4proxy is a transparent passthrough that filters this traffic at
the connection layer **before any HTTP request is sent**, without
decrypting traffic, without holding your private keys, and without
modifying the byte stream forwarded to your backend.

This page is the entry point for buyers, CISOs, security
questionnaire respondents, and anyone evaluating JA4proxy
commercially. It is intentionally short — the four documents below
hold the substance.

## The four documents you want

| Document | What you get |
|---|---|
| [`WHY_JA4PROXY.md`](WHY_JA4PROXY.md) | Plain-language business case, before/after narrative, "zero false-positives by design" explained without jargon. |
| [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) | Cloud, on-prem, and managed-service paths. Time-to-POC (~30 minutes), time-to-production. Integration prerequisites table. |
| [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) | Three worked monthly cost bands (small / enterprise / high-volume), MIT-licence terms, commercial-support posture, comparison vs. SSL inspection. |
| [`FAQ.md`](FAQ.md) | Buyer-focused Q&A: GDPR, Cloudflare interoperability, uptime, WAF integration, comparison vs. CDN bot-management, contractual SLA posture. |

## How to read in order

1. Skim [`WHY_JA4PROXY.md`](WHY_JA4PROXY.md) — five minutes. If
   the problem framing matches what you are seeing, continue.
2. Read [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) — confirm
   the three deployment paths fit your environment.
3. Read [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §3 (support
   posture) and §4 (cost bands). If those land, you have the
   commercial picture.
4. Read [`FAQ.md`](FAQ.md) for the questions your security and
   procurement teams will ask next.

## A note on what JA4proxy is and isn't

It is **not** a web application firewall. It does not stop SQL
injection, cross-site scripting, or business-logic abuse — those
live in the request body, which JA4proxy never reads. It is
**complementary** to your existing WAF, CDN, and bot-management
controls; it sees connection-layer signals that those products do
not.

It is **not** a CAPTCHA or human-verification system. Real
customers never see a challenge page. Decisions happen before any
request reaches your application.

It is **not** a data-collection product. It does not build
customer profiles, does not phone home, and does not send traffic
data to any third party. The connection metadata it records lives
in your own infrastructure.

## A note on the runtime

JA4proxy ships two implementations. The **production runtime is
the Go proxy** at `cmd/proxy/`, built to `bin/proxy` and shipped as
a container image — this is what you deploy. The Python proxy at
`proxy.py` is a **prototyping surface** retained for experimenting
with new signal modules; it is not for production traffic. All
references to "the proxy" in this track mean the Go proxy.

## Next steps

- Buyers and CISOs: read the four documents above in order.
- Operators looking for runbook-level guidance: see
  [`docs/FAQ.md`](../FAQ.md) and the operator track (landing in a
  later wave of Phase 105).
- Architects evaluating control coverage: see
  `docs/for-architects/` (also landing in a later wave of
  Phase 105).
- Engineers who want to try it: see
  [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) for the 30-minute
  POC path and
  [`docs/enterprise/deployment.md`](../enterprise/deployment.md)
  for technical depth.
