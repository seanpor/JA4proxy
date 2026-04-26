<!--
title: "Buyer FAQ"
audience: website-owners
last_reviewed: 2026-04-25
phase: 105
-->

# Buyer FAQ

Buyer-focused questions that recur in security questionnaires, RFP
responses, and procurement reviews. **This is distinct from the
operator FAQ** at [`docs/FAQ.md`](../FAQ.md), which covers
day-to-day commands and runbook-level questions. If you are
evaluating JA4proxy commercially, read this; if you have already
deployed it and need to know how to flush a ban, read the operator
FAQ.

For licence terms, cost bands, and the full commercial-support
posture, see [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md).

---

## 1. What does it cost to run?

The software is MIT-licensed and free to use. Your costs are the
infrastructure to run it (compute, Redis, observability, egress)
plus a fraction of an engineer's time to operate it. For a small
single-instance deployment that fraction is small; at multi-thousand
connection-per-second scale it becomes a meaningful share of an
operator's week.

[`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §4 contains three
worked monthly cost bands (small / enterprise / high-volume) with
estimates anchored to public list pricing as of 2026-04-25. Numbers
will vary by region, provider, and reservation strategy.

## 2. What is the risk of blocking real users?

The system is designed around the assumption that blocking a real
user is far more costly than letting a bad request through, and the
defaults reflect that posture. The key safety properties are:

- The proxy ships in **monitor mode** (dial = 0) by default; on
  first deployment it scores everything but blocks nothing.
- Browser traffic that negotiates HTTP/2 or HTTP/1.1 during the
  connection handshake **bypasses scoring entirely** — it cannot
  be blocked by any rule, threshold, or misconfiguration.
- All bans are short-lived (5-minute self-healing TTL by default).
  A false positive recovers without operator intervention.
- When external services are unavailable, the proxy fails open
  (lets the connection through, logs the failure).

Industry experience says no bot-mitigation product is *truly* free
of false positives. JA4proxy aims to make false positives rare
**and self-recovering**, not zero.

## 3. What is the GDPR posture?

JA4proxy processes connection metadata (source IP address, the
public TLS handshake fields, ASN, country) for the purpose of
filtering automated traffic. It does **not** decrypt traffic, read
HTTP bodies, build customer profiles, or transmit any of this data
to third parties. The data lives in your own infrastructure (your
Redis instance, your logs, your dashboards) under your existing
data-protection regime.

Operationally relevant GDPR points:

- **Lawful basis.** The processing is typically justified under
  Article 6(1)(f) (legitimate interests — protecting your service
  from automated abuse). Confirm with your DPO.
- **Retention.** All hot-path data has bounded TTLs; bans expire
  in 5 minutes by default, beaconing windows are short, signal
  caches are bounded. Long-term aggregates are subject to your
  log-retention policy.
- **Data subject access / erasure.** Because IP addresses are
  treated as personal data under GDPR, the project ships a
  `make gdpr-delete` Makefile target to purge a specific IP from
  Redis state on request.
- **No third-party data flows.** Optional integrations (AbuseIPDB,
  RDAP, MaxMind GeoIP) are explicit opt-ins; the source IP is
  shared with these services only when you enable them.

This is operational guidance, not legal advice. Run the deployment
past your privacy team.

## 4. Does it work behind Cloudflare (or AWS / Akamai / Fastly)?

Yes, with one caveat: the proxy must see the **real client TCP
connection**, not the CDN's edge IP. Two patterns work:

- **CDN in TLS-passthrough / SNI-routing mode.** The CDN forwards
  the raw TCP stream to your origin, and the proxy reads it as
  if from the internet. Real client behaviour is visible. Native
  fit.
- **CDN terminating TLS, proxy behind it.** In this mode the proxy
  cannot see the original handshake — it sees a connection from
  the CDN's egress. To recover the real client IP, the CDN must
  be configured to send the **PROXY protocol** header (v1 or v2;
  Cloudflare Spectrum, AWS NLB, and HAProxy all support this).
  Without PROXY protocol, the proxy will treat the CDN's egress
  IPs as the source — usually meaningless.

The product is **complementary** to your CDN's bot-management
feature, not a replacement. Most CDN bot-mitigation operates on
HTTP-layer signals; JA4proxy operates on connection-layer
signals. The two see different attackers.

## 5. What is the uptime impact?

The proxy is a stateless TCP passthrough; it adds one network hop
in the path from your load balancer to your backend. The Go
implementation adds sub-millisecond latency on the bypass path
(real browsers) and low-millisecond latency when the full scoring
pipeline runs.

Risk-relevant points:

- **Failure mode is fail-open.** If the proxy crashes, your load
  balancer's health check removes it from rotation; for a brief
  period traffic skips the proxy entirely. You lose the security
  control, you do not lose the site.
- **Stateless horizontal scaling.** Multiple proxy instances share
  state through Redis. Adding capacity is `kubectl scale` or its
  Compose equivalent.
- **No long-running stateful upgrades.** The proxy reloads
  configuration on `SIGHUP` without dropping connections.

For target service levels see
[`docs/SERVICE_TARGETS.md`](../SERVICE_TARGETS.md). These are
**self-imposed operational targets**, not contracted SLAs — see
question 12.

## 6. How do you know it's actually working?

Three measurement surfaces, all running from day one:

- **Block / allow counters in Grafana.** Connection counts by
  disposition (allow / flag / tarpit / block / ban) over time.
  In monitor mode the "would-have-blocked" counters tell you
  what raising the dial would catch.
- **Risk score histogram.** Distribution of risk scores across
  scored traffic. Sharp peaks at low scores indicate clean
  populations; long tails at high scores indicate attack
  campaigns.
- **Fingerprint top-N.** The most common connection signatures
  by volume; a sudden spike in a previously-unseen signature is
  an early signal of a campaign.

Buyers running a formal POC typically watch these dashboards for
a week in monitor mode, confirm that no real-browser traffic
appears in the high-score buckets, raise the dial in increments,
and watch for support-queue noise. The full evaluation playbook
will live in `docs/for-architects/EVALUATION_CHECKLIST.md`.

## 7. How does it integrate with our existing WAF?

The proxy sits **before** your WAF (between the load balancer and
the WAF, or between the load balancer and the origin if the WAF is
in your origin stack). It rejects clearly-bad traffic at the
connection layer, so the WAF sees less traffic and only the
non-trivial cases. Logs from both should ship to the same
SIEM/aggregator, where correlation rules can flag traffic that
JA4proxy let through but the WAF rejected (and vice versa) — both
patterns are diagnostic.

JA4proxy is **not** a WAF replacement. It does not stop SQL
injection, cross-site scripting, business-logic abuse, or any
attack class that lives in the request body. The two controls are
complementary.

## 8. How does it compare to Cloudflare Bot Management (or
DataDome, Akamai Bot Manager, etc.)?

Different shape of control, often complementary rather than
competing.

| Dimension | JA4proxy | CDN bot-management |
|---|---|---|
| Where it sits | In your infrastructure, in the TCP path | At the CDN edge, in the HTTP path |
| What it sees | Connection-layer signals (handshake shape, ASN, beaconing) | HTTP-layer signals (request patterns, headers, JS challenges, behavioural scoring) |
| Data custody | Your infrastructure, your Redis, your logs | Vendor's edge, vendor's analytics |
| Pricing | Open-source; you pay only for the infrastructure to run it | Per-million-requests or seat licensing |
| User-visible | Never; no challenge pages | Often presents CAPTCHAs / interactive challenges |
| Compliance scope | Out of payload-data scope (no decryption) | Vendor terms; may be in scope for some regimes |

Many production deployments run both: the CDN bot-management
catches HTTP-layer abuse and presents challenges where appropriate;
JA4proxy catches connection-layer abuse before it reaches the CDN
backend. They see different attackers.

## 9. Does it modify our application traffic?

No. Allowed connections pass through **byte-for-byte unchanged**.
The proxy reads the connection's first plaintext packet (the part
that is unencrypted by protocol design) to make its decision, then
forwards the entire stream untouched. Your TLS certificate stays
on your backend; the proxy does not see, hold, or process your
private key.

## 10. What is the licence and is there commercial support?

The software is licensed under the **MIT licence** (see the `LICENSE`
file in the repository root). There is **no commercial-support
tier offered by the project today**: support is community
best-effort via GitHub Issues and security disclosure via
`SECURITY.md`. The full statement, including the realistic options
for buyers who need contractual support, is in
[`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §3.

## 11. How is data retained, and can we delete a specific user?

Bans expire in 5 minutes by default. Beaconing and rate-window
state has bounded TTLs (minutes to hours). Signal caches (e.g.
reputation lookups) have day-scale TTLs. Aggregate metrics retained
in your Prometheus / log aggregator follow whatever retention
policy you have configured for those systems.

For per-IP erasure on data-subject request, the repository ships a
`make gdpr-delete IP=<address>` target that purges that IP's keys
from Redis. Operational specifics are in the operator FAQ and the
GDPR runbook.

## 12. Is there a contractual SLA?

No. The project is open-source under MIT; the licence explicitly
disclaims warranty and liability. The operational targets in
[`docs/SERVICE_TARGETS.md`](../SERVICE_TARGETS.md) are
**self-imposed targets** — useful for setting expectations with
your own internal stakeholders, **not contracted commitments from
the project**. Buyers requiring a contractual SLA against the
proxy will need either an in-house operations posture or a
third-party MSP relationship; both options are discussed in
[`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §3 and
[`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) §3.

## 13. Can it block an entire bot campaign with one action?

Often, yes — and this is the property that distinguishes
connection-layer fingerprinting from IP-based blocking. If a
campaign uses a single piece of attacker software, every
participating node typically produces the same connection
signature regardless of which IP it runs from. Adding that
signature to the blacklist blocks the entire fleet at once,
without you needing to enumerate the IPs.

A sufficiently-funded adversary can change their tooling's
connection software to evade a known signature; the response is
the layered scoring (ASN, beaconing behaviour, reputation) that
catches campaigns even when the connection signature shifts.

## 14. Does enabling it require a backend change?

No. The proxy is a transparent TCP passthrough. Your backend code,
your TLS certificate, your application configuration — none of it
changes. The visible change is in your load-balancer configuration
(it now forwards to the proxy address rather than directly to the
backend) and in your operational dashboards (new metrics, new
alerts).

## 15. What happens if the proxy itself is compromised?

The proxy never holds your TLS private keys, never sees decrypted
traffic, and never holds application secrets. A worst-case
compromise of the proxy itself yields connection metadata (IPs,
handshake fields, scores) that the operator already has access to
through normal logging — it does not yield customer data. The
project's security hardening (capability-dropping, seccomp
profiles, container non-root execution, secret-scanning in CI) is
documented in `SECURITY.md` and the architect-track scope doc.

For active vulnerability handling, follow the disclosure process
in `SECURITY.md`.

## 16. Are you CRA-compliant?

JA4proxy maintains a **self-assessed conformance statement** against the
EU Cyber Resilience Act (Regulation (EU) 2024/2847). It is **not** a
third-party certification — no accredited body has assessed JA4proxy
against the CRA. The full statement, with Annex I evidence mapping and
Annex II vulnerability-handling references, is at
[`docs/compliance/CRA_CONFORMANCE.md`](../compliance/CRA_CONFORMANCE.md).
The CRA's harmonised technical standards are still being drafted by
ETSI / CEN-CENELEC through 2026-2027; the statement will be refreshed
once they are published.

The project does not currently commit to a fixed support-period number;
the harmonised guidance will be reviewed once published and a position
taken at that time.

## 17. Do you support SLSA provenance verification?

Container images are built today with **SLSA Level 2** provenance —
keyless `cosign` signing plus a CycloneDX SBOM, per
[ADR-202d](../decisions/ADR-202d.md). The path to **SLSA Level 3**
(non-falsifiable provenance via `slsa-github-generator`) is documented
in [ADR-107a](../decisions/ADR-107a-slsa-level-3.md). A
`workflow_dispatch`-triggered verification workflow
(`.github/workflows/slsa-verify.yml`) is in place; an operator-runnable
verification runbook will land once the L3 attestation is wired
(sub-tasks 107c.3 + 107c.5, deferred for human-led execution).

---

## See also

- [`README.md`](README.md) — index of website-owner docs.
- [`WHY_JA4PROXY.md`](WHY_JA4PROXY.md) — plain-language business case.
- [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) — deployment shapes.
- [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) — costs, licence,
  support posture.
- [`docs/FAQ.md`](../FAQ.md) — operator-focused FAQ (distinct
  audience).
