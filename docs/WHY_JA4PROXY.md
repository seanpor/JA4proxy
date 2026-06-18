<!--
title: "Why JA4proxy — A Plain-Language Business Case"
audience: product
last_reviewed: 2026-04-25
phase: 105
-->

# Why JA4proxy

If you run a website with logins, signups, checkouts, or any
public-facing form, a non-trivial slice of the traffic hitting it
is not human. Credential-stuffing tools spray stolen passwords at
your login page. Inventory scrapers hammer your search and product
pages. Bulk-signup bots pollute your database. Carding bots probe
your checkout. By the time the abuse appears in your application
logs, the cost has already landed — in stolen accounts, inflated
cloud bills, checkout fraud, and customer-support tickets from
people whose accounts were taken over.

JA4proxy reduces that cost without taking custody of any data your
business is regulated for. It sits in front of your web
infrastructure as a transparent passthrough and decides, before any
content is exchanged, whether a connection deserves to reach your
application. It never decrypts, never holds your private keys, never
reads request bodies, and never modifies the byte stream forwarded
to your origin. Your compliance posture is unchanged — which is what
lets it deploy in front of regulated workloads (PCI-DSS checkouts,
healthcare portals, financial dashboards) where a traditional
inspection proxy would trigger a months-long legal review.

## Before and after

Before JA4proxy, the typical pattern looks like this. An adversary
rents thousands of residential proxy IPs and runs a
credential-stuffing tool with a plausible user agent against your
login page. Your WAF sees syntactically-correct requests and lets
them through. Your CDN's bot-score is dragged down by the IP
rotation. Customer support starts receiving "I didn't log in from
there" complaints two days later. You learn about the campaign
from the helpdesk queue, not from your security tooling.

After JA4proxy, the same campaign is recognised on the way in. The
tool's underlying connection software produces a stable signature
regardless of which proxy IP it runs from. The proxy spots the
signature on connection one — before the HTTP request is even sent
— and drops or stalls the connection. Real users on real browsers
are unaffected: their connection shape is structurally distinct
from any automated tool. Your support inbox no longer fills with
account-takeover reports, and your origin servers do less work
because the abuse never reaches them.

## "Zero false-positives by design"

The biggest fear when adding a new security layer is that it will
block real customers. Industry experience with bot-mitigation
products is that they all eventually do, and that the cost of a
blocked legitimate user dwarfs the cost of a missed bad request.

JA4proxy is built around that asymmetry. It treats blocking a real
customer as catastrophic and letting a bad request through as
merely expensive. Several practical consequences follow.

The proxy ships in **monitor mode** by default. On day one it
scores every connection but blocks none. You get a week of evidence
showing exactly what *would* have been blocked and why, so the
decision to start blocking is made on data, not trust. Rollout is a
knob you turn from 0 to 100 at your own pace.

There is a structural escape hatch for real browser traffic. Modern
browsers negotiate the next-generation HTTP protocols (HTTP/2 and
HTTP/1.1) during the connection handshake — a step the proxy can
see and that automated tools cannot fake without doing the work of
a real browser. Connections that present this signal **bypass
scoring entirely**: they cannot be blocked by any rule, threshold,
or misconfiguration. This is an architectural guarantee, not a
heuristic, and it is what lets you set aggressive thresholds for
known-bad signatures without worrying about catching real users in
the net. (Operators call this the "ALPN browser bypass"; you do not
need to remember the term.)

When external services the proxy talks to (reputation feeds, DNS,
geolocation) are slow or unavailable, the proxy does not fall back
to "block when in doubt". It skips the signal, lets the connection
through, and logs the failure. "Fail open" is the rule throughout,
because a proxy that lets bad traffic through is recoverable, and
one that locks out customers is not.

## What this is not

JA4proxy is not a web application firewall. It does not stop SQL
injection, XSS, or business-logic abuse — those live in the
request body. It complements your existing WAF and CDN; it does
not replace them.

It is not a CAPTCHA or human-verification system. Real customers
never see a challenge page. The proxy decides before any request
reaches your application, so there is nothing to challenge to.

It is not a data-collection product. It does not build customer
profiles, does not phone home, and does not send traffic data to
any third party. The connection metadata it records lives in your
own infrastructure, on your own dashboards.

## Next steps

- [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) — deployment
  shapes and time-to-production.
- [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) — licence,
  cost bands, support posture.
- [`FAQ.md`](FAQ.md) — buyer and security-questionnaire questions.
