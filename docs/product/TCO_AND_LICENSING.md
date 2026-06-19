<!--
title: "Total Cost of Ownership & Licensing"
audience: product
last_reviewed: 2026-04-25
phase: 106
-->

# JA4proxy — Total Cost of Ownership & Licensing

This page answers the two questions a buyer, RFP-completer, or website owner
typically asks first: **"What does it cost to run JA4proxy?"** and
**"How do I buy support?"**. It is honest about both — the project is open
source, the running costs are dominated by your existing infrastructure
provider's pricing, and there is no commercial-support tier on offer at the
date of this writing.

Numbers in this document are estimates based on **public list pricing as of
2026-04-25**. Estimates carry a footnote against every dollar figure. Your
actual costs will vary by region, provider, reservation strategy, and
existing contracts.

---

## 1. License

JA4proxy is released under the **MIT License**. The full, authoritative text
is in [`LICENSE`](../../LICENSE) at the root of the repository.

### What the MIT license permits

- **Commercial use.** You may run JA4proxy in production, including in
  revenue-generating services and inside paid-product offerings.
- **Modification.** You may modify the source for your own deployment or
  fork it as the basis of a derivative work.
- **Distribution.** You may redistribute the software, modified or
  unmodified, as long as the copyright notice and license text are
  preserved.
- **Sublicensing.** You may grant your downstream users rights under
  the same terms.
- **Private use.** You may use it internally without disclosing your
  modifications.

### What the MIT license does not provide

- **No warranty.** The software is provided "AS IS". The authors disclaim
  warranties of merchantability, fitness for a particular purpose, and
  non-infringement.
- **No liability.** The authors and copyright holders are not liable for
  any claim, damages, or other liability arising from use of the
  software.
- **No patent grant.** The MIT license is silent on patents. If patent
  exposure matters to your organisation, route the question through your
  legal team — Apache-2.0-licensed alternatives include an explicit
  patent grant; MIT does not.
- **No service-level commitment.** See §3 below and
  [`SERVICE_TARGETS.md`](../reference/SERVICE_TARGETS.md) — operational targets
  are self-imposed by the deploying organisation, not contracted by
  the project.

### Recommendations for downstream users

- **SBOM.** Generate a software bill of materials for every release you
  deploy. CycloneDX or SPDX format is fine. Most CI systems can produce
  one with a single step.
- **License scanning.** Run a license scanner (e.g. `licensecheck`,
  `scancode`, GitHub's dependency-graph licence column) over the
  transitive dependency tree. JA4proxy itself is MIT, but its
  dependencies span MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, and
  ISC; check that your downstream policy permits all of them.
- **Notice file.** If you redistribute a binary or container image, ship
  the upstream `LICENSE` file alongside it. The MIT licence requires
  preserving the copyright notice in all copies.
- **Forks.** If you maintain an internal fork, retain the upstream
  copyright header and add your own copyright above it; do not strip
  the original.

---

## 2. Open-source vs. commercial posture (one sentence)

JA4proxy is open-source software with an MIT licence and no current
commercial-support offering — see §3 for the detailed statement.

---

## 3. Commercial support posture

**JA4proxy is open-source software. Community support is available on
GitHub Issues at the project repository. Commercial support is not
currently offered; if a third party offers paid integration or operational
support, they do so independently and the JA4proxy project does not
endorse such offerings. Buyers requiring guaranteed response times should
plan for in-house operations or engage a third-party integrator.**

This statement is mirrored in [`SERVICE_TARGETS.md` §SLA posture](../reference/SERVICE_TARGETS.md)
and in [`SECURITY.md`](../../SECURITY.md). The three documents are
consistent — if you find drift, the runbook-linked targets in
`SERVICE_TARGETS.md` win.

### What this means in practice

- **Issues.** File bug reports, feature requests, and questions on
  GitHub Issues. The maintainers triage on a best-effort basis. There
  is no contractual response time.
- **Security disclosures.** Follow [`SECURITY.md`](../../SECURITY.md).
  The project commits to *target* response windows for vulnerability
  triage (24h critical, 48h high, 72h medium/low) but these are
  community commitments, not contractual SLAs.
- **Incidents in your deployment.** You own them. Your on-call rotation,
  your runbooks, your post-mortems. The project's runbooks under
  [`docs/runbooks/`](../runbooks/) are a starting point, not a
  managed service.
- **Upgrades.** You schedule them. The project follows semantic
  versioning and publishes a `CHANGELOG.md`, but there is no managed
  upgrade path or migration assistance.

### When you need more

If guaranteed response times, named-engineer escalation, or contractual
liability are non-negotiable for your deployment, the realistic options
are:

- **Hire and train an in-house team.** Account for the operational FTE
  estimates in §4 below.
- **Engage a third-party SI / MSP.** Independent integrators and
  managed-service providers may offer paid JA4proxy operations as part
  of a broader security package. Vet them independently — the project
  does not maintain a partner list and does not endorse providers.
- **Reconsider scope.** If your control needs require contractual
  uptime against a TLS-aware proxy, an SSL-inspection appliance from
  a commercial vendor may be a better fit despite the higher TCO
  (see §6).

---

## 4. TCO model — three worked scenarios

The numbers below are **monthly cost bands** rather than point estimates,
because cloud pricing varies by region, instance reservation strategy,
and bundled-discount agreements. Each band reflects a typical IaaS
deployment using mainstream public-cloud or VPS pricing.

For each dollar figure in this section: ^(Estimate based on public
pricing as of 2026-04-25. Your costs will vary by region, provider, and
reservation strategy.)

The infrastructure shapes below align with the deployment scenarios that
[`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md) (Phase 105 — *not yet
landed*; this document references it forward) will describe in detail.
Until that doc lands, read these scenarios as standalone.

### Scenario 1 — Small (single instance, < 100 conn/s)

**Use case.** A single-origin website, blog, or small SaaS that wants
JA4-based bot mitigation in front of a single backend. Monitor mode
during onboarding; dial raised cautiously after a quiet observation
period.

| Component | Shape | Approx monthly cost |
|---|---|---|
| Proxy host | 1× VM, 2 vCPU / 4 GB RAM | $20–$40 ^([1]) |
| Redis | Single instance, 1 GB, same VM or co-tenanted | $0–$15 ^([1]) |
| Observability | Self-hosted Prometheus + Grafana on the same VM | $0 ^([1]) |
| Logging | stdout / file + log rotation | $0 ^([1]) |
| Egress | < 100 GB/month | $0–$10 ^([1]) |
| **Infra subtotal** | | **$20–$65/month** ^([1]) |
| Operational FTE | 0.05 FTE (occasional check-ins, weekly metrics review) | varies ^([2]) |

**Notes.** Suitable for Hetzner Cloud, DigitalOcean, Vultr, or comparable
budget VPS providers. AWS / GCP / Azure equivalents land at the upper
end of the band. Operational FTE estimate assumes the operator is
already employed and JA4proxy is *one of several* small-ops
responsibilities.

### Scenario 2 — Enterprise (multi-instance, ~ 1000 conn/s)

**Use case.** A medium-traffic e-commerce or B2B application sitting
behind a load balancer with two or more origin clusters. Active dial
> 0, full alert routing, on-call coverage. Compliance posture (SOC 2,
ISO 27001) requires audit logging and metrics retention.

| Component | Shape | Approx monthly cost |
|---|---|---|
| Proxy hosts | 3× VM, 4 vCPU / 16 GB RAM | $200–$450 ^([1]) |
| Redis | 3-node cluster, HA, 4 GB each | $90–$300 ^([1]) |
| Analytics node | 1× VM, 2 vCPU / 8 GB RAM | $60–$140 ^([1]) |
| Observability | Prometheus + Grafana + Alertmanager (self-hosted) | $50–$120 ^([1]) |
| Log retention | 30 days at modest volume | $30–$80 ^([1]) |
| Egress | 1–2 TB/month | $40–$200 ^([1]) |
| **Infra subtotal** | | **$470–$1,290/month** ^([1]) |
| Operational FTE | 0.25 FTE (weekly tuning, alert response, quarterly review) | varies ^([2]) |

**Notes.** The wide band reflects the AWS / GCP / Azure premium over
Hetzner / OVH / Vultr. Reserved-instance commitments typically reduce
the upper band by 30–50%. Operational FTE estimate assumes the proxy is
one of several systems the operator looks after.

### Scenario 3 — High-volume (~ 10k+ conn/s)

**Use case.** A large public-internet property, CDN-fronted SaaS, or
high-traffic API gateway requiring multiple proxy instances behind a
geo-distributed load balancer with full incident-response tooling.

| Component | Shape | Approx monthly cost |
|---|---|---|
| Proxy hosts | 8–16× VM (4–8 vCPU / 16 GB) behind LB | $1,500–$5,500 ^([1]) |
| Redis cluster | 6+ nodes, replication, persistence enabled | $400–$1,500 ^([1]) |
| Analytics node | 2× VM, dedicated, with offline aggregation | $200–$550 ^([1]) |
| Observability | Prometheus + Grafana + Alertmanager + long-term storage | $200–$800 ^([1]) |
| Log retention | 90 days at high volume | $300–$1,200 ^([1]) |
| Egress | 10–50 TB/month | $400–$4,500 ^([1]) |
| Load balancer | Managed NLB / GLB | $25–$200 ^([1]) |
| **Infra subtotal** | | **$3,025–$14,250/month** ^([1]) |
| Operational FTE | 0.5–1.0 FTE (on-call rotation, capacity planning, security tuning) | varies ^([2]) |

**Notes.** Egress dominates at this scale. Reserved or committed-use
discounts on compute typically save 30–60% but require multi-year
contracts. The Go proxy
(`bin/ja4pd`, see project [`README.md`](../../README.md)) is recommended
at this scale — single-process Python tops out around 350 conn/s with
real Redis (see project memory). Phase 26 multi-process scaling is the
realistic stopgap for Python deployments.

### Footnotes

- **^([1])** Estimate based on public pricing as of 2026-04-25 from
  AWS On-Demand (eu-west-1, Linux), DigitalOcean Droplet pricing,
  Hetzner Cloud CX/CCX, and Vultr High Frequency. Your costs will
  vary by region, provider, and reservation strategy.
- **^([2])** Operational FTE is a *fraction* of an engineer's time, not
  a salary line item. Your fully-loaded engineer cost varies by
  geography; multiply the fraction by your standard rate.

---

## 5. Hidden costs — supplemental services & feeds

JA4proxy ships with sane defaults that work without any paid third-party
service. The signal modules become more accurate when paired with paid
data feeds; this table summarises the realistic options. Each row is
flagged `[ESTIMATE 2026-04-25]` to mark the volatility of the underlying
pricing.

| Service | Tier | Monthly cost band ^([1]) | Notes |
|---|---|---|---|
| MaxMind GeoLite2 (ASN, Country, City) | Free | $0 `[ESTIMATE 2026-04-25]` | Default. Account registration required since 2019. Updated weekly. |
| MaxMind GeoIP2 (commercial) | Paid | $24–$370/month `[ESTIMATE 2026-04-25]` | Higher accuracy. Useful only if GeoLite2 misclassifies enough traffic to matter. |
| AbuseIPDB | Free tier | $0 `[ESTIMATE 2026-04-25]` | 1,000 lookups/day. Sufficient for Scenario 1. |
| AbuseIPDB | Premium / Webmaster | $20–$350/month `[ESTIMATE 2026-04-25]` | 10k–unlimited lookups/day. Required at Scenario 2 and 3 volume. |
| Spamhaus DROP / EDROP | Public | $0 `[ESTIMATE 2026-04-25]` | Default. Sufficient for most deployments. Update interval ~hourly. |
| Spamhaus DROP+ / commercial feeds | Paid | quote-only `[ESTIMATE 2026-04-25]` | Faster updates, expanded coverage. Contact Spamhaus directly. |
| Recorded Future, CrowdStrike Falcon Intel, Mandiant | Enterprise | $20k–$200k+/year `[ESTIMATE 2026-04-25]` | Quote-only. Only relevant for Scenario 3 deployments with an existing TI subscription. |
| Tor exit-node list | Public | $0 `[ESTIMATE 2026-04-25]` | Public list maintained by the Tor project. |
| Datadog (managed observability) | Pro / Enterprise | $15–$34 per host/month + log volume `[ESTIMATE 2026-04-25]` | Replaces self-hosted Prometheus/Grafana. Quick to deploy, expensive at scale. |
| Self-hosted Grafana + Prometheus | Open source | infra cost only `[ESTIMATE 2026-04-25]` | Recommended default. Cost is the VM in §4. |
| Egress (cross-AZ + internet) | Provider-dependent | $0.01–$0.12 per GB `[ESTIMATE 2026-04-25]` | Often the largest line item at Scenario 3. |

**^([1])** Estimates use the vendors' published list pricing as of
2026-04-25; volume and enterprise discounts can reduce these
substantially.

**Decision posture.** The project ships with the *free* feeds in every
slot by default. Paying for any of the upgrades is a function of your
deployment size and risk appetite — not a project requirement.

---

## 6. TCO comparison — JA4proxy vs. SSL inspection

A common alternative to JA4proxy is **TLS-terminating ("SSL inspection")
proxy** appliances or services. The control surface is fundamentally
different, and so is the cost structure.

### What SSL inspection requires

- **Key custody.** The proxy holds private keys for every protected
  origin (or a CA private key for re-signing). This pulls the proxy
  into your highest compliance scope (PCI-DSS, HIPAA, SOC 2 high).
- **Hardware Security Module (often).** For PCI-DSS 4.0 and equivalent
  regimes, the private keys must live in an HSM or HSM-equivalent
  KMS. HSMs add a fixed monthly cost — typically several hundred to
  several thousand US dollars per region.
- **CPU cost for full TLS handshake + decryption.** Roughly 10–20× the
  per-connection CPU footprint of JA4proxy's metadata-only path,
  depending on cipher suites in use.
- **Legal and compliance overhead.** Auditors treat the SSL-inspection
  proxy as in-scope for any data the inspected traffic carries.
  Privacy reviews, DPIAs, and breach-notification scope expand
  accordingly.

### What JA4proxy does instead

- **Plaintext metadata only.** ClientHello fingerprints (JA4), SNI, TCP
  metadata, ALPN, certificate fields visible in the handshake. No
  key custody, no decryption, no HTTP body inspection. Forwarded
  traffic is byte-for-byte unchanged.
- **No TLS termination.** TLS terminates at the backend, exactly where
  it would without JA4proxy in the path. The proxy is a Layer-4
  passthrough.
- **Out-of-scope for compliance regimes that focus on payload data.**
  PCI-DSS scope, HIPAA scope, and equivalent regimes that hinge on
  access to plaintext cardholder / PHI data do not extend to a
  proxy that never sees it. Your compliance team should still
  review — but the conversation is dramatically shorter.

### Rough cost comparison

For an equivalent deployment (Scenario 2 — ~1000 conn/s):

- **JA4proxy (this document, §4):** $470–$1,290/month infrastructure
  ^([1]), 0.25 operational FTE.
- **SSL-inspection equivalent:** Typically **5–10× the operational +
  compliance cost**, driven by HSM or KMS spend, expanded compliance
  scope, expanded audit evidence requirements, and higher per-
  connection CPU.

This 5–10× ratio is a rough estimate, not a vendor benchmark. The
project does not endorse or denigrate any specific SSL-inspection
vendor; commercial offerings make different trade-offs, and some are
the right tool for some problems. The point is that **the cost
structures are not comparable on a like-for-like infrastructure-only
basis** — the dominant cost of SSL inspection is compliance scope, not
compute.

For the underlying architecture rationale, see
[`docs/enterprise/security-architecture.md`](../enterprise/security-architecture.md)
and [`docs/architecture/system-architecture.md`](../architecture/system-architecture.md).

**^([1])** Estimate based on public pricing as of 2026-04-25. Your
costs will vary by region, provider, and reservation strategy.

---

## 7. What this document is not

- **Not legal advice.** The license summary above is a plain-English
  paraphrase of the MIT licence. Where licence interpretation matters
  to a contract or a legal exposure, run it past your counsel — the
  authoritative text is in [`LICENSE`](../../LICENSE).
- **Not an exhaustive cost model.** Your actual TCO depends on
  variables this document cannot enumerate: your existing cloud
  contract, your engineer salary band, your compliance regime, your
  data-residency requirements, your shared services.
- **Not an SLA.** No number in this document is a service-level
  commitment from the project. Service targets and the SLA posture
  live in [`SERVICE_TARGETS.md`](../reference/SERVICE_TARGETS.md).
- **Not a price guarantee.** Vendor pricing changes. Public-cloud
  pricing in particular has shifted twice in the 24 months preceding
  this document. Treat the numbers as a snapshot, not a commitment.
- **Not an endorsement of providers.** Where a vendor is named (AWS,
  DigitalOcean, MaxMind, AbuseIPDB, Spamhaus, Datadog, etc.) the
  reference is for pricing-research purposes only. The project does
  not endorse, recommend, or partner with any provider listed.

---

## 8. Cross-references

- [`LICENSE`](../../LICENSE) — authoritative MIT licence text
- [`SECURITY.md`](../../SECURITY.md) — vulnerability reporting,
  responsible-disclosure policy, security-team contact
- [`docs/reference/SERVICE_TARGETS.md`](../reference/SERVICE_TARGETS.md) — SLI / SLO / SLA
  posture (sibling Phase 106 deliverable)
- [`docs/security/RISK_REGISTER.md`](../security/RISK_REGISTER.md) — operational and
  security risk register (sibling Phase 106 deliverable; landing in
  the same phase as this document)
- [`README.md`](../../README.md) — Phase 105
  audience-doc placeholder; lists this file
- [`DEPLOYMENT_OPTIONS.md`](DEPLOYMENT_OPTIONS.md)
  — Phase 105 deployment-shape catalogue (proposed, not yet landed
  at the time of writing)
- [`docs/operations/SCALING_GUIDE.md`](../operations/SCALING_GUIDE.md) — multi-process
  scaling guide; informs Scenario 2 and 3 sizing
- [`docs/security/DEPLOYMENT_SECURITY_MODEL.md`](../security/DEPLOYMENT_SECURITY_MODEL.md) —
  enterprise deployment reference
- [`docs/enterprise/security-architecture.md`](../enterprise/security-architecture.md)
  — security architecture rationale
- [`docs/architecture/system-architecture.md`](../architecture/system-architecture.md)
  — system-level component view

---

*Last reviewed: 2026-04-25. Pricing snapshot date: 2026-04-25. Next
review: at the next quarterly review of `SERVICE_TARGETS.md` or
whenever a vendor pricing change materially shifts the bands.*
