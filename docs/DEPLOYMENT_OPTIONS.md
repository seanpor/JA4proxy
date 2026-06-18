<!--
title: "Deployment Options"
audience: product
last_reviewed: 2026-04-25
phase: 105
-->

# Deployment Options

This document is for the buyer or website owner who has read
[`WHY_JA4PROXY.md`](WHY_JA4PROXY.md), is interested, and now wants to
know **how it actually gets in front of their site, who runs it, and
how long it takes to stand up.** It is non-technical by design;
operators and engineers should follow the link to
[`docs/DEPLOYMENT_SECURITY_MODEL.md`](DEPLOYMENT_SECURITY_MODEL.md) at the
end of each section for the technical depth.

## Three deployment paths

| Path | Who runs it | Time-to-POC | Time-to-production | Best for |
|---|---|---|---|---|
| **Cloud (Docker / Kubernetes)** | You | ~30 minutes | 1–2 weeks | Most public-internet web applications |
| **On-prem (bare metal / VM)** | You | ~1 hour | 2–4 weeks | Regulated workloads, air-gapped sites, EU data residency |
| **Managed service** | *Not currently offered* | n/a | n/a | Buyers wanting a single-vendor SLA |

A "POC" (proof of concept) here means: the proxy running in front of a
test backend in **monitor mode**, with metrics flowing to a dashboard.
"Production" means: the proxy in the live traffic path with the
blocking dial raised to a non-zero value after a stable observation
window.

### 1. Cloud — Docker or Kubernetes

This is the path most production deployments take. The Go proxy daemon
(`cmd/ja4pd`, shipped as a small statically-linked container image)
runs alongside a Redis instance and a Prometheus/Grafana observability
stack. Your existing load balancer (HAProxy, AWS NLB, GCP TCP LB,
nginx in TCP mode, anything that can do raw TCP forwarding) sits in
front; your existing backend sits behind. The proxy is a transparent
TCP passthrough — your backend's TLS certificate stays where it is,
your application code does not change.

A small Docker Compose deployment can be running on a single VM in
under thirty minutes, including the dashboard. A Kubernetes
deployment via the bundled Helm chart takes longer (mostly
namespace, ingress, and secret-management plumbing in your existing
cluster), typically half a day to a day for an experienced platform
team.

**Typical scale.** A single proxy instance handles up to several
thousand connections per second. For higher volumes, run multiple
instances behind your load balancer; they share state through
Redis, so a connection blocked by one instance is also blocked by
all the others.

For technical depth see
[`docs/DEPLOYMENT_SECURITY_MODEL.md`](DEPLOYMENT_SECURITY_MODEL.md) and
the SCALING_GUIDE referenced from there.

### 2. On-premises — bare metal or VM

Same software, same architecture, no cloud dependency. This is the
right path when:

- Your organisation's data-residency or air-gap policy forbids
  third-party cloud hosting for the components in scope.
- You are deploying in front of a regulated workload (PCI-DSS,
  HIPAA, EU healthcare, financial trading systems) and your
  compliance team has determined that the proxy's logs and Redis
  state are themselves in scope.
- You have an existing on-prem operations team with capacity to
  add another service.

The software stack is identical to the cloud path; only the hosting
substrate differs. Time-to-POC is similar (~1 hour on a prepared
VM), but time-to-production is typically longer because of internal
change-control processes that on-prem deployments tend to attract.

For technical depth see
[`docs/DEPLOYMENT_SECURITY_MODEL.md`](DEPLOYMENT_SECURITY_MODEL.md).

### 3. Managed service — not currently offered

There is no first-party managed-service offering. If a third party
offers paid integration or operational support, they do so
independently, and the JA4proxy project does not endorse such
offerings.

The honest options for buyers who need a vendor-managed posture:

- **Self-host with internal ops** — the cloud or on-prem paths above.
- **Engage a third-party SI / MSP** — vet independently. The project
  does not maintain a partner list.
- **Reconsider scope** — if a contractual SLA against a TLS-aware
  proxy is non-negotiable, a commercial SSL-inspection appliance may
  be the right fit despite the higher TCO and compliance scope. See
  [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §6 for the rough
  cost comparison.

This posture is documented in full in
[`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §3 and is mirrored in
the project's `SECURITY.md`.

## Integration prerequisites

Before a POC can run, the following items need to exist or be
arranged. None of them is exotic; the table is here so a buyer can
hand it to their platform team for a sanity check.

| Prerequisite | Why it is needed | Typical effort |
|---|---|---|
| **A load balancer in front, in TCP/passthrough mode** | The proxy reads the connection handshake; it cannot sit behind a TLS-terminating layer | None if you already have HAProxy / NLB / GCP TCP LB; minor reconfig if your LB is currently terminating TLS |
| **Reach to your backend on its existing port** | The proxy forwards traffic byte-for-byte to the same backend port that the LB used to | None; usually a routing/firewall rule that already exists |
| **A Redis instance (managed or self-hosted)** | Shared state for bans, rate limits, and signal caches across proxy instances | A small Redis is enough for a POC; production deployments may want a managed Redis (ElastiCache, Memorystore, etc.) |
| **Egress to a small set of well-known APIs** | Optional reputation feeds (AbuseIPDB, RDAP, MaxMind GeoIP downloads) — all free-tier-capable | Egress allowlist; no inbound exposure |
| **Prometheus / Grafana (or Datadog, or your existing stack)** | The proxy exposes metrics on a standard `/metrics` endpoint; pick whichever is already in your environment | None if you already have one; bundled stack ships in the repo |
| **A logging destination (stdout to your existing aggregator)** | Structured JSON logs go to stdout; ship them with whatever you already use (Loki, Splunk, ELK, Datadog) | None if you have container logging |
| **Operational ownership** | Someone to watch dashboards, raise the dial, and respond to alerts | Part-time at small scale; see [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) §4 for FTE estimates |

## What "30 minutes to a POC" really means

The 30-minute figure is for the cloud Docker Compose path on a
prepared VM with internet access, by an engineer who has run a
container before. It covers: clone the repository, configure two
environment variables (the backend address and a Redis password),
`make start`, and confirm the dashboard shows traffic.

What it does not cover: integrating the proxy into your existing
production load-balancer, sizing Redis for your peak traffic,
wiring your alerting backend, or running a representative load
test. Those steps are what take a real production deployment from
"first POC" to "in the live traffic path with the dial raised" —
typically one to two weeks for a focused team, longer if change
control is involved.

## A note on the runtime

The **production runtime is the Go proxy daemon** at `cmd/ja4pd/`, built to `bin/ja4pd` and packaged as a container image — this is what you deploy. All legacy Python prototyping components have been archived and removed. All references to "the proxy" in this document mean the Go proxy daemon.

## Where to go next

- [`TCO_AND_LICENSING.md`](TCO_AND_LICENSING.md) — running costs
  for each shape, support posture, licence summary.
- [`FAQ.md`](FAQ.md) — buyer-level answers on integration risk,
  GDPR, Cloudflare interoperability, and uptime.
- [`docs/DEPLOYMENT_SECURITY_MODEL.md`](DEPLOYMENT_SECURITY_MODEL.md) —
  technical reference for your platform team.
