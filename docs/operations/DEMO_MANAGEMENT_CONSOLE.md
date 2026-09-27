<!--
title: End-to-End Management Console Showcase Runbook
audience: operator
last_reviewed: 2026-09-18
phase: 816
-->

# End-to-End Management Console Showcase Runbook

This document provides the step-by-step operational narrative for demonstrating the JA4proxy stack to enterprise SecOps teams, security architects, and compliance assessors.

---

## Overview

The JA4proxy demonstration environment showcases the full defense lifecycle:
1. **Continuous TLS Traffic**: Real-world mix of legitimate browser traffic (HTTP/2 with ALPN) and malicious/automation traffic (Sliver C2, Cobalt Strike beacons, Python scrapers, credential stuffers).
2. **Real-time Telemetry**: Live Server-Sent Events (SSE) streaming connections into the modern Management Console (`http://localhost:8000` or lane port).
3. **JA4 Fingerprint Decomposition**: Human-readable decoding of cipher suites, ALPN negotiations, and extension counts directly in the UI.
4. **Live Mitigation**: One-click and REST API policy enforcement (JA4 blacklisting, IP banning, allowlisting) without restarts or downtime.
5. **Dynamic Aggression Control**: Real-time adjustment of the Blocking Dial (0 = Monitor, 50 = Balanced, 100 = Strict Enforce).
6. **Observability & Auditability**: Real-time Prometheus metrics and Grafana dashboards accompanied by tamper-evident cryptographic audit logging.

---

## Prerequisites

- **Docker & Docker Compose** (v2.20+)
- **Go 1.26+** (host build toolchain)
- **Local Ports Available**:
  - `8081` (Direct proxy TLS entrypoint)
  - `8090` / `8000` (Management Console UI & API)
  - `9090` (Proxy Prometheus metrics)
  - `9091` (Prometheus server)
  - `3000` (Grafana HTTPS dashboard)

---

## Quick Start

To launch the complete demonstration environment, seed initial security policies, start traffic generation, and verify stack health in a single command:

```bash
make demo
```

Alternatively, invoke the underlying orchestration script directly:

```bash
bash scripts/demo-mgmt.sh
```

### Dry-Run Verification

To simulate the startup sequence and verify prerequisites without modifying container state:

```bash
bash scripts/demo-mgmt.sh --dry-run
```

---

## Interactive Walkthrough

A structured 10-minute demonstration narrative for stakeholders:

### Step 1: Access the Management Console
1. Open your browser to `http://localhost:8000` (or the lane-mapped port output by `make demo`).
2. Log in using the administrative credentials generated in `.env`:
   - **Username**: `admin`
   - **Password**: Found in `.env` under `MANAGEMENT_ADMIN_PASSWORD` (or output in the terminal summary).

### Step 2: Observe Live SSE Traffic Stream
1. In the console, navigate to the **Live Connections** view.
2. Observe incoming requests updating in real time via Server-Sent Events (SSE).
3. Note the varied traffic mix:
   - Legitimate browser profiles showing `h2` ALPN and green status indicators.
   - Malicious profiles (e.g. `Sliver_C2`, `CobaltStrike`) flagged with elevated risk scores.

### Step 3: Inspect Fingerprint Decodes
1. Click on any connection in the table or feed.
2. Examine the modal displaying the decoded JA4 fingerprint breakdown:
   - **Transport**: TLS (`t`)
   - **Protocol Version**: TLS 1.3 (`13`) or TLS 1.2 (`12`)
   - **SNI Indication**: Domain present (`d`)
   - **Cipher & Extension Counts**: Distinctive counts distinguishing browsers from command-and-control agents.

---

## Live Mitigation

Showcase how an operator immediately responds to emerging threats without configuration restarts:

1. Identify an unblocked tool fingerprint in the live feed (e.g., `Sliver_C2` with JA4 `t13d091100_f91f431d341e_8e6e362c5eac`).
2. Click the **Blacklist** action button adjacent to the entry.
3. The Management API issues a REST call to `POST /api/v1/lists/ja4/blacklist/{entry}`.
4. The Go proxy immediately subscribes to policy updates via Redis and applies blocking rules to subsequent connections from that fingerprint.
5. In the **Lists** page, verify the entry is listed, along with the operator identity and timestamp.

---

## Blocking Dial

Demonstrate progressive policy rollout using the Blocking Dial:

1. Locate the **Blocking Dial** widget on the header or settings view.
2. Explain the operational philosophy:
   - **Dial 0 (Monitor Mode)**: Transparent inspection. High-risk traffic is flagged and logged with counterfactual actions (`would_block`), but permitted through to prevent false positives.
   - **Dial 25-50 (Balanced Protection)**: High-confidence malicious fingerprints and known C2 tools are blocked or tarpitted.
   - **Dial 100 (Full Enforcement)**: Strict risk scoring enforced.
3. Adjust the dial to **50** and click **Apply**.
4. Observe the immediate effect:
   - Connections matching the blacklisted fingerprints transition from allowed to blocked/tarpitted.
   - Grafana dashboard panels for `Blocked/sec` and `Action Breakdown` reflect the shift in real time.

---

## Verification

To validate that all six automated data-flow assertions are green:

```bash
make demo-verify
```

This runs `scripts/demo-verify.sh`, asserting:
1. Proxy metrics are actively incrementing (`ja4proxy_connections_total`).
2. Redis connection event stream (`events:connection`) is continuously populated.
3. JA4 blacklist entries are enforced at dial > 0.
4. JA4 whitelist entries successfully bypass blocking.
5. Management API dial updates propagate to the proxy's active runtime gauge (`ja4proxy_dial_current`).
6. Prometheus target scraping for `ja4proxy` is healthy and reporting active time series.

---

## Teardown

When the demonstration is concluded, gracefully stop and tear down all demo containers:

```bash
make demo-stop
```

Or run the full stop utility:

```bash
bash scripts/stop-all.sh
```
