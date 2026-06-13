---
phase: 240
title: Multi-DC SyncAgent Deployment & PKI Orchestration
status: PROPOSED
size: LARGE
created: 2026-06-13
audience: [developer, operator, secops]
dependencies: [239]
---

# PHASE 240 — Multi-DC SyncAgent Deployment & PKI Orchestration

This document outlines the design, configuration prerequisites, and step-by-step deployment plan for establishing secure cross-datacenter state replication using JA4proxy's built-in `syncagent`. It is written as an educational guide for junior engineers to understand multi-DC synchronization, mTLS tunnels, and WAN data consistency protocols.

---

## 📖 Architectural Concepts Explained

When protecting web applications deployed across multiple datacenters (e.g., DC-A in New York and DC-B in London), security states like IP bans, whitelists, and progressive blocking dial thresholds must be replicated to maintain a consistent security posture. 

### 1. Asynchronous State Replication vs. WAN Latency
A primary rule of high-performance reverse proxying is that **WAN (Wide Area Network) latency must never impact the connection hot path.**
*   **The Inefficient Way:** The proxy in DC-A intercepts a connection and makes a synchronous call over the internet to check the database in DC-B. This adds 100ms+ of latency, ruining the user experience.
*   **The JA4proxy Way:** Every datacenter runs a completely independent, local Redis server. The Go proxy daemon (`ja4pd`) reads and writes **only** to its local Redis instance. Telemetry lookups and scoring run in microseconds.
*   **Replication:** State changes are synchronized asynchronously in the background. If DC-A bans a bot, the event is copied to DC-B over the WAN in the background. The client experiences zero inline latency.

---

### 2. How the Built-in `syncagent` Works
Rather than replicating the entire database or exposing raw Redis ports across the public internet (which is highly insecure), JA4proxy uses a dedicated synchronization agent (`syncagent` implemented in Go under `internal/cluster/sync/`).

```
  [ Datacenter A ]                                           [ Datacenter B ]
 ┌────────────────┐                                         ┌────────────────┐
 │  ja4pd proxy   │                                         │  ja4pd proxy   │
 └───────┬────────┘                                         └───────┬────────┘
         │ (local write)                                            │ (local read)
         ▼                                                          ▼
 ┌───────────────┐                                         ┌───────────────┐
 │  Local Redis  │                                         │  Local Redis  │
 └───────┬───────┘                                         └───────▲───────┘
         │ (Redis Stream)                                           │ (Writes ban)
         ▼                                                          │
 ┌───────────────┐                                         ┌────────┴───────┐
 │   syncagent   │ ◄════════ Persistent mTLS Tunnel ══════► │   syncagent   │
 └───────────────┘             (WAN Port 7379)             └────────────────┘
```

1.  **Stream Capture:** The proxy writes connection events to a local **Redis Stream** named `events:connection` (configurable via `proxy.yml:webhooks:stream_key`, defaults to `events:connection`).
2.  **Persistent WAN Tunnel:** The local `syncagent` establishes a long-lived, persistent TCP connection (using TCP Keep-Alives) to the remote peer `syncagent` over port `7379`. Asynchronous stream events are written continuously over this connection, avoiding the high CPU overhead of performing a new TLS handshake for every single event.
3.  **Dynamic Cert Loading:** To support zero-downtime certificate rotation, `syncagent` wraps the TLS configuration's `GetCertificate` and `GetClientCertificate` callbacks. This enables loading updated certs from disk dynamically without restarting the daemon.
4.  **Rely on mTLS for Integrity (Simplified Cryptography):** Mutual TLS (mTLS) with client certificate verification against a private CA already guarantees data integrity, confidentiality, and peer identity. Additional application-layer signing (e.g. Ed25519) is omitted to simplify configuration, code size, and CPU overhead.
5.  **Robust Replay & PEL Healing:** If the WAN link drops (split-brain), the sync agent continues to track events locally. When the link heals, the loop first queries and processes all pending unacknowledged entries from the Pending Entries List (PEL) using Redis `XREADGROUP` with ID `"0"`, retrying delivery until successful. Only when all pending messages are acknowledged (`XACK`) does it resume streaming new events (ID `">"`), guaranteeing zero event loss.
6.  **Simple Database Writes:** Dynamic IP bans are transient keys with a TTL. A simple, blind write of the ban to local Redis (`SET EX` or `SADD`) is used. Strict conflict resolution via Lua/LWW is omitted as minor differences in TTL expiration are functionally acceptable for security enforcement.
7.  **Admin API for Dial Changes:** To avoid building custom multiplexing protocols, synchronous blocking threshold modifications ("Dial" changes) are routed via a secure HTTPS/mTLS POST request to the peer's existing Admin API port `8113` / `3023` (e.g. `/api/v1/config/dial`), leveraging the existing web application framework.

---

### 3. Can our Redis setup do this as-is?
**Yes.** The Redis instance deployed in our single-host configuration is standard Redis, which supports the Redis Streams (`XADD`, `XREADGROUP`) required by the `syncagent`.
*   **Security Benefit:** Because the `syncagent` runs locally on the host and binds to loopback (`127.0.0.1:6379`) to communicate with Redis, **our Redis configuration does not need to change**. It remains bound to localhost and completely offline. 
*   Exposing Redis directly to the WAN (which is required if using direct Redis replication) is insecure and should be avoided. The `syncagent` acts as a secure, authenticated gateway.

---

## 📋 Scope

- `internal/cluster/sync/agent.go` (Audit and refactor sync agent to support persistent Keep-Alive connections, ServerName checks, PEL retry, and dynamic cert callbacks)
- `scripts/setup_wizard.py` (Extend wizard to support Multi-DC setup options, generating mTLS certificates and `sync` configuration block)
- `docs/phases/manifest.yaml` (Proposed entry for Phase 233)
- `docs/PROJECT_STATUS.md` (Roadmap synchronization)
- `docs/phases/TODO.md` (Roadmap synchronization)

---

## 🛠️ Implementation Plan

### A — CLI Wizard Multi-DC Setup Extension
*   **CLI Structure:** Extend `setup_wizard.py` to prompt the operator for multi-datacenter setups (local DC ID, peer DC WAN addresses, and mTLS cert paths).
*   **Configuration Generation:** Generate the `sync` block in `proxy.yml` dynamically with correct addresses, ports, and cert targets.

### B — mTLS PKI Generation Script
*   **PKI Script:** Create `scripts/generate_sync_certs.sh` to automate the generation of a dedicated self-signed CA and individual client/server certificate pairs for each datacenter sync agent.
*   **Cert Restrictions:** Enforce CN constraints matching DC IDs. Ensure the client's `tls.Config` explicitly sets `ServerName` to the peer DC identifier during connection dials to satisfy hostname validation over WAN IP addresses.

### C — Dynamic Certificate Reloading
*   **Cert Callbacks:** Implement dynamic cert reloads in `internal/cluster/sync/agent.go` using TLS callbacks `GetCertificate` and `GetClientCertificate`. Ensure cert files are re-read from disk on change without daemon restart.

### D — Persistent Keep-Alive Sync Pipeline
*   **Long-Lived Connections:** Refactor the replication loop to maintain a single, long-lived, persistent TCP connection per peer with Keep-Alive configurations, instead of creating a new connection and handshake per event.
*   **PEL Drainage First:** Refactor the consumer group reader so that it reads and retries pending entries from the PEL (ID `"0"`) until they are successfully acknowledged before attempting to pull new events.
*   **Direct Redis Writes:** Apply incoming sync events directly to local Redis using standard commands (`SET`, `SADD`, `SREM`).

### E — Non-Blocking Control Plane Dial Changes
*   **API Dial Broadcast:** Refactor `BroadcastDialChange` to send Dial threshold changes via an asynchronous secure HTTPS POST request to the peer's existing `/api/v1/config/dial` Admin API endpoint, reducing the default block timeout to a configurable 2 seconds.
*   **Systemd Service Unit:** Create a host-level systemd service configuration `/etc/systemd/system/ja4proxy-syncagent.service` that launches `syncagent` as a background daemon starting automatically after Redis is initialized.

---

## 📋 Prerequisites for the Installing Firm

1.  **Global Server Load Balancing (GSLB):** 
    *   Configure a GSLB (e.g., Cloudflare, Route53, F5 GTM) to direct public traffic to the nearest healthy datacenter IP.
2.  **WAN Firewall Rules:**
    *   Open TCP port `7379` (mTLS replication port) and the Admin API port (`8113` / `3023`) between the public/VPN IPs of the two proxy hosts, restricting access exclusively to those peer IPs.
3.  **Clock Synchronization (NTP):**
    *   Install and run `chrony` or `ntpd` on both host VMs.
    *   Ensure clock drift between the hosts remains under `100ms` for general operational integrity.
4.  **Copy CA Certificates:**
    *   Securely copy the CA certificate from DC-A to DC-B's trusted CA pool to enable mutual TLS validation. No private keys or custom public keyrings need to be shared.

---

## 🧪 Test Strategy

- **mTLS & ServerName Verification Tests:** 
    *   Verify that connection requests without valid certificates or with mismatched Common Names are immediately rejected.
    *   Test connection verification when dialing via WAN IP address to ensure `ServerName` hostname checks pass.
- **Persistent Keep-Alive Connection Tests:**
    *   Verify that the sync agent uses a single persistent connection and does not re-authenticate or re-handshake for consecutive events.
- **Partition Replay & PEL Healing Tests:**
    *   Block port `7379` to simulate WAN failure. Inject multiple events in DC-A.
    *   Verify that unacknowledged messages are recorded in the PEL.
    *   Unblock port `7379` and verify that the sync agent drains the PEL and retries/delivers pending events *before* sending new events.
- **Dynamic Cert Reload Tests:** Verify that writing new certificate files to disk triggers dynamic reloading without process termination.

---

## 📋 Acceptance Criteria

### Functional
- [ ] Running `syncagent` successfully connects DC-A and DC-B, replicating whitelist and ban changes bidirectionally using a single persistent connection per peer.
- [ ] A ban injected via the CLI or Management UI in DC-A is applied in DC-B's Redis within 5 seconds under normal WAN conditions.
- [ ] Event replication succeeds only when valid mTLS certs are negotiated and CN identity checks pass.
- [ ] When a network partition heals, the PEL queue is fully processed and delivered before new live events are handled.
- [ ] Swapping certificate files on disk triggers dynamic reloading without dropping connection states.

### Security & Compliance
- [ ] The `syncagent` rejects any TCP connections on port `7379` that do not pass mutual TLS validation and CN identity mapping.
- [ ] Private keys are never shared or copied across datacenter hosts.
- [ ] Redis remains bound strictly to loopback (`127.0.0.1`) in both datacenters.

---

## 🚫 Out of Scope

- Setting up or configuring GSLB servers or DNS provider APIs.
- Setting up physical network links or VPN tunnels between datacenters.
- Managing database migrations for non-JA4proxy databases.
