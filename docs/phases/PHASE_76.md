# Phase 76: Enterprise RHEL Production Deployment Strategy

## 1. Overview
This phase paper outlines the definitive best-practice architecture and operational playbook for deploying JA4proxy into a strict enterprise environment. The target environment is a remote Red Hat Enterprise Linux (RHEL 8/9) server acting as a dedicated inline network middlebox, situated between a Load Balancer (LB) and the protected Backend Host.

**Key Constraints:**
- No development tools, compilers, or source code on the production host.
- Absolute minimal attack surface.
- Native RHEL tooling where possible.
- Zero-downtime updates via LB integration.

---

## 2. Architecture & Topologies

The host acts strictly as a Layer 7 / Layer 4 proxy depending on configuration.

**Traffic Flow:**
`Client` -> `Enterprise Load Balancer (F5, ALB, HAProxy)` -> `JA4proxy (RHEL Node)` -> `Protected Backend Application`

### 2.1 Dependencies
To guarantee predictable proxy performance, all stateful dependencies should be offloaded in a production tier:
- **Redis:** Must be externalized (e.g., AWS ElastiCache, internal Redis Enterprise cluster). Running Redis locally on the proxy node risks resource contention (CPU/Memory starvation) which can introduce latency spikes in inline traffic processing.
- **Log Aggregation:** Must be offloaded via an asynchronous shipper (see Logging section).

---

## 3. Artifact Delivery and Container Engine (The "Red Hat Way")

Docker daemon runs as root and is often prohibited in strict enterprise environments. The deployment will utilize **Podman** and **Systemd Quadlets**.

### 3.1 Pre-built Artifacts
1. Images for the Go Proxy, Python Analytics, and any sidecars are built in a secure CI/CD pipeline.
2. Images are scanned for CVEs, cryptographically signed (e.g., Cosign), and pushed to the enterprise's internal OCI registry (e.g., JFrog Artifactory, Harbor).

### 3.2 Systemd Quadlets Integration
Instead of manual `podman run` commands or `docker-compose`, the deployment will use Systemd Quadlets (`.container` files).
- These files are placed in `/etc/containers/systemd/`.
- Systemd automatically generates service units and manages the lifecycle of the containers natively.
- This ensures JA4proxy starts automatically on boot and recovers from crashes, utilizing systemd's robust dependency mapping (e.g., `After=network-online.target`).

---

## 4. Host Configuration & Security (RHEL Specifics)

### 4.1 Kernel Tuning (sysctl)
An inline proxy requires aggressive network tuning to handle high connection churn and prevent port exhaustion. Ansible should apply `/etc/sysctl.d/99-ja4proxy.conf`:
```ini
# Increase max connection tracking
net.netfilter.nf_conntrack_max = 2000000
# Ephemeral port range tuning
net.ipv4.ip_local_port_range = 1024 65535
# Allow binding to privileged ports if running rootless
net.ipv4.ip_unprivileged_port_start = 443
# TCP buffer sizing for high throughput
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

### 4.2 SELinux and Capabilities
SELinux **must** remain `Enforcing`.
- **Volumes:** All configuration files mounted into the container must be labeled with the `container_file_t` SELinux context. (e.g., `chcon -Rt svirt_sandbox_file_t /etc/ja4proxy/`).
- **Capabilities:** The containers should drop all capabilities (`--cap-drop=all`) and explicitly add only what is necessary (e.g., `CAP_NET_BIND_SERVICE` if binding to ports < 1024).

---

## 5. Volume Management

The host filesystem must be kept immutable where possible to prevent tampering and disk-exhaustion from logs.

1. **Configuration (`/etc/ja4proxy/`):**
   - Managed entirely by a configuration management tool (Ansible/Chef).
   - Mounted into the Podman containers as **Read-Only** (`:ro`).
2. **Secrets (`/etc/ja4proxy/certs/`):**
   - TLS certificates and Redis passwords must be restricted to root-only (`chmod 0400`).
   - Alternatively, inject secrets natively via Podman secrets which mount them into `tmpfs` (memory).
3. **No Persistent Data Volumes:**
   - Because Redis is externalized, there is no need for stateful data volumes (RDB/AOF) on the proxy node itself.

---

## 6. Log Gathering and Observability

Writing logs to a local disk inside a container is a severe anti-pattern for network appliances.

1. **Log Output:** All components (Go Proxy, Python Analytics) must log strictly to `stdout`/`stderr` in structured JSON format.
2. **Log Driver:** Podman must be configured to use the `journald` log driver.
3. **Log Shipping:** A lightweight log shipper (Vector or Fluent-bit) runs as a system service or Quadlet container on the host. It tails the `journald` entries for the JA4proxy services, enriches them with host metadata, and forwards them to the enterprise SIEM (Splunk, ELK) or observability platform (Datadog).
4. **Metrics:** The Go Proxy exposes a `/metrics` Prometheus endpoint on an internal-only port. An enterprise scrape agent (e.g., Datadog agent, Prometheus node) collects these metrics.

---

## 7. Deployment and Verification Workflow

Deployments must follow a strict, automated, zero-downtime workflow coordinated by Ansible or similar orchestrator.

### 7.1 Deployment Execution
1. **Drain:** Ansible instructs the Load Balancer to drain traffic from the target RHEL node.
2. **Update:** Ansible pulls the latest Podman images, updates the Quadlet configurations in `/etc/containers/systemd/`, and reloads the systemd daemon.
3. **Restart:** `systemctl restart ja4proxy-*`
4. **Wait for Health:** Systemd waits for the service to report healthy.

### 7.2 Verification (Post-Flight Checks)
Verification must be empirical and multi-layered:

1. **Host-Level Verification:**
   - `systemctl is-active ja4proxy`
   - Test internal `/health` endpoint: `curl -f http://localhost:9090/health`
2. **Dataplane Verification (Crucial):**
   - Generate synthetic traffic from the Ansible controller or a designated jump host.
   - Send a specifically crafted request to the Load Balancer, passing a unique trace ID header (e.g., `X-JA4-Test: <uuid>`).
   - Wait 5 seconds, then query the enterprise SIEM/Log Aggregator via API to verify that the request with the specific `<uuid>` was logged, parsed, and contains the expected JA4 fingerprint signatures.
3. **Backend Reachability:**
   - Confirm the synthetic request successfully reached the Backend Host and returned a `200 OK` to the client.
4. **Un-Drain:**
   - If all checks pass, Ansible instructs the Load Balancer to place the node back into the active pool.
   - If any check fails, Ansible instantly rolls back the Quadlet configuration and restarts the previous image, preserving the drained state for investigation.
