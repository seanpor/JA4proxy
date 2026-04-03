# PHASE 73 — Docker Isolation: Host-Level Hardening

## Status: OPEN

---

## Goal

Partition the physical resources of the i9-9900K host and minimize the attack surface by enforcing a "Two-Port Policy" across agent-specific loopback IP addresses.

---

## 73a. The "Two-Port Policy"

### Implementation

Update `docker-compose.poc.yml` to bind only HAProxy and Analytics to the host, using the `AGENT_BIND_IP` variable. Remove host-level port exposures for all other services.

### Code Change: `docker-compose.poc.yml`

```yaml
services:
  haproxy:
    ports:
      - "${AGENT_BIND_IP}:${HOST_PORT_INGRESS:-443}:443"
  
  analytics:
    ports:
      - "${AGENT_BIND_IP}:${HOST_PORT_ANALYTICS:-8080}:8080"
```

---

## 73b. CPU Partitioning

### Implementation

Implement `cpuset` pinning and resource limits for the i9-9900K (16 logical threads). Use the `${AGENT_CPU_SET}` variable from the environment.

### Code Change: `docker-compose.poc.yml`

```yaml
services:
  proxy:
    deploy:
      resources:
        limits:
          cpus: '2.0'
    cpuset: "${AGENT_CPU_SET}"
```

---

## 73c. Non-Root Execution & Quotas

### Implementation

Ensure all containers execute as a non-privileged user and implement log rotation limits to prevent disk exhaustion.

### Code Change: `docker-compose.poc.yml`

```yaml
services:
  proxy:
    user: "1000:1000"
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
```

---

## Acceptance Criteria

- [ ] Two-port policy (443, 8080) verified for running agents.
- [ ] Loopback IP binding (127.0.0.10-13) verified via `netstat`.
- [ ] `cpuset` pinning verified for i9-9900K threads.
- [ ] All containers run as non-root users (`user: "1000:1000"`).
- [ ] Log rotation enforced at 300MB per container.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker-compose.poc.yml` | Update host-level port binding and resource limits |
| `docker-compose.test.yml` | Update host-level port binding |
| `docs/architecture/ISOLATION_MODEL.md` | Update hardening documentation |
| `CHANGELOG.md` | Phase 73 entry |
