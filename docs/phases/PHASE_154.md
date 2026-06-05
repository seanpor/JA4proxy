# Phase 154: Multi-Environment Development Isolation

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 149, Phase 152
> **Owner:** Gemini CLI

## Goal
Enable running multiple independent JA4proxy environments on the same host machine by isolating Docker resources and parameterizing all host port mappings.

## Scope

### 1. Docker Project Isolation
- **COMPOSE_PROJECT_NAME**: Update `template.env` and the setup wizard to include a project prefix (defaulting to `ja4proxy`). This ensures Docker volumes, networks, and containers are uniquely named per folder.

### 2. Comprehensive Port Parameterization
- **Refactor Docker Compose**: Ensure all host-port mappings in all Compose files (`poc`, `monitoring`, `scale`) use environment variables with sensible defaults.
- **Port Offset Logic**: Update `.env` to include a `PORT_OFFSET` or individual variables for every exposed service:
    - `HOST_PORT_INGRESS` (default: 443)
    - `HOST_PORT_STATS` (default: 8404)
    - `HOST_PORT_METRICS` (default: 9090)
    - `HOST_PORT_PROMETHEUS` (default: 9091)
    - `HOST_PORT_GRAFANA` (default: 3000)
    - `HOST_PORT_ADMIN_API` (default: 8091)
    - `HOST_PORT_MANAGEMENT` (default: 8090)

### 3. Wizard Enhancements (`ja4p init`)
- Update the `ja4p-setup` tool to prompt for an **"Environment Name/Prefix"**.
- Prompt for a **"Port Offset"** (e.g., adding 1000 to all ports) to automatically avoid collisions with existing environments.

### 4. Script Robustness
- Update `start-poc.sh` and `start-monitoring.sh` to explicitly pass the project name to Docker Compose commands.

## Acceptance Criteria
- [ ] Two separate checkouts of the repo on the same machine can run simultaneously without port or container name conflicts.
- [ ] `ja4p init` allows setting a unique prefix and port range.
- [ ] Docker volumes are isolated (clearing one environment does not affect the other).

---

## Strategic Intent
This phase empowers developers and researchers to run parallel experiments or multi-version comparisons on a single machine without interference. It is a critical feature for rapid prototyping and A/B testing of security policies.
