# JA4proxy Ansible Role

Deploys the **JA4proxy Go proxy** on RHEL / Rocky / CentOS hosts. This role
provisions and starts the **Go binary only** — there is no reference to
`proxy.py` or any Python entrypoint. The Python proxy is deprecated and
out of scope.

## What It Does

| Feature | Implementation |
|---|---|
| **Deploy mode auto-detect** | Uses systemd binary by default; switches to Podman Quadlet if `/etc/containers/systemd/` exists |
| **Three deployment modes** | `binary` (systemd), `quadlet` (Podman), `docker` (container) |
| **Security hardening** | Read-only filesystem, cap_drop ALL, no-new-privileges, resource limits |
| **Health check** | HTTP GET `/health` on metrics port with retries |
| **ServiceNow CMDB** | Optional asset registration via `servicenow.itsm` collection |
| **Log rotation** | systemd journal + optional file-based logging |

## Quick Start

```bash
# 1. Install required collections
ansible-galaxy collection install community.docker servicenow.itsm

# 2. Copy and edit the inventory
cp deploy/ansible/inventory.ini.example inventory.ini
# Edit with your target host(s)

# 3. Set required host variables
#    In host_vars/<hostname>.yml or group_vars/all.yml:
#      backend_host: "backend.corp.local"
#      upstream_lb_host: "lb.corp.local"

# 4. Deploy
ansible-playbook -i inventory.ini deploy/ansible/playbooks/deploy-ja4proxy.yml
```

## Required Variables

| Variable | Description | Default |
|---|---|---|
| `backend_host` | Backend server hostname/IP | *(required)* |
| `upstream_lb_host` | Upstream load balancer hostname/IP | *(required)* |
| `ja4proxy_deploy_mode` | Deployment mode: `binary`, `docker`, `quadlet`, or `auto` | `auto` |
| `backend_port` | Backend port | `443` |
| `ja4proxy_port` | Proxy listen port | `8080` |
| `ja4proxy_metrics_port` | Prometheus metrics port | `9090` |
| `ja4proxy_redis_host` | Redis host for state storage | `127.0.0.1` |
| `servicenow_enabled` | Register in ServiceNow CMDB | `false` |

## Deployment Modes

### `auto` (default)

The role checks for `/etc/containers/systemd/` on the target host:
- If present → **Quadlet** deployment (Podman managed by systemd)
- If absent → **systemd binary** deployment (Go binary + `.service` unit)

### `binary`

Installs a pre-built Go binary, drops a systemd unit, and starts the service.
Set `ja4proxy_binary_src` to a local path or URL.

### `docker`

Pulls the container image and runs it with security hardening. Set
`ja4proxy_container_engine` to `"docker"` or `"podman"`.

### `quadlet`

Deploys a Podman Quadlet unit file under `/etc/containers/systemd/`.
Requires Podman >= 4.4 with Quadlet support.

## ServiceNow CMDB Integration (Phase 94k)

Set `servicenow_enabled: true` and ensure the `servicenow.itsm` collection
is installed. The role will register the node in CMDB with the following
custom fields:

- `u_version` — deployed image/binary version
- `u_upstream_lb` — upstream load balancer
- `u_downstream_backend` — backend server
- `u_environment` — deploy environment (production/staging/development)
- `u_last_deployed` — ISO 8601 timestamp
- `u_config_checksum` — SHA-256 of the deployed config

## Files Deployed

### Binary mode

```
/usr/local/bin/ja4proxy           # Go proxy binary
/etc/ja4proxy/
├── proxy.yml                     # Runtime configuration
/etc/systemd/system/
├── ja4proxy.service              # Systemd unit
/var/lib/ja4proxy/geoip/          # GeoIP databases
/var/log/ja4proxy/                # Log directory
```

### Quadlet mode

```
/etc/containers/systemd/
├── ja4proxy.container            # Quadlet unit file
```

### Docker mode

Container managed via Ansible `docker_container` module.

## Cross-References

- **Phase 76** — RHEL inline deployment strategy (paper recommendation)
- **Phase 64** — Smoke test / health check suite
- **Phase 94j** — This role baseline specification
- **Phase 94k** — ServiceNow CMDB integration
