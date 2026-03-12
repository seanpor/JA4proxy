# Phase 14d — Network Security: Operations, Documentation, and Management UI

## Status: OPEN

Supplement to `PHASE_14c.md`.

PHASE_14c specified the security controls. This phase adds:

1. **Layered control matrix** — for every setting, who owns it, what layer enforces
   it, whether the UI can change it, and what restart is required.
2. **Management UI — Network Administration** — new API routes and React pages so a
   SecOps or Ops engineer can view and modify network configuration without SSH or
   developer involvement.
3. **The Network Admin daemon** — a privileged host-side process that translates
   UI/Redis commands into nftables and systemd operations, keeping all containers
   unprivileged.
4. **Role-based documentation** — separate guides for each audience:
   Architecture, SecOps, Ops/SRE, Developer.
5. **Port change runbook** — step-by-step for the scenario "I need to move the proxy
   to a different port and I do not want to call a developer."
6. **Conflict detection** — the UI detects when app config and infrastructure are
   out of sync and shows a banner before anything breaks.

---

## 1. The Core Problem: Layered Controls

PHASE_14c introduces controls at four independent layers. A port number or TLS
setting can appear at any or all of them. When they disagree, the service breaks.
When only one is changed, the others silently contradict it.

```
Layer 1 — Application config     config/proxy.yml         hot-reload via SIGHUP
Layer 2 — Container runtime      docker-compose.yml       requires compose restart
Layer 3 — Host network rules     /etc/nftables.d/         requires nftables reload
Layer 4 — Service config files   redis.conf, nginx.conf   requires service reload
```

**Example: proxy data-plane port**

| Layer | Where it lives | What to change | Restart needed? |
|-------|---------------|----------------|-----------------|
| App config | `config/proxy.yml` `proxy.bind_port` | Edit + SIGHUP | No (but port rebind IS a restart — see §5) |
| Container runtime | `docker-compose.yml` `ports:` | Edit + `docker compose up -d proxy` | Yes — container restart |
| Host nftables | `/etc/nftables.d/ja4proxy.nft` `tcp dport 8080` | Edit + `nft reload` or via UI/daemon | No |
| HAProxy backend | `haproxy.cfg` `server proxy1 proxy:8080` | Edit + `haproxy -sf` | No — graceful reload |

Miss any one layer: the service either doesn't start, gets blocked, or silently
routes to the wrong place. This document ensures that every operator knows which
layers exist, which ones the UI can touch, and which ones require a planned change.

---

## 2. Layered Control Matrix

Complete reference for all network-security-relevant settings introduced in
PHASE_14c. Columns:

- **Setting** — the config key or parameter
- **Layer** — which of the four layers it lives in
- **UI-controllable** — whether the Management UI can change it
- **Change mechanism** — exact operation required to apply
- **Restart scope** — what stops/starts (nothing, reload, container, host)

### 2.1 Proxy data-plane

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| `proxy.bind_port` | App config | ⚠️ wizard | Edit `config/proxy.yml` + container restart | Container |
| `proxy.bind_host` | App config | ⚠️ wizard | Edit + container restart | Container |
| `backend.host` | App config | ✅ | `PUT /api/v1/config/network/backend` + SIGHUP | None |
| `backend.port` | App config | ⚠️ wizard | Edit + container restart | Container |
| `backend.tls.enabled` | App config | ✅ | `PUT /api/v1/config/tls/backend` + SIGHUP | None |
| `backend.tls.ca_cert_path` | App config | ✅ view | Cert files managed by scripts; path in config | None |
| `proxy allowed on :8080` | nftables | ✅ | daemon → `nft reload` | None |
| HAProxy backend address | HAProxy cfg | ❌ ops | Edit `haproxy.cfg` + `haproxy -sf $(pidof haproxy)` | Graceful reload |

### 2.2 Redis

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| `redis.url` | App config | ✅ | `PUT /api/v1/config/network/redis` + SIGHUP | None |
| `redis.tls.enabled` | App config | ✅ | `PUT /api/v1/config/tls/redis` + SIGHUP | None |
| Redis `tls-port` | redis.conf | ❌ ops | Edit + Redis container restart | Container |
| Redis `bind` addresses | redis.conf | ❌ ops | Edit + Redis container restart | Container |
| Redis ACL file | redis-acls.conf | ✅ view / ❌ edit | Edit + `redis-cli ACL LOAD` | None |
| `requirepass` | docker-compose.yml env | ❌ ops | Edit + compose restart | Container |
| Redis nftables bind rule | nftables | ✅ | daemon → `nft reload` | None |

### 2.3 Management UI

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| Nginx listen port (8090) | nginx.conf + compose | ⚠️ wizard | Edit both + nginx reload + compose up | Container |
| `management_ui.allowed_cidr` | App config | ✅ | `PUT /api/v1/config/network/mgmt_cidr` + SIGHUP | None |
| Nginx TLS cert path | nginx.conf + Docker secret | ✅ rotate | `scripts/rotate-certs.sh nginx` via daemon | None |
| FastAPI Unix socket path | App config + nginx.conf | ❌ ops | Edit both + container restart | Container |

### 2.4 Certificates

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| Internal CA cert | Docker secret | ❌ ops | Re-run `gen-internal-certs.sh`, compose up | All containers |
| Per-service cert | Docker secret | ✅ rotate | daemon → `rotate-certs.sh <svc>` | None (SIGHUP) |
| Cert expiry monitoring | Prometheus config | ❌ ops | Edit `prometheus.yml` + reload | None |

### 2.5 Container hardening

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| `cap_drop`, `cap_add` | docker-compose.yml | ❌ ops | Edit + compose up | Container |
| seccomp profile | docker-compose.yml | ❌ ops | Edit profile + compose up | Container |
| `read_only` | docker-compose.yml | ❌ ops | Edit + compose up | Container |
| Container user UID | docker-compose.yml | ❌ ops | Edit + compose up | Container |

### 2.6 Egress (nftables)

| Setting | Layer | UI | Change mechanism | Restart scope |
|---------|-------|----|-----------------|---------------|
| `proxy_allowed_egress` set (IPs) | nftables set | ✅ | daemon → `nft add element` | None |
| Log prefix / alert threshold | nftables + rules | ❌ ops | Edit nft file + reload | None |
| Block analytics egress | nftables | ❌ ops | Edit nft file + reload | None |

### 2.7 Legend

| Icon | Meaning |
|------|---------|
| ✅ | Fully controllable from the Management UI |
| ⚠️ wizard | UI shows a "Configuration Wizard" that generates the exact change commands and validates consistency; the final apply still requires an ops action |
| ❌ ops | Requires SSH + file edit; UI shows current value read-only |

---

## 3. Management UI — Network Administration Extensions

### 3.1 New API routes (Phase 14d additions to `management/`)

```
GET  /api/v1/network/status                 Network topology + port exposure matrix
GET  /api/v1/network/consistency            Detect cross-layer config conflicts
GET  /api/v1/network/egress                 Current nftables egress allowlist
POST /api/v1/network/egress                 Add IP/CIDR to egress allowlist
DELETE /api/v1/network/egress/{cidr}        Remove from egress allowlist
GET  /api/v1/network/ports                  Declared port assignments, all layers
POST /api/v1/network/ports/wizard           Validate a proposed port change
GET  /api/v1/tls/status                     TLS enabled/disabled per connection leg
PUT  /api/v1/tls/backend                    Toggle backend TLS on/off
PUT  /api/v1/tls/redis                      Toggle Redis TLS on/off
POST /api/v1/certs/rotate/{service}         Trigger cert rotation via daemon
GET  /api/v1/certs/expiry                   Days until expiry, all certs
GET  /api/v1/redis/acls                     Redis ACL user list (read-only)
GET  /api/v1/firewall/rules                 Current nftables rules (read-only)
POST /api/v1/firewall/reload                Trigger nftables reload via daemon
```

All routes require `Depends(require_api_key)`. Mutating routes additionally check
the caller's IP is in `management_ui.allowed_cidr`.

### 3.2 New React SPA pages

Add to the existing 9-page SPA (see PHASE_13b §5.4):

#### NetworkPage (`/network`)

The primary network management screen. Two-column layout:

**Left — Topology diagram (SVG, auto-generated from live data):**
```
Internet ──:443──▶ HAProxy ──:8080──▶ Proxy ──:6380──▶ Redis
                     │                              ↑
                     └── net-edge                   │
                              net-proxy ────────────┘
                              net-mgmt ── Analytics ── Management
```

Each service node is colour-coded: green = reachable + TLS, amber = reachable +
plaintext, red = unreachable, grey = unknown.

**Right — Status cards:**
- Per-connection-leg TLS status (backend, Redis, Prometheus scrape)
- Per-service network membership
- Port exposure matrix (what ports are published to the host and to which interface)
- Any cross-layer conflicts detected by `GET /api/v1/network/consistency`

**Conflict banner:** if the consistency endpoint reports any disagreement between
config/proxy.yml and the runtime state, a red banner appears at the top:

```
⚠ Configuration conflict detected: config/proxy.yml declares backend.port=8443
  but the running container is connected to backend:8080. A restart is needed.
  [View details] [Dismiss]
```

#### CertificatePage (`/certs`)

| Column | Content |
|--------|---------|
| Service | proxy, redis, analytics, management, nginx |
| Issued | date |
| Expires | date + colour (green >30d, amber 7–30d, red <7d) |
| Status | valid / expired / unreachable |
| Action | [Rotate] button → calls `POST /api/v1/certs/rotate/{service}` |

The Rotate action shows a confirmation modal with:
- "This will replace the cert without restarting the service."
- "Active connections will continue; new connections will use the new cert."
- [Confirm] [Cancel]

On success: shows "Cert rotated. New expiry: <date>."
On failure: shows the error from the daemon log.

#### EgressPage (`/egress`)

Left panel: table of current `proxy_allowed_egress` nftables set entries.
- Each row: CIDR, added date, label (AbuseIPDB CDN, DNS, RDAP IANA, custom).
- [Remove] button per row.

Right panel: add form.
- CIDR field with validation (must be valid IPv4/IPv6 CIDR).
- Optional label field.
- [Add] button → calls `POST /api/v1/network/egress`.

Bottom: last reload time + [Reload firewall rules] button → calls
`POST /api/v1/firewall/reload`.

#### TLSPage (`/tls`)

Four toggles:
- **Proxy → Backend TLS** — enabled/disabled. Warning shown if disabled:
  "Traffic between the proxy and backend will be unencrypted."
- **Proxy → Redis TLS** — enabled/disabled. Warning: "Redis communications will be
  plaintext. This is a CRITICAL security risk in production."
- **Metrics endpoint TLS** — enabled/disabled.
- **Metrics endpoint auth** — enabled/disabled + token field.

Each toggle calls the appropriate `PUT /api/v1/tls/*` endpoint, which writes to
`config/proxy.yml` and sends SIGHUP. The change takes effect for the next
connection without a restart.

#### PortWizardPage (`/ports`)

The answer to "I need to change a port without calling a developer."

Step 1 — Current state table:

| Service | Port | Layer | Status |
|---------|------|-------|--------|
| Proxy data-plane | 8080 | App config | ✅ consistent |
| Proxy data-plane | 8080 | HAProxy backend | ✅ consistent |
| Proxy data-plane | 8080 | nftables | ✅ consistent |
| Redis | 6380 | redis.conf | ✅ consistent |
| Redis | 6380 | App config | ✅ consistent |
| Management UI | 8090 | Nginx | ✅ consistent |
| Management UI | 8090 | Docker compose port | ✅ consistent |

Step 2 — Click any port number to enter "change mode". The UI renders a diff panel
showing every file that must change and exactly what to change in each.

Step 3 — For ports the daemon can handle (nftables, config/proxy.yml, Nginx reload):
[Apply managed changes]. For ports that require a compose restart or HAProxy edit:
the UI generates a downloadable shell script:

```bash
#!/bin/bash
# Generated by JA4Proxy Management UI at 2026-03-12T16:00:00Z
# PORT CHANGE: proxy data-plane 8080 → 8443
# Run this on the Docker host as the deploy user.

set -euo pipefail

# Step 1: Update docker-compose.yml
sed -i 's/server proxy1 proxy:8080/server proxy1 proxy:8443/' haproxy/haproxy.cfg
echo "[1/4] haproxy.cfg updated"

# Step 2: Reload HAProxy (graceful — no traffic drop)
haproxy -sf $(pidof haproxy) -f haproxy/haproxy.cfg
echo "[2/4] HAProxy reloaded"

# Step 3: Restart proxy container (required for port binding change)
docker compose up -d --no-deps proxy
echo "[3/4] Proxy container restarted"

# Step 4: Verify
sleep 2
curl -sf http://localhost:8443/health && echo "[4/4] Health check passed"
```

The script is shown in a code block with a [Download] button and a [Copy] button.

Step 4 — After applying, the user returns to the wizard. The consistency check
reruns automatically. When all layers agree, the table shows all green.

---

## 4. The Network Admin Daemon

### 4.1 Why it exists

Management containers run with `cap_drop: ALL` — they cannot modify nftables,
reload systemd units, or run scripts that require elevated privileges. But the
Management UI needs to be able to trigger:
- `nft add element inet ja4proxy proxy_allowed_egress { 1.2.3.4/32 }`
- `systemctl reload nginx`
- `./scripts/rotate-certs.sh redis`
- `nft reload` after an egress change

The Network Admin daemon is a small privileged process running on the **Docker host**
(not inside any container). It watches a Redis pub/sub channel and executes
pre-approved, strictly validated operations. It is the only component with elevated
privileges.

### 4.2 Implementation

```python
# /usr/local/lib/ja4proxy/netadmin.py
"""
JA4Proxy Network Admin Daemon.

Watches Redis channel `ja4proxy:netadmin:commands` for signed operation requests
from the Management API. Executes a pre-approved, strictly validated whitelist
of operations. All actions are audited to syslog.

This process runs as root on the Docker host. It must never be containerised.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import syslog
from ipaddress import ip_network, AddressValueError

import redis.asyncio as aioredis

logger = logging.getLogger("netadmin")
SHARED_SECRET = os.environ["NETADMIN_SECRET"]   # shared with management container
REDIS_URL     = os.environ["REDIS_URL"]

# ── Allowed operations (whitelist) ──────────────────────────────────────────

def _validate_cidr(cidr: str) -> str:
    """Raise ValueError if not a valid CIDR. Return normalised form."""
    return str(ip_network(cidr, strict=False))

def op_egress_add(payload: dict) -> str:
    cidr = _validate_cidr(payload["cidr"])
    subprocess.run(
        ["nft", "add", "element", "inet", "ja4proxy",
         "proxy_allowed_egress", f"{{ {cidr} }}"],
        check=True, capture_output=True
    )
    return f"egress_add:{cidr}"

def op_egress_remove(payload: dict) -> str:
    cidr = _validate_cidr(payload["cidr"])
    subprocess.run(
        ["nft", "delete", "element", "inet", "ja4proxy",
         "proxy_allowed_egress", f"{{ {cidr} }}"],
        check=True, capture_output=True
    )
    return f"egress_remove:{cidr}"

def op_firewall_reload(_payload: dict) -> str:
    subprocess.run(["nft", "-f", "/etc/nftables.d/ja4proxy.nft"],
                   check=True, capture_output=True)
    return "firewall_reload"

def op_cert_rotate(payload: dict) -> str:
    svc = payload.get("service", "")
    # Strictly validate service name — must be in known list
    allowed = {"redis", "proxy", "analytics", "management", "nginx", "prometheus"}
    if svc not in allowed:
        raise ValueError(f"Unknown service: {svc!r}")
    result = subprocess.run(
        ["/usr/local/bin/ja4proxy-rotate-certs.sh", svc],
        check=True, capture_output=True, text=True
    )
    return f"cert_rotate:{svc}"

def op_nginx_reload(_payload: dict) -> str:
    subprocess.run(["systemctl", "reload", "nginx"],
                   check=True, capture_output=True)
    return "nginx_reload"

DISPATCH = {
    "egress_add":       op_egress_add,
    "egress_remove":    op_egress_remove,
    "firewall_reload":  op_firewall_reload,
    "cert_rotate":      op_cert_rotate,
    "nginx_reload":     op_nginx_reload,
}

# ── HMAC signature verification ─────────────────────────────────────────────

def _verify_signature(message: dict) -> bool:
    """Verify HMAC-SHA256 signature on incoming command."""
    sig = message.pop("sig", "")
    canonical = json.dumps(message, sort_keys=True).encode()
    expected = hmac.new(
        SHARED_SECRET.encode(), canonical, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)

# ── Main loop ────────────────────────────────────────────────────────────────

async def main():
    syslog.openlog("ja4proxy-netadmin", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(syslog.LOG_INFO, "Network admin daemon starting")

    r = await aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe("ja4proxy:netadmin:commands")

    async for message in pubsub.listen():
        if message["type"] != "message":
            continue

        try:
            cmd = json.loads(message["data"])
        except json.JSONDecodeError:
            syslog.syslog(syslog.LOG_WARNING, f"Invalid JSON: {message['data']!r}")
            continue

        if not _verify_signature(cmd):
            syslog.syslog(syslog.LOG_WARNING,
                          f"Signature verification failed for op={cmd.get('op')!r}")
            await r.lpush("management:audit_log", json.dumps({
                "event": "netadmin_sig_failure",
                "op": cmd.get("op"),
                "timestamp": __import__("time").time(),
            }))
            continue

        op = cmd.get("op")
        handler = DISPATCH.get(op)
        if not handler:
            syslog.syslog(syslog.LOG_WARNING, f"Unknown op: {op!r}")
            continue

        try:
            result = handler(cmd.get("payload", {}))
            syslog.syslog(syslog.LOG_INFO,
                          f"op={op} result={result} actor={cmd.get('actor','?')}")
            await r.lpush("management:audit_log", json.dumps({
                "event": "netadmin_op_success",
                "op": op, "result": result,
                "actor": cmd.get("actor"),
                "timestamp": __import__("time").time(),
            }))
            # Publish result for UI polling
            await r.publish(
                f"ja4proxy:netadmin:results:{cmd.get('request_id')}",
                json.dumps({"status": "ok", "result": result})
            )
        except subprocess.CalledProcessError as exc:
            syslog.syslog(syslog.LOG_ERR,
                          f"op={op} failed: {exc.stderr.decode()!r}")
            await r.publish(
                f"ja4proxy:netadmin:results:{cmd.get('request_id')}",
                json.dumps({"status": "error", "detail": exc.stderr.decode()})
            )
        except ValueError as exc:
            syslog.syslog(syslog.LOG_ERR, f"op={op} validation error: {exc}")
            await r.publish(
                f"ja4proxy:netadmin:results:{cmd.get('request_id')}",
                json.dumps({"status": "error", "detail": str(exc)})
            )

if __name__ == "__main__":
    asyncio.run(main())
```

### 4.3 Security properties of the daemon

| Property | How |
|----------|-----|
| Only pre-approved operations | `DISPATCH` whitelist; unknown ops silently dropped |
| CIDR injection prevention | `ip_network()` validation before any `nft` call; no shell interpolation |
| Service name injection prevention | Allowlist check before passing to subprocess |
| No shell=True | All `subprocess.run()` calls use list args |
| HMAC-signed commands | Management API signs every command with `NETADMIN_SECRET` |
| Full audit trail | Every accepted and rejected operation written to syslog + Redis audit log |
| Runs on host, not in container | Cannot be escaped or modified via container escape |

### 4.4 systemd unit

```ini
# /etc/systemd/system/ja4proxy-netadmin.service
[Unit]
Description=JA4Proxy Network Admin Daemon
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /usr/local/lib/ja4proxy/netadmin.py
Restart=always
RestartSec=5
EnvironmentFile=/etc/ja4proxy/netadmin.env
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ja4proxy-netadmin

# Harden the daemon itself
NoNewPrivileges=false        # Must be false — needs to run nft as root
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/nftables.d /etc/systemd/system
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

`/etc/ja4proxy/netadmin.env` (permissions 0600, root:root):

```
NETADMIN_SECRET=<generated at deploy time>
REDIS_URL=rediss://management:password@localhost:6380
```

---

## 5. Role-Based Documentation

### 5.1 Architecture Guide

**Audience:** architects, technical leads, security reviewers.

#### Design principles

1. **No privileged containers.** All containers run `cap_drop: ALL`. Privileged
   host-level operations (nftables, cert rotation, Nginx reload) are delegated to
   the netadmin daemon — a single, audited, host-side process.

2. **Fail open on network controls.** If the netadmin daemon is unavailable, the
   proxy continues operating. Egress rules cannot be updated, but existing rules stay
   in place. The Management UI shows a warning.

3. **Defence in depth — four independent layers.** No single misconfiguration in one
   layer compromises the system. An attacker who compromises a container faces
   nftables rules on the host that were written outside any container.

4. **The UI controls what it safely can; everything else gets a wizard.**
   Settings that require a container restart are never applied automatically — the
   UI generates a validated change script for the ops team. Settings that can be
   applied safely (nftables set updates, cert rotation, config + SIGHUP) are
   applied directly via the daemon.

#### Trust model

```
Internet (untrusted)
    ↓ TLS :443
HAProxy (net-edge only)
    ↓ TLS :8080 or Unix socket
JA4proxy (net-proxy only)
    ↓ mTLS :6380
Redis (net-proxy + net-mgmt)
    ↑ mTLS :6380
Analytics (net-mgmt only) ── writes findings → Redis
Management FastAPI (net-mgmt only) ← operator API
    ↑ Unix socket
Nginx (net-mgmt only) ← operator browser via HTTPS :8090
    ↑ pub/sub
netadmin daemon (host, privileged) ← executes nftables/cert ops
```

No horizontal trust: HAProxy cannot reach Redis directly. Analytics cannot reach
the internet. Management cannot reach the proxy data plane. Each service is limited
to the minimum network surface it needs to function.

#### What cannot be changed without a developer

Nothing in normal operation. The things that require a container restart
(port binding, network assignment, capabilities) are all configuration, not code.
A container restart takes < 5 seconds and drops no connections if HAProxy is in
front (it retries on the active backend).

What requires a developer:
- Adding a new service to the topology (new container, new network assignment)
- Changing the seccomp profile or capabilities list
- Modifying the netadmin daemon's operation whitelist

---

### 5.2 SecOps Operations Guide

**Audience:** security operations team. Day-to-day security administration.

#### What you can do from the Management UI

| Task | Where | Notes |
|------|-------|-------|
| View network topology | `/network` | Live status; updates every 30s |
| View per-leg TLS status | `/network` or `/tls` | Green = TLS on; red = plaintext |
| Toggle backend TLS on/off | `/tls` | Takes effect on next connection; no restart |
| Toggle Redis TLS on/off | `/tls` | Takes effect on next connection; no restart |
| Add IP/CIDR to proxy egress allowlist | `/egress` | Immediate; no restart |
| Remove IP/CIDR from proxy egress allowlist | `/egress` | Immediate; no restart |
| Rotate a service cert | `/certs` | Takes effect in < 5s; no service restart |
| View cert expiry dates | `/certs` | Colour-coded warning at 30d, critical at 7d |
| View Redis ACL users | `/network` | Read-only; shows which commands each user can issue |
| View current firewall rules | `/network` | Read-only view of active nftables rules |
| Reload firewall rules | `/network` | Applies after any manual nft file edit |
| View config consistency | `/network` | Detects cross-layer mismatches |
| View all network-related audit log entries | `/audit?event_type=netadmin` | Full history |

#### Alerts you will receive and what to do

| Alert | Meaning | Immediate action |
|-------|---------|-----------------|
| `AnomalousContainerNetworkTraffic` | A container attempted a cross-network connection that the topology forbids | Check `/audit` for the container and operation; run `journalctl -k | grep JA4_ANOMALOUS`; consider pausing that container pending investigation |
| `ProxyProtocolSpoofAttempt` | A non-HAProxy IP tried to connect to the proxy on port 8080 | Check source IP; if attacker is on internal network, this is a significant escalation; rotate all internal credentials |
| `InternalCertExpirySoon` (30d) | A cert will expire in < 30 days | Navigate to `/certs`; click Rotate for the named service; verify new expiry |
| `InternalCertExpiryCritical` (7d) | Cert expires in < 7 days | Rotate immediately; if rotation fails, escalate to ops for daemon investigation |
| `InternalCertExpired` | Cert has expired | Service is likely broken; ops must investigate daemon and run rotation manually |
| `BackendTLSDisabled` | Proxy→backend traffic is plaintext | Navigate to `/tls`; enable backend TLS; if backend doesn't support TLS, raise with ops to configure backend cert |
| `RedisTLSDisabled` | Redis traffic is plaintext | Navigate to `/tls`; enable Redis TLS; this is a CRITICAL finding |
| `ContainerEgressBlocked` | A container tried to make an outbound connection that was blocked | Likely a legitimate new API endpoint not in the egress allowlist; check with the analytics/proxy team; if legitimate, add CIDR on `/egress` |

#### What requires an ops engineer (not UI-accessible)

- Changing any port number that affects container binding
- Changing a container's network assignment (adding/removing a container from a network)
- Modifying the Redis ACL file (changing what commands users can issue)
- Modifying the seccomp profile
- Replacing the internal CA cert (affects all services simultaneously)
- Modifying the netadmin daemon's operation whitelist

For these, raise a ticket to the Ops team with the desired change and the
justification. The ops team uses the PortWizardPage (`/ports`) to generate the
validated change script.

---

### 5.3 Ops / SRE Day-2 Runbook

**Audience:** operations and SRE engineers. Infrastructure changes, incident response,
and planned maintenance.

#### Pre-flight checklist for any network change

```
□ Check /network for existing conflicts before making any change.
  A change on top of an existing conflict produces unpredictable results.
□ Ensure netadmin daemon is running: systemctl status ja4proxy-netadmin
□ Confirm Redis is reachable: redis-cli -u management PING
□ Note current cert expiry dates: visit /certs in the UI or:
  openssl x509 -in certs/internal/redis.crt -noout -enddate
□ For port changes: check HAProxy stats page (:8404) to confirm zero
  active backend sessions before changing backend config.
```

#### Scenario: Change the proxy data-plane port

The proxy listens on port 8080. You need to move it to 8081 (e.g., port conflict
with another service on the host).

**Who:** Ops engineer (SSH access to Docker host required for step 4).
**Downtime:** < 5 seconds (HAProxy retries to new port).
**Prerequisite:** Access to the Management UI as SecOps admin.

**Step 1 — Use the Port Wizard**

Navigate to Management UI → `/ports`. Find "Proxy data-plane 8080". Click it.
The wizard shows:

```
Proposed change: proxy data-plane 8080 → 8081

The following changes are required:

  [DAEMON]  nftables rule update                             ← will be applied automatically
  [DAEMON]  config/proxy.yml: proxy.bind_port 8080 → 8081   ← will be applied automatically
  [MANUAL]  docker-compose.yml: container port binding        ← requires ops action
  [MANUAL]  haproxy.cfg: backend server address              ← requires ops action

Download change script: [change-proxy-port-8080-to-8081.sh]
```

Click [Download change script].

**Step 2 — Review the downloaded script**

```bash
#!/bin/bash
# JA4Proxy port change script — proxy data-plane 8080 → 8081
# Generated: 2026-03-12T16:00:00Z  Request-ID: a1b2c3d4
set -euo pipefail

echo "=== JA4Proxy port change: 8080 → 8081 ==="

# 1. Update HAProxy backend (graceful reload — no traffic drop)
sed -i 's|server proxy1 proxy:8080|server proxy1 proxy:8081|' haproxy/haproxy.cfg
haproxy -sf $(cat /var/run/haproxy.pid) -f haproxy/haproxy.cfg
echo "[1/3] HAProxy backend updated and reloaded"

# 2. Update docker-compose.yml proxy port
# (The UI managed proxy.bind_port and nftables already)
sed -i 's|- "127.0.0.1:8080:8080"|- "127.0.0.1:8081:8081"|' docker-compose.yml
docker compose up -d --no-deps proxy
echo "[2/3] Proxy container restarted on new port"

# 3. Verify
sleep 3
curl -sf http://localhost:8081/health && echo "[3/3] Health check passed on :8081"
```

**Step 3 — Apply managed changes via UI**

Back in the Port Wizard, click [Apply managed changes]. The UI applies the nftables
update and `config/proxy.yml` edit via the daemon. Status shows:

```
✅ nftables rule updated: tcp dport 8081 accept
✅ config/proxy.yml updated: proxy.bind_port = 8081
⏳ Waiting for ops to complete manual steps...
```

**Step 4 — Run the change script on the Docker host**

```bash
ssh deploy@docker-host
cd /opt/ja4proxy
bash change-proxy-port-8080-to-8081.sh
```

**Step 5 — Verify**

Return to the Management UI → `/ports`. The consistency check reruns automatically.
All rows should show ✅. If any show ❌, the wizard explains what still disagrees.

Also check:
```bash
# HAProxy stats page — backend should show UP on new port
curl -s http://localhost:8404/stats | grep proxy
# Proxy health check
curl -s http://localhost:8081/health
```

---

#### Scenario: A new external service needs to be reachable from the proxy

The proxy needs to call a new external threat feed API at `api.threatfeed.example.com`.

**Who:** SecOps admin (UI only — no SSH required).
**Downtime:** None.

**Step 1** — Resolve the API's IP addresses:

```bash
dig +short api.threatfeed.example.com
# Returns: 203.0.113.45, 203.0.113.46
```

**Step 2** — In the Management UI, navigate to `/egress`.

**Step 3** — Click [Add CIDR]. Enter `203.0.113.45/32`, label `threatfeed.example.com`.
Repeat for `203.0.113.46/32`. Click [Add] for each.

The UI calls `POST /api/v1/network/egress` which publishes to the netadmin daemon.
The daemon runs `nft add element` and publishes the result. The UI shows the new
entries in the table within 3 seconds.

**Step 4** — Test from the proxy container:

```bash
docker exec ja4proxy-proxy-1 curl -sf https://api.threatfeed.example.com/ping
```

---

#### Scenario: A cert expiry alert fires at 03:00

Alert: `InternalCertExpiryCritical — redis cert expires in 5 days`.

**Who:** On-call ops engineer.
**Downtime:** None.

**Step 1** — Navigate to Management UI → `/certs`. Confirm `redis` shows 5 days.

**Step 2** — Click [Rotate] next to redis. Confirm the dialog. The UI publishes
`cert_rotate:redis` to the netadmin daemon.

**Step 3** — The daemon runs `scripts/rotate-certs.sh redis` and sends Redis a
`CONFIG REWRITE` + SIGHUP. Within 10 seconds, the cert column for redis updates.

**Step 4** — Verify the new expiry is 365 days out. Silence the alert.

**If rotation fails:**

The UI shows the error from the daemon (e.g., `ca.key not found`). This means
the CA key was moved or the daemon cannot read the cert directory.

```bash
# On the host:
systemctl status ja4proxy-netadmin
journalctl -u ja4proxy-netadmin -n 50
ls -la certs/internal/
```

If the CA key is genuinely missing, escalate to the architecture team — re-generating
the CA means re-issuing all service certs and restarting all containers.

---

#### Scenario: `AnomalousContainerNetworkTraffic` fires

Alert: a container made a cross-network connection.

**Step 1** — Check the audit log in the Management UI (`/audit?event_type=anomalous`).

**Step 2** — Identify the source container and destination:
```bash
journalctl -k --since "10m ago" | grep JA4_ANOMALOUS
```

**Step 3 — Triage:**

| Source → Destination | Probable cause |
|---------------------|----------------|
| `analytics` → `net-edge` | Analytics container compromise or config error |
| `management` → `net-proxy` | Management container trying to reach Redis directly (config error) |
| `proxy` → unexpected external IP | Proxy calling new external API not in egress allowlist |

For `proxy` → unexpected IP: check if a new feature was deployed; if legitimate,
add CIDR to egress allowlist. If not expected, treat as a security incident.

For `analytics`/`management` → `net-edge`: treat as a container compromise. Isolate
by removing the container from its network:
```bash
docker network disconnect net-mgmt analytics
```
Escalate to security team. Do not restart — preserve the container state for forensics.

---

#### Scenario: The netadmin daemon is down

**Symptoms:** Cert rotation buttons in the UI return "daemon unavailable".
Egress changes time out. The management UI banner shows:
"Network admin daemon unreachable — managed operations unavailable."

**Impact:** The proxy continues operating normally. Existing nftables rules stay
in place. No cert rotations or egress changes can be made from the UI.

**Diagnosis:**
```bash
systemctl status ja4proxy-netadmin
journalctl -u ja4proxy-netadmin -n 100
# Check Redis connectivity:
redis-cli -u management PING
```

**Recovery:**
```bash
systemctl restart ja4proxy-netadmin
# Wait 10s, then verify:
systemctl status ja4proxy-netadmin
```

If the daemon fails to start, check `NETADMIN_SECRET` and `REDIS_URL` in
`/etc/ja4proxy/netadmin.env`. If the file is missing or wrong, regenerate:
```bash
echo "NETADMIN_SECRET=$(openssl rand -hex 32)" > /etc/ja4proxy/netadmin.env
echo "REDIS_URL=rediss://management:${REDIS_MANAGEMENT_PASSWORD}@localhost:6380" \
  >> /etc/ja4proxy/netadmin.env
chmod 600 /etc/ja4proxy/netadmin.env
systemctl restart ja4proxy-netadmin
# Sync the new secret to the management container:
docker compose up -d management
```

---

### 5.4 Developer Guide

**Audience:** engineers extending or modifying the system.

#### Adding a new service to the network topology

1. Decide which networks it needs. Use the minimum set:
   - Needs internet access? → `net-edge` + `net-proxy` (but justify it)
   - Needs Redis? → `net-proxy` or `net-mgmt` (not both unless required)
   - Management-only? → `net-mgmt` only

2. Add the service to `docker-compose.yml` with the hardening stanza from
   `PHASE_14c §7.1` (cap_drop, read_only, etc.).

3. Add a cert for it in `scripts/gen-internal-certs.sh`.

4. If it needs egress (outbound connections), add its target CIDRs to the
   nftables configuration in `PHASE_14c §6.2`.

5. If it needs a new nftables rule (not just a CIDR in the egress set), update
   `/etc/nftables.d/ja4proxy.nft` and the Ansible playbook. Document the rule
   in PHASE_14c.

6. Update the network topology diagram in `PHASE_14d §5.1`.

7. Add a test in `tests/integration/test_tls_connections.py` verifying that the
   new service can and cannot reach the expected networks.

#### Adding a new operation to the netadmin daemon

The daemon whitelist in `netadmin.py` `DISPATCH` is intentionally minimal.
Adding a new operation:

1. Write a handler function. It must:
   - Validate all inputs before passing them to any subprocess
   - Use `subprocess.run(list_args, check=True, capture_output=True)` — never `shell=True`
   - Raise `ValueError` for invalid input (caught and returned as error to UI)
   - Raise `subprocess.CalledProcessError` for execution failures (caught and returned)

2. Add it to `DISPATCH`.

3. Write a unit test mocking `subprocess.run` that verifies:
   - A valid payload calls the expected command
   - An invalid payload raises `ValueError` before calling subprocess
   - A failed subprocess is caught and returned as an error, not raised

4. Write an integration test (with a real subprocess target if possible).

5. Update the Management API to call the new operation and add a UI control.

#### Extending the seccomp profile

The seccomp profile at `security/seccomp/default.json` must be extended if a service
needs a syscall that isn't in the allow list. The process:

1. Identify the failing syscall: run the service with `seccomp=unconfined` and
   `strace -e trace=all` to observe what it calls.
2. Add the syscall to the `SCMP_ACT_ALLOW` list.
3. Re-run with the new profile. Verify it works.
4. Write a test in `tests/unit/test_network_hardening.py` confirming that
   `ptrace`, `mount`, `kexec_load` remain in the blocked list.
5. Document why the new syscall was added as a comment in the profile JSON.

#### Testing a port change before production

```bash
# 1. Start a test environment
docker compose -f docker-compose.yml -f docker-compose.test-override.yml up -d

# 2. Use the Port Wizard in the UI to preview the change (don't apply yet)
# 3. Apply managed changes via UI (nftables + config)
# 4. Run the generated script against the test environment
# 5. Run the integration test suite
python3 -m pytest tests/integration/test_tls_connections.py -v
# 6. Verify consistency check passes in UI
```

---

## 6. Conflict Detection

### 6.1 The consistency endpoint

`GET /api/v1/network/consistency` performs a cross-layer check and returns a list
of discrepancies.

```python
# management/routers/network.py (excerpt)

@router.get("/network/consistency")
async def check_network_consistency(
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """
    Compares the declared configuration across layers:
    1. config/proxy.yml (read from Redis key config:*)
    2. Live process state (proxy reports its actual bind address via Redis)
    3. nftables rules (read via netadmin daemon query)
    4. Docker container state (via Docker socket read-only query)

    Returns a list of conflicts. Empty list = everything consistent.
    """
    conflicts = []
    r = request.app.state.redis

    # Check 1: declared proxy port vs live bind address
    declared_port = int(await r.hget("config:proxy", "bind_port") or 8080)
    live_port     = int(await r.hget("runtime:proxy", "actual_bind_port") or 0)
    if live_port and live_port != declared_port:
        conflicts.append({
            "severity": "warning",
            "layer": "app_vs_runtime",
            "setting": "proxy.bind_port",
            "declared": declared_port,
            "actual": live_port,
            "message": f"config says {declared_port} but proxy is listening on {live_port}",
            "action": "Container restart required to apply config change",
        })

    # Check 2: declared backend TLS vs runtime state
    declared_tls = (await r.hget("config:backend", "tls_enabled") or "false") == "true"
    runtime_tls  = (await r.hget("runtime:proxy", "backend_tls") or "false") == "true"
    if declared_tls != runtime_tls:
        conflicts.append({
            "severity": "warning",
            "layer": "app_vs_runtime",
            "setting": "backend.tls.enabled",
            "declared": declared_tls,
            "actual": runtime_tls,
            "message": "Backend TLS config changed; SIGHUP required to apply",
            "action": "Send SIGHUP to proxy (hot reload applies this setting)",
        })

    # Check 3: cert expiry < 30d (surfaced as a conflict, not just an alert)
    expiry_data = await r.hgetall("runtime:cert_expiry")
    for svc, days_str in expiry_data.items():
        days = int(days_str)
        if days < 30:
            conflicts.append({
                "severity": "critical" if days < 7 else "warning",
                "layer": "certs",
                "setting": f"cert:{svc}",
                "declared": "valid",
                "actual": f"expires in {days} days",
                "message": f"Certificate for {svc} expires in {days} days",
                "action": f"Navigate to /certs and click Rotate for {svc}",
            })

    return {
        "consistent": len(conflicts) == 0,
        "conflicts": conflicts,
        "checked_at": __import__("time").time(),
    }
```

### 6.2 Proxy self-reporting

The proxy reports its actual runtime state to Redis at startup and after each
config reload. This is the "actual" side of the consistency check:

```python
# proxy.py — after successful bind
await self.redis_client.hset("runtime:proxy", mapping={
    "actual_bind_port":   str(self.server.sockets[0].getsockname()[1]),
    "actual_bind_host":   self.server.sockets[0].getsockname()[0],
    "backend_tls":        str(self.config["backend"]["tls"]["enabled"]).lower(),
    "redis_tls":          str(self.config["redis"]["tls"]["enabled"]).lower(),
    "started_at":         str(time.time()),
})
await self.redis_client.expire("runtime:proxy", 120)  # refreshed every 60s
```

### 6.3 UI conflict banner

Any page load triggers a background call to `GET /api/v1/network/consistency`.
If `consistent: false`, a banner renders at the top of every page until resolved:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ⚠ 2 configuration conflicts detected. [View on Network page] [Dismiss]  │
└──────────────────────────────────────────────────────────────────────────┘
```

The NetworkPage shows the full conflict list with resolution guidance.

---

## 7. New Redis Keys in This Phase

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `runtime:proxy` | Hash | 120s | proxy | Actual bind port, TLS state, started_at |
| `runtime:cert_expiry` | Hash | 86400s | netadmin | Days until expiry per service, updated daily |
| `ja4proxy:netadmin:commands` | pub/sub channel | — | management API | Signed daemon operation requests |
| `ja4proxy:netadmin:results:{id}` | pub/sub channel | — | netadmin daemon | Operation results |
| `config:proxy` | Hash | none | proxy hot reload | bind_port, bind_host |
| `config:backend` | Hash | none | proxy hot reload | host, port, tls_enabled |

---

## 8. TDD Test Checklist

### 14d-unit (`tests/unit/test_netadmin.py`)

- [ ] `test_egress_add_valid_cidr_calls_nft` — valid CIDR → `nft add element` called with sanitised args
- [ ] `test_egress_add_invalid_cidr_raises_valueerror` — `"not-a-cidr"` → ValueError, subprocess not called
- [ ] `test_egress_add_cidr_injection_rejected` — `"1.2.3.4; rm -rf /"` → ValueError
- [ ] `test_cert_rotate_unknown_service_raises` — `"../../etc/passwd"` → ValueError
- [ ] `test_cert_rotate_valid_service_calls_script` — `"redis"` → correct subprocess call
- [ ] `test_hmac_verification_valid_signature` — correct signature → accepted
- [ ] `test_hmac_verification_invalid_signature` — tampered payload → rejected, audit logged
- [ ] `test_hmac_verification_missing_signature` → rejected
- [ ] `test_firewall_reload_calls_nft` — correct nft command invoked
- [ ] `test_unknown_op_silently_dropped` — unknown op → no subprocess called, no crash
- [ ] `test_subprocess_failure_publishes_error` — `CalledProcessError` → error published to result channel
- [ ] `test_operation_success_written_to_audit_log` — successful op → `management:audit_log` LPUSH

### 14d-unit (`tests/unit/test_consistency.py`)

- [ ] `test_consistency_all_agree_returns_empty` — all layers consistent → `conflicts: []`
- [ ] `test_consistency_port_mismatch_detected` — declared 8080, runtime 8081 → conflict returned
- [ ] `test_consistency_tls_mismatch_detected` — declared true, runtime false → conflict returned
- [ ] `test_consistency_cert_expiry_surfaces_as_conflict` — expiry < 30d → conflict with action

### 14d-integration (`tests/integration/test_netadmin.py`)

- [ ] `test_management_api_triggers_egress_add` — POST /egress → command published to daemon channel
- [ ] `test_management_api_receives_daemon_result` — daemon publishes result → API returns it to caller
- [ ] `test_cert_rotation_end_to_end` — POST /certs/rotate/nginx → daemon runs script → UI cert expiry updates

### 14d-chaos (`tests/chaos/test_netadmin_resilience.py`)

- [ ] `test_daemon_unavailable_ui_shows_warning` — daemon not running → UI shows "daemon unreachable" banner
- [ ] `test_daemon_unavailable_proxy_continues` — daemon down → proxy continues handling connections
- [ ] `test_daemon_restart_resumes_operations` — restart daemon → pending operations processed

---

## 9. Acceptance Criteria

### 9a. Management UI — Network

- [ ] `GET /api/v1/network/status` returns topology, port matrix, and per-leg TLS status
- [ ] `GET /api/v1/network/consistency` detects port mismatch between config and runtime
- [ ] NetworkPage renders a topology diagram; green nodes for all healthy services
- [ ] Conflict banner appears when consistency check fails; disappears when resolved
- [ ] `POST /api/v1/network/egress` adds CIDR; netadmin daemon applies within 5s
- [ ] EgressPage shows current egress rules; remove works; reload button works
- [ ] CertificatePage shows expiry dates for all 5 services with correct colour coding
- [ ] Rotate button triggers cert rotation; new expiry shown within 15s
- [ ] PortWizardPage shows all ports, all layers; generates downloadable change script
- [ ] TLSPage toggles take effect within 2s (next connection); no restart required
- [ ] All new routes require authentication; unauthenticated → 401

### 9b. Netadmin daemon

- [ ] Daemon rejects command with invalid HMAC signature; audit log entry written
- [ ] Daemon rejects CIDR injection attempt; no subprocess called
- [ ] Daemon rejects unknown service name for cert rotation
- [ ] Daemon processes egress_add and publishes result within 3s
- [ ] Daemon is recoverable: restart after failure resumes normal operation
- [ ] systemd unit restarts daemon on crash; at most 3 restarts in 60s before alert
- [ ] All successful operations written to syslog and Redis audit log
- [ ] All failed operations written to syslog and returned as error to caller

### 9c. Conflict detection

- [ ] After changing `proxy.bind_port` in config without restarting, consistency check shows conflict
- [ ] After restarting proxy container, conflict clears automatically
- [ ] With cert expiry < 30 days, conflict appears in UI; rotate resolves it
- [ ] `GET /api/v1/network/consistency` returns within 500ms

### 9d. Documentation

- [ ] Architecture guide accurately describes trust model and layer responsibilities
- [ ] SecOps guide covers every alert with a concrete response procedure
- [ ] Ops runbook covers all 5 scenarios with exact commands
- [ ] Developer guide covers adding a service, adding a daemon operation, and testing
- [ ] Port change scenario produces a working generated script
- [ ] All role guides reviewed by at least one person in each role (gate before sign-off)

---

## 10. Files Added or Modified in This Phase

```
/usr/local/lib/ja4proxy/netadmin.py                 NEW — daemon
/etc/systemd/system/ja4proxy-netadmin.service       NEW — systemd unit
/etc/ja4proxy/netadmin.env                          NEW — daemon config (not in repo)
management/routers/network.py                       NEW — network/consistency/egress API
management/routers/certs.py                         NEW — cert expiry + rotation API
management/frontend/src/pages/NetworkPage.tsx       NEW — React page
management/frontend/src/pages/CertificatePage.tsx   NEW — React page
management/frontend/src/pages/EgressPage.tsx        NEW — React page
management/frontend/src/pages/TLSPage.tsx           NEW — React page
management/frontend/src/pages/PortWizardPage.tsx    NEW — React page
tests/unit/test_netadmin.py                         NEW (12 tests)
tests/unit/test_consistency.py                      NEW (4 tests)
tests/integration/test_netadmin.py                  NEW (3 tests)
tests/chaos/test_netadmin_resilience.py             NEW (3 tests)
docs/phases/PHASE_14d.md                            NEW (this file)
docs/REDIS_SCHEMA.md                                MODIFY — 6 new keys
```
