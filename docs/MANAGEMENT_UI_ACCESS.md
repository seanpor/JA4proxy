<!--
title: Remote Access — Management UI, Grafana, and All Services
audience: Operators, Developers
last_reviewed: 2026-04-05
phase: 13
-->

# Remote Access Guide

JA4proxy binds all management and monitoring ports to loopback addresses only — they
are never reachable over the internet without an SSH tunnel. This is a deliberate
security property: even if the management login endpoint has a vulnerability, it cannot
be reached unless you already have an SSH session on the server.

This guide covers how to access all services from a Chromebook (or any machine with SSH).

---

## How It Works

Each agent (e.g. `claude4`, `gemini`) gets its own loopback IP — for example
`127.0.0.21`. All that agent's services bind to that IP. The SSH tunnel forwards
each service's port from the server's loopback to your local machine, where Chrome
can open it as `http://localhost:PORT`.

```
Chromebook                            Server
──────────                            ──────
Chrome → localhost:8090  ══SSH══▶  127.0.0.21:8090  (Management UI, agent claude4)
Chrome → localhost:8080  ══SSH══▶  127.0.0.21:8080  (Analytics,     agent claude4)
Chrome → localhost:3001  ══SSH══▶  127.0.0.1:3001   (Grafana,       shared)
Chrome → localhost:9091  ══SSH══▶  127.0.0.1:9091   (Prometheus,    shared)
Chrome → localhost:8404  ══SSH══▶  127.0.0.21:8404  (HAProxy stats, agent claude4)
```

---

## Quick Start (one command)

On the server, find the tunnel command for your agent:

```bash
make tunnel NAME=claude4
```

Example output:
```
Agent: claude4  |  IP: 127.0.0.21

Run this in a NEW terminal on your Chromebook:

  ssh -N \
    -L 8090:127.0.0.21:8090 \
    -L 8080:127.0.0.21:8080 \
    -L 8404:127.0.0.21:8404 \
    -L 9091:127.0.0.1:9091 \
    -L 3001:127.0.0.1:3001 \
    USER@YOUR-SERVER

Then browse to:
  http://localhost:8090        — Management UI  (claude4)
  http://localhost:8080        — Analytics      (claude4)
  http://localhost:8404/stats  — HAProxy stats  (claude4)
  http://localhost:9091        — Prometheus     (shared)
  http://localhost:3001        — Grafana        (shared)
```

Copy the `ssh -N ...` command, open a **new terminal tab** on your Chromebook, paste
and run it. Leave that terminal open while you use the services.

If you know the server hostname upfront, you can also include it directly:

```bash
# Prints the command with the hostname already filled in — ready to copy-paste
make tunnel NAME=claude4 HOST=sean@myserver.example.com
```

---

## Services Reference

| Service | Local URL | Description |
|---------|-----------|-------------|
| Management UI | `http://localhost:8090` | Config, lists, bans, dial, audit log |
| Analytics | `http://localhost:8080` | Real-time traffic analysis, campaign detection |
| HAProxy Stats | `http://localhost:8404/stats` | Connection counts, backend status |
| Prometheus | `http://localhost:9091` | Raw metrics, ad-hoc queries |
| Grafana | `http://localhost:3001` | Dashboards — start with **JA4proxy Security Overview** |

### Finding your agent's IP

If you need the IP without running `make tunnel`:

```bash
grep AGENT_BIND_IP .env.claude4
# AGENT_BIND_IP=127.0.0.21
```

---

## Persistent Access (SSH Config)

For daily use, add an entry to `~/.ssh/config` on your Chromebook. This lets you
bring up all tunnels with a single short command.

```
# ~/.ssh/config on your Chromebook

Host ja4proxy-claude4
  HostName your-server-ip-or-hostname
  User your-username
  # Per-agent services (adjust IPs to match your agent's AGENT_BIND_IP)
  LocalForward 8090 127.0.0.21:8090   # Management UI
  LocalForward 8080 127.0.0.21:8080   # Analytics
  LocalForward 8404 127.0.0.21:8404   # HAProxy stats
  # Shared monitoring stack
  LocalForward 9091 127.0.0.1:9091    # Prometheus
  LocalForward 3001 127.0.0.1:3001    # Grafana
  # Keep tunnel alive through short inactivity periods
  ServerAliveInterval 60
  ServerAliveCountMax 3
```

Open the tunnel:

```bash
ssh ja4proxy-claude4 -N
```

Then browse to `http://localhost:8090` (and any of the other URLs above).

To add a second agent, duplicate the `Host` block with a different name and the
other agent's IP:

```
Host ja4proxy-gemini
  HostName your-server-ip-or-hostname
  User your-username
  # Use different local ports to avoid clashes with the claude4 entry
  LocalForward 8190 127.0.0.10:8090   # Management UI (gemini, on local :8190)
  LocalForward 8180 127.0.0.10:8080   # Analytics     (gemini, on local :8180)
  ...
```

---

## Starting Services on the Server

The tunnel forwards ports that must already be listening. Start the agent stack first:

```bash
# On the server:
make agent-up NAME=claude4
```

This starts the full stack (proxy, Redis, HAProxy, management, analytics). The output
shows all bound addresses and a reminder to run `make tunnel`.

To start the shared monitoring stack (Grafana, Prometheus):

```bash
make start-monitoring
```

Verify the management service is healthy before connecting:

```bash
curl http://127.0.0.21:8090/api/v1/health
# {"status": "ok", "redis": "ok", ...}
```

---

## Management UI Login

| Setting | Default | How to change |
|---------|---------|---------------|
| Username | `admin` | Set `MANAGEMENT_ADMIN_USER` in `.env.claude4` |
| Password | `admin` | Set `MANAGEMENT_ADMIN_PASSWORD` in `.env.claude4` |

**Change both before sharing access.** After editing the env file, restart the agent:

```bash
make agent-down NAME=claude4
make agent-up   NAME=claude4
```

Generate a strong JWT secret:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Add result as MANAGEMENT_JWT_SECRET in .env.claude4
```

---

## Security Notes

- Port 8090 binds to `127.0.0.X` only — never `0.0.0.0`. It will not appear in an
  external port scan.
- SSH key auth is enforced for the tunnel before the management login page is served.
  This gives you two layers of authentication.
- JWT tokens expire after 8 hours. The browser automatically redirects to `/login`
  when the session expires.
- The login endpoint rate-limits to 5 attempts per minute. There is no lockout —
  just a 60-second cooldown.

---

## Troubleshooting

**`Connection refused` when opening `http://localhost:8090`**
The tunnel is open but the service is not running. Run `make agent-up NAME=claude4`
on the server, then check `make management-logs NAME=claude4`.

**`Channel N: open failed: connect failed` in the SSH terminal**
The service is not listening on the expected IP/port. Check the bound address:
```bash
ss -tlnp | grep 8090
```
If the IP doesn't match what the tunnel expects, check `grep AGENT_BIND_IP .env.claude4`.

**Tunnel drops after a period of inactivity**
Add `ServerAliveInterval 60` and `ServerAliveCountMax 3` to the `Host` block in
`~/.ssh/config` (shown in the persistent access section above).

**Dashboard panels are blank**
The management UI shows live data from Redis. If no proxy traffic has been generated,
most panels will be empty. Run `make agent-up NAME=claude4` to ensure the proxy is
running, then send some test traffic or wait for real connections.

**`Bind for 127.0.0.1:8090 failed: port is already allocated`**
Two agents are both trying to bind port 8090 on the same IP. This should not happen
with the current setup (each agent uses its own IP). If it does, check whether an old
management-only container is still running:
```bash
docker ps | grep management
docker stop <container-name>
```

**Login page does not appear (blank page or 404)**
The management container may still be initialising. Wait 10 seconds and refresh.
Check `make management-logs` for startup errors.
