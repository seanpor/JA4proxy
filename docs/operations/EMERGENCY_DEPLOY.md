<!--
title: Emergency Deployment
audience: operator
last_reviewed: 2026-06-25
phase: 245.1
-->

# Emergency Deployment — Under Attack RIGHT NOW

Get JA4proxy in front of your server in under 5 minutes.
No config files, no wizard, no monitoring stack.

## Prerequisites

- Docker and Docker Compose (v2)
- Your backend server's hostname or IP (the server you're protecting)
- Ports 8443 (proxy), 8090 (dashboard), and 6379 (Redis, internal only) available

## Deploy

```bash
git clone https://github.com/seanpor/JA4proxy.git && cd JA4proxy

# Set your backend — this is the only thing you need to configure
export BACKEND_HOST=your-server.com

docker compose up -d
```

That's it. JA4proxy is now accepting TLS connections on port **8443** and
forwarding them to your backend. Point your DNS or load balancer at this
host's port 8443.

## See your traffic

Open the dashboard in your browser:

**http://localhost:8090**

Log in with `admin` / `changeme` (change these in production by setting
`MANAGEMENT_ADMIN_USER` and `MANAGEMENT_ADMIN_PASSWORD` environment variables).

The dashboard shows every connection arriving at your server — fingerprints,
risk scores, source countries, and top offenders. You can block fingerprints
and IPs directly from the UI.

## Verify it works

```bash
# Should return your backend's response through the proxy
curl -kv https://localhost:8443/

# Check the proxy is scoring connections
docker compose logs ja4proxy | tail -20
```

You should see log lines with JA4 fingerprints and risk scores, and the
dashboard will update in real time. In monitor mode (the default), everything
is allowed through — the proxy is scoring but not blocking.

## Start blocking

The proxy starts in **monitor mode** (dial=0) — it scores every connection
but blocks nothing. This is intentional: you can see what it would block
before you turn on enforcement.

To start blocking, use the admin CLI:

```bash
# See what's hitting you
./scripts/ja4-admin.sh status
./scripts/ja4-admin.sh top 10

# Block a specific JA4 fingerprint (immediate, no restart)
./scripts/ja4-admin.sh block-ja4 <fingerprint_hash>

# Block a specific IP (1-hour default)
./scripts/ja4-admin.sh block-ip 203.0.113.42
```

## Want port 443?

The default uses port 8443 to avoid requiring root. To listen on 443,
edit the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "443:8443"   # change "8443:8443" to "443:8443"
```

Or use `setcap` on the binary for a non-Docker deployment:
```bash
sudo setcap cap_net_bind_service=+ep ./bin/ja4pd
```

## What's next?

You're running a 3-container setup (proxy + Redis + dashboard). For production:

| Next step | Guide |
|-----------|-------|
| Full incident response (block fingerprints, IPs, CIDRs) | [Incident Response](INCIDENT_RESPONSE.md) |
| Add monitoring (Prometheus, Grafana, alerts) | [POC Quickstart](POC_QUICKSTART.md) |
| Full guided setup with all integrations | `make init` |
| Deployment behind nginx, AWS NLB, Cloudflare | [Deployment Modes](DEPLOYMENT_MODES.md) |
| Day-to-day operations | [Operations Guide](OPERATIONS_GUIDE.md) |
