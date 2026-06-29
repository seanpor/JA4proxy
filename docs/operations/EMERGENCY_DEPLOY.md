<!--
title: Emergency Deployment
audience: operator, secops
last_reviewed: 2026-06-29
phase: 511
-->

# Emergency Deployment — Under Attack RIGHT NOW

Get JA4proxy in front of your server. Assumes you are working **remotely** — at
home, over a corporate VPN, with the server in a datacentre.

---

## The 8-step emergency procedure

### Step 0: Connect to the server (remote access)

You need an SSH tunnel to reach the management dashboard. In most corporate
environments SSH to the DMZ goes via a bastion host:

```bash
ssh -J YOU@bastion.mgmt.corp.example.com YOU@dmz-web01 \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N &
```

If your org allows direct SSH from the VPN to DMZ hosts (no bastion):

```bash
ssh YOU@dmz-web01.corp.example.com \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N &
```

Verify the tunnel works:

```bash
curl -s http://127.0.0.1:8090/api/v1/health
# Expected: {"status":"ok",...}
```

If this fails, check [Dashboard Access](../runbooks/dashboard_access.md) for
troubleshooting. **Do not proceed until this works.**

---

### Step 1: Deploy JA4proxy on the server

Open a second terminal, SSH into the DMZ host (no port-forward this time), and run:

```bash
ssh -J YOU@bastion YOU@dmz-web01   # or direct ssh if no bastion

# Pull pre-built images — no build step needed
cd /opt && git clone https://github.com/seanpor/JA4proxy.git && cd JA4proxy
# OR if already cloned:
cd /opt/JA4proxy && git pull

# Set the backend (the server you're protecting)
export BACKEND_HOST=your-actual-backend.internal.example.com
export REDIS_PASSWORD=$(openssl rand -base64 24)

# Deploy in 30 seconds — no build
docker compose pull && docker compose up -d
```

Verify:

```bash
docker compose ps          # all containers should be "Up"
docker compose logs --tail=5 ja4proxy   # should show "proxy started"
curl -kv https://127.0.0.1:8443/       # should return backend response
```

If `curl` returns the backend response, the proxy is working in passthrough mode.

---

### Step 2: Open the dashboard

In your browser (on your laptop, using the SSH tunnel from Step 0):

```
https://127.0.0.1:8444
```

Click through the certificate warning (self-signed — expected). Log in with:
- **Username:** `admin`
- **Password:** `changeme` (or whatever is set in `.env`)

You are now watching live TLS connections being fingerprinted. The proxy is in
monitor mode — scoring everything, blocking nothing.

If `https://127.0.0.1:8444` shows a proxy error, try `http://127.0.0.1:8090`.

---

### Step 3: Identify the attack fingerprint

In the dashboard: look at **Top Fingerprints**. The attack will be obvious — one or
two fingerprints with a disproportionate connection count compared to the rest.

Signs of an attack fingerprint (vs legitimate browser traffic):
- No `h2` or `h1` ALPN label (browsers always have this)
- High connection rate with near-zero time-on-site
- Concentration in datacenter / hosting ASNs
- Geographically uniform origin (not normal user distribution)

Note the fingerprint hash — you need it for Step 5.

You can also use the CLI (in the server terminal):

```bash
./scripts/ja4-admin.sh top 10
```

---

### Step 4: Test before going live

Before routing production traffic through JA4proxy, verify it passes legitimate
requests cleanly:

```bash
# From the DMZ host — should return the same response as hitting the backend directly
curl -kv https://127.0.0.1:8443/your-application-path

# From your laptop (via the SSH tunnel the proxy port-forward):
curl -kv --resolve "your-domain.example.com:8443:127.0.0.1" \
    https://your-domain.example.com:8443/your-application-path
```

The response should be identical to a direct hit on the backend. If it is — proceed.
If not — check `docker compose logs ja4proxy` for errors before going live.

---

### Step 5: Insert JA4proxy into the live traffic path

**Use iptables redirect** when JA4proxy is on the same host as the existing
service (HAProxy, nginx, or the application directly):

```bash
# On the DMZ host:
make traffic-on
# This runs: sudo iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

**Instant rollback if anything looks wrong:**

```bash
make traffic-off
# Restores the original path in < 1 second. No restart needed.
```

If JA4proxy is on a different host, or iptables is not available, see
[Dashboard Access — Traffic Insertion](../runbooks/dashboard_access.md#step-5-insert-ja4proxy-into-the-live-traffic-path)
for DNS cutover and HAProxy backend swap procedures.

After cutting over: watch `docker compose logs -f ja4proxy` — you should see
log entries for every connection. If it goes silent, traffic is not reaching the proxy.

---

### Step 6: Raise the dial and block

With traffic flowing through the proxy:

```bash
# Dashboard: Settings → Enforcement Dial → 50 → Apply
# Wait 2 minutes. Watch the action panel for unexpected blocks.

# CLI equivalent:
./scripts/ja4-admin.sh dial 50
```

Wait 2 minutes. If nothing unexpected is blocked, raise to 80, wait again, then 100.

**Block the attack fingerprint:**

```bash
# Dashboard: click "Block" next to the fingerprint in the Top Fingerprints panel
# CLI:
./scripts/ja4-admin.sh block-ja4 t13d1516h2_8daaf6152771_02713d6af862
```

The attack rate should drop within seconds.

**Emergency dial — auto-reverts after 1 hour (useful if you have to drop off the call):**

```bash
./scripts/ja4-admin.sh dial 80 --emergency 3600
```

**Safety guarantee to say on the call:**
> "Real browsers using Chrome, Firefox, or Safari cannot be blocked by this proxy —
> browser TLS fingerprints always include h2/h1 ALPN and are bypassed before scoring.
> The fingerprint we're blocking is a Python library signature with no browser ALPN.
> Legitimate users on the form are unaffected."

---

### Step 7: Two datacentres

If traffic is split across two DCs, repeat Steps 1–6 on the second DC host.

If both DCs point at the same Redis instance (recommended), a block applied in DC1
propagates to DC2 automatically within seconds. If Redis is separate per DC, you
need to block explicitly in both:

```bash
# In a second terminal, with the DC2 tunnel from Step 0:
ssh -J YOU@bastion YOU@dmz-web01-dc2 -L 8091:127.0.0.1:8090 -N &
# Dashboard DC2: http://127.0.0.1:8091
# Block the same fingerprint via CLI on the DC2 host, or via the DC2 dashboard.
```

---

### Step 8: Document the change

File an emergency change record within 4 hours. Template:

```
EMERGENCY CHANGE RECORD
Date/time: [UTC]      Authorised by: [verbal approval — name + time]
Implemented by: [your name]

Systems: [hostnames and DC names]

Actions:
  - Deployed JA4proxy (no changes to existing services)
  - Verified passthrough in monitor mode before cutover
  - Inserted into traffic path via iptables PREROUTING redirect
  - Raised enforcement dial to [N] at [time UTC]
  - Blacklisted fingerprint(s): [list]

Reason: Credential-stuffing attack — [N] failed logins/second from [N] ASNs.
Attack uses Python requests TLS fingerprint (no browser ALPN) — confirmed not
affecting browser traffic.

Rollback: `make traffic-off` on [hostname] — instant, no restart.
Current state: [monitoring / blocking / rolled back]
```

---

## Rollback and wind-down

```bash
# Drop to monitor mode (stops blocking, proxy stays in path for data collection):
./scripts/ja4-admin.sh dial 0

# Full removal — takes JA4proxy out of the traffic path entirely:
make traffic-off

# Stop all containers (optional):
docker compose down
```

Leave the proxy running in monitor mode (dial=0) for at least 24 hours after the
attack if you can — the fingerprint and scoring data is useful for the post-incident
review.

---

## Prerequisites

Before the incident (run these in advance):
- Docker and Docker Compose v2 installed on the DMZ host
- SSH access: your key is authorised on the bastion and the DMZ host
- Port 8443 available on the DMZ host (not already in use)
- `sudo iptables` works on the DMZ host (needed for `make traffic-on`)

If `sudo iptables` is not available, use the HAProxy or DNS cutover methods in
[Dashboard Access](../runbooks/dashboard_access.md#step-5-insert-ja4proxy-into-the-live-traffic-path).

---

## Next steps after the incident

| What | Guide |
|------|-------|
| Full incident response, block CIDRs, country blocks | [Incident Response](INCIDENT_RESPONSE.md) |
| Add monitoring (Prometheus, Grafana, alerts) | [POC Quickstart](POC_QUICKSTART.md) |
| Production hardening | [Operations Guide](OPERATIONS_GUIDE.md) |
| Deployment behind nginx, AWS NLB, Cloudflare | [Deployment Modes](DEPLOYMENT_MODES.md) |
