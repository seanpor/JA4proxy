<!--
title: Dashboard Access — Remote, DMZ, and Emergency
audience: SecOps, Operators
last_reviewed: 2026-06-29
phase: 511
-->

# Dashboard Access — Remote, DMZ, and Emergency

This runbook covers how to reach the JA4proxy management dashboard when you are not
sitting at the server. The normal case is: the server is in a DMZ and you are working
remotely over a corporate VPN.

**tl;dr for a 2 AM incident:**

```bash
# 1. SSH tunnel (adjust hostnames — see your organisation's runbook for specifics)
ssh -J you@bastion.mgmt.corp.example.com you@dmz-web01 \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N &

# 2. Open dashboard in browser
open https://127.0.0.1:8444   # click through the cert warning
# or: http://127.0.0.1:8090   # if your corporate proxy doesn't intercept loopback

# 3. Log in: admin / changeme  (or whatever was set in .env)

# 4. Skip ahead to: "Step 4 — Raise the dial and block the attack"
```

---

## Why `http://localhost:8090` doesn't work from home

`localhost` resolves to your laptop, not the server. The management service is bound
to `127.0.0.1` on the DMZ host — it deliberately does not listen on the external
network interface. You need an SSH tunnel to reach it.

Additionally:
- Port 8090 is not in the standard corp→DMZ firewall ruleset. Even if you knew the
  server's IP, a direct connection to `:8090` would be blocked.
- Corporate web proxies sometimes intercept HTTP even for `localhost`. Use `127.0.0.1`
  as the hostname (not `localhost`) — most proxies skip loopback addresses.

---

## Step 0: Establish the SSH tunnel

Pick the pattern that matches your corporate network.

### Pattern A: Bastion / jump host required (most enterprise networks)

Direct SSH from the corporate LAN to DMZ hosts is typically blocked. SSH is only
permitted from a dedicated bastion host in a management zone.

```bash
ssh -J YOU@bastion.mgmt.corp.example.com YOU@dmz-web01.corp.example.com \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N
```

Replace:
- `YOU` — your SSH username
- `bastion.mgmt.corp.example.com` — your bastion hostname (ask your infra team)
- `dmz-web01.corp.example.com` — the DMZ host running JA4proxy

The `-N` flag keeps the tunnel open without opening a shell. Run it in a background
terminal or append `&` and note the PID.

**Two-datacentre setup (open two tunnels in separate terminals):**

```bash
# Terminal 1 — DC1 (e.g. London)
ssh -J YOU@bastion YOU@dmz-web01-lon -L 8090:127.0.0.1:8090 -L 8444:127.0.0.1:8444 -N &

# Terminal 2 — DC2 (e.g. Dublin)
ssh -J YOU@bastion YOU@dmz-web01-dub -L 8091:127.0.0.1:8090 -L 8445:127.0.0.1:8444 -N &

# DC1 dashboard: https://127.0.0.1:8444  (or http://127.0.0.1:8090)
# DC2 dashboard: https://127.0.0.1:8445  (or http://127.0.0.1:8091)
```

### Pattern B: Direct SSH from corp LAN to DMZ permitted

```bash
ssh YOU@dmz-web01.corp.example.com \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N
```

### Verify the tunnel is working

```bash
curl -s http://127.0.0.1:8090/api/v1/health
# Expected: {"status":"ok","version":"..."}
```

If this returns anything other than a JSON response, the tunnel is not working.
Check SSH output for errors. Common causes: wrong hostname, bastion requires 2FA,
SSH key not in `~/.ssh/` (try `ssh-add`).

---

## Step 1: Open the dashboard

### Option A: HTTPS (recommended — Caddy sidecar)

```
https://127.0.0.1:8444
```

Your browser will show a certificate warning because the cert is self-signed. This is
expected — the cert was generated automatically by Caddy and is not in a public CA.

To proceed: click **Advanced** → **Proceed to 127.0.0.1 (unsafe)**
(Chrome) or **Accept the Risk and Continue** (Firefox).

The connection is secure — you are talking to a process on your own machine via the
SSH tunnel. The self-signed cert warning is about the cert authority, not the channel.

### Option B: Plain HTTP (loopback — safe over SSH tunnel)

```
http://127.0.0.1:8090
```

Use `127.0.0.1` not `localhost`. Corporate web proxies usually bypass `127.0.0.1`
but may intercept `localhost`. If you see a 502 from your corporate proxy, switch to
Option A (HTTPS).

The HTTP connection is safe here because the port-forward runs inside the SSH tunnel —
the traffic between your browser and the server is encrypted at the SSH layer.

---

## Step 2: Log in

Default credentials (change these before production use):
- **Username:** `admin`
- **Password:** `changeme`

Set via env vars `MANAGEMENT_ADMIN_USER` and `MANAGEMENT_ADMIN_PASSWORD` in `.env`.

---

## Step 3: Understand the dashboard in 90 seconds

| Panel | What you're looking at |
|-------|------------------------|
| Top fingerprints | JA4 hashes ranked by connection count. Attack traffic clusters here. |
| Risk score distribution | Scores 0–100. An attack looks like a spike at the high end. |
| Action breakdown | At dial=0: everything is "monitor". Raise dial to see blocks. |
| Connections live | Every TLS handshake — fingerprint, source IP, score, action. |
| Countries | Useful for blanket country blocking if the attack is geographically concentrated. |

**Browser protection:** The dial defaults to 0 (monitor mode), so nothing is ever
blocked on first deploy — you can see what *would* be blocked before enforcing.
If you want to whitelist specific JA4 fingerprints so they bypass scoring entirely,
you can. The optional "ALPN h2/h1 bypass" (where any h2/h1 connection skips scoring)
is **off by default** because a bot can spoof `ALPN=h2` — so by default,
browser-*looking* traffic is scored like everything else. Real browsers are protected
by monitor-mode defaults, not unconditional escapes. This is worth saying on the incident call.

---

## Step 4: Raise the dial and block the attack

### Via the dashboard (recommended — easiest)

1. **Settings → Enforcement Dial** → move slider to **50** → Apply
2. Watch the "Actions" panel. If you see legitimate traffic being blocked (check the
   fingerprint — is it a browser fingerprint?), drop the dial back to 0.
3. Once comfortable at 50: raise to **80**, watch for 2 minutes, then **100**.

Do not jump straight to 100. Go 0 → 50 → 80 → 100 with 2-minute pauses.

### Via the CLI (if dashboard is unreachable)

All of these work over the SSH tunnel's Redis port-forward, or directly on the server:

```bash
# Show current state
./scripts/ja4-admin.sh status

# Show top fingerprints (find the attack fingerprint)
./scripts/ja4-admin.sh top 10

# Raise the dial
./scripts/ja4-admin.sh dial 50

# Emergency dial: raises to 80, auto-reverts to 0 after 1 hour (safety net)
./scripts/ja4-admin.sh dial 80 --emergency 3600

# Block a specific JA4 fingerprint (immediate, no restart)
./scripts/ja4-admin.sh block-ja4 t13d1516h2_8daaf6152771_02713d6af862

# Block a specific IP (default 1-hour ban)
./scripts/ja4-admin.sh block-ip 203.0.113.42

# Block a /24 CIDR (use sparingly — may affect shared hosting ranges)
./scripts/ja4-admin.sh block-ip 203.0.113.0/24 7200
```

### Via Redis directly (lowest-level fallback)

```bash
# If ja4-admin.sh is not available, use redis-cli directly:
REDIS_PASS=$(grep REDIS_PASSWORD .env | cut -d= -f2)

# Raise dial to 80
redis-cli -a "$REDIS_PASS" SET config:dial 80

# Block a fingerprint
redis-cli -a "$REDIS_PASS" SADD ja4:blacklist "t13d1516h2_8daaf6152771_02713d6af862"

# Block an IP for 1 hour
redis-cli -a "$REDIS_PASS" SET "ban:ip:203.0.113.42" 1 EX 3600
```

---

## Step 5: Insert JA4proxy into the live traffic path

**Before this step:** JA4proxy is running and scoring connections, but live traffic
is not flowing through it. Do steps 3–4 first to identify the attack, then cut over.

### Method 1: iptables redirect (same host — fastest, instant rollback)

Use this when JA4proxy is running on the same host as the existing webserver or
HAProxy. This requires `sudo` on the DMZ host.

```bash
# Redirect incoming :443 → JA4proxy :8443
# PREROUTING only affects incoming packets — no loopback loop risk
make traffic-on

# Or manually:
sudo iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

# Verify:
curl -kv https://your-domain.example.com/  # should return backend response
```

**Instant rollback:**

```bash
make traffic-off

# Or manually:
sudo iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

To override the default ports (e.g. if the site runs on 8443 externally):

```bash
make traffic-on TRAFFIC_PUBLIC_PORT=8443 TRAFFIC_PROXY_PORT=8080
```

### Method 2: HAProxy backend swap (HAProxy in TCP passthrough mode)

Use this when HAProxy is already in front in TCP mode (no `ssl` on the frontend bind).

Edit `/etc/haproxy/haproxy.cfg`:

```haproxy
# BEFORE:
backend web_servers
    mode tcp
    server web1 10.0.1.10:443 check

# AFTER:
backend web_servers
    mode tcp
    server ja4pd 127.0.0.1:8443 check   # JA4proxy, which forwards to 10.0.1.10:443
```

Reload without dropping connections:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg   # validate first
sudo systemctl reload haproxy
```

Rollback: revert the `server` line and reload again.

### Method 3: DNS cutover (JA4proxy on a separate host)

Use this when JA4proxy is deployed on a different host from the existing stack.

```bash
# Lower TTL before cutover (do this before the incident if possible)
# your-domain.example.com  A  TTL 60  →  ja4proxy-host-ip
```

Rollback: revert DNS. At TTL=60, this takes effect within 60 seconds for most clients.
Old connections stay on the original host until they reconnect.

### ⚠ If HAProxy currently terminates TLS

If HAProxy has `ssl` on its frontend bind (meaning it decrypts TLS), JA4proxy cannot
be inserted between HAProxy and the backend — JA4proxy needs to see the raw TLS
ClientHello before decryption.

Options in this case:
1. Use Method 1 (iptables) to put JA4proxy *before* HAProxy on the same host
2. Use Method 3 (DNS) to route directly to JA4proxy, bypassing HAProxy temporarily
3. Use TAP mode (passive) — JA4proxy reads a copy of traffic from a network mirror
   and pushes block decisions to Redis without touching the live path

---

## Step 6: Verify and monitor

```bash
# Confirm traffic is flowing through JA4proxy:
docker compose logs --tail=20 -f ja4proxy

# You should see log lines with fingerprints and scores, not silence.
# Each line = one TLS handshake evaluated by the proxy.

# Confirm backend is still responding:
curl -kv https://your-domain.example.com/

# Check block rate (should be rising if attack is active):
./scripts/ja4-admin.sh status
```

---

## Step 7: Document what you did (emergency change record)

Copy and fill in this template. Most incident management systems (ServiceNow, Jira,
PagerDuty) accept a brief description. The goal is to have a written record within
4 hours of the incident.

```
EMERGENCY CHANGE RECORD
=======================
Date/time of action: [UTC timestamp]
Authorised by: [verbal approval from Change Manager — name, time]
Implemented by: [your name]

System affected: [hostname(s)] in [DC name(s)]

Action taken:
  1. Deployed JA4proxy container stack on [hostname] — no changes to existing services
  2. Verified backend response through JA4proxy in monitor mode (dial=0)
  3. Inserted JA4proxy into traffic path via [iptables redirect / HAProxy swap / DNS]
  4. Raised enforcement dial to [N] at [time]
  5. Blacklisted JA4 fingerprint(s): [list fingerprints]
  6. Blocked [N] source IPs / CIDRs

Reason: Credential-stuffing attack — [X] failed login attempts/second from [N] ASNs.
Attack fingerprint is a Python requests library TLS signature with no browser ALPN
— confirmed not a browser fingerprint.

Safety guarantee: Chrome, Firefox, and Safari use h2/h1 ALPN. JA4proxy bypasses
all traffic with browser ALPN before scoring — real users on the login form are
unaffected regardless of dial setting or blacklist entries. This is an architectural
guarantee, not a configuration option.

Rollback procedure: `make traffic-off` on [hostname] (removes iptables rule, restores
original traffic path — takes effect immediately, no restart required).
Estimated rollback time: < 30 seconds.

Current state at time of filing: [monitoring / blocking / rolled back]
```

---

## Step 8: Rollback and wind-down

```bash
# Drop dial back to monitor mode (stops all blocking, keeps proxy in path for data)
./scripts/ja4-admin.sh dial 0

# OR remove JA4proxy from the traffic path entirely (instant):
make traffic-off

# Stop the proxy stack (optional — safe to leave running in monitor mode)
docker compose down
```

Leave JA4proxy in monitor mode (dial=0) for at least 24 hours after an attack. The
fingerprint data it collects is valuable for the post-incident review and can be used
to tune rules before the next event.

---

## What never works (and why)

| What you might try | Why it fails |
|--------------------|--------------|
| `http://localhost:8090` from your laptop | `localhost` is your laptop, not the server |
| `http://dmz-host.corp.example.com:8090` | Port 8090 blocked at corp→DMZ firewall |
| `https://dmz-host.corp.example.com:8444` | Port 8444 blocked at corp→DMZ firewall |
| `ssh user@dmz-host` without bastion | SSH from corp LAN → DMZ blocked in most enterprise configs |
| Port-forward via browser developer tools | Corporate web proxy still intercepts |
| Using `localhost` instead of `127.0.0.1` in the browser | Corporate proxy may intercept `localhost` HTTP |
