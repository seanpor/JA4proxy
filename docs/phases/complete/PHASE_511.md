---
phase: 511
title: "SecOps Emergency Dashboard Access — DMZ TLS, SSH Tunnel Runbook & Traffic Insertion"
parent: 500
created: 2026-06-29
revised: 2026-06-29
status: COMPLETE
---

# Phase 511 — SecOps Emergency Dashboard Access

## What Was Delivered

Phase 511 addresses the gap between "JA4proxy is deployed" and "the SecOps engineer
can actually use it from home at 2 AM during an incident."

The central insight driving the design: the problem is not just "how do I reach port
8090" — the bigger problems are (1) JA4proxy wasn't in the live traffic path yet,
(2) no tested procedure existed for safely inserting it, and (3) no rollback command
existed. This phase fixes all three.

### Files Changed

| File | Change |
|------|--------|
| `docker-compose.yml` | Added `management-tls` Caddy sidecar (HTTPS on :8444, self-signed cert, loopback-only) |
| `deploy/caddy/Caddyfile.management` | New — one-line Caddy config: `tls internal` + reverse-proxy to management:8090 |
| `template.env` | Added `MGMT_TLS_PORT=8444` |
| `Makefile` | Added `traffic-on` and `traffic-off` targets (iptables PREROUTING redirect) |
| `docs/runbooks/dashboard_access.md` | New — complete remote access runbook with SSH patterns, traffic insertion, CLI fallbacks, two-DC procedure, emergency change template |
| `docs/operations/EMERGENCY_DEPLOY.md` | Rewritten — remote-first, pre-built images, test-before-cutover, 8-step procedure |
| `README.md` | Fixed `http://localhost:8090` — now shows SSH tunnel command and links to runbook |

---

## The Colin Scenario (why this matters)

Colin is a Principal SecOps engineer woken at 2 AM for a credential-stuffing attack.
He's at home, on a corporate VPN, with the server in a DMZ. The CTO is on the call.

The existing documentation told him to open `http://localhost:8090`. That URL resolves
to his laptop. Every approach he might try fails for a concrete reason:

| What Colin tries | Why it fails |
|-----------------|--------------|
| `http://localhost:8090` | localhost is his laptop |
| `http://dmz-host:8090` directly | Port 8090 blocked at corp→DMZ firewall |
| `ssh user@dmz-host` without bastion | SSH from corp LAN → DMZ blocked in most enterprise configs |
| `http://localhost:8090` after port-forward | Corporate web proxy intercepts `localhost` HTTP |

**The correct procedure** (now in `EMERGENCY_DEPLOY.md` and `dashboard_access.md`):

```bash
# 1. SSH tunnel through the bastion host (the standard corporate pattern)
ssh -J YOU@bastion.mgmt.corp.example.com YOU@dmz-web01 \
    -L 8090:127.0.0.1:8090 \
    -L 8444:127.0.0.1:8444 \
    -N &

# 2. Dashboard (use 127.0.0.1 not localhost — bypasses corporate web proxy)
open https://127.0.0.1:8444   # self-signed cert warning — click through

# 3. Pull pre-built images (no build step at 2am)
# On the DMZ host:
docker compose pull && docker compose up -d

# 4. Test passthrough before going live
curl -kv https://127.0.0.1:8443/your-application-path

# 5. Insert into live traffic path (iptables redirect — instant rollback)
make traffic-on

# 6. Raise dial gradually: 0 → 50 → 80 → 100
./scripts/ja4-admin.sh dial 50

# 7. Block the attack fingerprint
./scripts/ja4-admin.sh block-ja4 <fingerprint>

# 8. Rollback at any time (< 1 second)
make traffic-off
```

---

## Key Design Decisions

### iptables PREROUTING for traffic insertion

`PREROUTING` only affects packets arriving from the network. Packets that JA4proxy
itself sends to the backend (via the `OUTPUT` chain) are not affected — no loopback
loop. This works regardless of whether HAProxy, nginx, or the application itself is
currently on port 443.

`make traffic-on` wraps: `sudo iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443`
`make traffic-off` wraps: `sudo iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443`

Both require `sudo`. If `sudo iptables` is not available, the runbook documents
HAProxy backend swap and DNS cutover as alternatives.

### Caddy sidecar for management HTTPS

Corporate web proxies sometimes intercept HTTP even on loopback (when using `localhost`
as the hostname; `127.0.0.1` usually bypasses them). Adding a Caddy sidecar on port
8444 with `tls internal` (auto-self-signed cert) gives HTTPS without cert management.

The sidecar is in the default `docker-compose.yml` — not an opt-in overlay. A
browser warning on first visit (self-signed cert) is lower friction than discovering
the sidecar doesn't exist at 2 AM.

### 127.0.0.1 not localhost in the runbook

Most corporate web proxies bypass `127.0.0.1` but may intercept `localhost`. All
URLs in the runbook use `127.0.0.1`.

### Two-datacentre: manual two-terminal procedure, not automated sync

For a light-traffic site (loan forms, low baseline), a minute of Redis replication
lag is acceptable — the goal is to cut most of the attack volume, not achieve
sub-second global consistency. Phase 511 documents the two-terminal manual procedure.
Redis replication across DCs is out of scope.

### Dial strategy: 0 → 50 → 80 → 100, not 0 → 100

The runbook explicitly says to pause at each level and watch the action panel. The
`--emergency` flag on `ja4-admin.sh dial` auto-reverts to 0 after a configurable
TTL — useful if Colin has to step away.

---

## What Phase 511 Does NOT Do

- Redis replication between datacentres (out of scope — manual two-terminal procedure documented)
- Let's Encrypt / ACME cert (operator concern; requires a public domain)
- Automate HAProxy reconfiguration (too site-specific; documented as an alternative)
- New authentication or RBAC (JWT + role-based access already in place)
- Firewall rule provisioning (the SSH tunnel explicitly avoids needing new firewall rules)

---

## Open Questions Answered

| Question | Decision |
|----------|----------|
| Caddy sidecar: default or overlay? | Default — simpler for 2 AM emergency |
| Management port binding: 127.0.0.1 or 0.0.0.0? | 127.0.0.1 — SSH tunnel always works, no firewall rule needed |
| Two-DC: automated sync or manual? | Manual two-terminal procedure — lag acceptable for light-traffic sites |
| traffic-on: iptables or DNS or HAProxy? | iptables as primary; others documented as alternatives |

---

## Questions Still Open (Need Owner Input)

**Q1 — Does `sudo iptables` work on your DMZ hosts?**
`make traffic-on` and `make traffic-off` require it. If not available (some hardened
systems block it), the HAProxy backend swap or DNS cutover are the alternatives —
both are documented in `dashboard_access.md`. Worth testing before the next incident.

**Q2 — Are the bastion hostnames known?**
The runbooks use `bastion.mgmt.corp.example.com` as a placeholder. The actual
bastion hostname and SSH port should be filled in and kept in a printed quick-reference
card — because at 2 AM, finding it in a wiki is not acceptable.

**Q3 — Are pre-built images being published to GHCR on every merge?**
`go-proxy-image.yml` CI workflow exists and publishes to GHCR. Verify the images
are actually public and pullable without auth: `docker pull ghcr.io/seanpor/ja4proxy:latest`
If this requires a PAT, it needs fixing before the next incident.
