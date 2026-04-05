# Management UI Access via SSH Tunnel

The JA4proxy Management UI runs on port 8090 bound to `127.0.0.1` only. This means
it is not reachable from the internet — you must connect through an SSH tunnel from a
machine that has SSH access to the server.

This document covers access from a Chromebook (Linux container), but the same
instructions apply to any Linux/macOS machine.

---

## Why SSH Tunnel?

Port 8090 is deliberately bound to loopback (`127.0.0.1:8090`) and not to the server's
public interface. This prevents the management API from being reachable over the internet
without the protection of an SSH session. The management API has a login endpoint, but
exposing it directly to the internet adds unnecessary attack surface.

SSH tunnelling means:
- The management UI never appears in port scans of your server
- Brute-force attacks against the login endpoint are not possible from the internet
- You get the security of SSH key authentication "for free" before the management login
  page is even presented

---

## Quick Start

This is the minimum you need. Run this on your local machine (Chromebook, laptop, etc.):

```bash
# On your Chromebook / local machine:
ssh -L 8090:localhost:8090 user@your-server-ip -N

# Then open in Chrome:
# http://localhost:8090
```

The `-L 8090:localhost:8090` flag forwards your local port 8090 to port 8090 on the
remote server. The `-N` flag opens the tunnel without starting a shell.

Leave this terminal open while you use the UI. Press Ctrl+C to close the tunnel.

---

## Persistent Tunnel for Regular Use

For day-to-day use, add a host entry to `~/.ssh/config` on your Chromebook so you can
bring the tunnel up with a single short command.

```bash
# Add to ~/.ssh/config on your Chromebook (create the file if it doesn't exist):

Host ja4proxy-mgmt
  HostName your-server-ip
  User your-username
  LocalForward 8090 localhost:8090
  ServerAliveInterval 60
  ServerAliveCountMax 3
```

Then open the tunnel with:

```bash
ssh ja4proxy-mgmt -N
```

And navigate to: `http://localhost:8090`

The `ServerAliveInterval 60` and `ServerAliveCountMax 3` settings keep the tunnel alive
through short periods of inactivity (up to 3 minutes without traffic before the connection
drops).

---

## Chromebook Linux Container Specifics

The Chromebook's Linux container (Crostini) has a full OpenSSH client available in the
Terminal app. Port forwarding set up inside the Linux container is accessible in Chrome
on the Chromebook — Chrome can open `http://localhost:8090` directly.

Steps:
1. Open the Terminal app (Linux apps → Terminal)
2. Run: `ssh -L 8090:localhost:8090 user@your-server-ip -N`
3. Open Chrome and navigate to: `http://localhost:8090`

The Chromebook does not require any special firewall configuration — the port forwarding
works entirely within the Linux container's loopback interface, and Chrome can reach it.

---

## Starting the Management UI on the Server

Before connecting via SSH tunnel, ensure the management service is running on the server:

```bash
# On the server, in the JA4proxy directory:
cd /path/to/JA4proxy4
make management-up

# Verify it started:
curl http://localhost:8090/api/v1/health
# Expected: {"status": "ok", ...}
```

To check logs:

```bash
make management-logs
```

To stop:

```bash
make management-down
```

---

## Default Credentials

| Setting | Default | Environment Variable |
|---------|---------|---------------------|
| Username | `admin` | `MANAGEMENT_ADMIN_USER` |
| Password | `admin` | `MANAGEMENT_ADMIN_PASSWORD` |

These defaults are intentionally weak. Change them before sharing access with any team
member. See the security checklist below.

---

## Changing Credentials

Set these in your `.env` file in the JA4proxy root directory (never commit `.env` to git):

```bash
# In /path/to/JA4proxy4/.env:
MANAGEMENT_JWT_SECRET=<random-32-char-string>
MANAGEMENT_ADMIN_USER=youruser
MANAGEMENT_ADMIN_PASSWORD=your-strong-password
```

Generate a random JWT secret:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

After updating `.env`, restart the management service:

```bash
make management-down && make management-up
```

---

## Security Checklist

Complete this checklist before sharing management access with any team member:

- [ ] Set `MANAGEMENT_JWT_SECRET` to a random 32+ character string in `.env`
- [ ] Set `MANAGEMENT_ADMIN_PASSWORD` to a strong password in `.env`
- [ ] Verify port 8090 is NOT listed in your server firewall's allowed inbound rules
      (check: `curl --connect-timeout 5 http://<server-public-ip>:8090` from an external
      machine — it should time out)
- [ ] Use SSH key authentication for the SSH tunnel (not password auth)
- [ ] Ensure your SSH private key is passphrase-protected on the Chromebook

---

## Troubleshooting

**"Connection refused" when opening http://localhost:8090:**
The SSH tunnel is open but the management service is not running on the server.
Run `make management-up` on the server.

**"Channel 3: open failed: connect failed" in the SSH terminal:**
The management service is not listening on port 8090 on the server. Check:
`docker compose -f docker-compose.poc.yml ps management`

**Tunnel drops frequently:**
Add to your SSH config or use `-o ServerAliveInterval=60 -o ServerAliveCountMax=3`
on the command line.

**Login page does not appear (blank page or 404):**
The management service may still be starting up. Wait 10 seconds and refresh.
Check `make management-logs` for startup errors.

**"Too many requests" on login:**
The login endpoint rate-limits to 5 attempts per 60 seconds. Wait 60 seconds and try
again with the correct credentials.
