<!--
title: Demo_Runbook
audience: operator
last_reviewed: 2026-08-17
phase: 826
-->

# Demo runbook — showing JA4proxy to someone

A scripted walk-through: your own browser, a second browser, one deliberate
bot connection, then the bulk attack. Each step says what to click and **what
proves it worked** — so a step that silently does nothing is visible to you
before it is visible to your audience.

Ports are lane-specific. Get yours first:

```bash
source .env
echo "Console:  http://127.0.0.1:${HOST_PORT_MANAGEMENT}"
echo "Grafana:  https://127.0.0.1:${HOST_PORT_GRAFANA}"   # https, self-signed
echo "Proxy:    127.0.0.1:${HOST_PORT_DIRECT}"
```

Log in with `MANAGEMENT_ADMIN_USER` / `MANAGEMENT_ADMIN_PASSWORD` from `.env`.

---

## 0. Before anyone is watching

```bash
make demo-check
```

Verifies the pipeline end to end and refuses to pass on a stale stack. If it
fails, do not start the demo — fix it first. It checks the things that have
actually broken before: analytics ingesting, the dial writable, panels not
500ing, findings being produced.

---

## 1. Your own browser — "this is you, and the system knows it"

Open a **new private window** and visit `https://127.0.0.1:${HOST_PORT_DIRECT}`.
Accept the certificate warning (self-signed backend).

Then in the console:

- **Dashboard → recent connections** — your connection appears, with its JA4.
- Click your fingerprint.

**What proves it worked:** the fingerprint page shows a decoded breakdown —
`TCP, TLS 1.3, SNI present, N ciphers, M extensions, ALPN HTTP/2` — and a
**browser-shaped** badge. That badge is derived from ALPN, and the page says
plainly that ALPN is attacker-controlled. Say that out loud: it is the honest
version of the claim and it is why the ALPN bypass ships disabled.

This is the audit story: *a real user connected, we fingerprinted the
handshake, we never decrypted anything, and here is the whole record.*

## 2. A different browser — "different client, different fingerprint"

Repeat with a different browser (Firefox if you used Chrome). Click the new
fingerprint.

**What proves it worked:** a *different* JA4 string, with different cipher and
extension counts — but still **browser-shaped**. Two different real users, both
correctly not flagged.

If both browsers produce the *same* fingerprint, say so — it means they share a
TLS stack. That is a real property of JA4, not a bug, and it is better to
volunteer it than to be asked.

## 3. One deliberate bot connection — "now something that isn't a browser"

```bash
scripts/demo-bot.sh
```

One connection from a scripted client: no ALPN, short cipher list. Then click
that fingerprint in the console.

**What proves it worked:** the decode reads `ALPN none offered`, a small cipher
count, and the badge says **not browser-shaped**. Nothing was blocked — at
dial 0/monitor this is observation only. That is the point: the system saw it
without acting on it.

## 4. The bulk attack — "now at volume"

```bash
./scripts/generate-tls-traffic.sh 90 15 20
```

85% attack traffic across several tool profiles, 15% browsers.

Watch, in this order:

1. **Dashboard** — connection rate climbs; the score distribution spreads.
2. **Under Attack** — the live view populates.
3. **Intelligence** — findings appear, e.g.
   *"JA4 t13d301100_… blocked on 1350/1350 connections (100%) and never
   allowed, from 1 source IP(s)"*, tagged HIGH with an evidence count and an
   FP estimate.
4. **Grafana** (sidebar → Metrics & Logs) — the same events as time series.

**What proves it worked:** the Intelligence panel is not empty, and each
finding names a fingerprint you can click through to a decode.

Note the suggested action is **investigate**, never **block**. Acting on a
fingerprint affects every client that shares it. Blocking a real browser costs
far more than missing a bot — that asymmetry is the product's core design
position, and this is the moment to say it.

---

## Enforcement, if they ask "can it actually stop anything?"

Blocking on score alone will not fire on this stack (see caveat below). Show
enforcement through the JA4 blacklist, which blocks at the bypass level,
independently of scoring:

```bash
./scripts/ja4-admin.sh block-ja4 <fingerprint-from-the-console>
docker kill -s HUP <proxy-container>     # new blocks are picked up on reload
```

Re-run the traffic. `ja4proxy_connections_total{action="block"}` climbs and the
console shows blocks.

**Why the SIGHUP:** by design, new blocks propagate on reload rather than
instantly, while *removals* propagate immediately over pub/sub. Unblocking a
real user must take effect at once; adding a block can wait. Worth saying —
it demonstrates the asymmetry is implemented, not just talked about.

To undo:

```bash
./scripts/ja4-admin.sh unblock-ja4 <fingerprint>
```

---

## Known caveats — say these before you are caught by them

- **Score-based blocking does not fire.** Nothing currently scores above 55, so
  `block`/`ban`/`tarpit` are unreachable by score alone; `rate_limit` is the
  only scored action seen at volume. Enforcement demos must use the blacklist.
- **Campaign and slow-scan detection cannot fire here.** They need ≥10 and ≥20
  unique source IPs respectively; the traffic generator is one container, so
  it produces one source IP. JA4 intelligence findings work because they key on
  per-fingerprint block rate instead.
- **The fingerprint corpus is small and dated** — 12 fingerprints, browsers
  only, roughly Chrome 118–122 / Firefox 102–121 / Safari 17, with no curl or
  wget entries. Current browsers may not be recognised. Do not claim
  comprehensive browser coverage.
- **Grafana is a separate login.** The sidebar links to it; it does not share
  the console session.
