<!--
title: Use Case — Stopping Form-Abuse Bots
audience: operator, secops
last_reviewed: 2026-07-06
phase: 524
-->

# Use Case: Stopping Form-Abuse Bots

> Your signup / login / contact form is being hammered by automated submissions. You need to cut the bot traffic without blocking real customers, today.

This guide walks you through deploying JA4proxy to stop form-abuse bots in a production-emergency scenario. It assumes you have a working deployment or emergency instance running (see [Emergency Deploy](EMERGENCY_DEPLOY.md)).

---

## What JA4proxy Catches Out of the Box

**Non-browser bots** (the majority of automated form abuse) have distinctive TLS fingerprints and are caught immediately:

- **curl, wget, Python `requests`, Go `net/http`, Ruby `Net::HTTP`** — all produce unique JA4 fingerprints that differ from real browsers.
- **Commodity bot frameworks** (Selenium, Splash, basic JavaScript engines) — often use simplified TLS stacks or missing extensions, making them identifiable.
- **Custom bot tools** (curl wrappers, custom TCP libraries, headless browser alternatives) — frequently skip HTTP/2 negotiation (h2 ALPN), making them distinct from real browser traffic.

**Key point:** Because the default configuration has `alpn_browser_bypass: false`, even a bot that *claims* to use `ALPN=h2` (HTTP/2, standard browser behaviour) is **still scored** like any other connection. A bot cannot fake its way past JA4proxy by spoofing ALPN alone—it must match the entire TLS fingerprint, which is much harder.

**What happens immediately:**
1. Deploy in **monitor mode** (`dial=0`). The proxy scores every connection but blocks nothing.
2. Watch the decision log / dashboard — attack traffic clusters on 1–3 distinct JA4 fingerprints.
3. Block those fingerprints with a single command.
4. Real browsers and customers continue unaffected; bot traffic (99.8%+) stops.

---

## The Honest Limit — Real-Browser-Driven Bots

Here is the **critical limitation**: if the attacker uses a **real, unmodified browser under automation** (Headless Chrome via Puppeteer, Playwright, Selenium with a real browser backend), that traffic looks *identical at the TLS layer* to a human's Chrome.

- **JA4 fingerprint is genuine.** The browser produces real h2 ALPN, real ciphers, real TLS extensions.
- **Rate limiting is the primary defense.** A human clicking a form ~1–2 times/minute; a bot driven browser submits 10–100/minute.
- **Beaconing detection** spots regular-interval submissions (e.g. exactly every 5 seconds).
- **ASN/datacenter classification** flags connections from cloud IPs (AWS, GCP, Azure, etc.) where the bot is actually running.
- **AbuseIPDB reputation** catches IPs known for abuse.
- **Analytics signals** — multi-factor analysis combining all above.

**What JA4proxy is NOT:** a CAPTCHA, a human-verification system, or an application-layer WAF. It cannot inspect form contents, analyze user behaviour, or replace your application's validation. It is excellent at identifying *how the connection was made* (the TLS layer), but not *why the request was made* (the business logic).

---

## Step-by-Step Playbook

### 1. Deploy in Monitor Mode & Watch the Dashboard

```bash
# If you just deployed, the dial is already 0 (monitor mode)
./scripts/ja4-admin.sh status  # verify dial=0

# Watch the decision log in real time
docker compose -f deploy/docker/docker-compose.poc.yml logs -f proxy | grep -E 'action=|fingerprint='

# Or use the dashboard:
# https://127.0.0.1:8444 (management UI)
# http://127.0.0.1:3000 (Grafana)
```

**Watch for patterns:** Attack traffic will cluster on 1–3 JA4 fingerprints. Real browsers will have diverse fingerprints (Chrome, Firefox, Safari, Mobile Safari, etc.).

### 2. Block the Obvious Non-Browser Bot JA4s

```bash
# Find the top attacking fingerprints
./scripts/ja4-admin.sh top 10

# Block the obvious bots (example fingerprints — use your actual ones)
./scripts/ja4-admin.sh block-ja4 t13d1516h2_8daaf6152771_02713d6af862  # curl wrapper
./scripts/ja4-admin.sh block-ja4 t13d1315h2_7c5a8b9d1234_5678abcdef00  # custom scraper

# Verify the block took effect
./scripts/ja4-admin.sh status  # lists active blacklist entries
```

This is **immediate and low-risk:** you're only blocking identifiably non-browser traffic. Real browsers have never produced these fingerprints.

### 3. Raise the Dial Gradually

Once obvious bots are blocked, gradually enforce the dial to catch more sophisticated attacks:

```bash
# Raise to 50 (lenient scoring)
./scripts/ja4-admin.sh dial 50

# Watch for 2 minutes — monitor the decision log and error rates
sleep 120
./scripts/ja4-admin.sh status

# If you see legitimate traffic being blocked (unlikely at 50), drop back to 0
./scripts/ja4-admin.sh dial 0
```

If 50 is clean, continue:

```bash
# Raise to 80 (moderate enforcement)
./scripts/ja4-admin.sh dial 80
sleep 120

# If still clean, go to 100 (full enforcement)
./scripts/ja4-admin.sh dial 100
```

**Never jump straight to 100.** The dial affects rate limiting and other signals; a high dial on an attack can cause collateral damage if the scoring rules aren't tuned for your specific traffic.

### 4. For Cloud-Hosted Browser Bots — Enable Datacenter & Rate Limits

If you see attack traffic from browser fingerprints (real TLS), fall back to signal-based detection:

```bash
# In the management UI or config: enable datacenter blocking for your region
# Example: block AWS IPs (cloud providers used by cheap bot hosting)
# https://127.0.0.1:8444 → Settings → Datacenter Policy

# Or via the CLI if datacenter blocking is available
# (depends on your config; see the config/proxy.yml documentation)

# Tune rate limiting: lower the threshold to catch browser bots submitted too fast
# Default: suspicious at 2 req/s, block at 5 req/s
# For form abuse: consider lowering to block at 3 req/s
```

**AbuseIPDB integration** (if enabled):
```bash
# Check if an IP is known for abuse
./scripts/ja4-admin.sh check-ip 203.0.113.42  # example IP
```

### 5. Important: The ALPN Browser Bypass Tradeoff

**Do NOT enable `alpn_browser_bypass`** for this use case.

The bypass is disabled by default because a bot *can* trivially set `ALPN=h2` to look like a browser to a naive detector. If you enable it, you're saying "any connection advertising h2 ALPN is automatically allowed," which defeats rate limiting and beaconing detection for that traffic. Your form-abuse bots can then spoof it and bypass the entire security pipeline.

Keep it disabled. Let the TLS scoring and rate limiting protect you.

---

## Expectation-Setting & Limitations

### What JA4proxy Will Do

✅ **Immediate impact:** Non-browser bots (curl, wget, custom scripts) — blocked instantly. Typical bot framework attack traffic — reduced 90–99% on first day.

✅ **Sustainable protection:** Real browsers are whitelisted by fingerprint if desired; legitimate users never blocked. Bandwidth savings from stopping obvious bots is 50–80% on typical form-abuse attacks.

✅ **Single command enforcement:** No redeployment, no config edits, no restart needed. Raise the dial, blacklist a fingerprint, enable a datacenter block — all take effect immediately.

### What JA4proxy Will NOT Do

❌ **Stop application-layer abuse:** Form submission logic, CAPTCHA bypass, sequential attack patterns, payment fraud — these live in your app, not the TLS layer. JA4proxy is a first-line filter, not a replacement for app-layer validation.

❌ **Distinguish a bot-driven Chrome from a human's Chrome:** Both are identical at the TLS layer. Use rate limiting and beaconing detection instead.

❌ **Serve as your sole defence:** Pair JA4proxy with your existing WAF, rate limiter, and bot-detection rules. It is excellent at the TLS metadata layer; your application is excellent at the business-logic layer.

❌ **Protect against all bots.** A sophisticated attacker with a real, unmodified browser can still submit forms. Your rate limiting, analytics, and user validation rules are your secondary defences.

---

## Recovery & Next Steps

### If You Accidentally Block Real Traffic

```bash
# Lower the dial
./scripts/ja4-admin.sh dial 0

# Or unblock a specific fingerprint
./scripts/ja4-admin.sh unblock-ja4 t13d1516h2_8daaf6152771_02713d6af862
```

### What to Do After the Attack Stops

1. **Keep the dial where it is.** If dial=100 has stopped the attack and not blocked real traffic, leave it there. It's your new baseline.
2. **Monitor for a week.** Attackers may rotate IPs, fingerprints, or tactics. Watch the dashboards daily.
3. **Tune datacenter & rate limits.** If the attack was from a specific cloud provider, keep datacenter blocking enabled. If it was fast-submission bots, lower rate limits accordingly.
4. **Document the fingerprints.** Save the JA4 hashes of the attack in your runbook so you can block them faster next time.

---

## References

- [Emergency Deploy](EMERGENCY_DEPLOY.md) — full production-emergency setup guide
- [Dashboard Access](../../docs/runbooks/dashboard_access.md) — how to monitor in real time
- [Incident Response](INCIDENT_RESPONSE.md) — longer-term hardening after an incident
- Phase 524 for context on why the ALPN bypass is off by default (see: JA4PROXY-2026-0004)
