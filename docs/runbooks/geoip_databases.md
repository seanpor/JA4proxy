<!--
title: GeoIP_Databases
audience: Operators, Security Teams
last_reviewed: 2026-08-18
phase: 827
-->

# Runbook — GeoIP and ASN databases

## Symptom

One of these at proxy startup:

```
asn_classifier: GeoLite2-ASN database not found — ASN enrichment disabled.
asn_classifier: no GeoIP database configured — country blocking and ASN enrichment disabled.
```

Or, in the console and findings: connections have a country but no ASN or
organisation; findings never mention a shared ASN; `asn_datacenter` never
appears in a score breakdown.

## Why this matters — it is not cosmetic

The proxy **starts, runs, forwards traffic and reports healthy** without these
databases. Nothing fails. What is lost is silent:

| Lost | Effect |
|---|---|
| `asn_datacenter` (+20) | Traffic from AWS/GCP/Azure/OVH scores the same as a home broadband user |
| `asn_vpn` (+10) | Commercial VPN egress is invisible |
| `asn_unknown` (+5) | No signal for unattributable space |
| `client.as.number`, `client.as.organization.name` on events | The analytics node cannot tell a consumer ISP /24 from a hosting provider /24 |
| `asn` / `asn_org` correlation dimensions | Findings cannot say "all 45 IPs belong to one hosting provider" |

That last row is the one that bites. `docs/reference/GOOD_TRAFFIC_PROFILE.md`
rule 5 — *consumer ASN is exculpatory, hosting ASN is probative* — depends
entirely on this data. Without it, the only discriminator protecting a CGNAT'd
consumer subnet from being treated as a scan is fingerprint diversity.

**Tor detection keeps working** (separate downloaded list, checked before the
DB lookup), which is why an ASN-blind proxy can look like it is enriching
correctly.

## The two databases

| Database | Purpose | Access | Path |
|---|---|---|---|
| IP2Location LITE DB1 | IP → country | Anonymous, no key | `data/geoip/IP2LOCATION-LITE-DB1.BIN` |
| MaxMind GeoLite2-ASN | IP → ASN + organisation | **Free account** | `config/GeoLite2-ASN.mmdb` |

Paths come from `config/proxy.yml` (`geoip.database_path`,
`security.asn_classifier.maxmind_db_path`) and must match what
`docker-compose.poc.yml` mounts: `../../data/geoip:/app/geoip:ro` and
`../../config:/app/config:ro`. If you move either database, move the mount too.

### Format: it must be `.mmdb`, not CSV

MaxMind offer every GeoLite2 dataset in two formats. **Download "GeoIP2 Binary
(.mmdb)", not "CSV".** The proxy memory-maps the binary format via
`geoip2.Open()`; it has no CSV reader, and a directory full of CSVs produces
exactly the same "DB absent" behaviour as having nothing at all. The CSVs are
for loading into your own database — they are not a drop-in substitute.

### Why one is committed and the other is not

`data/geoip/IP2LOCATION-LITE-DB1.BIN` **is** in the repository. That is
deliberate: IP2Location LITE is CC-BY-SA-4.0 and the licence text sits beside
it, so redistribution is permitted.

MaxMind's EULA does **not** permit redistribution, so `*.mmdb` is gitignored and
every operator fetches their own. This is why the ASN database needs an account
and the country one does not.

## Fix

### 1. Check what you actually have

```bash
make check-geoip        # reports the age of BOTH databases, downloads nothing
```

### 2. Get a MaxMind licence key (one-off)

The ASN database is the one that needs a key. It is free.

1. Sign up: <https://www.maxmind.com/en/geolite2/signup>
2. Account → **Manage License Keys** → create a key
3. Make it available, either:

```bash
export MAXMIND_LICENSE_KEY=...          # this shell only
```

or add it to `.env`, which `update-geoip.sh` reads automatically:

```
MAXMIND_LICENSE_KEY=...
```

### 3. Download both

```bash
make update-geoip
```

The script backs up any existing database to `*.prev`, validates the download
(size, and that an `.mmdb` really is a MaxMind file rather than an HTML error
page saved under that name), and **exits non-zero if the ASN half failed** so a
cron run surfaces the problem instead of logging success.

### 4. Restart to load them

```bash
make stop && make start
```

Neither database is hot-reloadable — both are memory-mapped at startup.

### 5. Confirm

Startup log should no longer carry the `asn_classifier` warning. Then check a
connection event actually carries the fields:

```bash
redis-cli --user analytics -a "$ANALYTICS_REDIS_PASSWORD" --no-auth-warning \
  XREVRANGE events:connection + - COUNT 1
```

`client.as.number` and `client.as.organization.name` should be populated, not
empty strings. Empty means the DB is present but the lookup is missing that IP
(normal for RFC1918 and other private space — test with a public address).

## Manual install (air-gapped or no account)

Download `GeoLite2-ASN` in **mmdb** format from MaxMind and place it at
`config/GeoLite2-ASN.mmdb`, then restart. The proxy only reads the file; it
does not care how it got there.

## Refresh cadence

- IP2Location LITE: monthly.
- MaxMind GeoLite2: twice weekly (Tuesdays and Fridays).

A monthly cron covers both adequately:

```
0 3 1 * * cd /path/to/JA4proxy && MAXMIND_LICENSE_KEY=... ./scripts/update-geoip.sh >> /var/log/ja4proxy-geoip.log 2>&1
```

Because the script exits non-zero when the ASN database is missing or stale-
failing, a plain cron mail alert is enough to catch a revoked key.

## Related

- `docs/reference/GOOD_TRAFFIC_PROFILE.md` — why ASN provenance is load-bearing
- `docs/runbooks/analytics_lag.md` — the other "everything is healthy but nothing works" failure
