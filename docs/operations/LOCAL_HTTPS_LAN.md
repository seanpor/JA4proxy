<!--
title: Trusted HTTPS for Local/LAN Services (Private CA)
audience: operator
last_reviewed: 2026-08-11
phase: n/a (ad-hoc how-to)
-->

# Trusted HTTPS for Local & LAN Services

How to get a browser-trusted padlock - no warnings, no click-throughs - for
services you run in Docker on your own machine or home LAN (Grafana on
`:3000`, Portainer, Prometheus, etc.), including when you browse from a phone,
Chromebook, or a second laptop.

## The pattern: one private CA, not per-service self-signed certs

Don't create a separate self-signed cert per service. That means one browser
exception per service, re-doing it all at every expiry, and it trains you to
ignore certificate warnings - the exact habit certificates exist to prevent.

Instead:

1. Create **one private Certificate Authority (CA)** once.
2. Install that single CA certificate into the trust store of **every client
   device** (laptop, phone, Chromebook, ...) **once**.
3. Mint as many server certificates as you like from that CA - every one is
   instantly trusted everywhere you installed the CA, with zero warnings.

```
                +----------------------+
                |  Your private CA     |  rootCA.pem      = public, install everywhere
                |  rootCA-key.pem      |  rootCA-key.pem  = SECRET, never leaves the CA machine
                +----------+-----------+
                           | signs
        +------------------+------------------+
        v                  v                  v
  cert: mypc.lan     cert: *.mypc.lan     cert: 192.168.1.50
        |                  |                  |
   Grafana :3000      Caddy/Traefik      Portainer :9443
   Prometheus :9090   (all services)     anything else
```

We use [mkcert](https://github.com/FiloSottile/mkcert), the standard tool for
this. It automates CA creation, trust-store installation, and SAN handling.

---

## Step 1 - Create the CA (on the machine that runs Docker)

```bash
sudo apt install mkcert libnss3-tools   # libnss3-tools: lets mkcert reach Firefox's store
mkcert -install
```

This creates `rootCA.pem` + `rootCA-key.pem` under `mkcert -CAROOT`
(usually `~/.local/share/mkcert/`) and installs the root into:

- the system trust store (used by Chrome/Chromium, curl, most tooling), and
- Firefox's **separate** NSS store (this is what `libnss3-tools`/`certutil`
  is for - without it, Firefox alone will still warn).

Lock the key down - it is the single most sensitive file in this setup:

```bash
chmod 600 "$(mkcert -CAROOT)/rootCA-key.pem"
```

## Step 2 - Mint a server certificate

A browser checks the cert against the exact hostname/IP in the URL, so list
**every** address you'll ever type, as Subject Alternative Names (SANs):

```bash
mkdir -p ~/certs && cd ~/certs   # any working dir
mkcert mypc.lan localhost 127.0.0.1 ::1 mypc.local 192.168.1.50
# -> mypc.lan+5.pem  and  mypc.lan+5-key.pem
#    (mkcert names the files after the FIRST name, +5 = the other five SANs)
```

**Prefer a name over a raw IP.** DHCP will eventually change your LAN IP and
every cert with the old IP in its SANs breaks. Easiest to hardest:

- **mDNS** (`mypc.local`) - zero config if the host runs avahi (most desktop
  Linux does); works well from Linux, macOS and iOS, usually from recent
  Windows 10/11, and is **flaky on Android** (version-dependent) - don't rely
  on it as your only option.
- **Router DHCP reservation + local DNS name** - many routers let you pin
  `mypc` -> `192.168.1.50` permanently and will serve that name over LAN DNS.
- **Pi-hole / dnsmasq** - add a Local DNS record; covers every client that
  uses it as DNS (including Android).
- **`/etc/hosts`** on each client - fine for laptops, impossible on
  phones/Chromebooks.

If you must use a raw IP, reserve it in the router first, then put it in the
SAN list. Re-issuing after an IP change is cheap (re-run `mkcert`, redeploy -
the CA stays installed on all your devices).

## Step 3 - Deploy into Docker

One cert works for **all** services on the same host, because the SANs are
identical - just mount it into each container. Note the two different keys
in play: the **server key** (`mypc.lan+5-key.pem`) *must* live wherever TLS
is terminated - mounting it read-only into the container is normal and
required. The **CA key** (`rootCA-key.pem`) is the one that must never be
copied anywhere.

> Compose gotcha: `~` is **not** expanded in `volumes:` paths. Use
> `${HOME}/certs/...` (Compose expands environment variables) or an absolute
> path, as in the examples below.

### Option A - TLS terminated by each app (fine for 1-2 services)

Grafana example:

```yaml
services:
  grafana:
    ports: ["3000:3000"]
    volumes:
      - ${HOME}/certs/mypc.lan+5.pem:/etc/grafana/certs/cert.pem:ro
      - ${HOME}/certs/mypc.lan+5-key.pem:/etc/grafana/certs/key.pem:ro
    environment:
      GF_SERVER_PROTOCOL: https
      GF_SERVER_CERT_FILE: /etc/grafana/certs/cert.pem
      GF_SERVER_CERT_KEY: /etc/grafana/certs/key.pem
```

Most self-hosted apps have equivalent `CERT_FILE`/`KEY_FILE` settings.

### Option B - One reverse proxy in front (better beyond ~2 services)

Terminate TLS in one place; backends stay plain HTTP on the internal Docker
network (that traffic never leaves the host, so plain HTTP there is fine).
Caddy example:

```yaml
services:
  caddy:
    image: caddy:2-alpine
    ports: ["8443:8443", "9443:9443"]   # must publish every port the Caddyfile listens on
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ${HOME}/certs/mypc.lan+5.pem:/etc/caddy/cert.pem:ro
      - ${HOME}/certs/mypc.lan+5-key.pem:/etc/caddy/key.pem:ro
```

```caddyfile
# Caddyfile - route by port (no DNS needed)
mypc.lan:8443 {
    tls /etc/caddy/cert.pem /etc/caddy/key.pem
    reverse_proxy grafana:3000
}
mypc.lan:9443 {
    tls /etc/caddy/cert.pem /etc/caddy/key.pem
    reverse_proxy prometheus:9090
}
```

With local DNS (Pi-hole/dnsmasq) you can route by name instead
(`grafana.mypc.lan`, `prometheus.mypc.lan`, ...) on one 443 port - issue one
wildcard (`mkcert mypc.lan "*.mypc.lan" 192.168.1.50`) and it covers every
current and future service.

> Caddy alternative: `tls internal` makes Caddy run its **own** private CA.
> Then you skip mkcert for the server certs and instead install Caddy's root
> (`/data/pki/authorities/local/root.crt` inside its data volume) on your
> devices. Same end state; mkcert keeps everything in one tool.

## Step 4 - Trust the CA on every device

Copy **`rootCA.pem` only** (never `rootCA-key.pem`) to each device. It is a
*public* certificate - safe to move over plain channels:

```bash
# easiest: serve it on the LAN from the CA machine
cd "$(mkcert -CAROOT)" && python3 -m http.server 8000
# then browse to http://192.168.1.50:8000/rootCA.pem from each device
```

USB stick, email-to-self, Syncthing, etc. all work too. If you want to verify
integrity before trusting (paranoid but cheap), compare fingerprints:

```bash
openssl x509 -in rootCA.pem -noout -fingerprint -sha256
```

### Linux laptop (Chrome/Chromium/Edge/curl)

```bash
sudo cp rootCA.pem /usr/local/share/ca-certificates/mylab.crt   # note: .crt extension
sudo update-ca-certificates
```

Firefox has a **separate store**: Settings -> Privacy & Security ->
Certificates -> View Certificates -> **Authorities** -> Import -> check
"Trust this CA to identify websites".

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain rootCA.pem
```

Or GUI: Keychain Access -> System keychain -> import -> double-click it ->
Trust -> "Always Trust". Firefox on macOS still needs its own import (as
above).

### Windows laptop

Double-click `rootCA.pem` -> Install Certificate -> Local Machine -> Place in
**Trusted Root Certification Authorities** (needs admin). Or elevated:

```powershell
certutil -addstore -f ROOT rootCA.pem
```

Covers Chrome/Edge. Firefox needs its own import (as above).

### Android phone

1. Get `rootCA.pem` onto the phone (download from the LAN URL above, USB,
   or `adb push rootCA.pem /sdcard/Download/`).
2. Settings -> Security & privacy -> More security settings ->
   **Encryption & credentials** -> **Install a certificate** -> **CA
   certificate** -> pick the file. (Menu names vary slightly by Android
   version/OEM.)
3. Chrome on Android trusts user-installed CAs, so your sites are padlocked
   immediately.

Expect a one-time "your network may be monitored" notification - that's
Android telling you a user CA exists; it's *your* CA, so it's fine. Note:
since Android 7 (API 24), most **apps** deliberately ignore user CAs, so
banking apps etc. are unaffected - browsers are what matter here.

### iPhone / iPad

Two steps - everyone misses the second:

1. Get the file on the device (AirDrop the `.pem`, or download it) -> iOS
   shows "Profile Downloaded" -> Settings -> General -> **VPN & Device
   Management** -> install the profile.
2. **Then enable full trust**: Settings -> General -> **About** ->
   **Certificate Trust Settings** -> toggle your root ON.

Skip step 2 and Safari will still warn. To remove later: delete the profile.

### Chromebook (ChromeOS)

1. Download `rootCA.pem` so it appears in the Files app.
2. Go to `chrome://settings/certificates` -> **Authorities** -> **Import**.
3. Select the file, check **"Trust this certificate for identifying
   websites"**.

The trust is per-user-account on the device, and **managed** (school/work)
Chromebooks may block installing CAs entirely.

## Optional - containers that call each other over TLS

Clients (browsers) are the ones that need the CA, not your containers. But if
service A calls service B over HTTPS, copy `rootCA.pem` into `~/certs/` and
mount it into A's container:

```yaml
volumes:
  - ${HOME}/certs/rootCA.pem:/usr/local/share/ca-certificates/mylab.crt:ro
command: sh -c "update-ca-certificates && exec myapp"
```

Language-specific shortcuts: Node.js `NODE_EXTRA_CA_CERTS=/path/rootCA.pem`,
Python requests `REQUESTS_CA_BUNDLE=/path/rootCA.pem`, Go honours the system
store.

## Renewal & lifecycle

- Server certs from mkcert last about two years; check with
  `openssl x509 -in mypc.lan+5.pem -noout -enddate`. Re-run the `mkcert`
  command and redeploy to renew - devices keep trusting automatically.
- The CA itself lasts ~10 years. When it finally expires you repeat this
  whole guide once.
- To retract trust from a device: `mkcert -uninstall` on the CA machine, or
  delete the imported root from the device's certificate settings.

## Security notes (read once)

- **Guard `rootCA-key.pem`.** Anyone who obtains it can mint certificates
  that every one of your trusted devices will accept for *any* website -
  it is a universal MITM key for your own devices. `chmod 600`, never commit
  it, never copy it to other devices, and exclude it from backups you sync to
  cloud storage (or encrypt those backups).
- Installing any root CA (including yours) means that CA can vouch for
  anything. That's why the key stays on one machine and only the public
  `rootCA.pem` travels.
- HTTPS here protects traffic on your LAN and stops passive snooping; it does
  not replace service logins - keep authentication enabled on Grafana etc.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ERR_CERT_COMMON_NAME_INVALID` | The name/IP in your URL isn't in the SAN list - re-issue the cert with it. |
| Works in Chrome, warns in Firefox | Firefox has its own store - import into Authorities (Step 4). |
| Works on laptop, warns on iPhone | You installed the profile but skipped Certificate Trust Settings (Step 4, iOS step 2). |
| Worked yesterday, broken today | DHCP changed the host IP - use a name, or reserve the IP and re-issue. |
| Android Chrome can't resolve `mypc.local` | Android mDNS support is version-dependent/flaky - use Pi-hole/router DNS or the IP SAN instead. |
| Warning after ~2 years | Server cert expired - re-run the mkcert issuance command and redeploy. |
