<!--
title: Deployment Modes
audience: operator
last_reviewed: 2026-06-25
phase: 245.9
-->

# Deployment Modes

JA4proxy supports several deployment topologies. The proxy does TLS passthrough
(never decrypts traffic), so it sits in the TCP path between clients and your
backend.

## Direct Mode (Default)

JA4proxy listens directly on a port. Clients connect to it, and it forwards
to your backend. No upstream load balancer or PROXY protocol.

```yaml
# config/proxy.minimal.yml (or relevant section of proxy.yml)
proxy:
  bind_host: "0.0.0.0"
  bind_port: 8443
  backend_host: "your-server.com"
  backend_port: 443
  proxy_protocol: false
```

```bash
# Verify
curl -kv https://localhost:8443/
```

Client IP is taken from the TCP connection. This is the simplest mode and the
default for the root `docker-compose.yml`.

---

## Behind HAProxy

HAProxy in TCP mode forwards connections with PROXY protocol v2, preserving
the real client IP.

**HAProxy config:**

```
frontend tls_in
    bind *:443
    mode tcp
    default_backend ja4proxy

backend ja4proxy
    mode tcp
    server proxy1 ja4proxy:8080 send-proxy-v2
```

**JA4proxy config:**

```yaml
proxy:
  bind_port: 8080
  proxy_protocol: true
```

```bash
# Verify (connect to HAProxy, not the proxy directly)
curl -kv https://localhost:443/
```

---

## Behind nginx

nginx's `stream` module supports TCP proxying with PROXY protocol.

**nginx config:**

```nginx
stream {
    upstream ja4proxy {
        server ja4proxy:8080;
    }

    server {
        listen 443;
        proxy_pass ja4proxy;
        proxy_protocol on;
    }
}
```

**JA4proxy config:**

```yaml
proxy:
  bind_port: 8080
  proxy_protocol: true
```

```bash
# Verify
curl -kv https://localhost:443/
```

> **Note:** This requires the `ngx_stream_core_module` (included in most nginx
> packages but not always enabled). Check with `nginx -V 2>&1 | grep stream`.

---

## Behind AWS NLB

AWS Network Load Balancer supports PROXY protocol v2 on TCP target groups.

**AWS setup:**

1. Create a TCP target group pointing at JA4proxy's port (e.g. 8080)
2. Enable PROXY protocol v2 on the target group:
   ```bash
   aws elbv2 modify-target-group-attributes \
     --target-group-arn <arn> \
     --attributes Key=proxy_protocol_v2.enabled,Value=true
   ```
3. Create an NLB listener on port 443 forwarding to the target group

**JA4proxy config:**

```yaml
proxy:
  bind_port: 8080
  proxy_protocol: true
```

```bash
# Verify (replace with your NLB DNS name)
curl -kv https://my-nlb-1234.elb.amazonaws.com/
```

> **Note:** AWS ALB terminates TLS, so it cannot be used with JA4proxy's TLS
> passthrough model. Use NLB (layer 4) instead.

---

## Behind Cloudflare

Cloudflare's standard proxy terminates TLS, which prevents JA4proxy from seeing
the original TLS ClientHello. Two options:

### Option A: Cloudflare Spectrum (Enterprise)

Cloudflare Spectrum provides TCP-level proxying without TLS termination.
Configure a Spectrum application pointing at your origin's JA4proxy port.

**JA4proxy config:**

```yaml
proxy:
  bind_port: 8443
  proxy_protocol: true  # Spectrum supports PROXY protocol
```

### Option B: Cloudflare DNS-only (grey cloud)

Set the DNS record to DNS-only (grey cloud icon) so Cloudflare does not proxy
traffic. Clients connect directly to your origin IP.

**JA4proxy config:**

```yaml
proxy:
  bind_port: 8443
  proxy_protocol: false  # direct connections
```

> **Caveat:** DNS-only exposes your origin IP. Spectrum preserves Cloudflare's
> DDoS protection while allowing JA4proxy to see the real TLS handshake.

---

## Writing PROXY Protocol to the Backend

If your backend (nginx, Apache, etc.) also supports PROXY protocol and you want
it to see the real client IP, enable outbound PROXY protocol:

```yaml
proxy:
  write_proxy_protocol: true
  write_proxy_protocol_version: 1  # nginx requires v1; HAProxy supports both
```

This is independent of *receiving* PROXY protocol from an upstream LB.

**nginx backend config:**

```nginx
server {
    listen 443 ssl proxy_protocol;
    set_real_ip_from <ja4proxy_ip>;
    real_ip_header proxy_protocol;
}
```

**Apache backend config:**

```apache
RemoteIPProxyProtocol On
RemoteIPTrustedProxy <ja4proxy_ip>
```
