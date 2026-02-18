# Secure Redis Deployment (Ansible)

Ansible role to deploy Redis 7 in a high-security environment for JA4proxy.

## What It Does

| Feature | Implementation |
|---|---|
| **TLS everywhere** | TLS 1.2/1.3 only, mutual TLS with client certs, plaintext port disabled |
| **ACL access control** | `proxy` user restricted to `ja4:*` keys only, `exporter` is read-only |
| **Encryption at rest** | LUKS2 with AES-XTS-512 on the data volume |
| **Dangerous commands** | FLUSHALL, CONFIG, DEBUG, SHUTDOWN, SCRIPT all disabled |
| **Prometheus metrics** | redis-exporter with TLS client cert, dedicated `exporter` ACL user |
| **Auth monitoring** | Cron job detects auth failures → syslog alert + Prometheus metric |
| **Host firewall** | iptables rules restrict Redis port to allowed CIDRs only |
| **Container hardening** | read-only, cap_drop ALL, no-new-privileges, resource limits |

## Quick Start

```bash
# 1. Install Ansible collections
ansible-galaxy collection install community.docker community.crypto ansible.posix community.general

# 2. Copy and edit the inventory
cp inventory.ini.example inventory.ini
# Edit inventory.ini with your Redis host

# 3. Create the vault file with secrets
cp vault.yml.example vault.yml
# Edit vault.yml — set all passwords to strong random values:
#   openssl rand -base64 32 | tr -d '/+=' | head -c 40
ansible-vault encrypt vault.yml

# 4. Deploy
ansible-playbook -i inventory.ini deploy-redis.yml --ask-vault-pass
```

## ACL Users

| User | Password | Key Access | Commands | Purpose |
|---|---|---|---|---|
| `admin` | From vault | All keys | All commands | Maintenance only |
| `proxy` | From vault | `ja4:*` only | GET SET DEL EXISTS EXPIRE TTL INCR SCAN KEYS PING INFO | JA4proxy application |
| `exporter` | From vault | Read-only | INFO PING DBSIZE SLOWLOG CONFIG GET | Prometheus scraping |
| `default` | Disabled | None | None | No anonymous access |

## Connecting from JA4proxy

After deployment, configure the proxy to use TLS + client cert:

```yaml
# config/proxy.yml
redis:
  host: redis01.dmz.corp.local
  port: 6379
  username: proxy
  password: ${REDIS_PROXY_PASSWORD}
  ssl: true
  ssl_cert: /app/tls/client-proxy.crt
  ssl_key: /app/tls/client-proxy.key
  ssl_ca: /app/tls/ca.crt
```

Copy the client certificates from the Redis host:
```bash
scp redis01:/opt/ja4proxy/redis/tls/client-proxy.{crt,key} ./ssl/
scp redis01:/opt/ja4proxy/redis/tls/ca.crt ./ssl/
```

## Files Deployed

```
/opt/ja4proxy/redis/
├── config/
│   ├── redis.conf          # Main config (TLS, memory, persistence)
│   └── users.acl           # ACL definitions (3 users)
├── tls/
│   ├── ca.crt              # Internal CA certificate
│   ├── ca.key              # CA private key (root only)
│   ├── redis.crt           # Server certificate
│   ├── redis.key           # Server private key
│   ├── client-proxy.crt    # Client cert for JA4proxy
│   ├── client-proxy.key    # Client key for JA4proxy
│   ├── client-exporter.crt # Client cert for Prometheus exporter
│   └── client-exporter.key # Client key for exporter
├── data/                   # LUKS-encrypted mount point
├── logs/
│   ├── auth-failures.log   # Auth failure monitoring log
│   └── auth-monitor.log    # Monitor script output
├── metrics/
│   └── redis_auth_failures.prom  # Textfile for Prometheus node-exporter
└── redis-auth-monitor.sh   # Cron script for auth failure detection
```

## Disabling LUKS (for testing)

If you don't have a spare block device for LUKS:

```yaml
# In your playbook vars or host_vars:
redis_luks_enabled: false
```

Redis will use a standard directory instead.

## Prometheus Scrape Config

```yaml
# Add to prometheus.yml
- job_name: 'redis-secure'
  static_configs:
    - targets: ['redis01.dmz.corp.local:9121']
  scheme: http  # exporter itself is on localhost:9121
```
