# Redis Security — POC Status and Production Requirements

**Last reviewed:** 2026-02-23
**Scope:** Current POC configuration. Redis holds security state only (ban lists, rate windows, JA4 fingerprint sets) — no user data or credentials beyond its own auth password.

---

## Current State

| # | Issue | POC Status | Production Requirement |
|---|-------|-----------|----------------------|
| 1 | Password strength | ✅ Auto-generated (32 chars, `openssl rand`) by `../scripts/start-poc.sh` | Use Docker secrets |
| 2 | TLS encryption | ❌ Plaintext (Docker-internal only) | TLS with mutual auth |
| 3 | Network exposure | ✅ No host port — Docker internal network only | Keep internal, `internal: true` |
| 4 | Command ACLs | ❌ Single password, full access | ACL file with least-privilege role |
| 5 | Password in environment | ❌ Visible in `docker inspect` | Docker secrets or Vault |
| 6 | Password rotation | ❌ Manual restart required | Scripted rotation procedure |

**POC risk:** Acceptable — Redis is not exposed outside Docker networking, and the password is randomly generated. The main residual risk is no encryption on the Docker-internal channel, which matters if the host is multi-tenant.

**Production:** Issues 2, 4, 5, 6 must be addressed before deployment.

---

## Production Hardening

### 1. Move password to Docker secrets

```bash
# Generate password
openssl rand -base64 32 > secrets/redis_password.txt
chmod 600 secrets/redis_password.txt
```

```yaml
# docker-compose.prod.yml
services:
  redis:
    secrets:
      - redis_password
    command:
      - sh
      - -c
      - redis-server --requirepass "$$(cat /run/secrets/redis_password)" --maxmemory 256mb
  proxy:
    secrets:
      - redis_password
    environment:
      - REDIS_PASSWORD_FILE=/run/secrets/redis_password

secrets:
  redis_password:
    file: ./secrets/redis_password.txt
```

### 2. Enable TLS

Generate certificates:

```bash
CERT_DIR="./ssl/redis"
mkdir -p "$CERT_DIR"

# CA
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" -subj "/CN=Redis CA"

# Server cert
openssl genrsa -out "$CERT_DIR/redis.key" 4096
openssl req -new -key "$CERT_DIR/redis.key" -out "$CERT_DIR/redis.csr" -subj "/CN=redis"
openssl x509 -req -days 365 -in "$CERT_DIR/redis.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/redis.crt"

# Client cert (for proxy)
openssl genrsa -out "$CERT_DIR/client.key" 4096
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" -subj "/CN=proxy"
openssl x509 -req -days 365 -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/client.crt"

chmod 600 "$CERT_DIR"/*.key
```

Redis command:

```
--tls-port 6379 --port 0
--tls-cert-file /etc/redis/ssl/redis.crt
--tls-key-file  /etc/redis/ssl/redis.key
--tls-ca-cert-file /etc/redis/ssl/ca.crt
--tls-auth-clients yes
```

Update `config/proxy.yml`:

```yaml
redis:
  ssl: true
  ssl_cert_reqs: "required"
```

### 3. Redis ACL — restrict proxy to only what it needs

```
# /etc/redis/users.acl

# Proxy user — can read/write its own key namespaces, no dangerous commands
user ja4proxy on ><password> ~ja4:* ~rate:* ~banned:* ~blocked:* ~suspicious:* ~enforcement:* ~audit:* ~geoip:* ~repeat_block:* &* +@read +@write +@set +@sortedset +@string +@hash +@hyperloglog +expire +del +exists +ping -@dangerous

# Admin user — full access for ops tools (ja4-admin.sh)
user admin on ><admin-password> ~* &* +@all

# Default user disabled
user default off nopass nocommands
```

### 4. Password rotation

```bash
NEW_PW=$(openssl rand -base64 32)
OLD_PW=$(cat secrets/redis_password.txt)

# Apply to running Redis (no restart needed)
docker exec ja4proxy-redis redis-cli -a "$OLD_PW" CONFIG SET requirepass "$NEW_PW"

# Persist
echo "$NEW_PW" > secrets/redis_password.txt
chmod 600 secrets/redis_password.txt

# Restart proxy to pick up new password
docker compose -f docker-compose.prod.yml restart proxy
```

---

## Verifying network isolation

Redis should never be reachable from outside Docker:

```bash
# Should fail — no host port mapped
redis-cli -h localhost -p 6379 PING
# Expected: Connection refused

# Should succeed — via Docker exec
docker exec ja4proxy-redis redis-cli -a "${REDIS_PASSWORD}" ping
# Expected: PONG
```

---

## References

- [Redis Security](https://redis.io/docs/management/security/)
- [Redis TLS](https://redis.io/docs/management/security/encryption/)
- [Redis ACL](https://redis.io/docs/management/security/acl/)
