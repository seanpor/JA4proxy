# Redis Security - Quick Reference

## 🔴 Current Issues (POC)

1. **Password:** Auto-generated via start-poc.sh (stored in .env)
2. **Encryption:** None (plaintext)
3. **Port:** No host port (Docker network only)
4. **Access Control:** None
5. **Authentication:** Single password

**Status:** ⚠️ **NOT PRODUCTION READY**

---

## ✅ Production Solution

### Quick Setup (5 minutes)

```bash
# 1. Run security setup script
./scripts/setup-redis-security.sh

# 2. Deploy production stack
docker compose -f docker-compose.prod.yml up -d

# 3. Verify
docker exec ja4proxy-redis redis-cli --tls \
  --cert /etc/redis/ssl/client.crt \
  --key /etc/redis/ssl/client.key \
  --cacert /etc/redis/ssl/ca.crt \
  -a "$(cat secrets/redis_password.txt)" \
  PING
```

---

## What Gets Created

### Passwords (secrets/)
- `redis_password.txt` - App user (32 random chars)
- `redis_admin_password.txt` - Admin user  
- `redis_monitor_password.txt` - Monitoring
- `redis_backup_password.txt` - Backup operations

### TLS Certificates (ssl/redis/)
- `ca.crt`, `ca.key` - Certificate Authority (10 years)
- `redis.crt`, `redis.key` - Server certificate (1 year)
- `client.crt`, `client.key` - Client certificate (1 year)

### Configuration
- `config/redis/redis.conf` - Production Redis config
- `config/redis/users.acl` - Access control lists

---

## Security Features

### ✅ TLS Encryption
- TLSv1.2 and TLSv1.3 only
- Strong cipher suites
- Certificate validation
- Mutual authentication (mTLS)

### ✅ Access Control
**4 User Roles:**
1. **admin** - Full access (emergency only)
2. **ja4proxy** - Restricted to `ja4:*`, `rate:*` keys
3. **monitor** - Read-only (Prometheus)
4. **backup** - Backup operations only

### ✅ Network Security
- No exposed ports (internal only)
- Network isolation
- Protected mode enabled

### ✅ Command Restrictions
**Disabled dangerous commands:**
- FLUSHDB, FLUSHALL
- KEYS (use SCAN instead)
- CONFIG, SHUTDOWN
- BGSAVE, SAVE
- DEBUG, MODULE

---

## Testing

### Test TLS Connection
```bash
# Should succeed
redis-cli -h redis -p 6379 --tls \
  --cert ssl/redis/client.crt \
  --key ssl/redis/client.key \
  --cacert ssl/redis/ca.crt \
  -a "$(cat secrets/redis_password.txt)" \
  PING

# Expected: PONG
```

### Test ACL Restrictions
```bash
# Should fail (disabled command)
redis-cli --tls -a "..." FLUSHALL
# Expected: Error

# Should succeed (allowed command)
redis-cli --tls -a "..." SET test value
# Expected: OK
```

### Test Network Isolation
```bash
# From host (should fail)
telnet localhost 6379
# Expected: Connection refused
```

---

## Migration Steps

1. **Generate Secrets** - `./scripts/setup-redis-security.sh`
2. **Backup Data** - `redis-cli SAVE && docker cp ...`
3. **Update Proxy Code** - Use TLS connection
4. **Deploy Production** - `docker compose -f docker-compose.prod.yml up`
5. **Verify** - Run tests
6. **Cutover** - Switch from POC to prod

**Time:** ~1 hour with testing

---

## Python Connection Example

```python
import redis
import ssl
import os

def connect_secure_redis():
    # Read password from Docker secret
    with open('/run/secrets/redis_password', 'r') as f:
        password = f.read().strip()
    
    # Configure TLS
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations('/etc/redis/ssl/ca.crt')
    ssl_context.load_cert_chain(
        certfile='/etc/redis/ssl/client.crt',
        keyfile='/etc/redis/ssl/client.key'
    )
    
    # Create connection
    return redis.Redis(
        host='redis',
        port=6379,
        db=0,
        password=password,
        ssl=True,
        ssl_context=ssl_context,
        socket_timeout=5,
        max_connections=50,
        health_check_interval=30
    )
```

---

## Compliance

✅ **PCI DSS** - Encryption in transit (Requirement 4.1)  
✅ **SOC 2** - Access controls (CC6.1)  
✅ **HIPAA** - Data security (§164.312(e)(1))  
✅ **GDPR** - Security measures (Article 32)  
✅ **ISO 27001** - A.10.1.1, A.13.1.3

---

## Troubleshooting

**Problem:** Connection refused  
**Solution:** Check TLS configuration, verify certificates

**Problem:** Authentication failed  
**Solution:** Verify password file path, check ACL

**Problem:** Permission denied  
**Solution:** Check user has access to key pattern

**Problem:** Certificate error  
**Solution:** Regenerate certificates, check CA validity

---

## Maintenance

### Certificate Renewal (Annually)
```bash
# Backup old certificates
cp -r ssl/redis ssl/redis.backup.$(date +%Y%m%d)

# Regenerate
./scripts/setup-redis-security.sh

# Rolling restart
docker compose restart redis
docker compose restart proxy
```

### Password Rotation (Quarterly)
```bash
# Generate new password
NEW_PASS=$(openssl rand -base64 32)

# Update Redis
docker exec ja4proxy-redis redis-cli -a "$OLD_PASS" \
  ACL SETUSER ja4proxy >$NEW_PASS

# Update secret
echo "$NEW_PASS" > secrets/redis_password.txt

# Restart proxy
docker compose restart proxy
```

---

## Cost & Timeline

**Setup:** 3-4 days  
**Testing:** 1-2 days  
**Deployment:** 1 day  
**Total:** ~1 week

**Effort:**
- Certificate generation: 2 hours
- Configuration: 4 hours
- Code updates: 6 hours
- Testing: 8 hours
- Documentation: 4 hours

---

## Files Reference

**Documentation:**
- `docs/REDIS_SECURITY_REVIEW.md` - Complete security review (50 pages)
- `docs/REDIS_SECURITY_QUICK.md` - This quick reference

**Configuration:**
- `config/redis/redis.conf` - Production Redis configuration
- `config/redis/users.acl` - Access control lists

**Scripts:**
- `scripts/setup-redis-security.sh` - Automated setup
- `scripts/rotate-redis-password.sh` - Password rotation
- `scripts/test-redis-tls.sh` - Connection testing

---

## Support

**Questions:** Review `docs/REDIS_SECURITY_REVIEW.md`  
**Issues:** Check troubleshooting section  
**Implementation:** Follow migration steps  

**Status:** ✅ Ready for production implementation
