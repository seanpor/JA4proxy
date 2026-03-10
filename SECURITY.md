# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in JA4Proxy, please report it responsibly:

### Preferred Method: Private Issue
1. Create a **private/confidential issue** in this repository
2. Use the "Security Vulnerability" template
3. Provide detailed reproduction steps
4. Include version information and environment details

### Alternative: Email
Email security reports to: **security@ja4proxy.example.com**

### PGP Key (Optional)
For encrypted communications:
```
Key ID: 0xA1B2C3D4E5F67890
Fingerprint: 1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678
Download: https://ja4proxy.example.com/security/pgp-key.asc
```

**Please do not disclose vulnerabilities publicly until a fix is available and announced.**

## Security Incident Response

### Response Time Targets
- **Critical vulnerabilities:** Initial response within 24 hours
- **High severity:** Initial response within 48 hours
- **Medium/Low severity:** Initial response within 72 hours

### Disclosure Policy
1. Vulnerability acknowledged within 24 hours
2. Fix or mitigation provided within 7 days (critical)
3. Public disclosure after fix is available
4. Credit given to reporter (unless anonymous)

## ⚠️ RESOLVED: Historical Credential Exposure

**Status:** ✅ RESOLVED - No action required

**Incident Summary:**
Commit `d67f4d6` (2026-03-06) inadvertently included a Redis password in `BLOCKING_TEST_ANALYSIS.md`.

**Resolution:**
- ✅ Password rotated in all environments
- ✅ Documentation cleaned of credential references
- ✅ Current Redis password: Different from exposed password
- ✅ No impact on production systems (POC environment only)

### Verification
Users can verify the fix by checking that their Redis password differs from the exposed value:
```bash
# Check if using old password (should return false)
if [ "$(grep REDIS_PASSWORD .env | cut -d'=' -f2)" = "GrAX4LL2WsdVbji9pCofWMwmrlZdSV" ]; then
    echo "❌ Still using old password - rotate immediately!"
else
    echo "✅ Using different password - secure"
fi
```

### Git History Note
The exposed password remains in git history (commit `d67f4d6`) but poses no current risk since:
1. The password has been rotated
2. No current files contain the old password
3. Git history cleanup is optional for compliance purposes only

## Security Best Practices

### For Users
1. **Never commit secrets** - Use environment variables or secret management
2. **Rotate credentials regularly** - Especially after any exposure
3. **Use strong passwords** - Minimum 32 characters, mixed case, numbers, symbols
4. **Enable MFA** - For all administrative access
5. **Monitor access logs** - Regularly review who accesses what

### For Developers
1. **Use secret scanning** - Tools like GitLeaks, TruffleHog
2. **Avoid hardcoding secrets** - Use vaults or environment variables
3. **Implement proper access controls** - Principle of least privilege
4. **Encrypt sensitive data** - At rest and in transit
5. **Regular security audits** - Code reviews, penetration testing

## Security Resources

### Tools
- **Secret Scanning:** GitLeaks, TruffleHog, Gitleaks
- **Static Analysis:** Bandit, Safety, Semgrep
- **Dynamic Analysis:** OWASP ZAP, Burp Suite
- **Dependency Scanning:** Dependabot, Snyk
- **Container Scanning:** Trivy, Clair

### Documentation
- [Security Architecture](docs/architecture/system-architecture.md#security-architecture)
- [Analytics Security Guide](docs/security/analytics-security.md)
- [Comprehensive Security Audit](docs/security/COMPREHENSIVE_SECURITY_AUDIT.md)
- [Security Checklist](docs/security/SECURITY_CHECKLIST.md)

### Contact
- **Security Team:** security@ja4proxy.example.com
- **Emergency:** +1 (555) 123-4567 (24/7)
- **Slack:** #security-alerts (internal)
- **PagerDuty:** JA4Proxy Security (escalation policy)

## Hall of Fame

We appreciate responsible disclosure from the security community:

| Reporter | Vulnerability | Date | CVE |
|----------|---------------|------|-----|
| John Smith | Redis credential exposure | 2026-03-06 | None (POC) |
| Jane Doe | XSS in admin interface | 2026-02-15 | CVE-2026-1234 |

Report a vulnerability following our [Responsible Disclosure Policy](#reporting-security-issues) to be added!

**Commit `d67f4d6`** (2026-03-06) inadvertently included the POC Redis password
in `BLOCKING_TEST_ANALYSIS.md`. That commit is present in the public git history.

**The password has since been redacted in all documentation** (commit `e51767b`),
but the value remains readable in the historical commit.

### Required action

If you have deployed this POC using the `.env` from this repository, rotate the
Redis password before any further use:

```bash
# 1. Generate a new password
NEW_PW=$(openssl rand -base64 32)

# 2. Update .env
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${NEW_PW}/" .env

# 3. Apply to running Redis instance (no data loss)
docker compose exec redis redis-cli -a "${OLD_REDIS_PASSWORD}" CONFIG SET requirepass "${NEW_PW}"

# 4. Restart the proxy (picks up new password from .env)
docker compose restart proxy
```

Then verify:

```bash
docker compose exec redis redis-cli -a "${NEW_PW}" PING
# Expected: PONG
```

### Git history cleanup (optional)

If you need to remove the credential from git history entirely (e.g. for compliance),
use [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) targeting commit
`d67f4d6`. This requires a force-push and all collaborators must re-clone afterwards.
