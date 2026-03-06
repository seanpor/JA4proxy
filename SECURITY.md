# Security Policy

## Reporting a Vulnerability

Open a private issue or email the maintainer directly. Do not disclose vulnerabilities publicly until a fix is available.

## Known Credential Exposure — Action Required

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
