---
phase: 510b
title: "Bug Hunt Guide — Infrastructure, Scripts & Supply Chain"
parent: 500
created: 2026-06-22
audience: [developer, security, operations]
---

# Bug Hunt Guide — Infrastructure, Scripts & Supply Chain

This guide covers sub-phases **510d–510f**: misconfiguration, cryptographic integrity,
and supply chain security in Docker, Ansible, scripts, and configuration.

## Before you start

```bash
# Validate compose files
docker compose -f deploy/docker/docker-compose.prod.yml config
docker compose -f deploy/docker/docker-compose.poc.yml config
# Run isolation checks
scripts/check-isolation.sh
```

---

## 510d — Misconfiguration & Fail-Open

**CWE-1188: Insecure Default / CWE-250: Excessive Privileges**

### What to look for

Dangerous defaults that ship out-of-the-box: default passwords, ports bound to
`0.0.0.0`, missing TLS, containers running as root, Redis without ACLs, test-mode
enabled in production.

### Files to read

| File | What to check |
|------|--------------|
| `deploy/docker/docker-compose.prod.yml` | Port bindings — are internal services on `127.0.0.1`? |
| `deploy/docker/docker-compose.poc.yml` | Same port checks, plus network isolation |
| `config/redis/redis.conf` | Is `requirepass` set? Are dangerous commands renamed/disabled? |
| `config/redis/users.acl` | Are placeholder passwords replaced? Are ACLs scoped? |
| `config/proxy.yml` | Is `pubsub_hmac_secret` empty by default? Is `test_mode` off? |
| `management/api/main.py` | CORS configuration — is wildcard `*` allowed in production? |
| `template.env` | Are all required secrets present? Are defaults safe? |

### Grep commands

```bash
# Find all port bindings in compose files — check for 0.0.0.0 exposure
rg 'ports:' deploy/docker/ -A 2

# Find all default credentials in compose — should not exist
rg ':-admin|:-password|:-changeme|:-secret' deploy/docker/ config/

# Find all privileged containers — should not exist
rg 'privileged.*true' deploy/docker/ deploy/ansible/

# Find all cap_add — should be minimal
rg 'cap_add' deploy/docker/ -A 1

# Find all read_only settings — should be true on all services
rg 'read_only' deploy/docker/

# Find all no-new-privileges — should be true
rg 'no-new-privileges' deploy/docker/
```

### Checklist

- [ ] No default passwords in compose files (`admin`, `password`, `changeme`)
- [ ] Internal services (Redis, analytics, tarpit) not exposed on host ports
- [ ] All containers run as non-root (`user: "1000:1000"`)
- [ ] All containers have `cap_drop: ALL` with minimal `cap_add`
- [ ] All containers have `no-new-privileges: true`
- [ ] All containers have `read_only: true` (except Redis data volume)
- [ ] Redis has `requirepass` and ACL file configured
- [ ] `template.env` has no real secrets (only placeholders with generation guidance)
- [ ] CORS is not `*` in production
- [ ] `MANAGEMENT_TEST_MODE` is not set in production compose
- [ ] `scripts/check-isolation.sh` passes all checks

### Example bug (from prior findings)

```
JA4PROXY-2026-0015 (HIGH): Grafana defaulted to admin/admin credentials.
Fix: Grafana refuses to start without GRAFANA_PASSWORD env var.
```

### Regression test pattern

```python
def test_no_default_credentials_in_compose():
    """Verify no compose file contains default credentials."""
    compose_files = glob.glob("deploy/docker/docker-compose*.yml")
    for path in compose_files:
        content = open(path).read()
        assert ":-admin" not in content, f"{path} contains :-admin default"
        assert ":-password" not in content, f"{path} contains :-password default"
        assert ":-changeme" not in content, f"{path} contains :-changeme default"
```

---

## 510e — Cryptographic Integrity (Python/Infra)

**CWE-327: Broken Crypto / CWE-330: Use of Insufficiently Random Values**

### What to look for

Weak or missing cryptographic verification: CSRF tokens that are predictable,
HMAC secrets that are empty, config signatures that can be bypassed, Ansible vaults
with plaintext secrets.

### Files to read

| File | What to check |
|------|--------------|
| `management/api/middleware/csrf.py` | HMAC key source — is it the JWT signing key? Token entropy? Replay window? |
| `management/api/pubsub_signing.py` | Which channels are signed? What happens when secret is empty? |
| `scripts/config-signer.py` | Key file permissions (0600)? TOCTOU on key creation? |
| `internal/backup/crypto.go` | PBKDF2 iterations, empty passphrase rejection, GCM tag verification |
| `deploy/ansible/vault.yml.example` | Are there any real secrets (not placeholders)? |
| `deploy/docker/docker-entrypoint.sh` | Are secrets injected safely (not in process arguments)? |

### Grep commands

```bash
# Find all HMAC operations in Python — verify hmac.compare_digest
rg 'hmac\.' management/api/ scripts/ -n

# Find all random/secret generation — verify crypto-safe
rg 'random\.|os\.urandom|secrets\.' management/api/ scripts/ -n

# Find all Ansible vault references — verify they are encrypted
rg 'vault' deploy/ansible/ -n

# Find all hardcoded secrets in scripts
rg 'password|secret|token' scripts/ -n | grep -v 'test\|example\|placeholder\|PLACEHOLDER\|README'
```

### Checklist

- [ ] CSRF token uses HMAC-SHA256 with same key as JWT signing
- [ ] CSRF token has ≤1h validity window
- [ ] PubSub HMAC covers all critical channels (config:reload, blacklist, dial)
- [ ] When `pubsub_hmac_secret` is empty, critical PubSub commands are rejected or warned
- [ ] Config signer creates key files with 0600 permissions
- [ ] Ansible vault files contain only `!vault` references (not plaintext)
- [ ] Docker entrypoint injects secrets via env vars (not command arguments)

---

## 510f — Supply Chain & Script Security

**CWE-200: Information Exposure / CWE-918: SSRF**

### What to look for

Shell scripts that can be injected, Docker build stages that leak secrets, CI/CD
workflows with excessive permissions, dependency confusion risks.

### Files to read

| File | What to check |
|------|--------------|
| `scripts/docker-entrypoint.sh` | Secret injection, `exec "$@"` safety, shell injection |
| `scripts/gdpr_delete.py` | Redis key injection via IP input, mass-delete safety |
| `scripts/config-signer.py` | Key file handling, TOCTOU on `O_CREAT\|O_EXCL` |
| `deploy/ansible/playbooks/apply-policy.yml` | Variable interpolation in `ansible.builtin.command` |
| `deploy/docker/Dockerfile.*` | Multi-stage isolation, secret leaking in build cache |
| `.github/workflows/*.yml` | Action SHA pinning, GITHUB_TOKEN scope, secret handling |
| `requirements*.txt` / `go.mod` | Dependency freshness, known CVEs |

### Grep commands

```bash
# Find all shell scripts — check for shell injection vectors
rg 'eval|exec|`\$|"\$' scripts/ deploy/ -n

# Find all Dockerfiles — check for secret leaks in build stages
rg 'COPY.*secret|COPY.*\.env|COPY.*key' deploy/docker/Dockerfile* -n

# Find all GitHub Actions — verify SHA pinning (not @v4, @v5, etc.)
rg 'uses:' .github/workflows/ -n | grep -v '@[a-f0-9]\{40\}'

# Find all pip install in CI — verify no --no-deps bypass
rg 'pip install' .github/ scripts/ -n

# Find all temp file usage — verify no symlink/race conditions
rg 'mktemp|NamedTemporaryFile|tempfile' scripts/ -n
```

### Checklist

- [ ] `docker-entrypoint.sh` uses `exec "$@"` (not `eval "$@"`)
- [ ] `docker-entrypoint.sh` does not print secrets to stdout
- [ ] `gdpr_delete.py` validates IP with `ipaddress.ip_address()` before Redis key use
- [ ] `config-signer.py` uses `os.open(path, O_CREAT|O_EXCL, 0o600)` (no TOCTOU)
- [ ] Ansible playbooks use `ansible.builtin.command` (not `shell`) where possible
- [ ] Dockerfiles do not `COPY` secrets, `.env` files, or private keys
- [ ] All GitHub Actions are SHA-pinned (no `@v4`, `@v5`)
- [ ] `GITHUB_TOKEN` has minimal permissions (`permissions: read-all` at top level)
- [ ] No `pip install` with `--no-deps` in CI
- [ ] Temp files use `os.O_CREAT | os.O_EXCL` to prevent race conditions

### Example bug (from prior findings)

```
JA4PROXY-2026-0018 (HIGH): Docker entrypoint script printed secrets to stdout
during initialization. Fix: secrets are injected via env vars, never printed.
```

---

## How to register a finding

Same format as the Go guide — add to `docs/security/findings.yaml`:

```yaml
- id: JA4PROXY-2026-510d-1
  severity: MEDIUM
  cwe: CWE-1188
  file: deploy/docker/docker-compose.prod.yml:45
  description: "Service X is bound to 0.0.0.0 instead of 127.0.0.1"
  impact: "Unnecessary attack surface on public interfaces"
  regression_test: tests/unit/test_container_config.py:TestXxx
  remediation: "Bind service to ${AGENT_BIND_IP:-127.0.0.1}"
  status: OPEN
  phase: 510d
```
