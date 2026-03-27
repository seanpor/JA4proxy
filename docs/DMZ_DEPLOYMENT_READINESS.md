<!--
title: Dmz_Deployment_Readiness
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# DMZ Deployment Readiness Assessment

**JA4proxy — TLS Fingerprinting Security Proxy**
**Assessment Date:** February 2026 (updated 2026-03-15 — Phase 14 gap analysis)

---

## Executive Summary

JA4proxy is a TLS fingerprinting proxy that blocks malicious traffic based on JA4 ClientHello fingerprints — without decrypting TLS. It currently operates as a hardened POC with container security, auto-generated secrets, and network segmentation.

This document assesses readiness for deployment in a corporate DMZ and identifies the gaps a security team will flag, along with remediation steps.

**Overall readiness: POC ✅ — Production DMZ: 4 items addressed in Phase 14; 2 deferred (Redis TLS, image signing)**

*Note: Several items listed as gaps at assessment time have since been implemented (Phases 0–13).
The Phase 14 plan in `docs/phases/PHASE_14.md` is the authoritative source of remaining work.*

---

## ✅ What's Already in Place

| Control | Status | Detail |
|---|---|---|
| Non-root containers | ✅ | `USER proxy` / `USER backend` in Dockerfiles |
| Read-only filesystems | ✅ | `read_only: true` on all containers, tmpfs for /tmp |
| Dropped capabilities | ✅ | `cap_drop: ALL`, minimal `cap_add` where needed |
| Privilege escalation prevention | ✅ | `no-new-privileges: true` on all containers |
| Resource limits | ✅ | CPU + memory limits on every container |
| Secret management | ✅ | Auto-generated with `openssl rand`, no hardcoded passwords |
| Network segmentation | ✅ | Separate frontend/backend/monitoring Docker networks |
| Localhost-only ports | ✅ | Internal services bound to `127.0.0.1` |
| Redis not exposed | ✅ | No host port — Docker network only |
| CI security scanning | ✅ | Bandit, Safety, Semgrep, Trivy in GitHub Actions |
| Container health checks | ✅ | HEALTHCHECK in Dockerfiles |
| Sensitive data filtering | ✅ | Log filter redacts passwords, tokens, card numbers, emails |
| CSRF protection | ✅ | Cryptographic tokens with `os.urandom()` |
| Input validation | ✅ | JA4 fingerprint format validation, sanitisation |
| Centralized logging | ✅ | Loki + Promtail aggregating all container logs |
| Alerting | ✅ | Prometheus alerting rules + Alertmanager |
| GeoIP filtering | ✅ | Country whitelist/blacklist at proxy level |

---

## 🔴 Gaps a Security Team Will Flag

### 1. No TLS on Internal Communications

**Risk:** Traffic between HAProxy → Proxy → Backend → Redis is unencrypted inside the Docker network.

**What they'll say:** "An attacker with network access to the Docker bridge can sniff internal traffic."

**Remediation:**
```yaml
# config/proxy.yml — enable mTLS to backend
proxy:
  ssl: true
  ssl_cert: /app/ssl/proxy.crt
  ssl_key: /app/ssl/proxy.key

# Redis — enable TLS
redis:
  command: ["--tls-port", "6379", "--tls-cert-file", "/tls/redis.crt", ...]
```

**Effort:** Medium. Generate internal CA, issue certs to each service, configure Redis TLS and proxy-to-backend mTLS.

**Workaround for POC:** Document that the Docker internal network is isolated and equivalent to a VLAN — acceptable for DMZ with host-level network controls.

---

### 2. No Container Image Signing or SBOM

**Risk:** No proof that the running images match what was built, and no Software Bill of Materials for vulnerability tracking.

**What they'll say:** "How do we verify image provenance? What dependencies are in these containers?"

**Remediation:**
```yaml
# Add to CI pipeline:
- name: Generate SBOM
  run: syft ja4proxy:latest -o spdx-json > sbom.json

- name: Sign image
  run: cosign sign --key cosign.key ghcr.io/org/ja4proxy:${{ github.sha }}
```

**Effort:** Low. Add Syft (SBOM) and Cosign (signing) steps to the existing CI pipeline.

---

### 3. No Runtime Security Monitoring (Falco/Sysdig)

**Risk:** No detection of anomalous container behaviour at runtime (unexpected processes, file access, network connections).

**What they'll say:** "What if the container itself is compromised?"

**Remediation:**
```yaml
# Add Falco sidecar or DaemonSet
falco:
  image: falcosecurity/falco:latest
  privileged: true  # required for kernel module
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - /proc:/host/proc:ro
```

**Effort:** Low-Medium. Falco is a drop-in with pre-built rulesets. Alert to existing Alertmanager.

---

### 4. Python Runtime in DMZ

**Risk:** Python is an interpreted language with a large standard library attack surface. Security teams prefer compiled, minimal binaries in DMZ.

**What they'll say:** "Why isn't this compiled? Can we get a distroless or scratch container?"

**Remediation options:**
1. **Distroless Python** — Switch FROM to `gcr.io/distroless/python3-debian12` (no shell, no package manager)
2. **Multi-stage build** — Build dependencies in a builder stage, copy only the app and `.so` files to a minimal runtime
3. **Long-term** — Rewrite the hot path in Go/Rust for a static binary with zero runtime dependencies

**Effort:** Low for distroless (Dockerfile change), High for rewrite.

**Workaround for POC:** The container already runs read-only, non-root, all-caps-dropped. The Python attack surface is mitigated by container isolation.

---

### 5. No External Secret Manager Integration

**Risk:** Secrets are in a `.env` file on disk. Enterprise environments use Vault, AWS Secrets Manager, or Azure Key Vault.

**What they'll say:** "Secrets at rest on the filesystem aren't acceptable."

**Remediation:**
```bash
# Example: HashiCorp Vault integration
REDIS_PASSWORD=$(vault kv get -field=password secret/ja4proxy/redis)
GRAFANA_PASSWORD=$(vault kv get -field=password secret/ja4proxy/grafana)
```

**Effort:** Low. The system already reads from environment variables — any secret manager that can inject env vars or files works without code changes.

---

### 6. No SIEM/SOC Integration

**Risk:** Security events stay in Prometheus/Loki. Enterprise SOCs expect events in Splunk, Sentinel, QRadar, or via syslog/CEF.

**What they'll say:** "We need this in our SIEM for correlation with other DMZ telemetry."

**Remediation options:**
1. **Syslog output** — Add a syslog handler to Python logging (CEF format)
2. **Loki → SIEM** — Configure Promtail to forward to syslog or use Grafana's Splunk/Elasticsearch output plugins
3. **Webhook alerts** — Alertmanager already supports webhook receivers for SIEM integration

**Effort:** Low-Medium. Syslog handler is ~20 lines of Python. Promtail syslog forwarding is a config change.

---

## 🟡 Items They May Raise (Already Mitigated)

| Concern | Our Answer |
|---|---|
| "Runs as root?" | No — `USER proxy` in Dockerfile, verified non-root |
| "Can containers write to disk?" | No — `read_only: true` with tmpfs for /tmp only |
| "Can containers escalate?" | No — `no-new-privileges`, `cap_drop: ALL` |
| "What if Redis is compromised?" | Redis has no host port, auth required, maxmemory set, volatile-lru eviction |
| "What about dependency vulns?" | Trivy scans in CI, Safety checks Python deps, Bandit scans for code issues |
| "What about DDoS?" | Rate limiting at proxy, resource limits on containers, HAProxy connection limits |
| "GDPR?" | IP addresses hashed in storage, configurable retention, documented in compliance docs |
| "Can it scale?" | HAProxy + horizontal proxy scaling, tested to ~840 conn/s with 4 instances |

---

## Deployment Checklist for Security Team Review

```
Pre-deployment:
□ Run Trivy scan on all images — verify no CRITICAL/HIGH CVEs
□ Review .env file permissions (should be 600)
□ Verify network segmentation matches DMZ zones
□ Confirm only port 443 is exposed to the internet
□ Review HAProxy config for appropriate timeouts and limits
□ Validate GeoIP country whitelist matches business requirements

Day-of:
□ Deploy with docker compose -f docker-compose.poc.yml up -d
□ Verify health: ./poc-status-check.sh
□ Start monitoring: ./start-monitoring.sh
□ Run smoke test: ./smoke-test.sh
□ Confirm Grafana dashboard shows traffic

Ongoing:
□ Monitor Prometheus alerts
□ Review Grafana security dashboard daily
□ Rotate secrets quarterly (regenerate .env, restart services)
□ Update container images monthly (rebuild with latest base)
□ Review blocked traffic patterns for new threat signatures
```

---

## Architecture for DMZ Placement

```
                    ┌─── DMZ ────────────────────────────┐
                    │                                     │
  Internet ──443──► │ HAProxy (TLS passthrough)           │
                    │    │                                │
                    │    ▼                                │
                    │ JA4proxy (fingerprint + filter)     │
                    │    │         │                      │
                    │    ▼         ▼                      │
                    │ Backend   Tarpit    Redis           │
                    │                    (no host port)   │
                    └─────────────────────────────────────┘
                              │
                              ▼ (monitoring network)
                    ┌─── Management ──────────────────────┐
                    │ Prometheus → Grafana → Alertmanager  │
                    │ Loki ← Promtail                      │
                    │         ↓                            │
                    │   SIEM / SOC (future)                │
                    └──────────────────────────────────────┘
```

Only port 443 is exposed to the internet. All management UIs are on a separate network, accessible only from the management VLAN.

---

## Priority Remediation Roadmap

| Priority | Item | Effort | Impact |
|---|---|---|---|
| **P1** | Distroless container base | Low | Eliminates shell/pkg manager attack surface |
| **P1** | Container image signing (Cosign) | Low | Proves image provenance |
| **P2** | SBOM generation (Syft) | Low | Enables vulnerability tracking |
| **P2** | SIEM integration (syslog/CEF) | Low-Med | SOC visibility |
| **P2** | Vault/secret manager integration | Low | Enterprise secret management |
| **P3** | Internal mTLS | Medium | Encrypted east-west traffic |
| **P3** | Runtime monitoring (Falco) | Low-Med | Container anomaly detection |
| **P4** | Compiled language rewrite | High | Maximum performance + minimal surface |

---

*This assessment is based on the current POC state (v3.2.0). The system is designed so that each remediation item can be addressed independently without architectural changes.*
