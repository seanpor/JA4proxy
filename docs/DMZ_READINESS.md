<!--
title: "DMZ Readiness Summary"
audience: architects
last_reviewed: 2026-04-25
phase: 105
-->

# DMZ Readiness Summary

JA4proxy is designed for placement in a corporate DMZ in front of HTTPS web
infrastructure. This document summarises the **current** posture against the
controls a security team will typically check during pre-production review.

> A more detailed pre-Phase-200 gap analysis is preserved at
> [`docs/reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md`](reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md)
> for audit traceability. The items below reflect Phase 200-series hardening
> and the Go-runtime production promotion.

---

## Controls in place

| Control | Status | Evidence |
|---|---|---|
| Production runtime is a static Go binary | In place | Phase 15 / ADR-015; `cmd/proxy/main.go`, `Dockerfile.go-proxy` |
| Non-root container user | In place | `USER proxy` in `Dockerfile.go-proxy` |
| Read-only container filesystem | In place | `read_only: true` in `docker-compose*.yml` |
| Dropped capabilities (`cap_drop: ALL`) | In place | Compose files; Helm chart `securityContext` |
| `no-new-privileges` | In place | Compose files |
| Container resource limits | In place | Compose + Helm charts |
| Image signing (Cosign) | In place | `.github/workflows/go-proxy-image.yml` |
| SBOM generation (Syft) | In place | `.github/workflows/go-proxy-image.yml` |
| TLS for east-west traffic (Redis TLS) | In place (Phase 200-series) | `config/proxy.yml` `redis.tls.enabled` |
| PROXY protocol v2 | In place (Phase 200-series) | `internal/proxyproto/` |
| Default-credential removal | In place (Phase 200-series) | Env-var-only secrets; CI guard |
| Network segmentation | In place | Frontend / backend / monitoring Docker networks |
| Centralised logging (ECS) | In place | [`docs/api/ecs_extension.md`](api/ecs_extension.md) |
| SIEM integration recipes | In place | [SIEM Integration](SIEM_INTEGRATION.md) |
| External Dynamic Lists (EDL) export | In place | [`docs/runbooks/tap_mode.md`](runbooks/tap_mode.md) §EDL; [`docs/decisions/ADR-021.md`](decisions/ADR-021.md) |
| GeoIP filtering | In place | Phase 6; MaxMind GeoLite2 |
| CSRF protection on Management UI | In place | Phase 13 |
| Webhook HMAC signing | In place | `internal/webhook/delivery.go` |
| Container CVE scanning in CI | In place | Trivy in `.github/workflows/ci.yml` |
| Dependency audit (Go + Python) | In place | `govulncheck`, `pip-audit` in CI |

---

## Forward-looking items

These are valid security-team asks that remain open as roadmap items rather
than gaps:

| Item | Status | Notes |
|---|---|---|
| External secret manager integration | Pluggable | Reads from environment; works with Vault, AWS Secrets Manager, Azure Key Vault when those inject env vars or files |
| Runtime container monitoring (Falco/Sysdig) | Operator-deployed | JA4proxy does not bundle a runtime EDR; install Falco as a DaemonSet alongside |
| Hardware security module (HSM) for HMAC keys | Operator-deployed | The webhook HMAC key can be sourced from a KMS-backed env var |

---

## Pre-deployment checklist

Use this as the gate before exposing JA4proxy on a DMZ host:

- [ ] Trivy scan passes on the deployed image (no `CRITICAL` or `HIGH` CVEs)
- [ ] Cosign signature verified at deploy time
- [ ] Secrets sourced from a secret manager (not from `.env` on disk)
- [ ] Only port 443 (or the configured listen port) is exposed to the
      internet
- [ ] Redis bound to the internal network only; AUTH and TLS enabled
- [ ] PROXY protocol v2 trusted upstream CIDR matches your load balancer
- [ ] `logging.format: ecs` set; SIEM ingestion verified end-to-end
- [ ] Dial value is `0` at first start (monitor mode); see
      [Evaluation Checklist](EVALUATION_CHECKLIST.md)
- [ ] Backup procedure tested against a non-production Redis
- [ ] [`docs/INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) walked through
      with the on-call team

---

## Architecture for DMZ placement

```
                    +---- DMZ -----------------------------+
                    |                                      |
  Internet --443--> | HAProxy (TLS passthrough + PROXYv2)  |
                    |    |                                 |
                    |    v                                 |
                    | JA4proxy (Go, read-only, no-root)    |
                    |    |          |                      |
                    |    v          v                      |
                    | Backend    Tarpit       Redis (TLS)  |
                    |                                      |
                    +--------------------------------------+
                              |
                              v   (monitoring network)
                    +---- Management ----------------------+
                    | Prometheus -> Grafana -> Alertmgr    |
                    | Promtail   -> Loki -> SIEM forwarder |
                    +--------------------------------------+
```

---

## Related reading

- [Scope and Limitations](SCOPE_AND_LIMITATIONS.md) — what JA4proxy does NOT
  cover
- [`docs/DEPLOYMENT_SECURITY_MODEL.md`](DEPLOYMENT_SECURITY_MODEL.md) —
  trust boundaries and OS user model
- [`docs/enterprise/security-architecture.md`](enterprise/security-architecture.md)
  — full target security architecture
- [`docs/reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md`](reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md)
  — historical pre-Phase-200 gap analysis
