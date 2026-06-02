# Phase 124: Production Security Remediation (Attack Surface Audit)

> **Status:** IN_PROGRESS
> **Size:** XLARGE
> **Depends on:** Phase 123 (Base Hardening)
> **Owner:** Gemini CLI (on behalf of Junior Engineer)

## Goal

Remediate 14+ prioritized security findings identified during the internet-facing attack surface audit. This phase focuses on the Go production proxy's handling of fragmented TLS handshakes, JA4 specification compliance, and hardening the trust relationship between the proxy and its management/control plane.

## Scope

### Components in Scope
- **Go Production Proxy**: `internal/tls/`, `internal/security/`, `cmd/proxy/`.
- **Sync Agent**: `cmd/syncagent/` (mesh integrity).
- **Control Plane Integration**: Signed dial validation and Redis ACL enforcement.

### Out of Scope
- Python Management API (retained but out of Go remediation scope).
- Infrastructure deployment (RHEL/Quadlets) - covered by Phase 76.
- Compliance CSV generation (retained in Python).

---

## Implementation Plan

Remediation is sequenced by risk priority. Each task **must** include a red-to-green regression test.

### Wave 1: Critical Control Bypasses (Priority 1)

| ID | Task | Description | Size |
|---|---|---|---|
| **124.1** | **Handshake Reassembly** | Fix ClientHello fragmentation across multiple TLS records (F1). Reassemble based on uint24 length. | M |
| **124.2** | **JA4 Spec Compliance** | Align JA4 computation with FoxIO spec (F2): exclude ALPN, include sigalgs in hash, cap counts at 99. | S |
| **124.3** | **Effective TLS Version** | Read TLS version from `supported_versions` instead of `legacy_version` (F7). | S |
| **124.4** | **Sync Mesh Integrity** | Remove `config:dial` from sync mesh; fail closed if `IntegrityKeyFile` is missing (PE-6). | S |
| **124.5** | **Signed Dial** | Implement HMAC signing for the `config:dial` value in Redis to prevent unauthorized overrides (M1). | M |

### Wave 2: High-Leverage Hardening (Priority 2)

| ID | Task | Description | Size |
|---|---|---|---|
| **124.6** | **SNI Canonicalization** | Centralize `CanonicalizeSNI()` with allowlist regex; grade suspect/malicious strings (F3). | M |
| **124.7** | **Config Race Fix** | Snapshot `cfg := p.cfg` in `handleConn` to avoid data races during reload (F6). | XS |
| **124.8** | **Absolute Exec Paths** | Update NTP monitoring to use absolute paths for `chronyc`/`ntpstat` (PE-1). | XS |
| **124.9** | **Dial Clamping** | Ensure `GetDial` clamps Redis values to `0-100` on read (M2). | XS |
| **124.10** | **DNS Isolation** | Route FCrDNS enrichment through dedicated non-recursive resolvers (C-DNS). | S |

### Wave 3: Defense-in-Depth (Priority 3)

| ID | Task | Description | Size |
|---|---|---|---|
| **124.11** | **Webhook SSRF** | Implement host filtering and redirect blocking for the webhook dispatcher (PE-2). | S |
| **124.12** | **Tarpit Defaults** | Audit and update tarpit `OverflowAction` to default to `block` instead of `allow` (F8). | XS |
| **124.13** | **Parser Bounds** | Reject TLS records with `recordLen > 16384` per RFC 8446 (F5). | XS |
| **124.14** | **Prod Safety Gates** | Refuse startup if `ALLOW_UNAUTH_REDIS` is set in `ENVIRONMENT=production` (PE-3). | XS |

---

## Test Strategy

### Red-to-Green Methodology
Every fix must be accompanied by a `pentest_<topic>_regression_test.go` that:
1.  **Fails** against the unpatched code (proving the vulnerability exists).
2.  **Passes** against the patched code.

### Tools to Run
```bash
go test -race -count=1 ./...
govulncheck ./...
gosec ./...
```

---

## Acceptance Criteria

- [ ] All Wave 1 "Priority 1" findings (F1, F2, F7, PE-6, M1) are remediated and verified.
- [ ] SNI canonicalization is implemented and used by all Go proxy consumers.
- [ ] No data races detected by `go test -race` during config reloads.
- [ ] Webhook dispatcher correctly rejects loopback/private IP targets.
- [ ] JA4 fingerprints generated match the FoxIO reference vectors.
- [ ] Definition of Done (Section 8 of the review) met for every finding.

---

## Reference Material

Detailed findings, threat models, and specific "fix directions" are documented in `docs/phases/archive/PHASE_124_review.md`.
