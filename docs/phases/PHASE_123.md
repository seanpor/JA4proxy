# Phase 123: Security Hardening & Operational Excellence

> **Status:** IN_PROGRESS
> **Size:** LARGE
> **Depends on:** Phase 200-203 (Go Proxy Foundation)
> **Owner:** Gemini CLI (on behalf of Junior Engineer)

## Goal

Transform the JA4proxy from a functional tool into a **resilient, defense-in-depth** component. This phase implements a comprehensive set of security "recipes" across the Go codebase and the Linux operational environment to mitigate DoS, protocol spoofing, and privilege escalation risks.

## Scope

### Components in Scope
- **Go Production Proxy**: `internal/`, `cmd/proxy/`, `cmd/syncagent/`
- **Operational Environment**: systemd service units, iptables/nftables rules, filesystem layout.
- **CI/CD Pipeline**: GitHub Actions security scanners.
- **Redis Integration**: ACL and authentication configuration.

### Out of Scope
- Python prototype remediation (except where it influences shared Redis state).
- Management API hardening (covered by Phase 124).
- Cloud-specific IAM roles (focused on Linux host-level security).

---

## Implementation Plan

This phase is divided into two primary execution waves.

### Wave 1: Development & Code Hardening
Focuses on internal logic, memory safety, and dependency integrity.

| ID | Task | Description | Size |
|---|---|---|---|
| **123.1** | **Dependency Audit** | Run `govulncheck` and `gosec` on the entire Go tree; fix all findings. | S |
| **123.2** | **Memory Safety** | Implement secrets zeroing for sensitive variables (e.g., Redis passwords) in `internal/redis/`. | XS |
| **123.3** | **Integer Overflow** | Audit all `make([]byte, size)` calls in `internal/tls/` for overflow checks. | S |
| **123.4** | **PROXY Validation** | Implement regex-based whitelist validation for PROXY protocol headers in `internal/proxy/`. | S |
| **123.5** | **Timeout Enforcement** | Verify and set explicit `SetReadDeadline` and `SetWriteDeadline` on all network connections. | M |
| **123.6** | **Fuzz Testing** | Create a `go test -fuzz` harness for the `internal/tls/` ClientHello parser. | M |

### Wave 2: Operational & Runtime Hardening
Focuses on the Linux host environment and service isolation.

| ID | Task | Description | Size |
|---|---|---|---|
| **123.7** | **Least Privilege** | Create a dedicated `ja4proxy` system user and group. | XS |
| **123.8** | **systemd Sandboxing** | Update `ja4proxy.service` with `NoNewPrivileges=yes`, `PrivateTmp=yes`, and `ProtectSystem=strict`. | S |
| **123.9** | **Firewalling** | Implement host-level `iptables` rules to restrict metrics/proxy ports to trusted IPs. | S |
| **123.10** | **Redis ACLs** | Configure Redis 6+ ACLs for the proxy user, restricting commands to `+@read +set +del`. | M |
| **123.11** | **Permission Audit** | Apply `chmod 640` to config files and `750` to directories, owned by the proxy user. | XS |

---

## Test Strategy

### Security Regression Tests
- **Fuzzing**: `go test -fuzz=FuzzProxyParser -fuzztime=5m` must run without crashes.
- **Unauthorized Access**: Attempt to connect to `:9090` (metrics) from an untrusted IP; verify drop/reject.
- **Malformed Input**: Send invalid PROXY headers and verify they are rejected by the parser.

### Operational Verification
- **Privilege Check**: Verify `ps aux` shows the proxy running as `ja4proxy`.
- **Sandbox Check**: Verify `systemctl show ja4proxy | grep NoNewPrivileges=yes`.
- **Audit Logging**: Verify auth failures are visible in `journalctl -u ja4proxy`.

---

## Acceptance Criteria

- [ ] `govulncheck ./...` and `gosec ./...` exit 0 with no high-severity findings.
- [ ] No hardcoded passwords remain (verified by `git grep`).
- [ ] Proxy binary runs successfully under a non-root system user.
- [ ] `internal/tls/` parser resists malformed inputs in fuzz tests.
- [ ] Firewall rules are persisted and active after a reboot.
- [ ] Redis ACLs are enforced (wrong password or disallowed command fails).

---

## Reference Material

Detailed hardening "recipes" and threat models are documented in `docs/phases/archive/PHASE_123_review.md`.
