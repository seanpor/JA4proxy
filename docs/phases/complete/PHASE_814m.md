# Pentest: Container, Host, Orchestration, and Assume-Breach

> Sub-phase 814m of the Phase 814 penetration testing programme (`PHASE_814.md` §5).
> Preceded by Phase 814l (Cryptography and Secrets).

## 1. Goal

Execute an adversarial penetration test of JA4proxy's container definitions, host boundaries, orchestration configurations, and post-exploitation blast radius:
1. **CIS Docker Benchmark Audit**: Review all Dockerfiles and compose files (`docker-compose.prod.yml`, `monitoring.yml`, `scale.yml`, `poc.yml`, `test.yml`, `redis-tls.yml`, `pentest.yml`) against CIS Docker Benchmark requirements (least privilege, non-root execution, `cap_drop: ALL`, `no-new-privileges: true`, read-only root filesystems, resource limits, and health checks).
2. **TAP Sensor Capability & Seccomp Hardening**: Audit the privileged `ja4-tap` sensor container and host binary. Verify whether seccomp BPF syscall filtering is actually loaded and enforced in production or if it silently fails open. Verify capability drops (`CAP_NET_RAW`, `CAP_DAC_OVERRIDE`) and verify `PR_SET_NO_NEW_PRIVS` invocation prior to filter installation.
3. **Host Port Exposure & Boundary Lockdown**: Verify network isolation and host port publishing across all compose files. Ensure internal proxy worker endpoints, HAProxy stats pages, and monitoring listeners do not publish on `0.0.0.0` or allow external ingress bypasses.
4. **Assume-Breach & Post-Exploitation Blast Radius (PTES)**: Model an attacker achieving remote code execution inside each container in turn (proxy, TAP sensor, analytics, management, monitoring sidecars). Evaluate lateral traversal paths to Redis, credential access from environment/mounts, and host escape risks.
5. **Kubernetes / Helm Benchmark**: Audit `deploy/charts/ja4proxy/` against CIS Kubernetes Benchmark standards (Pod Security Standards restricted profile, read-only rootfs, `seccompProfile: RuntimeDefault`, `capabilities.drop: [ALL]`, `NetworkPolicy` default-deny).

---

## 2. Scope

### In Scope
- `deploy/docker/docker-compose.prod.yml`, `docker-compose.monitoring.yml`, `docker-compose.scale.yml`, `docker-compose.poc.yml`, `docker-compose.test.yml`, `docker-compose.redis-tls.yml`
- `deploy/docker/Dockerfile.*`
- `cmd/ja4-tap/main.go`, `internal/tap/hardening.go`, `internal/tap/seccomp_linux.go`
- `deploy/charts/ja4proxy/values.yaml` and Helm templates
- Assume-breach isolation and network segmentation tests
- Two-state regression testing and automated verification

### Out of Scope
- IaC / Terraform / Ansible deployment scripting (reserved for Phase 814n)
- Downstream SIEM / SOAR syslog and webhook egress injection (reserved for Phase 814n)
- Purple team TTP mapping and detection validation (reserved for Phase 814o)

---

## 3. Discovered Findings & Threat Vectors

### JA4PROXY-2026-0127 (HIGH, CVSS 7.1)
- **Title**: TAP sensor fails open without seccomp filtering due to missing `PR_SET_NO_NEW_PRIVS` and default non-enforcement
- **CWE**: CWE-693 (Protection Mechanism Failure), CWE-1188 (Insecure Default Initialization)
- **Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`
- **Mechanism**: In `internal/tap/hardening.go`, `DropCapabilities()` transitions the process UID to unprivileged `nobody` (65534) and clears `PR_SET_KEEPCAPS` before `LoadSeccomp()` executes. Under Linux, calling `seccomp(SECCOMP_SET_MODE_FILTER, ...)` without `CAP_SYS_ADMIN` strictly requires `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Because `PR_SET_NO_NEW_PRIVS` was never set, `SYS_SECCOMP` returns `EACCES`. In `cmd/ja4-tap/main.go:295-305`, `LoadSeccomp()` error handling logs a warning and proceeds unconfined (`--seccomp-required` defaults to false). The sensor runs with completely unconfined syscall access. In `docker-compose.prod.yml`, `ja4-tap` omits `--seccomp-required`.
- **Remediation**:
  1. In `internal/tap/seccomp_linux.go`, set `unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` immediately prior to calling `SYS_SECCOMP`.
  2. In `cmd/ja4-tap/main.go`, default to failing closed on supported Linux platforms unless explicitly bypassed via a `--seccomp-fallback-allowed` flag.
  3. In `deploy/docker/docker-compose.prod.yml`, specify `--seccomp-required` in the `ja4-tap` entrypoint.

### JA4PROXY-2026-0128 (HIGH, CVSS 7.5)
- **Title**: Unrestricted 0.0.0.0 host port bindings in multi-process scale compose bypass HAProxy ingress and expose internal worker and stats ports
- **CWE**: CWE-668 (Exposure of Resource to Wrong Sphere), CWE-284 (Improper Access Control)
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Mechanism**: In `deploy/docker/docker-compose.scale.yml`, HAProxy stats port (`8404:8404`) and backend worker direct ports (`8080:8080`, `8083:8083`, `8084:8084`, `8085:8085`) are published directly on all host network interfaces (`0.0.0.0`). External network attackers can bypass the HAProxy load balancer and TLS termination layer by communicating directly with backend workers, or inspect internal routing metrics via the unauthenticated stats port.
- **Remediation**:
  1. Restrict HAProxy stats port to loopback only (`${AGENT_BIND_IP:-127.0.0.1}:8404:8404`).
  2. Remove public host port publishing for `proxy-worker-1..4` or bind exclusively to loopback `${AGENT_BIND_IP:-127.0.0.1}`, as inter-container routing from HAProxy uses Docker internal DNS over `ja4proxy-network`.

### JA4PROXY-2026-0129 (MEDIUM, CVSS 5.3)
- **Title**: Read-only root filesystem and capability drop omissions in production and monitoring compose files (CIS Docker Benchmark 5.12 & 5.27)
- **CWE**: CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment)
- **Vector**: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`
- **Mechanism**: In `deploy/docker/docker-compose.prod.yml`, the `alloy` monitoring container and `grafana` service omit `read_only: true` and appropriate `tmpfs` mounts, violating CIS Docker Benchmark 5.12. In the event of application compromise, an attacker can modify rootfs binaries, write persistent backdoors, or stage local toolchains.
- **Remediation**:
  1. Configure `read_only: true` on `alloy` and `grafana` services in `deploy/docker/docker-compose.prod.yml` and `docker-compose.monitoring.yml`.
  2. Provide necessary `tmpfs` mounts (`/tmp`, `/var/run`, etc.) to support temporary file generation.

---

## 4. Implementation Plan

1. **TAP Sensor Seccomp & Privileges (`internal/tap/`, `cmd/ja4-tap/`)**:
   - In `internal/tap/seccomp_linux.go`: Add `unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` before `syscall.RawSyscall(317, ...)` so unprivileged users can load seccomp BPF filters.
   - In `cmd/ja4-tap/main.go`: Make `--seccomp-required` the default when running on Linux amd64, requiring an explicit flag to disable.
   - Update `deploy/docker/docker-compose.prod.yml` `ja4-tap` service definition.
2. **Compose Host Port Lockdown (`deploy/docker/docker-compose.scale.yml`)**:
   - Bind HAProxy stats port to `${AGENT_BIND_IP:-127.0.0.1}:8404:8404`.
   - Update worker ports in `docker-compose.scale.yml` to loopback `${AGENT_BIND_IP:-127.0.0.1}` or remove unnecessary host bindings.
3. **CIS Benchmark Compose Hardening (`deploy/docker/`)**:
   - Enforce `read_only: true` and `tmpfs` mounts for `alloy` and `grafana`.
4. **Assume-Breach Test Suite**:
   - Add unit/integration tests verifying compose configuration parity, seccomp execution, and network isolation invariants.

---

## 5. Test Strategy & Revert Proofs

- **Regression Tests**:
  - `internal/tap/pentest_seccomp_no_new_privs_regression_test.go`: Assert that `LoadSeccomp()` succeeds after `DropCapabilities()` has switched process to unprivileged UID.
  - `tests/unit/test_pentest_compose_port_exposure_regression.py`: Assert that all compose files restrict non-ingress ports to `127.0.0.1` / loopback and do not expose worker ports on `0.0.0.0`.
  - `tests/unit/test_pentest_container_read_only_rootfs_regression.py`: Assert that production compose services enforce `read_only: true`.
- **Two-State Revert Verification**:
  - Execute `scripts/verify_revert.sh` for each finding to prove test sensitivity.

---

## 6. Acceptance Criteria

- [ ] Findings `JA4PROXY-2026-0127`, `JA4PROXY-2026-0128`, and `JA4PROXY-2026-0129` registered with linked GitHub issues.
- [ ] TAP sensor invokes `PR_SET_NO_NEW_PRIVS` and successfully loads seccomp filters as non-root.
- [ ] `docker-compose.scale.yml` restricts stats and worker ports to loopback.
- [ ] Compose monitoring services enforce `read_only: true` with tmpfs.
- [ ] Two-state regression tests pass and fail on revert.
- [ ] Expert reviews (Security, Concurrency, Code Quality) all APPROVE.
- [ ] Preflight and CI gates green.
