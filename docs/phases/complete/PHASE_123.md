# Phase 123: Foundation & Operational Security

> **Status:** IN_PROGRESS
> **Size:** 3x SMALL SUB-PHASES
> **Depends on:** Phase 200-203
> **Owner:** Gemini CLI

## Goal
Establish a resilient baseline. Broken down into three small, focused execution units with step-by-step instructions.

---

### Phase 123a: Build & Dependency Hygiene (SMALL)

#### Tasks
| ID | Task | Size |
|---|---|---|
| 123.a1 | **Vulnerability Scan**: Run `govulncheck ./...` and fix all findings. | S |
| 123.a2 | **Static Analysis**: Run `gosec ./...` and remediate findings. | S |
| 123.a3 | **Toolchain Pinning**: Update Docker/CI to Go 1.25.6 with SHA256 digests. | XS |

#### Execution Guide (123a)
1. **Scans**:
   - Install tools: `go install golang.org/x/vuln/cmd/govulncheck@latest` and `go install github.com/securego/gosec/v2/cmd/gosec@latest`.
   - Run scans from project root and save results: `govulncheck ./... > vuln_report.txt` and `gosec -fmt=json -out=sec_report.json ./...`.
   - Remediate by updating `go.mod` (use `go get -u <pkg>`) or fixing insecure code patterns.
2. **Docker**:
   - Edit `deploy/docker/Dockerfile.go-proxy`.
   - Change `FROM golang:1.25` to `FROM golang:1.25.6-alpine3.20@sha256:7ae13620...` (verify latest SHA on Docker Hub).

---

### Phase 123b: Redis & Network Basics (SMALL)

#### Tasks
| ID | Task | Size |
|---|---|---|
| 123.b1 | **Redis ACLs**: Configure user-restricted commands. | S |
| 123.b2 | **Prod Safety Gate**: Implement `ALLOW_UNAUTH_REDIS` check. | XS |
| 123.b3 | **Timeout Audit**: Set explicit `SetReadDeadline` on listeners. | S |
| 123.b4 | **Firewall Rules**: Script `iptables` for core ports. | S |

#### Execution Guide (123b)
1. **Redis**:
   - Update `deploy/ansible/roles/redis-secure/templates/users.acl.j2`.
   - Ensure the proxy user is restricted: `user proxy-user on >password ~* +@read +set +del -@all`.
2. **Safety Gate**:
   - Edit `cmd/proxy/main.go`.
   - Add a check: `if os.Getenv("ENVIRONMENT") == "production" && os.Getenv("ALLOW_UNAUTH_REDIS") == "true" { log.Fatal("Insecure Redis config blocked in production") }`.
3. **Timeouts**:
   - Search for `net.Listen` and `Accept()` calls in `internal/proxy/`.
   - Ensure `conn.SetReadDeadline(time.Now().Add(30 * time.Second))` is called immediately after accepting a connection.

---

### Phase 123c: Host Hardening (SMALL)

#### Tasks
| ID | Task | Size |
|---|---|---|
| 123.c1 | **Service Identity**: Script creation of `ja4proxy` user/group. | XS |
| 123.c2 | **systemd Sandbox**: Apply sandboxing to service unit. | S |
| 123.c3 | **Filesystem Audit**: Implement `chmod 640/750`. | XS |

#### Execution Guide (123c)
1. **systemd**:
   - Edit `deploy/ansible/roles/ja4proxy/templates/ja4proxy.service.j2`.
   - Add the following to the `[Service]` section:
     ```ini
     NoNewPrivileges=yes
     PrivateTmp=yes
     ProtectSystem=strict
     ProtectHome=yes
     ReadOnlyPaths=/
     ReadWritePaths=/var/log/ja4proxy
     ```
2. **Permissions**:
   - Update `deploy/ansible/roles/ja4proxy/tasks/main.yml` to ensure config files are installed with `mode: 0640` and directories with `mode: 0750`.
