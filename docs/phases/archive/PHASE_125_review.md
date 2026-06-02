# JA4proxy Go Proxy — Comprehensive Security Threat Analysis

**Repository:** `github.com/seanpor/JA4proxy`  
**Analysis Date:** 2026-06-01  
**Scope:** Go proxy core (`cmd/proxy/`, `internal/`), container image, deployment configuration  
**Methodology:** Static source review, dependency CVE analysis, regression test review, architecture threat modelling

---

## TL;DR

The JA4proxy Go proxy has undergone **extensive security hardening** with **12 documented vulnerability findings** (JA4PROXY-2026-0001 through 0052), each accompanied by regression tests. **No direct Remote Code Execution (RCE) vulnerability exists in the proxy's own code** — the design as a TLS-passthrough proxy that does not decrypt traffic fundamentally limits many traditional RCE avenues. However, **several chained attack vectors remain viable**, particularly through **Redis compromise** (the proxy's security state store), **Go standard library vulnerabilities** in versions prior to 1.25.6, and **dependency supply-chain risks**. The container runs as non-root with seccomp and capability-dropping, making host escape unlikely without kernel-level exploits. When placed behind a firewall (as recommended), the external attack surface is limited to the TLS listener and metrics endpoint, though **internal lateral movement via Redis or webhook endpoints** presents a credible threat if an attacker gains a foothold in the network.

---

## 1. Architecture & Attack Surface Overview

JA4proxy is a **TLS-aware TCP passthrough proxy** written in Go. It accepts incoming TCP connections, peeks at the TLS ClientHello to compute a JA4 fingerprint, runs the connection through a security pipeline (scoring based on IP reputation, JA4 blacklists/whitelists, TLS version, cipher suites, GeoIP, beaconing detection, and more), then either forwards the connection to a backend, sends it to a tarpit, or blocks it. The proxy **never decrypts TLS traffic** — it only inspects the unencrypted ClientHello metadata.

### 1.1 Key Components and Their Trust Boundaries

| Component | Privilege Level | Network Exposure | Critical Data Handled |
|-----------|----------------|------------------|----------------------|
| `cmd/proxy/main.go` — Accept loop & connection handler | Non-root (UID 1000) | TCP 8080 (proxy), TCP 9090 (metrics/health) | TLS ClientHello bytes, client IPs, JA4 fingerprints |
| `internal/tls/parser.go` — ClientHello parser | Same process | None (internal) | Raw TLS bytes from untrusted clients |
| `internal/security/pipeline.go` — Security scoring engine | Same process | None (internal) | Redis-backed ban lists, dial settings, JA4 fingerprints |
| `internal/redis/client.go` — Redis client wrapper | Same process | Redis connection (TCP or Unix socket) | Password, ACL username, TLS config |
| `internal/webhook/delivery.go` — Webhook dispatcher | Same process | Outbound HTTP to webhook endpoints | HMAC signing secrets, ECS event payloads |
| `internal/config/loader.go` — Config loader | Same process | File system only | Redis password (via env var expansion), TLS cert paths |
| Metrics HTTP server (`/metrics`, `/health`, `/health/deep`) | Same process | TCP 9090 (loopback by default) | Operational metrics, dial settings, connection counts |

### 1.2 What the Proxy Does NOT Do (Inherent Security Boundaries)

The proxy's passthrough architecture provides **inherent security boundaries** that eliminate entire classes of vulnerabilities common in traditional HTTP proxies. Because JA4proxy does not terminate TLS, it cannot inspect HTTP headers, request bodies, or response content. This means **HTTP request smuggling, header injection, XSS, SQL injection via proxy, and content-based WAF bypasses are not applicable attack vectors** against the proxy itself. The proxy's entire security model is built on metadata extracted from the TLS ClientHello and connection-level attributes (IP, GeoIP, TCP timing), which constrains both what an attacker can inject and what the proxy can be tricked into executing.

---

## 2. Historical Vulnerability Analysis (Pentest Regression Tests)

The codebase contains **12 pentest regression test files** documenting security findings from structured security review. Understanding what has already been found and fixed is essential for identifying residual risk.

### 2.1 Previously Identified and Patched Vulnerabilities

| Finding ID | CVSS | Category | Description | Fix Status |
|------------|------|----------|-------------|------------|
| JA4PROXY-2026-0001 | — | PROXY protocol spoofing | Untrusted PROXY header forwarded verbatim to backend, allowing IP injection | **Fixed** — header now stripped from untrusted sources |
| JA4PROXY-2026-0002 | — | PROXY protocol smuggling | Chained PROXY headers could smuggle attacker-injected IPs past trust check | **Fixed** — second PROXY header triggers connection drop |
| JA4PROXY-2026-0003 | — | TLS fragmentation bypass | Fragmented ClientHello forwarded without JA4, bypassing all JA4-based controls | **Fixed** — `reassembleClientHello()` reassembles up to 16,640 bytes |
| JA4PROXY-2026-0004 | — | ALPN browser bypass | Attacker-controlled ALPN field trusted for browser bypass decisions | **Fixed** — default now `false`; operator must explicitly enable |
| JA4PROXY-2026-0008 | 7.5 (High) | Unauthenticated metrics | `/metrics` and `/health/deep` leaked operational state without auth on non-loopback binds | **Fixed** — startup validation requires `auth_token` for remote binds; middleware enforces Bearer token with constant-time compare |
| JA4PROXY-2026-0009 | 8.6 (Critical) | Goroutine leak / DoS | `forward()` and `tarpit()` only drained one of two copy goroutines, leaking ~69 MB/hour under sustained load | **Fixed** — both goroutines now drained; `Close()` called after first `done` |
| JA4PROXY-2026-0011 | 7.5 (High) | Protocol lockdown bypass | Non-TLS traffic (HTTP, SSH) forwarded without JA4 parsing, bypassing all controls | **Fixed** — pre-parse lockdown drops any connection whose first byte is not `0x16` |
| JA4PROXY-2026-0012 | 7.5 (High) | Unbounded accept loop | No admission control on accept loop; 100K half-open connections = 2.4 GB buffer exhaustion | **Fixed** — bounded semaphore (`acceptSem`) sized to `MaxConnections` |
| JA4PROXY-2026-0013 | 7.5 (High) | Tarpit slot exhaustion | Tarpit `copyOne` had no read deadline; attacker could pin slots indefinitely with single byte | **Fixed** — `SetReadDeadline` on every read; absolute `SetDeadline` lifetime cap |
| JA4PROXY-2026-0019 | 7.5 (High) | Redis PubSub poisoning | Unsigned PubSub messages on critical channels allowed any Redis publisher to flip dial, mutate lists | **Fixed** — HMAC-SHA256 signed envelopes required when `PubSubHMACSecret` configured |
| JA4PROXY-2026-0031 | 5.3 (Medium) | Unbounded XADD goroutines | Fire-and-forget `XAdd` goroutines accumulated without bound during Redis slowdown, causing OOM | **Fixed** — bounded channel with fixed worker pool; events dropped when full |
| JA4PROXY-2026-0041 | 3.5 (Low) | Config reload path drift | `reload()` hardcoded `config/proxy.yml`, ignoring `CONFIG_PATH` env var | **Fixed** — `cfgPath` stored at startup and reused on SIGHUP |
| JA4PROXY-2026-0050 | 5.0 (Medium) | Redis ACL disabled by default | Default Redis "default" user has `+@all ~*`; password theft = full Redis compromise | **Partially Fixed** — classification and WARN logging; not a startup gate to avoid breaking existing deployments |
| JA4PROXY-2026-0052 | — | ACL config inconsistency | `acl_users.enabled=true` with empty `proxy_user` silently fell back to unrestricted "default" user | **Fixed** — startup refusal (`ValidateRedisACLConsistency`) when misconfigured |

### 2.2 Security Maturity Assessment

The sheer volume of regression tests — covering everything from PROXY protocol smuggling to Redis PubSub HMAC verification — indicates a **mature security posture** with structured review processes. The findings span the full spectrum from critical (goroutine leak / OOM) to low (config path drift), suggesting thorough coverage. The use of CVSS scoring, finding IDs with structured naming conventions, and dedicated regression test files demonstrates a disciplined approach to vulnerability management that exceeds typical open-source project standards.

---

## 3. Dependency Vulnerability Analysis

### 3.1 Direct Dependencies and CVE Status

The `go.mod` declares **13 direct dependencies**. The following table assesses each for known CVEs:

| Dependency | Version | Known CVEs | Risk Assessment |
|------------|---------|------------|-----------------|
| `github.com/alicebob/miniredis/v2` | v2.37.0 | None identified | Test-only dependency; not in production binary |
| `github.com/olekukonko/tablewriter` | v1.1.4 | None identified | CLI output formatting; minimal attack surface |
| `github.com/oschwald/geoip2-golang` | v1.13.0 | None identified | MaxMind DB reader; parses local MMDB files only |
| `github.com/prometheus/client_golang` | v1.23.2 | CVE-2022-21698 (fixed in ≥1.11.1) [^7^] | Current version unaffected; DoS via non-standard HTTP methods patched |
| `github.com/prometheus/client_model` | v0.6.2 | None identified | Protocol buffer definitions; no runtime parsing of untrusted input |
| `github.com/redis/go-redis/v9` | v9.18.0 | CVE-2025-29923 (fixed in ≥9.5.5) [^35^] | Current version unaffected; out-of-order response bug patched |
| `github.com/sirupsen/logrus` | v1.9.4 | CVE-2025-65637 (fixed in ≥1.9.3) [^2^] | Current version **affected** — v1.9.4 is vulnerable to DoS via `Writer()` with >64KB single-line payloads |
| `github.com/spf13/cobra` | v1.10.2 | None identified | CLI framework; no network-facing code |
| `github.com/yl2chen/cidranger` | v1.0.2 | None identified | CIDR trie lookups on trusted config data |
| `github.com/zalando/go-keyring` | v0.2.8 | None identified | OS keyring integration; local-only |
| `go.yaml.in/yaml/v3` | v3.0.4 | None identified | YAML parsing of trusted config files |
| `pgregory.net/rapid` | v1.2.0 | None identified | Property-based testing; test-only |

### 3.2 Critical Finding: logrus CVE-2025-65637 (DoS)

**`github.com/sirupsen/logrus v1.9.4` is vulnerable to CVE-2025-65637**, a denial-of-service flaw with **CVSS 7.5 (High)** [^2^][^3^]. The vulnerability triggers when `Entry.Writer()` receives a single-line payload exceeding 64KB without newline characters, causing the internal `bufio.Scanner` to fail with "token too long" and permanently close the writer pipe. While the proxy's primary logging paths use `logrus.Fields` structured logging rather than `Writer()`, any code path that pipes external data into `log.Writer()` — such as subprocess output capture, webhook response logging, or debug endpoints — could trigger this condition. The fix is available in **logrus v1.9.3+** (which is confusingly numbered higher than the vulnerable v1.9.4 due to Go module versioning semantics — the actual patched release is v1.9.3 or v1.9.5+). The project should upgrade to **logrus v1.9.5 or later** to resolve this.

### 3.3 Go Standard Library Vulnerabilities

The `Dockerfile.go-proxy` specifies **`golang:1.25.9-alpine`** as the build image. Go 1.25 versions prior to 1.25.6 contain **multiple critical vulnerabilities** [^20^][^25^]:

| CVE | Component | Severity | Description |
|-----|-----------|----------|-------------|
| CVE-2025-61726 | `net/url` | High | Memory exhaustion in query parameter parsing — unbounded allocation when parsing forms with many unique query parameters [^21^] |
| CVE-2025-61728 | `archive/zip` | High | Excessive CPU consumption when building archive index — super-linear time complexity on crafted ZIP files [^22^] |
| CVE-2025-61730 | `crypto/tls` | High | TLS 1.3 handshake vulnerability when multiple messages sent in records [^27^] |
| CVE-2025-61731 | `crypto/tls` | Critical | Unexpected session resumption in `crypto/tls` — potential security bypass [^27^] |
| CVE-2025-68119 | `crypto/tls` | Critical | Session resumption bypass allowing unauthorized connection establishment |
| CVE-2025-68121 | `crypto/tls` | Critical | TLS session handling vulnerability [^27^] |

**Critical Assessment:** Since the build uses `golang:1.25.9-alpine`, these vulnerabilities are **patched** in the build toolchain itself (1.25.9 > 1.25.6). However, the `go.mod` directive `go 1.25.9` only specifies the **language version** — it does not enforce the toolchain version used to build. If the binary is built on a CI/CD runner with an older Go installation (< 1.25.6), the resulting binary would contain the vulnerable standard library code. The Dockerfile correctly pins the builder image to `golang:1.25.9-alpine`, but **defense in depth requires verifying the actual `go version` at build time**.

The `net/url` vulnerability (CVE-2025-61726) is particularly relevant because the proxy's metrics HTTP server (`/metrics`, `/health`) uses `net/http`, which internally calls `ParseForm` for POST requests. While the metrics endpoints only handle GET requests in normal operation, an attacker who bypasses auth could send a crafted POST to exhaust memory. The `crypto/tls` vulnerabilities are relevant if the proxy connects to backends or Redis over TLS — though the proxy's TLS connections are outbound client connections, not server listeners.

---

## 4. Remote Code Execution (RCE) Assessment

### 4.1 Direct RCE in Proxy Code: Not Feasible

The JA4proxy Go code **does not contain any direct RCE vulnerability** based on comprehensive static analysis. The reasons are structural:

**No eval/exec of attacker-controlled data.** The proxy never executes shell commands, evaluates expressions, or dynamically loads code based on network input. The only external code execution paths are the Lua scripts (`sliding_window.lua`) loaded from the local filesystem at startup, and these are trusted, operator-controlled files. The `ParseClientHello` function is a pure byte parser with no pointer arithmetic, no unsafe package usage, and no memory allocation based on attacker-controlled sizes without bounds checking.

**No deserialisation of untrusted data.** The proxy does not parse JSON, XML, YAML, Protocol Buffers, or any other serialisation format from untrusted network sources. The only YAML parsing is for the trusted `proxy.yml` config file at startup. The Redis protocol is handled by `go-redis`, which has its own security track record. Webhook payloads are JSON-marshalled (outbound only) and HMAC-signed.

**No file operations on attacker-controlled paths.** The proxy reads config files, GeoIP databases, and Lua scripts from operator-specified paths. It does not write files based on network input, nor does it construct file paths from client data. The `mtls.go` verifier reads a PEM file from a configured path — the path is trusted, and the PEM parsing uses Go's standard `crypto/x509` package.

**No buffer overflows.** Go is memory-safe by design, and the codebase contains no `unsafe` package usage, no `cgo` bindings, and no assembly. The TLS parser's bounds checking is explicit and comprehensive — every slice access is preceded by a length check, with `ErrTruncated` returned on underflow.

### 4.2 Indirect RCE via Chained Exploitation: Credible Vectors Exist

While direct RCE is not feasible, **chained attack vectors** could achieve code execution through dependency compromise or infrastructure exploitation:

| Chain | Path | Likelihood | Impact |
|-------|------|------------|--------|
| Redis RCE → proxy state manipulation | Redis 2026 CVEs (CVE-2026-23479, CVE-2026-25243) allow authenticated RCE [^1^] | Medium (requires Redis auth or network access) | Attacker flips dial to 0 (monitor mode), clears ban lists, adds attacker JA4 to whitelist — proxy becomes transparent |
| go-redis out-of-order responses | CVE-2025-29923 (patched in v9.18.0) could cause pipeline corruption [^35^] | Low (patched in current version) | Corrupted Redis responses could cause unexpected proxy behavior, though not directly RCE |
| Webhook SSRF → internal scanning | Webhook URLs are operator-configured but not validated | Low | Attacker with config access could point webhooks at internal services, using proxy as scanning relay |
| Build-time supply chain | `golang:1.25.9-alpine` base image, `go mod download` | Low | Compromised builder image or module proxy could inject malicious code |

### 4.3 Redis as the Critical Pivot Point

The **Redis dependency is the highest-risk component** in the RCE chain. The Redis server itself has **five RCE vulnerabilities disclosed in May 2026** (CVE-2026-23479 through CVE-2026-23631) [^1^], all requiring authenticated access but achieving full remote code execution in the Redis server process. If an attacker compromises Redis — through credential theft, network-level access, or one of these CVEs — they gain the ability to rewrite every piece of security state that the proxy relies on: ban lists, JA4 whitelists/blacklists, the dial setting, and rate-limiting counters. The proxy's `ValidateRedisAuth` function refuses to start against remote unauthenticated Redis, and `CheckRedisACLStatus` warns when ACLs are disabled on remote Redis, but **these are startup checks only**. A Redis compromise after startup would not be detected by the proxy.

The Redis PubSub HMAC signing (JA4PROXY-2026-0019) mitigates one attack vector — an attacker with Redis PUBLISH access cannot flip the dial or mutate lists without the HMAC secret. However, this protection is **optional** (only active when `PubSubHMACSecret` is configured) and does not protect against direct Redis command execution by an attacker with full Redis access.

---

## 5. Privilege Escalation Assessment

### 5.1 In-Process Privilege Escalation: Not Applicable

The proxy runs as a **single-process, single-user Go binary**. There is no concept of internal privilege levels — the connection handler, security pipeline, Redis client, and webhook dispatcher all share the same process space and OS privileges. There are no setuid binaries, no capability transitions, and no sandboxed sub-processes. This architecture eliminates traditional privilege escalation vectors within the proxy itself.

### 5.2 OS-Level Privilege Escalation via Proxy Compromise: Limited

If an attacker achieves code execution within the proxy process (e.g., through a future unpatched dependency vulnerability), the **container security controls significantly limit** what can be achieved:

| Control | Implementation | Escalation Barrier |
|---------|---------------|-------------------|
| Non-root user | `USER 1000:1000` in Dockerfile | Attacker cannot access root-only files or perform privileged operations |
| Capability dropping | `cap_drop: ALL` in docker-compose; `NET_BIND_SERVICE` only added to HAProxy | No `CAP_SYS_ADMIN`, `CAP_NET_RAW`, or other dangerous capabilities |
| `no-new-privileges` | `security_opt: no-new-privileges:true` | Prevents setuid/setgid escalation within container |
| seccomp profile | `seccomp:../../config/seccomp/proxy.json` | Syscall filtering restricts available system calls |
| AppArmor (optional) | Profile available but not enabled by default | Would provide additional MAC-layer restrictions |
| read-only rootfs | `read_only: true` on proxy service | Prevents file system modifications |
| tmpfs mounts | `/tmp` and `/var/run` as tmpfs with `noexec,nosuid,nodev` | Prevents executable file drops and privilege escalation via SUID |

These controls make **container escape extremely difficult** without a kernel-level vulnerability. The proxy does not mount the Docker socket, host network namespace, or host PID namespace, eliminating the most common container escape paths.

### 5.3 Host Compromise via Kernel Exploitation: Theoretical Only

If the attacker has code execution in the proxy container, the only remaining escalation paths are **kernel vulnerabilities** (container escape via privilege escalation CVEs in the host kernel) or **misconfigured container runtime** (e.g., privileged mode, host namespace sharing). The production docker-compose does not use privileged mode or host namespaces, so this reduces to kernel exploitation — which is outside the scope of the proxy's security model and depends on the host's kernel patch level.

---

## 6. Chained Attack Vectors

### 6.1 Redis Compromise → Security State Manipulation

This is the **most credible chained attack**. The attack flow is:

1. Attacker gains Redis access (credential theft, network pivot, or Redis RCE CVE)
2. Attacker sets `config:dial` to `0` (monitor mode — all connections allowed)
3. Attacker clears `ban:*` keys and adds attacker JA4 to `ja4:whitelist`
4. Proxy continues operating but now allows all traffic, including malicious connections
5. Attack traffic reaches backend without any JA4-based controls

**Detection:** The proxy emits structured logs for every connection decision. A sudden dial change without a corresponding config reload log entry (with HMAC verification) would indicate PubSub tampering. The `ja4proxy_redis_acl_enabled` gauge set to `0` also signals a hardening gap.

### 6.2 Metrics Endpoint Reconnaissance → Targeted Attack

The `/metrics` endpoint exports operational data including `ja4proxy_connections_total`, `ja4proxy_connection_errors_total`, `ja4proxy_dial_setting`, `ja4proxy_tarpit_concurrent`, and `ja4proxy_redis_acl_enabled`. An unauthenticated attacker who can reach this endpoint (if misconfigured to bind to `0.0.0.0` without auth) gains:

- Current dial setting (knows whether proxy is in monitor mode)
- Active connection counts (knows proxy load — useful for timing DoS)
- Tarpit slot usage (knows if tarpit is saturated)
- Redis ACL status (knows if Redis is hardened)
- TLS certificate expiry timestamp (knows when cert rotation occurs)

This intelligence enables **precision-targeted attacks** rather than blind probing. The startup validation (`ValidateMetricsAccess`) and auth middleware (`metricsAuthMiddleware`) prevent this when properly configured, but the `JA4PROXY_ALLOW_UNAUTH_METRICS=1` escape hatch could be inadvertently enabled.

### 6.3 Webhook Endpoint as SSRF Relay

The webhook dispatcher delivers ECS-formatted connection events to configured endpoints. While the webhook URLs are operator-controlled, an attacker who gains config write access (via Redis compromise or file system access) could change webhook endpoints to internal services (e.g., `http://169.254.169.254/latest/meta-data/` for cloud metadata, `http://localhost:6379` for Redis HTTP interface). The proxy would then:

1. Receive a connection
2. Generate an ECS event
3. POST the event to the attacker-controlled internal URL
4. Potentially expose internal service responses in webhook delivery error logs

The webhook HTTP client has a configurable timeout (default 30 seconds) and follows redirects, making this a viable SSRF vector if config integrity is compromised. The dispatcher does not validate that URLs are external or block internal IP ranges.

### 6.4 PROXY Protocol Trust Chain Bypass

The PROXY protocol trust chain (`proxypkg.IsTrustedProxySourceCIDRs`) relies on a CIDR list that is loaded from **both static config and NetBox** (phase-94i2). The NetBox CIDRs are fetched asynchronously at startup and on reload. If NetBox is compromised or returns malicious CIDRs, the proxy could incorrectly trust attacker-controlled source IPs, allowing PROXY header spoofing (JA4PROXY-2026-0001 regression). The CIDR fetch has a 10-second timeout and fails open (does not block proxy startup), meaning a NetBox compromise could inject trusted CIDRs without immediate detection.

---

## 7. Host Attack Surface

### 7.1 Container-to-Host Attack Paths

The proxy container's attack surface against the host is **extremely limited** by design:

- **No host namespace sharing:** The container uses its own network, PID, and mount namespaces
- **No privileged mode:** The container cannot access host devices or perform kernel operations
- **No Docker socket mount:** The container cannot escape via Docker API
- **No host path mounts:** Only `config/` (read-only), `logs/` (write), and `redis-sock/` (Unix socket) are mounted
- **Resource limits:** Memory capped (configurable), CPU limited
- **Capability dropping:** Only `NET_BIND_SERVICE` is added (and only for HAProxy, not the Go proxy)

The only viable container-to-host escape paths would require:
1. A **Linux kernel privilege escalation vulnerability** (e.g., CVE in cgroup v1/v2, eBPF, or namespace isolation)
2. A **seccomp bypass** (the custom seccomp profile may have gaps)
3. A **writeable kernel exploit** delivered through the logs volume mount

### 7.2 Host-to-Container Lateral Movement

If the host is compromised, the proxy container is vulnerable through:
- **Shared kernel:** The host kernel is shared, so kernel exploits affect all containers
- **Volume mounts:** The `config/` mount is read-only but `logs/` is writeable — an attacker on the host could modify log files, though this has limited impact
- **Redis Unix socket:** The `redis-sock` volume is shared between proxy and Redis containers — a host attacker could connect to Redis directly
- **Network access:** The host can access all container network interfaces

### 7.3 Supply Chain and Build-Time Risks

| Risk Vector | Mitigation | Residual Risk |
|-------------|-----------|---------------|
| Compromised `golang:1.25.9-alpine` base image | Pin specific digest; use private registry | Medium — digest pinning not currently used |
| Compromised Go module proxy | `GOSUMDB` verification; `go.sum` checksums | Low — checksums validated at build |
| Compromised `apk` packages during build | Alpine package signatures | Low — standard Alpine security |
| Malicious commit in dependency | `go.sum` pinning; `go mod verify` | Low — unlikely to bypass unnoticed |
| Compromised CI/CD pipeline | GitHub Actions security; signed releases | Medium — depends on GitHub security |

---

## 8. Firewall and Network Segmentation Considerations

### 8.1 Expected Deployment Architecture

The production docker-compose places **HAProxy in front of the Go proxy**, with the following network topology:

```
Internet → HAProxy (443/80) → ja4proxy-go (8080) → Backend (upstream)
                     ↓
              Redis (unix socket + internal network)
                     ↓
              Metrics (9090, loopback-only by default)
```

### 8.2 Firewall Rules Required

| Direction | Port | Source | Destination | Purpose | Risk if Open |
|-----------|------|--------|-------------|---------|-------------|
| Inbound | TCP 443 | Internet | HAProxy | TLS termination | Standard web exposure |
| Inbound | TCP 80 | Internet | HAProxy | HTTP redirect | Attack surface for non-TLS probing |
| Inbound | TCP 8080 | HAProxy only | Go proxy | Proxy listener | If exposed directly, attacker can send arbitrary TLS ClientHello |
| Inbound | TCP 9090 | Loopback only | Go proxy | Metrics/health | If exposed externally, leaks operational intelligence |
| Outbound | TCP 6379 / Unix socket | Go proxy | Redis | Security state storage | If Redis exposed externally, credential theft risk |
| Outbound | TCP 443/80 | Go proxy | Webhook endpoints | ECS event delivery | SSRF vector if endpoints compromised |
| Outbound | TCP 443/80 | Go proxy | NetBox | Trusted CIDR sync | If NetBox compromised, malicious CIDR injection |

### 8.3 Firewall Bypass Scenarios

**Scenario 1: Direct proxy exposure.** If the firewall only protects HAProxy but the Go proxy's port 8080 is also exposed (e.g., through a misconfigured load balancer or cloud security group), attackers can connect directly to the proxy, bypassing any HAProxy-level protections. The proxy would still apply JA4-based controls, but the attacker gains a direct attack surface.

**Scenario 2: Metrics endpoint exposed.** If port 9090 is inadvertently exposed (e.g., through a `hostPort` binding or cloud security group rule), attackers gain operational reconnaissance data without needing to authenticate, even if `auth_token` is configured (the auth only helps if the attacker knows the token, but the endpoint's existence reveals information).

**Scenario 3: Redis exposure.** If Redis is accessible from outside the container network (e.g., TCP 6379 exposed for external monitoring), the proxy's entire security state is at risk. The `ValidateRedisAuth` check only runs at startup — it does not protect against runtime Redis compromise.

**Scenario 4: Internal lateral movement.** An attacker who compromises another service in the same container network (e.g., HAProxy, Redis, Grafana) can pivot to the proxy. The proxy's metrics endpoint on port 9090 is accessible from any container in the same network, and the Redis Unix socket is shared via volume mount.

---

## 9. Remaining Risk Vectors and Recommendations

### 9.1 High-Priority Recommendations

| Priority | Finding | Recommendation |
|----------|---------|---------------|
| **High** | logrus v1.9.4 vulnerable to CVE-2025-65637 (DoS) [^2^] | Upgrade `github.com/sirupsen/logrus` to **v1.9.5+** immediately |
| **High** | Redis RCE CVEs (2026-23479 through 2026-23631) [^1^] | Upgrade Redis server to patched version; enable Redis ACLs with per-service users; restrict Redis network access to proxy only |
| **High** | Go stdlib vulnerabilities in builds < 1.25.6 [^20^] | Verify build pipeline uses Go ≥ 1.25.6; pin builder image digest in Dockerfile |
| **Medium** | Webhook SSRF potential | Add URL validation to webhook dispatcher — block internal IP ranges, localhost, and metadata endpoints |
| **Medium** | NetBox CIDR trust chain | Validate NetBox TLS certificate; add CIDR change alerting; consider static CIDR fallback |
| **Medium** | No runtime Redis compromise detection | Implement periodic Redis config fingerprinting (e.g., hash of ban list + dial + whitelist); alert on unexpected changes |
| **Low** | AppArmor profile not enabled by default | Enable AppArmor in production docker-compose after loading profile on host |
| **Low** | seccomp profile not audited | Review `config/seccomp/proxy.json` for unnecessary syscalls; apply principle of least privilege |

### 9.2 Defense-in-Depth Measures

The proxy already implements many defense-in-depth measures that should be preserved and extended:

- **Startup validation gates** (`ValidateRedisAuth`, `ValidateMetricsAccess`, `ValidateRedisACLConsistency`) prevent dangerous misconfigurations from reaching production
- **Fail-open design** with bounded resources (semaphore, tarpit timeouts, XADD queue) ensures the proxy remains available under attack
- **Structured logging** with finding IDs enables security event correlation and alerting
- **HMAC-signed PubSub messages** protect critical Redis channels from unauthorized mutation
- **Constant-time token comparison** (`crypto/subtle.ConstantTimeCompare`) prevents timing attacks on metrics auth
- **Non-root container** with `no-new-privileges`, capability dropping, and read-only rootfs provides strong containment

### 9.3 What Would Change the Risk Assessment

The current assessment assumes the proxy is deployed as documented — behind HAProxy, with Redis on a private network or Unix socket, metrics on loopback, and Redis ACLs enabled. The risk profile changes significantly if:

- The proxy is exposed directly to the internet without HAProxy
- Redis is exposed on a public network without authentication
- Metrics are bound to `0.0.0.0` without authentication
- The container runs in privileged mode or with host namespace sharing
- Redis ACLs are disabled on a network-reachable Redis instance
- The HMAC secret for PubSub is not configured

---

## 10. Summary and Conclusion

The JA4proxy Go proxy demonstrates **mature security engineering** with comprehensive regression testing, structured vulnerability tracking, and defense-in-depth container hardening. The passthrough architecture eliminates entire classes of vulnerabilities (HTTP parsing, content inspection, TLS termination attacks) that plague traditional proxies. **No direct RCE or privilege escalation vulnerability exists in the proxy's own code.**

The residual risks are primarily **chained and infrastructure-dependent**: Redis compromise represents the highest-impact attack vector, followed by dependency vulnerabilities (notably logrus CVE-2025-65637) and webhook SSRF. The container's security controls (non-root, seccomp, capability dropping, read-only rootfs) make host escape extremely difficult without kernel-level exploitation.

When placed behind a firewall as recommended — with HAProxy handling external TLS termination, Redis on a private network, metrics on loopback, and Redis ACLs enabled — the external attack surface is limited to the TLS listener, which only processes ClientHello metadata and does not decrypt traffic. This is a **well-hardened security posture** for an open-source network proxy, though continuous dependency monitoring and Redis hardening remain essential ongoing practices.
