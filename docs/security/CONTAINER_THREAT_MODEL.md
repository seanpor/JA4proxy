# Container Threat Model: cAdvisor Privilege Footprint

## 1. Description
cAdvisor (Container Advisor) provides resource usage and performance characteristics of running containers. To query this information, it requires read-only host-level access to the cgroup system and filesystem mounts.

## 2. Capabilities Requested
- `volume: /:/rootfs:ro`
- `cap_add: [SYS_PTRACE, DAC_READ_SEARCH]`
- `/dev/kmsg` device access

## 3. Blast Radius Analysis
If the cAdvisor container is compromised (e.g. through a remote code execution vulnerability in its metrics collector API):
- **Host Read Access:** The attacker can read all files on the host root directory (including `/etc/shadow`, credentials, and private keys) via the `/rootfs` mount.
- **Process Inspection:** The `SYS_PTRACE` capability allows the attacker to trace processes running on the host, potentially extracting secrets from environment memory.
- **Kernel Logs:** `/dev/kmsg` exposes kernel ring-buffer messages, which may leak sensitive information from other containers' system calls.

## 4. Current Mitigations
1. **Network Isolation:** cAdvisor binds its port `8080` only to `ja4proxy-monitoring` — an internal bridge network not accessible from any external interface.
2. **No Host Network:** cAdvisor does not run with `network_mode: host`.
3. **Read-Only Root Mount:** The host filesystem is mounted strictly read-only (`:ro`). The attacker cannot write to host files or overwrite configuration.
4. **No New Privileges:** `security_opt: [no-new-privileges:true]` prevents privilege escalation through setuid binaries.
5. **Non-Root User:** cAdvisor runs without `privileged: true`; all unused capabilities are dropped via `cap_drop: [ALL]`.

## 5. Residual Risk Rationale
The operational value of real-time memory exhaustion monitoring (to prevent silent Redis evictions) outweighs the residual risk, provided cAdvisor remains isolated behind the internal monitoring network with no direct routing from the external interface. Stricter isolation (e.g. running a lightweight metrics sidecar instead) is tracked as a future hardening opportunity if the threat model changes.
