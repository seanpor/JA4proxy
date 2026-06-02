# Phase 56 — Critique Notes

**Written:** 2026-04-06
**Scope:** Critical review of all deliverables for Phases 34 (AppArmor) and 56 (deceptive defense).

---

## What's solid

**DeceptionChecker design is excellent.**
The implementation in `src/security/deception.py` is a well-structured, single-responsibility
class. It uses `frozenset` for O(1) hot-path lookups, normalises SNIs to lowercase at load time
(not at check time, which would waste cycles per connection), and fails open at every error
boundary — config parse failure, YAML corruption, Redis write failure. The fail-open property
is correctly prioritised for a system where blocking a real user is the worst outcome.

**Test coverage for the deception module is thorough.**
`tests/unit/security/test_deception.py` covers: disabled state, empty lists, JA4 fingerprint
match (ban key written, trigger dict returned, silent_drop key present), non-matching JA4,
None JA4, SNI match, case-insensitive SNI, non-matching SNI, None SNI, Redis `set()` raising
ConnectionError (fail open), Redis client None (fail open), and pipeline integration (both
fingerprint and SNI paths route to `action='silent_drop'`, non-matching routes to `allow`).
This is 16 test cases with realistic asyncio exercising — a solid safety net.

**`config/deception.yml` is operator-safe.**
`enabled: false` by default with prominent CAUTION comment prevents an operator from
accidentally banning real browsers by populating `honey_fingerprints` with a JA4 that
real Chrome happens to produce. The comment explaining the risk is exactly right.

**Dead-Man's Switch is well-engineered.**
`src/security/dead_man_switch.py` handles the never-ran guard correctly (a monitor that
has never completed a check should not trigger self-termination — only a known-good monitor
that subsequently goes silent should). The grace period prevents spurious kills during startup.
Fires once only (self._fired flag). Prometheus counter correctly emitted. Fail-open for
internal watchdog errors.

**AppArmor profile is correct for its constraints.**
`config/apparmor/ja4proxy` accurately describes what AppArmor can enforce: exec/ptrace denial,
write restriction to tmpfs paths only, Python runtime access. The profile acknowledges its own
limitation on outbound IP whitelisting (a known AppArmor restriction — network rules require
static IPs, not env-var-resolved hostnames) and correctly defers that to the nftables layer.

**Both compose files fully match on ephemeral filesystem settings.**
`/tmp` and `/var/run` tmpfs with `noexec,nosuid,nodev` enforced in both
`docker/docker-compose.poc.yml` and `docker/docker-compose.prod.yml`. `read_only: true` on all
services. This is the strongest defence against write-based persistence attacks.

**Seccomp profile is comprehensive.**
`config/seccomp/proxy.json` uses `SCMP_ACT_ERRNO` as `defaultAction` (deny-all by default,
allow only the listed syscalls). The allowlist is well-chosen for an async Python TLS proxy:
socket operations, epoll, eventfd, pipe, futex, mmap — all necessary. Notably absent from
the allowlist: `execve`, `fork`, `clone3`, `ptrace` — which is correct.

---

## Gaps or risks

**Dead-Man's Switch IS wired into proxy.py.**
`proxy.py:1802–1812` imports and instantiates `DeadManSwitch` inside the integrity monitor
setup block. Config is read from `deception.dead_man_switch` in `proxy.yml`. This is
correctly placed after `IntegrityMonitor` initialisation.

**Deception checker IS wired into the pipeline.**
`src/security/pipeline.py:338` constructs `DeceptionChecker(config, redis_client)` during
`Pipeline.__init__()`. The check fires at `pipeline.py:621`. Hot-reload is handled at
`pipeline.py:548`. The Redis client is passed correctly from the pipeline's own `redis_client`
argument, so bans will be written in production.

**Two-stage seccomp runtime transition wiring — FIXED in commit 55c9695.**
The critique originally flagged `apply_runtime_seccomp()` as dead code. This was immediately
addressed: `proxy.py` now calls `apply_runtime_seccomp()` after `asyncio.start_server()` binds
the listening socket (the correct moment — startup file-loading phase is complete). The `seccomp`
Python library is documented in `requirements.txt` as an optional dependency with install
instructions. Config key `deception.seccomp_transition.enabled` (default: true) allows operators
to disable the transition. The function fails open if `python3-seccomp` is not installed — the
proxy continues on the Docker-applied startup profile rather than refusing to start.

**Seccomp profile allows `clone`.**
`clone` (without `CLONE_NEWUSER`) is needed for threading. However, the entry lists plain
`clone` with no argument filter. An attacker with code execution could use `clone` to
spawn a thread for lateral movement. The original plan called for allowing only specific
`clone` flags via argument filters in seccomp. This is a known limitation of Docker's
seccomp JSON format — argument filtering requires `args` fields on the rule. Consider
narrowing if the threat model includes code execution inside the container.

**AppArmor profile `deny /usr/bin/env x` is incomplete.**
The profile denies `/usr/bin/env` execution but `/usr/bin/env` is just one way to spawn
a shell. Python's `subprocess`, `os.system()`, or `ctypes.cdll.LoadLibrary()` can invoke
arbitrary binaries by absolute path. The explicit deny list (`/bin/sh`, `/bin/bash`, etc.)
is a belt-and-suspenders addition but the real enforcement comes from the `rix` rule on
`/usr/bin/python3*` — only Python is allowed to execute. This is actually correct: any
non-Python binary that the Python process tries to exec will be denied by the absence of
an `ix` rule for that binary's path. The explicit deny list is redundant but harmless.

**Dead-Man's Switch has a test suite.**
`tests/unit/security/test_dead_man_switch.py` exists, which is necessary given that this
module sends `SIGTERM`. Verify the test suite covers: fires only after grace period, fires
only when monitor has previously run (never-ran guard), fires only once (`_fired` flag),
does not fire when monitor is current, does not raise on attribute errors, and
`enabled=False` returns immediately without firing.

**`config/deception.yml` ships with empty lists.**
This is correct for safety, but it means Phase 56a delivers the detection infrastructure
with no pre-populated honey assets. Operators must be told, in the runbook, how to identify
safe honey fingerprints (fingerprints produced by no known legitimate client). Without
guidance, the feature will sit disabled indefinitely. The PHASE_56.md docs and the YAML
comments are the only guidance — consider adding a runbook entry in `docs/runbooks/`.

**No integration test verifying the ban key survives a Redis restart.**
The unit tests mock Redis — they confirm the `SET` call is made but cannot confirm the
key survives flushes or that the TTL is correctly set. An integration test that writes a
ban key and then reads it back from a real Redis instance (e.g., fakeredis with TTL support)
would close this gap.

---

## AppArmor limitations

The `config/apparmor/ja4proxy` profile is commented out in both Docker Compose files
(comment reads: `# - apparmor:ja4proxy`). This is intentional — AppArmor profiles must be
loaded into the **host kernel** before Docker can reference them. The host-load step is a
manual, privileged operation:

```bash
sudo apparmor_parser -r config/apparmor/ja4proxy
# or for persistence across reboots:
sudo install -m 644 config/apparmor/ja4proxy /etc/apparmor.d/ja4proxy
sudo apparmor_parser -r /etc/apparmor.d/ja4proxy
```

This creates a real operational burden:
1. **Deployment checklist step** that is invisible to `docker compose up`. An operator who
   forgets the host-load step silently runs without AppArmor enforcement — no error, no
   warning from Docker.
2. **Kernel version dependency.** AppArmor is standard on Ubuntu/Debian kernels but absent on
   stock RHEL/CentOS without additional packages (`apparmor-utils`). RHEL uses SELinux by
   default; the two systems coexist poorly. Phase 76 (RHEL production deployment) must address
   this — either provide a SELinux policy equivalent, or document that AppArmor requires a
   non-default RHEL kernel configuration.
3. **CI/CD gap.** The AppArmor profile cannot be validated in a standard GitHub Actions
   runner (Ubuntu runners have AppArmor available, but profile loading requires `sudo` and
   is frequently restricted in CI). This means the profile can drift from the running
   implementation without any automated catch.
4. **Profile reload on update.** If `config/apparmor/ja4proxy` is changed, the host must
   re-run `apparmor_parser -r` — a container restart alone does not pick up the change.

Mitigation: Add a make target (`make apparmor-load`) and a startup check in the operator
runbook that verifies the profile is loaded before raising `security_opt: - apparmor:ja4proxy`
in the compose file.

---

## Namespace isolation

The original 56b plan called for `unshare(CLONE_NEWNET | CLONE_NEWPID)` after initial socket
binding. This is architecturally blocked inside Docker with `cap_drop: ALL`:

- `unshare(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` (to create a new network namespace) or
  `CAP_NET_ADMIN` (to move interfaces into the namespace). Both are dropped.
- `unshare(CLONE_NEWPID)` requires `CAP_SYS_ADMIN`. Also dropped.
- Docker's `--pid=host` mode can expose the host PID namespace but provides no isolation.

This is not a deficiency in the implementation — it is a deliberate security trade-off.
`cap_drop: ALL` is the stronger defence (prevents most privilege escalation paths). Namespace
isolation via `unshare()` would require restoring a dangerous capability.

**Alternatives that preserve the security properties:**

1. **Docker `--pid` namespace per container.** Docker already runs each container in a
   separate PID namespace by default. The proxy process cannot see host PIDs. This is
   already in effect.
2. **Docker network isolation (Phase 72).** Three-tier network (DMZ/APP/ORIGIN) already
   prevents lateral movement at the network layer. This is a stronger guarantee than PID
   namespace isolation for the threat model (lateral movement via network).
3. **Bare-metal RHEL: `systemd` `PrivatePIDs=yes` / `PrivateNetwork=yes`.** For Phase 76
   bare-metal deployments, the `systemd` unit file can provide namespace isolation without
   requiring `CAP_SYS_ADMIN` — systemd handles the `unshare` call as root before dropping
   to the service user. Document this in `scripts/namespace_setup.sh` or a runbook.
4. **Kubernetes `securityContext.runAsNonRoot + PodSecurityPolicy`.** If the proxy is ever
   deployed to Kubernetes (Phase 83), namespace isolation is provided by the pod sandbox.

The conclusion is that namespace isolation as originally specified (in-process `unshare()`)
is not achievable in the Docker container model without compromising the `cap_drop: ALL`
posture. The existing Docker network isolation (Phase 72) and seccomp profile together
provide equivalent or stronger lateral-movement resistance for the Docker deployment target.
For bare-metal RHEL, the systemd unit file approach is the correct mechanism and should be
documented in a runbook or Phase 76's implementation notes.
