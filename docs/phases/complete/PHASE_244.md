---
phase: 244
title: "Seccomp Hardening for TAP Sensor"
size: MEDIUM
created: 2026-06-24
audience: [security, developer]
---

# Seccomp Hardening for TAP Sensor

## What is this?

Replace the placeholder `LoadSeccomp()` stub in `internal/tap/hardening.go` with a real
seccomp implementation that restricts the TAP sensor to a minimal syscall set. This
addresses F-400-02 (issue #244) and provides defense-in-depth beyond the Docker-level
seccomp profile.

## Scope

### In scope
- Implement in-process seccomp BPF filter loading in `internal/tap/hardening.go`
- Prune `config/seccomp_tap.json` to a minimal Go-appropriate allowlist
- Add unit tests in `internal/tap/hardening_test.go`
- Update `cmd/ja4-tap/main.go` error handling
- Create Docker-level seccomp entry for TAP sensor (compose/Dockerfile)

### Out of scope
- seccomp profile transition (startup → runtime) — that's the proxy's pattern
- ARM64 syscall number mapping (x86_64 only for now)

## Implementation plan

### Step 1: Prune the seccomp profile

`config/seccomp_tap.json` was written for the Python TAP sensor (Phase 20). The Go binary
doesn't need: `fork`, `vfork`, `execve`, `execveat`, `clone` (with non-thread flags),
`ptrace`, `personality`, `keyctl`, `add_key`, `request_key`, `remap_file_pages`,
`mbind`, `set_mempolicy`, `move_pages`, `migrate_pages`.

Create `config/seccomp_tap_go.json` with a minimal allowlist derived from the proxy's
profile pattern (`config/seccomp/proxy.json`) plus AF_PACKET-specific syscalls:
`fanotify_mark`, `inotify_add_watch`, `inotify_rm_watch`, and the `*_fstat` variants.

### Step 2: Implement LoadSeccomp() with raw BPF

Since the build uses `CGO_ENABLED=0`, we cannot use `libseccomp-golang`. Instead:

1. Parse the JSON profile at startup (file path configurable, default
   `/etc/ja4proxy/seccomp_tap.json`, fallback to embedded default)
2. Map syscall names to numbers via a lookup table (x86_64)
3. Build a BPF program: `SECCOMP_RET_ALLOW` for whitelisted syscalls,
   `SECCOMP_RET_KILL_PROCESS` for everything else
4. Load via `unix.Seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`

The implementation goes in `internal/tap/seccomp_linux.go` (Linux-only build tag)
with a stub `seccomp_other.go` for non-Linux platforms.

### Step 3: Embed the default profile

Use `//go:embed` to embed `config/seccomp_tap_go.json` as a fallback. If the external
file exists, use it; otherwise use the embedded copy. This ensures the TAP sensor is
hardened even without a mounted config.

### Step 4: Update main.go

Update the `LoadSeccomp()` call in `cmd/ja4-tap/main.go` to pass the profile path.
On failure, the current behaviour (warn and continue) is appropriate — seccomp failure
should not prevent the sensor from running, but should be loudly logged.

### Step 5: Add unit tests

`internal/tap/hardening_test.go`:
- `TestLoadSeccomp_ProfileParsing` — verify JSON is valid and maps to syscall numbers
- `TestLoadSeccomp_DefaultProfile` — verify embedded profile loads without error
- `TestSeccompBPF_SyscallWhitelist` — verify allowed syscalls produce `RET_ALLOW`
- `TestSeccompBPF_DeniedSyscall` — verify non-listed syscalls produce `RET_KILL`

Note: Actual `seccomp(2)` syscall cannot be tested in unit tests (requires root +
real kernel). Tests validate the BPF program construction and profile parsing.

### Step 6: Docker-level seccomp (follow-up)

- Add `security_opt: seccomp:config/seccomp_tap_go.json` to TAP sensor compose entry
- Ensure the TAP sensor has its own Dockerfile if not already present

## Test strategy

1. `make test-unit` — unit tests for profile parsing and BPF construction
2. `make test` — full test suite (Go native + Python in container)
3. `make lint` — ruff + go vet + staticcheck
4. Manual: run TAP sensor with `--pcap-file` and verify seccomp is active via
   `/proc/self/status` (Seccomp field should be 2 = SECCOMP_MODE_FILTER)

## Acceptance criteria

- [ ] `LoadSeccomp()` loads a real BPF filter from JSON profile
- [ ] Non-whitelisted syscalls are denied (SECCOMP_RET_KILL_PROCESS)
- [ ] Embedded default profile works without external file
- [ ] Unit tests pass for profile parsing and BPF construction
- [ ] `make lint` and `make test` pass
- [ ] TAP sensor functions correctly with seccomp active (pcap replay works)
