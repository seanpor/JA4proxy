- **Constrain the TAP seccomp filter to linux/amd64 (issue #244)**: the filter in
  `internal/tap/seccomp_linux.go` is x86_64-specific in two ways — it invokes
  `seccomp(2)` by the raw number `317` (that is `SYS_SECCOMP` on amd64; on arm64
  seccomp is `277` and `317` is unassigned), and its BPF program compares
  `seccomp_data.arch` against `AUDIT_ARCH_X86_64`. It was nevertheless tagged
  `//go:build linux` alone, so on linux/arm64 the raw syscall returned `ENOSYS`,
  `LoadSeccomp` returned that error, and `cmd/ja4-tap` logged "proceeding without
  seccomp" and continued — leaving the sensor with unrestricted syscall access
  while appearing hardened. Now tagged `linux && amd64`, with a new
  `seccomp_linux_unsupported.go` returning an explicit architecture error for
  other Linux targets. `arm64` is a released build target (`.goreleaser.yml`) and
  `Dockerfile.ja4-tap` pins no platform, so an arm64 host builds an arm64 sensor.
