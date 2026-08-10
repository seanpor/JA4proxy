//go:build linux && !amd64

package tap

import (
	"fmt"
	"runtime"
)

// The seccomp filter in seccomp_linux.go is x86_64-specific in two independent
// ways, so it is built only for linux/amd64 and this file covers every other
// Linux architecture:
//
//  1. It invokes seccomp(2) by the raw number 317. That is SYS_SECCOMP on
//     amd64 only — on arm64 seccomp is 277, and 317 is not assigned at all.
//  2. Its BPF program compares seccomp_data.arch against AUDIT_ARCH_X86_64
//     (0xC000003E). On any other architecture every syscall mismatches that
//     check and takes the KILL branch.
//
// Before this file existed, seccomp_linux.go was tagged `linux` alone. On
// linux/arm64 the raw syscall returned ENOSYS, LoadSeccomp returned that error,
// and cmd/ja4-tap logged "failed to load seccomp profile; proceeding without
// seccomp" and carried on — leaving the sensor with unrestricted syscall access
// while appearing hardened. That is the F-400-02 impact (issue #244) surviving
// on a second architecture after being fixed on the first.
//
// Returning an explicit, accurate error here is deliberately preferred over
// silently attempting a filter that cannot work. It also removes a live hazard:
// correcting only the syscall number, without the arch constant, would load a
// filter that kills the sensor on its first syscall.
//
// To add support for another architecture, both the syscall number and the
// AUDIT_ARCH_* constant must be made architecture-aware, and the BPF filter
// re-verified on that architecture.

func loadSeccompProfile(path string) error {
	return fmt.Errorf("seccomp: unsupported architecture %s/%s (filter is linux/amd64 only): %s",
		runtime.GOOS, runtime.GOARCH, path)
}

func applySeccompProfile(_ []byte) error {
	return fmt.Errorf("seccomp: unsupported architecture %s/%s (filter is linux/amd64 only)",
		runtime.GOOS, runtime.GOARCH)
}
