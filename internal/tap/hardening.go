package tap

import (
	_ "embed"
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

//go:embed seccomp_tap_go_embed.json
var defaultSeccompProfile []byte

// DropCapabilities switches the process from root to the nobody user, dropping
// all Linux capabilities in the process. It must be called after any privileged
// setup (e.g. AF_PACKET socket bind) and before any network capture begins.
//
// The ordering is deliberate: supplementary groups first, then GID, then UID.
// Changing the UID from 0 (root) to a non-zero value causes the kernel to
// discard all capabilities unless PR_SET_KEEPCAPS is set (we explicitly clear
// it as belt-and-suspenders).
func DropCapabilities() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_KEEPCAPS=0: %w", err)
	}
	if err := syscall.Setgroups([]int{65534}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(65534); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(65534); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	log.Printf("privileges dropped: uid=%d gid=%d groups=%v", syscall.Getuid(), syscall.Getgid(), []int{65534})
	return nil
}

// LoadSeccomp loads a seccomp BPF filter that restricts the process to a minimal
// syscall set required for packet capture and metric exporting. If profilePath is
// non-empty the file is loaded; otherwise the embedded default is used.
func LoadSeccomp(profilePath string) error {
	if profilePath != "" {
		return loadSeccompProfile(profilePath)
	}
	return applySeccompProfile(defaultSeccompProfile)
}

// ErrSeccompFallback is returned when an external seccomp profile fails and the
// caller should decide whether to fall back to the embedded default.
var ErrSeccompFallback = fmt.Errorf("seccomp: external profile failed")
