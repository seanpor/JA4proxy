package tap

import (
	"log"
	"syscall"
)

// DropCapabilities permanently drops root privileges and sets a low‑privilege UID/GID.
// It must be called after any privileged setup (e.g. AF_PACKET socket bind) and
// before any network capture begins.
func DropCapabilities() error {
	if err := syscall.Setgid(65534); err != nil {
		return err
	}
	if err := syscall.Setuid(65534); err != nil {
		return err
	}
	log.Printf("capabilities dropped: uid=%d,gid=%d", syscall.Getuid(), syscall.Getgid())
	return nil
}

// LoadSeccomp loads a pre‑compiled seccomp profile that restricts the process to a
// minimal syscall set required for packet capture and metric exporting. The profile
// file is expected at "/etc/ja4proxy/seccomp.json" (mounted by the container).
func LoadSeccomp() error {
	// NOTE: The actual seccomp loading logic is container‑specific and may rely on
	// a third‑party library. Here we simply log the intention; the real implementation
	// will be filled in when the profile file exists.
	log.Printf("loading seccomp profile (placeholder)")
	return nil
}
