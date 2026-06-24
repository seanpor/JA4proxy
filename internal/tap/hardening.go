package tap

import (
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
	return nil
}
