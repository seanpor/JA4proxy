package tap

import (
	_ "embed"
	"log"
	"syscall"
)

//go:embed seccomp_tap_go_embed.json
var defaultSeccompProfile []byte

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

// LoadSeccomp loads a seccomp BPF filter that restricts the process to a minimal
// syscall set required for packet capture and metric exporting. If profilePath is
// non-empty and the file exists, it is loaded; otherwise the embedded default is used.
func LoadSeccomp(profilePath string) error {
	if profilePath != "" {
		if err := loadSeccompProfile(profilePath); err != nil {
			log.Printf("seccomp: external profile %s failed (%v), using embedded default", profilePath, err)
		} else {
			return nil
		}
	}
	return applySeccompProfile(defaultSeccompProfile)
}
