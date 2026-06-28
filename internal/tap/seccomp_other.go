//go:build !linux

package tap

import "fmt"

func loadSeccompProfile(path string) error {
	return fmt.Errorf("seccomp is only supported on Linux")
}

func applySeccompProfile(data []byte) error {
	return fmt.Errorf("seccomp is only supported on Linux")
}
