// Package config provides configuration loading for the JA4proxy Go proxy.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoadConfigYAML(f *testing.F) {
	// Seed with valid and invalid config strings
	f.Add([]byte(`
proxy:
  listen_port: 8443
  backend_host: "127.0.0.1"
  backend_port: 443
redis:
  host: "127.0.0.1"
  port: 6379
security:
  tarpit_enabled: true
`))
	f.Add([]byte(``))
	f.Add([]byte(`::: invalid yaml :::`))
	f.Add([]byte(`
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "proxy.yml")
		if err := os.WriteFile(configFile, data, 0o600); err != nil {
			return
		}

		// Load must never panic on arbitrary input
		cfg, err := Load(configFile)
		if err == nil && cfg != nil {
			_ = cfg.Security.ProtocolLockdownEnabled()
		}
	})
}
