package main

import (
	"testing"
)

// TestBuildRedisOptions_PasswordPrecedence exercises F-017: --redis-password
// must win over REDIS_PASSWORD, which must win over a password embedded in
// --redis-url, so operators have an escape from ever putting a credential on
// the command line.
func TestBuildRedisOptions_PasswordPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		redisURL   string
		flagPw     string
		envPw      string
		wantPasswd string
	}{
		{"url-only", "redis://:urlpass@localhost:6379", "", "", "urlpass"},
		{"env-overrides-url", "redis://:urlpass@localhost:6379", "", "envpass", "envpass"},
		{"flag-overrides-env-and-url", "redis://:urlpass@localhost:6379", "flagpass", "envpass", "flagpass"},
		{"flag-only-no-url-password", "redis://localhost:6379", "flagpass", "", "flagpass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.envPw != "" {
				t.Setenv("REDIS_PASSWORD", c.envPw)
			} else {
				t.Setenv("REDIS_PASSWORD", "")
			}
			cfg := runConfig{redisURL: c.redisURL, redisPassword: c.flagPw}
			opt, err := buildRedisOptions(cfg)
			if err != nil {
				t.Fatalf("buildRedisOptions: %v", err)
			}
			if opt.Password != c.wantPasswd {
				t.Errorf("Password = %q, want %q", opt.Password, c.wantPasswd)
			}
		})
	}
}

// TestBuildRedisOptions_ForcesTLS exercises F-018: --redis-tls must force TLS
// even when --redis-url uses the plain redis:// scheme, and must not clobber
// TLS config already implied by a rediss:// URL.
func TestBuildRedisOptions_ForcesTLS(t *testing.T) {
	t.Run("redis-tls forces TLS on a plain redis:// URL", func(t *testing.T) {
		cfg := runConfig{redisURL: "redis://localhost:6379", redisTLS: true}
		opt, err := buildRedisOptions(cfg)
		if err != nil {
			t.Fatalf("buildRedisOptions: %v", err)
		}
		if opt.TLSConfig == nil {
			t.Fatal("TLSConfig = nil, want non-nil with --redis-tls set")
		}
	})

	t.Run("no redis-tls leaves a plain redis:// URL in cleartext", func(t *testing.T) {
		cfg := runConfig{redisURL: "redis://localhost:6379"}
		opt, err := buildRedisOptions(cfg)
		if err != nil {
			t.Fatalf("buildRedisOptions: %v", err)
		}
		if opt.TLSConfig != nil {
			t.Fatal("TLSConfig != nil, want nil (default is cleartext, unchanged behavior)")
		}
	})

	t.Run("rediss:// URL already implies TLS without the flag", func(t *testing.T) {
		cfg := runConfig{redisURL: "rediss://localhost:6379"}
		opt, err := buildRedisOptions(cfg)
		if err != nil {
			t.Fatalf("buildRedisOptions: %v", err)
		}
		if opt.TLSConfig == nil {
			t.Fatal("TLSConfig = nil, want non-nil for rediss:// scheme")
		}
	})
}
