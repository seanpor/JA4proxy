package config

import (
	"errors"
	"strings"
	"testing"
)

// Regression test for JA4PROXY-2026-0010 — Redis Fail-Open Masks
// Misconfiguration (CRITICAL, CVSS 8.2).
//
// Before the fix, the Go proxy happily connected to an unauthenticated
// Redis on any network host. Anyone who could reach that Redis (same
// VPC/subnet, misplaced security group, curious tenant) could mutate ban
// lists, whitelists, and the dial setting. ValidateRedisAuth now refuses
// startup when a non-local Redis host is paired with an empty password,
// unless the operator has set JA4PROXY_ALLOW_UNAUTH_REDIS=1 to opt out for
// integration test clusters.

func cfgWith(host, password string) *Config {
	cfg := &Config{}
	cfg.Redis.Host = host
	cfg.Redis.Password = password
	return cfg
}

func TestRegression_JA4PROXY_2026_0010_refuses_remote_unauth_redis(t *testing.T) {
	cases := []string{
		"redis",
		"redis.internal",
		"10.0.0.5",
		"192.168.5.5",
		"2001:db8::1",
		"example.com",
	}
	for _, host := range cases {
		t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "")
		err := ValidateRedisAuth(cfgWith(host, ""))
		if err == nil {
			t.Errorf("host=%q: expected ErrRedisAuthRequired, got nil", host)
			continue
		}
		if !errors.Is(err, ErrRedisAuthRequired) {
			t.Errorf("host=%q: expected ErrRedisAuthRequired, got %v", host, err)
		}
		if !strings.Contains(err.Error(), "JA4PROXY-2026-0010") {
			t.Errorf("host=%q: error must name the finding ID for ops; got %v", host, err)
		}
	}
}

func TestRegression_JA4PROXY_2026_0010_allows_local_unauth_redis(t *testing.T) {
	cases := []string{
		"localhost",
		"LOCALHOST",
		"127.0.0.1",
		"127.0.0.2",
		"::1",
		"[::1]",
		"/var/run/redis.sock",
		"unix:/run/redis.sock",
		"",
	}
	for _, host := range cases {
		t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "")
		if err := ValidateRedisAuth(cfgWith(host, "")); err != nil {
			t.Errorf("host=%q: local host must not require password; got %v", host, err)
		}
	}
}

func TestRegression_JA4PROXY_2026_0010_allows_remote_with_password(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "")
	if err := ValidateRedisAuth(cfgWith("redis.prod", "s3cret")); err != nil {
		t.Fatalf("remote host with password must pass; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0010_env_override_allows_unauth(t *testing.T) {
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "1")
	if err := ValidateRedisAuth(cfgWith("redis.test", "")); err != nil {
		t.Fatalf("JA4PROXY_ALLOW_UNAUTH_REDIS=1 must bypass the check; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0010_rejects_whitespace_only_password(t *testing.T) {
	// A password of "   " or "" is equally useless — reject both.
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "")
	if err := ValidateRedisAuth(cfgWith("redis.prod", "   ")); err == nil {
		t.Fatal("whitespace-only password must not count as authentication")
	}
}

func TestRegression_JA4PROXY_2026_0010_nil_config_is_safe(t *testing.T) {
	if err := ValidateRedisAuth(nil); err != nil {
		t.Fatalf("nil config must not explode; got %v", err)
	}
}

func TestRegression_JA4PROXY_2026_0010_sentinel_host_falls_back(t *testing.T) {
	// When Host is empty but Sentinels is set, the first sentinel governs.
	cfg := &Config{}
	cfg.Redis.Sentinels = []string{"redis-sentinel-a:26379", "redis-sentinel-b:26379"}
	t.Setenv("JA4PROXY_ALLOW_UNAUTH_REDIS", "")
	if err := ValidateRedisAuth(cfg); err == nil {
		t.Fatal("remote sentinel without password must be rejected")
	}
	cfg.Redis.Password = "s3cret"
	if err := ValidateRedisAuth(cfg); err != nil {
		t.Fatalf("sentinel with password must pass; got %v", err)
	}
}
