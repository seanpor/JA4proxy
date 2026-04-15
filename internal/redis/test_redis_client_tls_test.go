package redis

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/sirupsen/logrus"
)

// TestRedisClient_TLS_Enabled tests that when SSL=true in Config, the
// go-redis client's TLSConfig is set with MinVersion TLS 1.2 (201b).
func TestRedisClient_TLS_Enabled(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
		SSL:     true,
	}, log)
	defer c.Close()

	// Verify that rdb.Options().TLSConfig is not nil and has the right MinVersion.
	opts := c.rdb.Options()
	if opts.TLSConfig == nil {
		t.Fatal("SSL=true but TLSConfig is nil")
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSConfig.MinVersion = %d, want %d (TLS 1.2)", opts.TLSConfig.MinVersion, tls.VersionTLS12)
	}
}

// TestRedisClient_TLS_Disabled tests that when SSL=false, TLSConfig is nil.
func TestRedisClient_TLS_Disabled(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
		SSL:     false,
	}, log)
	defer c.Close()

	opts := c.rdb.Options()
	if opts.TLSConfig != nil {
		t.Error("SSL=false but TLSConfig is not nil")
	}
}

// TestRedisClient_TLS_Username tests that Username is passed through to
// goredis.Options when provided.
func TestRedisClient_TLS_Username(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:     mr.Host(),
		Port:     mr.Server().Addr().Port,
		Timeout:  2 * time.Second,
		SSL:      true,
		Username: "testuser",
	}, log)
	defer c.Close()

	opts := c.rdb.Options()
	if opts.Username != "testuser" {
		t.Errorf("Username = %q, want %q", opts.Username, "testuser")
	}
}

// TestRedisClient_TLS_Sentinel tests that Sentinel mode also supports SSL
// with the correct TLS configuration.
func TestRedisClient_TLS_Sentinel(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		MasterName: "mymaster",
		Sentinels:  []string{"sentinel1:26379", "sentinel2:26379"},
		DB:         0,
		Password:   "secret",
		Timeout:    2 * time.Second,
		SSL:        true,
		Username:   "sentinel-user",
	}, log)
	defer c.Close()

	// For failover clients, use FailoverOptions.
	fopts := c.rdb.FailoverOptions()
	if fopts.TLSConfig == nil {
		t.Fatal("SSL=true in sentinel mode but TLSConfig is nil")
	}
	if fopts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSConfig.MinVersion = %d, want %d (TLS 1.2)", fopts.TLSConfig.MinVersion, tls.VersionTLS12)
	}
	if fopts.Username != "sentinel-user" {
		t.Errorf("Username = %q, want %q", fopts.Username, "sentinel-user")
	}
}

// TestRedisClient_TLS_ExistingOpsStillWork verifies that Get, Set, SIsMember,
// etc. continue to work correctly when TLS is configured (even though
// miniredis doesn't actually use TLS — we're testing the code path isn't
// broken by the SSL flag).
func TestRedisClient_TLS_ExistingOpsStillWork(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
		SSL:     true,
	}, log)
	defer c.Close()

	ctx := context.Background()

	// Test Set/Get
	c.Set(ctx, "tls-key", "tls-value", 0)
	val, err := c.Get(ctx, "tls-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "tls-value" {
		t.Errorf("Get: got %q, want %q", val, "tls-value")
	}

	// Test SIsMember
	mr.SAdd("tls-set", "member1") //nolint:errcheck // miniredis test setup
	if !c.SIsMember(ctx, "tls-set", "member1") {
		t.Error("SIsMember: expected true for present member")
	}

	// Test SMembers
	members := c.SMembers(ctx, "tls-set")
	if len(members) != 1 || members[0] != "member1" {
		t.Errorf("SMembers: got %v, want [member1]", members)
	}

	// Test Ping
	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}

	// Test SlidingWindowSHA (should work even with SSL flag)
	sha := c.SlidingWindowSHA()
	if sha == "" {
		t.Error("SlidingWindowSHA should be non-empty after successful init")
	}
}
