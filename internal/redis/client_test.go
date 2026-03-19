package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/sirupsen/logrus"
)

func newTestClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	c := New(Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	return c, mr
}

func TestClient_GetSet(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	ctx := context.Background()

	c.Set(ctx, "k1", "hello", 0)
	val, err := c.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "hello" {
		t.Errorf("Get: got %q, want %q", val, "hello")
	}
}

func TestClient_GetMissing(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	val, err := c.Get(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("Get missing key: %v", err)
	}
	if val != "" {
		t.Errorf("Get missing: got %q, want empty string", val)
	}
}

func TestClient_GetDial_Missing(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	// No dial key → fail open → 0 (monitor mode)
	dial := c.GetDial(context.Background())
	if dial != 0 {
		t.Errorf("GetDial missing: got %d, want 0", dial)
	}
}

func TestClient_GetDial_Set(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	ctx := context.Background()
	c.Set(ctx, "config:dial", "75", 0)

	dial := c.GetDial(ctx)
	if dial != 75 {
		t.Errorf("GetDial: got %d, want 75", dial)
	}
}

func TestClient_GetDial_Clamped(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	ctx := context.Background()
	c.Set(ctx, "config:dial", "200", 0)

	dial := c.GetDial(ctx)
	if dial != 100 {
		t.Errorf("GetDial clamped: got %d, want 100", dial)
	}
}

func TestClient_SIsMember(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	ctx := context.Background()
	mr.SAdd("myset", "member1") //nolint:errcheck // miniredis test setup

	if !c.SIsMember(ctx, "myset", "member1") {
		t.Error("SIsMember: expected true for present member")
	}
	if c.SIsMember(ctx, "myset", "absent") {
		t.Error("SIsMember: expected false for absent member")
	}
}

func TestClient_Ping(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestClient_FailOpen_RedisDown(t *testing.T) {
	// Point at a port that is not listening
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	c := New(Config{
		Host:    "127.0.0.1",
		Port:    19999,
		Timeout: 100 * time.Millisecond,
	}, log)

	ctx := context.Background()

	// Get should return empty, not panic
	val, err := c.Get(ctx, "key")
	if err != nil {
		t.Errorf("Get on down Redis: unexpected error %v (should fail open)", err)
	}
	if val != "" {
		t.Errorf("Get on down Redis: got %q, want empty", val)
	}

	// GetDial should return 0 (monitor mode — fail open)
	dial := c.GetDial(ctx)
	if dial != 0 {
		t.Errorf("GetDial on down Redis: got %d, want 0", dial)
	}

	// SIsMember should return false (fail open)
	if c.SIsMember(ctx, "set", "member") {
		t.Error("SIsMember on down Redis: should return false (fail open)")
	}
}
