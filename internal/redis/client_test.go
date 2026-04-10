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

func streamValuesToMap(values []string) map[string]string {
	m := make(map[string]string)
	for i := 0; i < len(values)-1; i += 2 {
		m[values[i]] = values[i+1]
	}
	return m
}

func TestClient_SyncCapture(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	stream := "test:sync:out"
	c.EnableSync(stream)
	ctx := context.Background()

	// 1. Test SET (syncable: ban:*)
	c.Set(ctx, "ban:1.2.3.4", "test-ban", 1*time.Hour)
	msgs, _ := mr.Stream(stream)
	if len(msgs) != 1 {
		t.Fatalf("Sync SET: expected 1 message, got %d", len(msgs))
	}
	v := streamValuesToMap(msgs[0].Values)
	if v["op"] != "set" || v["key"] != "ban:1.2.3.4" {
		t.Errorf("Sync SET: wrong message values: %v", v)
	}

	// 2. Test SADD (syncable: ja4:whitelist)
	c.SAdd(ctx, "ja4:whitelist", "fp1")
	msgs, _ = mr.Stream(stream)
	if len(msgs) != 2 {
		t.Fatalf("Sync SADD: expected 2 messages total, got %d", len(msgs))
	}
	v = streamValuesToMap(msgs[1].Values)
	if v["op"] != "sadd" || v["key"] != "ja4:whitelist" {
		t.Errorf("Sync SADD: wrong message values: %v", v)
	}

	// 3. Test SREM (tombstone pattern: ja4:whitelist)
	c.SRem(ctx, "ja4:whitelist", "fp1")
	msgs, _ = mr.Stream(stream)
	// SRem should result in a SADD to :removals stream
	if len(msgs) != 3 {
		t.Fatalf("Sync SREM: expected 3 messages total, got %d", len(msgs))
	}
	v = streamValuesToMap(msgs[2].Values)
	if v["op"] != "sadd" || v["key"] != "ja4:whitelist:removals" {
		t.Errorf("Sync SREM tombstone: wrong message values: %v", v)
	}

	// 4. Test LOCAL-ONLY (should not sync)
	c.Set(ctx, "session:1.2.3.4", "data", 0)
	msgs, _ = mr.Stream(stream)
	if len(msgs) != 3 {
		t.Errorf("Sync LOCAL-ONLY: expected no new message, got %d", len(msgs))
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
