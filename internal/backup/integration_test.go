//go:build integration

// Real-Redis integration test (Phase 315a, decision D2). miniredis only supports
// DUMP for string keys, so the every-type + IPv6 round-trip — the test that
// actually proves the artifact is restorable — must run against a real Redis.
//
//	REDIS_ADDR=localhost:6379 go test -tags integration ./internal/backup/
package backup

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

func realRedis(t *testing.T) goredis.UniversalClient {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	c := goredis.NewClient(&goredis.Options{Addr: addr})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Skipf("no real Redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestIntegration_EveryTypeRoundTrip backs up one key of every Redis type plus
// an IPv6 ban key, then RESTOREs the dumped values into a flushed DB and asserts
// they come back byte-identical with TTLs preserved.
func TestIntegration_EveryTypeRoundTrip(t *testing.T) {
	rdb := realRedis(t)
	ctx := context.Background()
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}

	// Populate one key of every type, all under in-scope prefixes.
	rdb.Set(ctx, "config:dial", "42", 0)
	rdb.Set(ctx, "ban:9.9.9.9", "1", time.Hour) // string + TTL
	rdb.Set(ctx, "ban:2001:db8::dead:beef", "1", 0)
	rdb.RPush(ctx, "blocklist:list", "a", "b", "c")
	rdb.SAdd(ctx, "ja4:blacklist", "t13d_aaa", "t13d_bbb")
	rdb.ZAdd(ctx, "beacon:suspects", goredis.Z{Score: 1, Member: "x"}, goredis.Z{Score: 2, Member: "y"})
	rdb.HSet(ctx, "management:policy_audit", "f1", "v1", "f2", "v2")

	// Capture originals for comparison.
	want := map[string]string{}
	for _, k := range []string{"config:dial", "ban:9.9.9.9", "ban:2001:db8::dead:beef", "blocklist:list", "ja4:blacklist", "beacon:suspects", "management:policy_audit"} {
		d, err := rdb.Dump(ctx, k).Result()
		if err != nil {
			t.Fatalf("seed dump %q: %v", k, err)
		}
		want[k] = d
	}

	eng := New(rdb, Config{
		Dir:         t.TempDir(),
		KeyPrefixes: DefaultKeyPrefixes,
		Passphrase:  "integration-pw",
	}, silentLog(), NopMetrics{})
	res, err := eng.Backup(ctx)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if res.KeyCount != len(want) {
		t.Fatalf("key count: got %d want %d", res.KeyCount, len(want))
	}

	// Decrypt the artifact and RESTORE each entry into a flushed DB.
	raw, _ := os.ReadFile(res.Path)
	gz, err := DecryptPayload(raw, "integration-pw")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	body, err := gunzipBytes(gz)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var snap snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushdb pre-restore: %v", err)
	}
	for _, e := range snap.Entries {
		ttl := time.Duration(0)
		if e.TTLMillis > 0 {
			ttl = time.Duration(e.TTLMillis) * time.Millisecond
		}
		if err := rdb.RestoreReplace(ctx, e.Key, ttl, string(e.Payload)).Err(); err != nil {
			t.Fatalf("restore %q: %v", e.Key, err)
		}
	}

	// Every key must come back, and re-DUMP equal to the original.
	for k, w := range want {
		got, err := rdb.Dump(ctx, k).Result()
		if err != nil {
			t.Fatalf("post-restore dump %q: %v", k, err)
		}
		if got != w {
			t.Errorf("key %q did not round-trip identically", k)
		}
	}
	// TTL preserved (with slack) on the TTL'd key.
	if d := rdb.TTL(ctx, "ban:9.9.9.9").Val(); d <= 0 || d > time.Hour {
		t.Errorf("ban:9.9.9.9 TTL not preserved: %v", d)
	}
}
