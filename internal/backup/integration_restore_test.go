//go:build integration

// Real-Redis restore integration tests (Phase 315b).
//
//	REDIS_ADDR=localhost:6379 go test -tags integration ./internal/backup/
package backup

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// TestIntegration_RestoreRoundTrip backs up one key of every type, flushes, and
// restores via the real Restore() path (--include-blocks --force), asserting the
// values come back byte-identical.
func TestIntegration_RestoreRoundTrip(t *testing.T) {
	rdb := realRedis(t)
	ctx := context.Background()
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}
	rdb.Set(ctx, "config:dial", "42", 0)
	rdb.Set(ctx, "ban:9.9.9.9", "1", time.Hour)
	rdb.SAdd(ctx, "ja4:whitelist", "t13d_aaa", "t13d_bbb")
	rdb.ZAdd(ctx, "beacon:suspects", goredis.Z{Score: 1, Member: "x"})
	rdb.HSet(ctx, "management:policy_audit", "f1", "v1")

	want := map[string]string{}
	for _, k := range []string{"config:dial", "ban:9.9.9.9", "ja4:whitelist", "beacon:suspects", "management:policy_audit"} {
		want[k] = rdb.Dump(ctx, k).Val()
	}

	art := backupTo(t, rdb)
	res, err := newRestoreEngine(rdb).Restore(ctx, art, RestoreOptions{
		Passphrase: "pw", IncludeBlocks: true, Force: true,
	}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Restored == 0 {
		t.Fatal("nothing restored")
	}
	for k, w := range want {
		if got := rdb.Dump(ctx, k).Val(); got != w {
			t.Errorf("key %q did not round-trip", k)
		}
	}
}

// TestIntegration_RestoreSkipsErased proves a real restore never resurrects a
// subject erased after the backup (live erasure log, read pre-flush).
func TestIntegration_RestoreSkipsErased(t *testing.T) {
	rdb := realRedis(t)
	ctx := context.Background()
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}
	rdb.Set(ctx, "ban:1.2.3.4", "1", 0)
	rdb.Set(ctx, "ban:9.9.9.9", "1", 0)
	art := backupTo(t, rdb)

	// Post-backup: erase 1.2.3.4 (recorded in the live erasure log).
	entry, _ := json.Marshal(map[string]any{
		"timestamp": time.Now().Add(time.Second).UTC().Format(time.RFC3339),
		"ip":        "1.2.3.4",
		"dry_run":   false,
	})
	rdb.LPush(ctx, "management:gdpr_erasure_log", string(entry))

	res, err := newRestoreEngine(rdb).Restore(ctx, art, RestoreOptions{
		Passphrase: "pw", IncludeBlocks: true, Force: true,
	}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.SkippedErased != 1 {
		t.Errorf("SkippedErased: got %d want 1", res.SkippedErased)
	}
	if rdb.Exists(ctx, "ban:1.2.3.4").Val() != 0 {
		t.Error("erased subject 1.2.3.4 resurrected — GDPR breach")
	}
	if rdb.Exists(ctx, "ban:9.9.9.9").Val() != 1 {
		t.Error("non-erased ban 9.9.9.9 should have restored")
	}
}
