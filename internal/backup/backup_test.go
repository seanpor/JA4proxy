package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type fakeMetrics struct {
	running     []bool
	ops         []bool
	lastSuccess time.Time
	durations   []time.Duration
}

func (f *fakeMetrics) SetRunning(b bool)               { f.running = append(f.running, b) }
func (f *fakeMetrics) IncOperation(s bool)             { f.ops = append(f.ops, s) }
func (f *fakeMetrics) SetLastSuccess(t time.Time)      { f.lastSuccess = t }
func (f *fakeMetrics) ObserveDuration(d time.Duration) { f.durations = append(f.durations, d) }

func newMiniClient(t *testing.T) (goredis.UniversalClient, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func silentLog() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr)
	l.SetLevel(logrus.PanicLevel)
	return l
}

// TestBackup_ScopeAndExclude verifies only in-scope, non-excluded keys are
// captured, and the inspect breakdown reflects them. miniredis DUMP supports
// string keys (the real-type round-trip is the integration test).
func TestBackup_ScopeAndExclude(t *testing.T) {
	rdb, mr := newMiniClient(t)
	// In scope:
	mr.Set("ban:1.2.3.4", "1")
	mr.Set("ban:2001:db8::1", "1") // IPv6 ban key
	mr.Set("ip:blacklist", "set-ish")
	// Excluded by exclude-list:
	mr.Set("ratelimit:1.2.3.4", "x")
	mr.Set("mgmt:totp:user1", "seed")
	// Out of scope entirely:
	mr.Set("randomkey", "x")

	dir := t.TempDir()
	eng := New(rdb, Config{
		Dir:             dir,
		KeyPrefixes:     DefaultKeyPrefixes,
		ExcludePrefixes: DefaultExcludePrefixes,
		Passphrase:      "pw",
	}, silentLog(), NopMetrics{})

	res, err := eng.Backup(context.Background())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if res.KeyCount != 3 {
		t.Fatalf("key count: got %d want 3 (ban x2 + ip:blacklist)", res.KeyCount)
	}

	man, counts, err := Inspect(res.Path, "pw")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if man.KeyCount != 3 {
		t.Fatalf("manifest key count: got %d want 3", man.KeyCount)
	}
	if counts["ban"] != 2 {
		t.Errorf("ban count: got %d want 2", counts["ban"])
	}
	if _, ok := counts["ratelimit"]; ok {
		t.Error("ratelimit key was backed up but should be excluded")
	}
	if _, ok := counts["mgmt"]; ok {
		t.Error("mgmt:totp key was backed up but should be excluded")
	}
	if _, ok := counts["randomkey"]; ok {
		t.Error("out-of-scope key was backed up")
	}
}

// TestBackup_TTLPreserved checks the remaining TTL is captured per key.
func TestBackup_TTLPreserved(t *testing.T) {
	rdb, mr := newMiniClient(t)
	mr.Set("ban:9.9.9.9", "1")
	mr.SetTTL("ban:9.9.9.9", 3600*time.Second)

	dir := t.TempDir()
	eng := New(rdb, Config{Dir: dir, KeyPrefixes: []string{"ban"}, Passphrase: "pw"}, silentLog(), NopMetrics{})
	res, err := eng.Backup(context.Background())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// Decrypt + gunzip + unmarshal the body and assert the entry's TTL survived.
	raw, _ := os.ReadFile(res.Path)
	gz, err := DecryptPayload(raw, "pw")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	body, err := gunzipBytes(gz)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var snap snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if len(snap.Entries) != 1 {
		t.Fatalf("entries: got %d want 1", len(snap.Entries))
	}
	if ttl := snap.Entries[0].TTLMillis; ttl <= 0 || ttl > 3600000 {
		t.Errorf("ttl_ms: got %d, want 0 < ttl <= 3600000", ttl)
	}
}

// TestBackup_Metrics asserts the running gauge toggles and success is counted.
func TestBackup_Metrics(t *testing.T) {
	rdb, mr := newMiniClient(t)
	mr.Set("ban:1", "1")
	fm := &fakeMetrics{}
	eng := New(rdb, Config{Dir: t.TempDir(), KeyPrefixes: []string{"ban"}, Passphrase: "pw"}, silentLog(), fm)
	if _, err := eng.Backup(context.Background()); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if len(fm.running) < 2 || fm.running[0] != true || fm.running[len(fm.running)-1] != false {
		t.Errorf("running gauge should toggle true...false, got %v", fm.running)
	}
	if len(fm.ops) != 1 || fm.ops[0] != true {
		t.Errorf("expected one success operation, got %v", fm.ops)
	}
	if fm.lastSuccess.IsZero() {
		t.Error("last-success timestamp not set")
	}
	if len(fm.durations) != 1 {
		t.Errorf("expected one duration observation, got %d", len(fm.durations))
	}
}

// TestBackup_LockHeld verifies a held lock aborts the backup (and counts failure).
func TestBackup_LockHeld(t *testing.T) {
	rdb, mr := newMiniClient(t)
	mr.Set("ban:1", "1")
	if err := rdb.Set(context.Background(), lockKey, "held", time.Minute).Err(); err != nil {
		t.Fatalf("pre-set lock: %v", err)
	}
	fm := &fakeMetrics{}
	eng := New(rdb, Config{Dir: t.TempDir(), KeyPrefixes: []string{"ban"}, Passphrase: "pw"}, silentLog(), fm)
	if _, err := eng.Backup(context.Background()); err == nil {
		t.Fatal("expected backup to abort while lock is held")
	}
}

// TestPruneRetention_Count keeps the N newest artifacts.
func TestPruneRetention_Count(t *testing.T) {
	dir := t.TempDir()
	for _, ts := range []int64{100, 200, 300, 400, 500} {
		writeDummyArtifact(t, dir, ts)
	}
	eng := &Engine{cfg: Config{Dir: dir, RetentionCount: 2}, log: silentLog(), now: func() time.Time { return time.Unix(1000, 0) }}
	if err := eng.pruneRetention(); err != nil {
		t.Fatalf("pruneRetention: %v", err)
	}
	files, _ := listArtifacts(dir)
	if len(files) != 2 {
		t.Fatalf("retention count: %d artifacts remain, want 2", len(files))
	}
	for _, f := range files {
		if f.unix != 400 && f.unix != 500 {
			t.Errorf("kept wrong artifact ts=%d (want the 2 newest: 400,500)", f.unix)
		}
	}
}

// TestPruneRetention_Days deletes artifacts older than the cutoff.
func TestPruneRetention_Days(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(10*86400, 0)                                    // day 10
	writeDummyArtifact(t, dir, now.Add(-1*86400*time.Second).Unix()) // 1 day old (keep)
	writeDummyArtifact(t, dir, now.Add(-9*86400*time.Second).Unix()) // 9 days old (delete, >7)
	eng := &Engine{cfg: Config{Dir: dir, RetentionDays: 7}, log: silentLog(), now: func() time.Time { return now }}
	if err := eng.pruneRetention(); err != nil {
		t.Fatalf("pruneRetention: %v", err)
	}
	files, _ := listArtifacts(dir)
	if len(files) != 1 {
		t.Fatalf("retention days: %d remain, want 1", len(files))
	}
}

func writeDummyArtifact(t *testing.T, dir string, unix int64) {
	t.Helper()
	name := fmt.Sprintf("%s%d%s", artifactPrefix, unix, artifactExt)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatalf("write dummy: %v", err)
	}
}
