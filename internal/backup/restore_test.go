package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type fakeRestoreMetrics struct {
	running   []bool
	ops       []bool
	durations []time.Duration
	skipped   map[string]int
}

func (f *fakeRestoreMetrics) SetRunning(b bool)               { f.running = append(f.running, b) }
func (f *fakeRestoreMetrics) IncOperation(s bool)             { f.ops = append(f.ops, s) }
func (f *fakeRestoreMetrics) ObserveDuration(d time.Duration) { f.durations = append(f.durations, d) }
func (f *fakeRestoreMetrics) IncSkipped(r string) {
	if f.skipped == nil {
		f.skipped = map[string]int{}
	}
	f.skipped[r]++
}

// backupTo writes a backup artifact from rdb's current contents and returns its path.
func backupTo(t *testing.T, rdb goredis.UniversalClient) string {
	t.Helper()
	eng := New(rdb, Config{Dir: t.TempDir(), KeyPrefixes: DefaultKeyPrefixes, Passphrase: "pw"}, silentLog(), NopMetrics{})
	res, err := eng.Backup(context.Background())
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	return res.Path
}

func newRestoreEngine(rdb goredis.UniversalClient) *Engine {
	return New(rdb, Config{}, silentLog(), NopMetrics{})
}

// TestRestore_BlockGatedByDefault — the core asymmetry: a snapshot full of bans
// must NOT re-block anyone by default; allow-state restores.
func TestRestore_BlockGatedByDefault(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ban:1.2.3.4", "1")
	srcMr.Set("ip:whitelist", "w")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw"}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.SkippedBlocks != 1 {
		t.Errorf("SkippedBlocks: got %d want 1", res.SkippedBlocks)
	}
	if res.Restored != 1 {
		t.Errorf("Restored: got %d want 1 (ip:whitelist)", res.Restored)
	}
	if dst.Exists(ctx, "ban:1.2.3.4").Val() != 0 {
		t.Error("ban was restored by default — must be gated")
	}
	if dst.Exists(ctx, "ip:whitelist").Val() != 1 {
		t.Error("allow-state ip:whitelist was not restored")
	}
}

// TestRestore_IncludeBlocks restores block-state when explicitly asked.
func TestRestore_IncludeBlocks(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ban:1.2.3.4", "1")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw", IncludeBlocks: true}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.SkippedBlocks != 0 || res.Restored != 1 {
		t.Errorf("got skipped=%d restored=%d, want 0/1", res.SkippedBlocks, res.Restored)
	}
	if dst.Exists(ctx, "ban:1.2.3.4").Val() != 1 {
		t.Error("ban not restored with --include-blocks")
	}
}

// TestRestore_GDPRTombstoneFile — an erased subject is never resurrected (via file).
func TestRestore_GDPRTombstoneFile(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ban:1.2.3.4", "1")
	srcMr.Set("ban:9.9.9.9", "1")
	art := backupTo(t, src)
	ctx := context.Background()

	tomb := filepath.Join(t.TempDir(), "tomb.txt")
	if err := os.WriteFile(tomb, []byte("# erased subjects\n1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst, _ := newMiniClient(t)
	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{
		Passphrase: "pw", IncludeBlocks: true, TombstoneFile: tomb,
	}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.SkippedErased != 1 {
		t.Errorf("SkippedErased: got %d want 1", res.SkippedErased)
	}
	if dst.Exists(ctx, "ban:1.2.3.4").Val() != 0 {
		t.Error("ERASED subject 1.2.3.4 was resurrected — GDPR breach")
	}
	if dst.Exists(ctx, "ban:9.9.9.9").Val() != 1 {
		t.Error("non-erased ban 9.9.9.9 should have restored")
	}
}

// TestRestore_GDPRLiveLogPreFlush — tombstones from the live erasure log are read
// BEFORE --force FLUSHDB destroys it.
func TestRestore_GDPRLiveLogPreFlush(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ban:1.2.3.4", "1")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	// Seed the TARGET's erasure log with a post-backup erasure of 1.2.3.4.
	entry, _ := json.Marshal(map[string]any{
		"timestamp": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"ip":        "1.2.3.4",
		"dry_run":   false,
	})
	dst.LPush(ctx, "management:gdpr_erasure_log", string(entry))

	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{
		Passphrase: "pw", IncludeBlocks: true, Force: true, // force needed: target non-empty
	}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.SkippedErased != 1 {
		t.Errorf("SkippedErased: got %d want 1 (read pre-flush)", res.SkippedErased)
	}
	if dst.Exists(ctx, "ban:1.2.3.4").Val() != 0 {
		t.Error("erased subject resurrected despite live erasure-log tombstone")
	}
}

// TestRestore_DryRunWritesNothing previews without touching Redis.
func TestRestore_DryRunWritesNothing(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ip:whitelist", "w")
	srcMr.Set("ban:1.2.3.4", "1")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw", DryRun: true, IncludeBlocks: true}, NopRestoreMetrics{})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Restored != 2 {
		t.Errorf("dry-run would-restore: got %d want 2", res.Restored)
	}
	if n, _ := dst.DBSize(ctx).Result(); n != 0 {
		t.Errorf("dry-run wrote %d keys, want 0", n)
	}
}

// TestRestore_NonEmptyTargetNeedsForce refuses to clobber populated Redis.
func TestRestore_NonEmptyTargetNeedsForce(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ip:whitelist", "w")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, dstMr := newMiniClient(t)
	dstMr.Set("existing", "x")
	if _, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw"}, NopRestoreMetrics{}); err == nil {
		t.Fatal("expected refusal to restore onto a non-empty target without --force")
	}
}

// TestRestore_TamperedArtifactFailsClosed never writes from a corrupt artifact.
func TestRestore_TamperedArtifactFailsClosed(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ip:whitelist", "w")
	art := backupTo(t, src)
	raw, _ := os.ReadFile(art)
	raw[len(raw)-1] ^= 0xFF
	tampered := art + ".bad"
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dst, _ := newMiniClient(t)
	if _, err := newRestoreEngine(dst).Restore(ctx, tampered, RestoreOptions{Passphrase: "pw"}, NopRestoreMetrics{}); err == nil {
		t.Fatal("tampered artifact should fail closed")
	}
	if n, _ := dst.DBSize(ctx).Result(); n != 0 {
		t.Errorf("tampered restore wrote %d keys, want 0", n)
	}
}

// TestRestore_SchemaDowngradeBlock refuses a backup newer than this binary.
func TestRestore_SchemaDowngradeBlock(t *testing.T) {
	// Hand-craft an artifact with a bumped schema version.
	snap := snapshot{Manifest: Manifest{SchemaVersion: schemaVersion + 1, CreatedAt: time.Now().UTC()}}
	body, _ := json.Marshal(&snap)
	gz, _ := gzipBytes(body)
	art, _ := EncryptPayload(gz, "pw")
	path := filepath.Join(t.TempDir(), "future.bin")
	if err := os.WriteFile(path, art, 0o600); err != nil {
		t.Fatal(err)
	}
	dst, _ := newMiniClient(t)
	if _, err := newRestoreEngine(dst).Restore(context.Background(), path, RestoreOptions{Passphrase: "pw"}, NopRestoreMetrics{}); err == nil {
		t.Fatal("expected refusal of a newer-schema artifact")
	}
}

// TestRestore_AuditAndMetrics checks the audit trail and metric toggles.
func TestRestore_AuditAndMetrics(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ip:whitelist", "w")
	srcMr.Set("ban:1.2.3.4", "1")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	fm := &fakeRestoreMetrics{}
	res, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw"}, fm)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// Audit trail written.
	if dst.Exists(ctx, "backup:last_restore").Val() != 1 {
		t.Error("backup:last_restore not written")
	}
	if n := dst.LLen(ctx, "management:policy_audit").Val(); n < 1 {
		t.Error("no policy_audit entry written for the restore")
	}
	entry := dst.LIndex(ctx, "management:policy_audit", 0).Val()
	if !bytes.Contains([]byte(entry), []byte("backup.restored")) {
		t.Errorf("policy_audit entry missing action type: %s", entry)
	}
	// Metrics toggled.
	if len(fm.running) < 2 || fm.running[0] != true || fm.running[len(fm.running)-1] != false {
		t.Errorf("running gauge should toggle true..false, got %v", fm.running)
	}
	if len(fm.ops) != 1 || !fm.ops[0] {
		t.Errorf("expected one success op, got %v", fm.ops)
	}
	if fm.skipped["block_gated"] != 1 {
		t.Errorf("expected 1 block_gated skip, got %v", fm.skipped)
	}
	_ = res
}

// TestRestore_LockHeld aborts while the operation lock is held.
func TestRestore_LockHeld(t *testing.T) {
	src, srcMr := newMiniClient(t)
	srcMr.Set("ip:whitelist", "w")
	art := backupTo(t, src)
	ctx := context.Background()

	dst, _ := newMiniClient(t)
	dst.Set(ctx, lockKey, "held", time.Minute)
	if _, err := newRestoreEngine(dst).Restore(ctx, art, RestoreOptions{Passphrase: "pw"}, NopRestoreMetrics{}); err == nil {
		t.Fatal("expected restore to abort while the lock is held")
	}
}
