package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// erasureLogKey is the GDPR Right-to-Erasure audit list written by
// scripts/gdpr_delete.py (LPUSH, last 1000). Each entry is JSON
// {timestamp, ip, dry_run, ...}. The restore reads it to build the tombstone set.
const erasureLogKey = "management:gdpr_erasure_log"

// policyAuditKey records every policy change; a restore is a big one.
const policyAuditKey = "management:policy_audit"

// RestoreOptions controls a restore run. The zero value is the safe default:
// allow-state only, no clobber, write for real.
type RestoreOptions struct {
	Passphrase    string
	IncludeBlocks bool   // also restore block-state (bans, blacklists, dial)
	Force         bool   // FLUSHDB a non-empty target before restoring
	DryRun        bool   // report only; write nothing
	TombstoneFile string // host-mounted file of IPs that must never be resurrected
	Actor         string // who ran the restore (for the audit trail)
	ProxyVersion  string // current build, for the config-divergence warning
	ConfigHash    string // current config hash, for the config-divergence warning
}

// RestoreResult summarises a completed restore.
type RestoreResult struct {
	SourcePath    string
	Restored      int
	SkippedBlocks int
	SkippedErased int
	DryRun        bool
	StartedAt     time.Time
	FinishedAt    time.Time
}

// Duration returns the wall-clock restore duration.
func (r *RestoreResult) Duration() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// RestoreMetrics is the engine's view of the restore Prometheus series.
type RestoreMetrics interface {
	SetRunning(running bool)
	IncOperation(success bool)
	ObserveDuration(d time.Duration)
	IncSkipped(reason string)
}

// NopRestoreMetrics records nothing.
type NopRestoreMetrics struct{}

func (NopRestoreMetrics) SetRunning(bool)               {}
func (NopRestoreMetrics) IncOperation(bool)             {}
func (NopRestoreMetrics) ObserveDuration(time.Duration) {}
func (NopRestoreMetrics) IncSkipped(string)             {}

// tombstones is the set of canonical IPs that must never be resurrected.
type tombstones struct{ ips map[string]struct{} }

func (t tombstones) erased(canonicalIP string) bool {
	_, ok := t.ips[canonicalIP]
	return ok
}

// Restore loads a 315a artifact back into Redis with the safety guard-rails:
// allow-state by default (block-state only with IncludeBlocks), never resurrects
// a GDPR-erased subject, integrity-verified, audited, locked. A failure is
// fail-safe (logs, counts failure, releases the lock, returns an error).
func (e *Engine) Restore(ctx context.Context, artifactPath string, opts RestoreOptions, m RestoreMetrics) (res *RestoreResult, err error) {
	if m == nil {
		m = NopRestoreMetrics{}
	}
	if opts.Passphrase == "" {
		return nil, errors.New("restore: decryption passphrase is required")
	}

	// 1. Decrypt + verify + unpack BEFORE touching Redis (D3: fail closed).
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("restore: reading artifact: %w", err)
	}
	gz, err := DecryptPayload(raw, opts.Passphrase)
	if err != nil {
		return nil, err // wrong key / tampered / truncated — already fail-closed
	}
	body, err := gunzipBytes(gz)
	if err != nil {
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("restore: parsing snapshot: %w", err)
	}

	// 2. Schema downgrade-block: refuse a backup newer than this binary understands.
	if snap.Manifest.SchemaVersion > schemaVersion {
		return nil, fmt.Errorf("restore: artifact schema v%d is newer than supported v%d — upgrade ja4proxy", snap.Manifest.SchemaVersion, schemaVersion)
	}

	// 3. Config-divergence: WARN only (restore is a deliberate manual op).
	if opts.ConfigHash != "" && snap.Manifest.ConfigHash != "" && opts.ConfigHash != snap.Manifest.ConfigHash {
		e.log.WithFields(map[string]interface{}{
			"backup_config_hash": snap.Manifest.ConfigHash,
			"active_config_hash": opts.ConfigHash,
		}).Warn("restore: active config differs from the backup's — proceeding")
	}

	// 4. Lock (D7) — abort if a backup or another restore holds it.
	ok, lerr := e.rdb.SetNX(ctx, lockKey, e.now().UTC().Format(time.RFC3339), lockTTL).Result()
	if lerr != nil {
		return nil, fmt.Errorf("restore: acquiring lock: %w", lerr)
	}
	if !ok {
		return nil, errors.New("restore: another backup/restore is in progress (lock held)")
	}
	defer func() { _ = e.rdb.Del(context.Background(), lockKey).Err() }()

	m.SetRunning(true)
	defer m.SetRunning(false)
	started := e.now()
	defer func() {
		if err != nil {
			m.IncOperation(false)
		}
	}()

	// 5. Build the tombstone set — READ THE LIVE ERASURE LOG NOW, before any
	//    --force FLUSHDB would destroy it (D9), merged with the --tombstone-file.
	tomb, err := e.loadTombstones(ctx, opts.TombstoneFile, snap.Manifest.CreatedAt)
	if err != nil {
		return nil, err
	}

	// 6. Refuse to clobber a populated target without --force (D4). DBSize includes
	//    the operation_lock we hold (step 4), so >1 means real pre-existing data.
	if !opts.DryRun && !opts.Force {
		n, derr := e.rdb.DBSize(ctx).Result()
		if derr != nil {
			return nil, fmt.Errorf("restore: checking target size: %w", derr)
		}
		if n > 1 {
			return nil, fmt.Errorf("restore: target Redis is not empty (%d keys) — use --force to flush and replace", n-1)
		}
	}

	// 7. FLUSHDB only on an explicit --force (and never on --dry-run).
	if opts.Force && !opts.DryRun {
		if ferr := e.rdb.FlushDB(ctx).Err(); ferr != nil {
			return nil, fmt.Errorf("restore: flushing target: %w", ferr)
		}
	}

	// 8. Restore entries, gated + tombstoned, paced in batches.
	res = &RestoreResult{SourcePath: artifactPath, DryRun: opts.DryRun, StartedAt: started}
	for i := 0; i < len(snap.Entries); i += e.cfg.BatchSize {
		end := i + e.cfg.BatchSize
		if end > len(snap.Entries) {
			end = len(snap.Entries)
		}
		if rerr := e.restoreBatch(ctx, snap.Entries[i:end], opts, tomb, m, res); rerr != nil {
			return nil, rerr
		}
		if e.cfg.BatchDelay > 0 && end < len(snap.Entries) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(e.cfg.BatchDelay):
			}
		}
	}

	// 9. Audit (unless dry-run): policy_audit + backup:last_restore / restored_from.
	if !opts.DryRun {
		if aerr := e.writeRestoreAudit(ctx, res, opts); aerr != nil {
			e.log.WithError(aerr).Warn("restore: writing audit trail failed (restore itself succeeded)")
		}
	}

	res.FinishedAt = e.now()
	m.IncOperation(true)
	m.ObserveDuration(res.FinishedAt.Sub(started))
	e.log.WithFields(map[string]interface{}{
		"restored":       res.Restored,
		"skipped_blocks": res.SkippedBlocks,
		"skipped_erased": res.SkippedErased,
		"dry_run":        res.DryRun,
	}).Info("restore: completed")
	return res, nil
}

// restoreBatch classifies, gates and restores one batch of entries.
func (e *Engine) restoreBatch(ctx context.Context, entries []Entry, opts RestoreOptions, tomb tombstones, m RestoreMetrics, res *RestoreResult) error {
	for _, ent := range entries {
		// Block-state is gated behind --include-blocks (D1) — never re-block by default.
		if ClassifyKey(ent.Key) == ClassBlock && !opts.IncludeBlocks {
			res.SkippedBlocks++
			m.IncSkipped("block_gated")
			continue
		}
		// Never resurrect a GDPR-erased subject (D2).
		if ip, isSubject := SubjectIP(ent.Key); isSubject && tomb.erased(ip) {
			res.SkippedErased++
			m.IncSkipped("erased")
			continue
		}
		if opts.DryRun {
			res.Restored++ // would-restore count
			continue
		}
		ttl := time.Duration(0) // 0 = no expiry
		if ent.TTLMillis > 0 {
			ttl = time.Duration(ent.TTLMillis) * time.Millisecond
		}
		if err := e.rdb.RestoreReplace(ctx, ent.Key, ttl, string(ent.Payload)).Err(); err != nil {
			return fmt.Errorf("restore: RESTORE %q: %w", ent.Key, err)
		}
		res.Restored++
	}
	return nil
}

// loadTombstones builds the set of IPs that must not be resurrected: from the
// live erasure log (entries newer than the backup) and the optional host-mounted
// tombstone file (every IP listed, unconditionally).
func (e *Engine) loadTombstones(ctx context.Context, file string, backupCreatedAt time.Time) (tombstones, error) {
	t := tombstones{ips: make(map[string]struct{})}

	// Live erasure log — read NOW (pre-flush). Best-effort: a Redis error here
	// must not abort a disaster-recovery restore, but we log it loudly.
	entries, err := e.rdb.LRange(ctx, erasureLogKey, 0, -1).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		e.log.WithError(err).Warn("restore: reading erasure log for tombstones failed; relying on --tombstone-file")
	}
	for _, raw := range entries {
		var rec struct {
			IP        string `json:"ip"`
			Timestamp string `json:"timestamp"`
			DryRun    bool   `json:"dry_run"`
		}
		if json.Unmarshal([]byte(raw), &rec) != nil || rec.DryRun || rec.IP == "" {
			continue
		}
		// Only erasures AFTER the backup matter: earlier ones aren't in the artifact.
		if ts, perr := time.Parse(time.RFC3339, rec.Timestamp); perr == nil {
			if !ts.After(backupCreatedAt) {
				continue
			}
		}
		if canon, ok := canonicalIP(rec.IP); ok {
			t.ips[canon] = struct{}{}
		}
	}

	// Tombstone file — every listed IP is skipped unconditionally.
	if file != "" {
		f, ferr := os.Open(file)
		if ferr != nil {
			return t, fmt.Errorf("restore: opening tombstone file: %w", ferr)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Allow "<ip>" or "<ip> <anything>"; take the first field.
			if sp := strings.IndexAny(line, " \t"); sp >= 0 {
				line = line[:sp]
			}
			if canon, ok := canonicalIP(line); ok {
				t.ips[canon] = struct{}{}
			} else {
				e.log.WithField("line", line).Warn("restore: ignoring non-IP line in tombstone file")
			}
		}
		if serr := sc.Err(); serr != nil {
			return t, fmt.Errorf("restore: reading tombstone file: %w", serr)
		}
	}
	return t, nil
}

// writeRestoreAudit records the restore in management:policy_audit and the
// backup:last_restore / backup:restored_from keys (REDIS_SCHEMA).
func (e *Engine) writeRestoreAudit(ctx context.Context, res *RestoreResult, opts RestoreOptions) error {
	now := e.now().UTC()
	actor := opts.Actor
	if actor == "" {
		actor = "ja4p restore"
	}
	auditEntry, _ := json.Marshal(map[string]interface{}{
		"timestamp":      now.Format(time.RFC3339),
		"action_type":    "backup.restored",
		"actor_id":       actor,
		"source":         res.SourcePath,
		"restored":       res.Restored,
		"skipped_blocks": res.SkippedBlocks,
		"skipped_erased": res.SkippedErased,
		"include_blocks": opts.IncludeBlocks,
	})
	pipe := e.rdb.Pipeline()
	pipe.LPush(ctx, policyAuditKey, string(auditEntry))
	pipe.LTrim(ctx, policyAuditKey, 0, 999)
	pipe.Set(ctx, "backup:last_restore", now.Format(time.RFC3339), 0)
	restoredFrom, _ := json.Marshal(map[string]interface{}{
		"filename":    res.SourcePath,
		"restored_at": now.Format(time.RFC3339),
		"keys_count":  res.Restored,
		"actor":       actor,
	})
	pipe.Set(ctx, "backup:restored_from", string(restoredFrom), 0)
	_, err := pipe.Exec(ctx)
	return err
}

// canonicalIP parses s as an IP and returns its canonical string form.
func canonicalIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return addr.String(), true
}
