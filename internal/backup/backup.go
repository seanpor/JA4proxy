package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// schemaVersion is the artifact schema version. Bump when the manifest/entry
// shape changes in a way restore (315b) must migrate.
const schemaVersion = 1

// lockKey is the distributed lock guarding backup/restore against concurrent
// runs producing a torn artifact. Documented in docs/REDIS_SCHEMA.md.
const lockKey = "backup:operation_lock"
const lockTTL = 600 * time.Second

// artifactPrefix / artifactExt frame the on-disk filename:
// ja4proxy-backup-<unix>.bin.
const (
	artifactPrefix = "ja4proxy-backup-"
	artifactExt    = ".bin"
)

// Config controls a backup run. All fields have safe, conservative defaults
// applied by New when zero.
type Config struct {
	Dir             string        // destination directory (created 0700)
	KeyPrefixes     []string      // security-state prefixes to back up (SCAN MATCH prefix*)
	ExcludePrefixes []string      // prefixes to skip (ephemeral + credential/session keys)
	RetentionCount  int           // keep at most N newest artifacts (0 = unlimited)
	RetentionDays   int           // delete artifacts older than this many days (0 = unlimited)
	BatchSize       int           // SCAN/pipeline batch size (default 100)
	BatchDelay      time.Duration // sleep between batches to spare the Redis thread (default 10ms)
	Passphrase      string        // encryption passphrase (required)
	ProxyVersion    string        // build version, recorded in the manifest
	ConfigHash      string        // active-config SHA-256, recorded in the manifest
}

// Manifest is the metadata header stored (gzipped, encrypted) alongside the entries.
type Manifest struct {
	CreatedAt     time.Time `json:"created_at"`
	KeyCount      int       `json:"key_count"`
	SchemaVersion int       `json:"schema_version"`
	ProxyVersion  string    `json:"proxy_version"`
	ConfigHash    string    `json:"config_hash"`
}

// Entry is one backed-up key: its value (Redis DUMP bytes) and its remaining TTL.
// TTLMillis follows Redis PTTL semantics: -1 = no expiry, >0 = ms remaining.
type Entry struct {
	Key       string `json:"key"`
	TTLMillis int64  `json:"ttl_ms"`
	Payload   []byte `json:"payload"` // raw DUMP bytes (base64-encoded by encoding/json)
}

// snapshot is the full decrypted body: manifest + entries.
type snapshot struct {
	Manifest Manifest `json:"manifest"`
	Entries  []Entry  `json:"entries"`
}

// Result summarises a completed backup for the caller (CLI) to report and to
// emit as a textfile-collector .prom.
type Result struct {
	Path       string
	KeyCount   int
	StartedAt  time.Time
	FinishedAt time.Time
}

// Duration returns the wall-clock backup duration.
func (r *Result) Duration() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// Metrics is the engine's view of the Prometheus series the backup alerts
// watch. Injected so the engine is unit-testable without the global registry.
type Metrics interface {
	SetRunning(running bool)
	IncOperation(success bool)
	SetLastSuccess(t time.Time)
	ObserveDuration(d time.Duration)
}

// NopMetrics is a Metrics that records nothing.
type NopMetrics struct{}

func (NopMetrics) SetRunning(bool)               {}
func (NopMetrics) IncOperation(bool)             {}
func (NopMetrics) SetLastSuccess(time.Time)      {}
func (NopMetrics) ObserveDuration(time.Duration) {}

// Engine performs encrypted Redis backups.
type Engine struct {
	rdb     goredis.UniversalClient
	cfg     Config
	log     logrus.FieldLogger
	metrics Metrics
	now     func() time.Time // injectable clock for tests
}

// New builds an Engine, applying conservative defaults for unset Config fields.
func New(rdb goredis.UniversalClient, cfg Config, log logrus.FieldLogger, m Metrics) *Engine {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchDelay <= 0 {
		cfg.BatchDelay = 10 * time.Millisecond
	}
	if log == nil {
		log = logrus.New()
	}
	if m == nil {
		m = NopMetrics{}
	}
	return &Engine{rdb: rdb, cfg: cfg, log: log, metrics: m, now: time.Now}
}

// Backup acquires the operation lock, snapshots the configured key scope into an
// encrypted artifact, prunes old artifacts per retention, and updates metrics.
// A failure never touches live traffic — it logs, counts a failure, releases the
// lock and returns an error (fail-safe).
func (e *Engine) Backup(ctx context.Context) (res *Result, err error) {
	if e.cfg.Passphrase == "" {
		return nil, errors.New("backup: encryption passphrase is required")
	}
	if len(e.cfg.KeyPrefixes) == 0 {
		return nil, errors.New("backup: no key_prefixes configured")
	}

	// Acquire the lock; abort if held (another backup or a restore is running).
	ok, lerr := e.rdb.SetNX(ctx, lockKey, e.now().UTC().Format(time.RFC3339), lockTTL).Result()
	if lerr != nil {
		return nil, fmt.Errorf("backup: acquiring lock: %w", lerr)
	}
	if !ok {
		return nil, errors.New("backup: another backup/restore is in progress (lock held)")
	}
	defer func() { _ = e.rdb.Del(context.Background(), lockKey).Err() }()

	e.metrics.SetRunning(true)
	defer e.metrics.SetRunning(false) // runs even on panic/crash unwind
	started := e.now()

	// On any error path: count a failure. On success: count success + last-success.
	defer func() {
		if err != nil {
			e.metrics.IncOperation(false)
		}
	}()

	entries, err := e.collect(ctx)
	if err != nil {
		return nil, err
	}

	snap := snapshot{
		Manifest: Manifest{
			CreatedAt:     started.UTC(),
			KeyCount:      len(entries),
			SchemaVersion: schemaVersion,
			ProxyVersion:  e.cfg.ProxyVersion,
			ConfigHash:    e.cfg.ConfigHash,
		},
		Entries: entries,
	}

	body, err := json.Marshal(&snap)
	if err != nil {
		return nil, fmt.Errorf("backup: marshalling snapshot: %w", err)
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return nil, err
	}
	artifact, err := EncryptPayload(gz, e.cfg.Passphrase)
	if err != nil {
		return nil, err
	}

	path, err := e.writeArtifact(artifact, started)
	if err != nil {
		return nil, err
	}

	if perr := e.pruneRetention(); perr != nil {
		// Pruning failure must not fail the backup itself — the artifact is written.
		e.log.WithError(perr).Warn("backup: retention prune failed")
	}

	finished := e.now()
	e.metrics.IncOperation(true)
	e.metrics.SetLastSuccess(finished)
	e.metrics.ObserveDuration(finished.Sub(started))

	res = &Result{Path: path, KeyCount: len(entries), StartedAt: started, FinishedAt: finished}
	e.log.WithFields(logrus.Fields{
		"path":     path,
		"keys":     len(entries),
		"duration": finished.Sub(started).String(),
	}).Info("backup: completed")
	return res, nil
}

// collect SCANs each configured prefix and pipelines PTTL+DUMP per batch,
// yielding the Redis CPU between batches.
func (e *Engine) collect(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	seen := make(map[string]struct{})

	for _, prefix := range e.cfg.KeyPrefixes {
		var cursor uint64
		match := prefix + "*"
		for {
			keys, next, err := e.rdb.Scan(ctx, cursor, match, int64(e.cfg.BatchSize)).Result()
			if err != nil {
				return nil, fmt.Errorf("backup: SCAN %q: %w", match, err)
			}
			cursor = next

			batch := keys[:0:0]
			for _, k := range keys {
				if _, dup := seen[k]; dup {
					continue
				}
				if e.excluded(k) {
					continue
				}
				seen[k] = struct{}{}
				batch = append(batch, k)
			}
			if len(batch) > 0 {
				got, err := e.dumpBatch(ctx, batch)
				if err != nil {
					return nil, err
				}
				entries = append(entries, got...)
				if e.cfg.BatchDelay > 0 {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(e.cfg.BatchDelay):
					}
				}
			}
			if cursor == 0 {
				break
			}
		}
	}
	return entries, nil
}

// dumpBatch pipelines PTTL + DUMP for a batch of keys.
func (e *Engine) dumpBatch(ctx context.Context, keys []string) ([]Entry, error) {
	pipe := e.rdb.Pipeline()
	ttlCmds := make([]*goredis.DurationCmd, len(keys))
	dumpCmds := make([]*goredis.StringCmd, len(keys))
	for i, k := range keys {
		ttlCmds[i] = pipe.PTTL(ctx, k)
		dumpCmds[i] = pipe.Dump(ctx, k)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, goredis.Nil) {
		return nil, fmt.Errorf("backup: pipeline DUMP: %w", err)
	}

	out := make([]Entry, 0, len(keys))
	for i, k := range keys {
		dump, derr := dumpCmds[i].Result()
		if errors.Is(derr, goredis.Nil) || dump == "" {
			// Key expired or vanished mid-snapshot — best-effort, skip it.
			continue
		}
		if derr != nil {
			return nil, fmt.Errorf("backup: DUMP %q: %w", k, derr)
		}
		ttl, terr := ttlCmds[i].Result()
		if terr != nil && !errors.Is(terr, goredis.Nil) {
			return nil, fmt.Errorf("backup: PTTL %q: %w", k, terr)
		}
		out = append(out, Entry{Key: k, TTLMillis: ttl.Milliseconds(), Payload: []byte(dump)})
	}
	return out, nil
}

// excluded reports whether key matches any configured exclude prefix.
func (e *Engine) excluded(key string) bool {
	for _, p := range e.cfg.ExcludePrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// writeArtifact writes the artifact atomically (temp + rename) at 0600 in a
// 0700 directory.
func (e *Engine) writeArtifact(artifact []byte, started time.Time) (string, error) {
	if err := os.MkdirAll(e.cfg.Dir, 0o700); err != nil {
		return "", fmt.Errorf("backup: creating dir %q: %w", e.cfg.Dir, err)
	}
	name := fmt.Sprintf("%s%d%s", artifactPrefix, started.UTC().Unix(), artifactExt)
	final := filepath.Join(e.cfg.Dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, artifact, 0o600); err != nil {
		return "", fmt.Errorf("backup: writing artifact: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("backup: finalising artifact: %w", err)
	}
	return final, nil
}

// pruneRetention deletes artifacts beyond RetentionCount and older than
// RetentionDays. Both are best-effort; zero means unlimited.
func (e *Engine) pruneRetention() error {
	files, err := listArtifacts(e.cfg.Dir)
	if err != nil {
		return err
	}
	// Newest first.
	sort.Slice(files, func(i, j int) bool { return files[i].unix > files[j].unix })

	cutoff := int64(0)
	if e.cfg.RetentionDays > 0 {
		cutoff = e.now().UTC().Add(-time.Duration(e.cfg.RetentionDays) * 24 * time.Hour).Unix()
	}
	for i, f := range files {
		over := e.cfg.RetentionCount > 0 && i >= e.cfg.RetentionCount
		old := cutoff > 0 && f.unix < cutoff
		if over || old {
			if rmErr := os.Remove(f.path); rmErr != nil {
				e.log.WithError(rmErr).WithField("path", f.path).Warn("backup: removing old artifact")
			}
		}
	}
	return nil
}

type artifactFile struct {
	path string
	unix int64
}

// listArtifacts returns backup artifacts in dir parsed by their unix timestamp.
func listArtifacts(dir string) ([]artifactFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []artifactFile
	for _, de := range ents {
		n := de.Name()
		if !strings.HasPrefix(n, artifactPrefix) || !strings.HasSuffix(n, artifactExt) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(n, artifactPrefix), artifactExt)
		var unix int64
		if _, perr := fmt.Sscanf(stamp, "%d", &unix); perr != nil {
			continue
		}
		out = append(out, artifactFile{path: filepath.Join(dir, n), unix: unix})
	}
	return out, nil
}

// Inspect decrypts an artifact and returns its manifest plus a per-prefix key
// count, WITHOUT contacting Redis — for offline verification by operators.
func Inspect(path, passphrase string) (Manifest, map[string]int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("backup: reading artifact: %w", err)
	}
	gz, err := DecryptPayload(raw, passphrase)
	if err != nil {
		return Manifest{}, nil, err
	}
	body, err := gunzipBytes(gz)
	if err != nil {
		return Manifest{}, nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Manifest{}, nil, fmt.Errorf("backup: parsing snapshot: %w", err)
	}
	counts := make(map[string]int)
	for _, ent := range snap.Entries {
		counts[prefixOf(ent.Key)] += 1
	}
	return snap.Manifest, counts, nil
}

// prefixOf returns the colon-delimited namespace of a Redis key (e.g. "ban:1.2.3.4"
// -> "ban"), for the inspect breakdown.
func prefixOf(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i]
	}
	return key
}

func gzipBytes(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(in); err != nil {
		return nil, fmt.Errorf("backup: gzip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("backup: gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

func gunzipBytes(in []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, fmt.Errorf("backup: gunzip: %w", err)
	}
	defer zr.Close()
	out, err := readAllLimited(zr)
	if err != nil {
		return nil, fmt.Errorf("backup: gunzip read: %w", err)
	}
	return out, nil
}
