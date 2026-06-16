package redis

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/metrics"
)

// observeOp records a Redis operation outcome to the SLO counter (phase-63).
// Pass "ok" or "error" as result.
func observeOp(command, result string) {
	metrics.RedisOperationsTotal.WithLabelValues(command, result).Inc()
}

// Client wraps go-redis and exposes the operations used by the pipeline.
// All methods fail open: errors are logged and a safe zero value is returned.
type Client struct {
	rdb              *goredis.Client
	log              *logrus.Logger
	scriptMu         sync.RWMutex // protects slidingWinSHA (phase-201c)
	slidingWinSHA    string       // EVALSHA hash for sliding_window.lua
	syncStream       string       // Redis Stream for cross-DC sync
	integrityKeyFile string       // path to HMAC secret
}

// Config holds the Redis connection parameters.
type Config struct {
	// Single node (legacy/standalone)
	Host string
	Port int

	// Sentinel (High Availability)
	MasterName string
	Sentinels  []string

	DB               int
	Password         string
	Username         string // phase-201a: Redis 6+ ACL username; "" = default user
	SSL              bool   // phase-201a: enable TLS to Redis (MinVersion 1.2)
	Timeout          time.Duration
	IntegrityKeyFile string // JA4PROXY-2026-0040: Signed Dial secret path
}

// buildStandaloneOptions builds goredis.Options for single-node mode. phase-201a.
func buildStandaloneOptions(cfg Config) *goredis.Options {
	opts := &goredis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.Timeout,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
		// phase-306 (from PR #95): a larger pool with pre-warmed idle
		// connections keeps the hot path from serialising on Redis and avoids
		// cold-start dial latency under load.
		PoolSize:     100,
		MinIdleConns: 10,
	}
	if cfg.SSL {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return opts
}

// buildFailoverOptions builds goredis.FailoverOptions for Sentinel mode. phase-201a.
func buildFailoverOptions(cfg Config) *goredis.FailoverOptions {
	opts := &goredis.FailoverOptions{
		MasterName:    cfg.MasterName,
		SentinelAddrs: cfg.Sentinels,
		Username:      cfg.Username,
		Password:      cfg.Password,
		DB:            cfg.DB,
		DialTimeout:   cfg.Timeout,
		ReadTimeout:   cfg.Timeout,
		WriteTimeout:  cfg.Timeout,
	}
	if cfg.SSL {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return opts
}

// Raw returns the underlying go-redis client for use by packages that need
// direct Redis access (e.g. webhook dispatcher). Phase 122 H-4.
func (c *Client) Raw() goredis.UniversalClient {
	return c.rdb
}

// newFromOptions is a test seam: constructs a Client from pre-built options.
func newFromOptions(opts *goredis.Options, log *logrus.Logger) *Client {
	if log == nil {
		log = logrus.New()
	}
	rdb := goredis.NewClient(opts)
	c := &Client{rdb: rdb, log: log, integrityKeyFile: ""}
	c.loadScripts()
	if opts.TLSConfig != nil {
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(pingCtx).Err(); err != nil {
			log.WithError(err).Error("redis: TLS ping failed; continuing fail-open")
		}
	}
	return c
}

// New creates a new Client and loads Lua scripts.
// Fails open: if the connection fails, the caller can still proceed with
// local-cache-only mode (all Redis ops will return zero values).
func New(cfg Config, log *logrus.Logger) *Client {
	if log == nil {
		log = logrus.New()
	}

	var rdb *goredis.Client
	if cfg.MasterName != "" {
		rdb = goredis.NewFailoverClient(buildFailoverOptions(cfg))
		log.WithFields(logrus.Fields{
			"master":    cfg.MasterName,
			"sentinels": cfg.Sentinels,
		}).Info("redis: initialized in sentinel mode")
	} else {
		rdb = goredis.NewClient(buildStandaloneOptions(cfg))
	}

	log.WithFields(logrus.Fields{
		"ssl":      cfg.SSL,
		"username": cfg.Username != "",
	}).Info("redis: dial options configured")

	c := &Client{rdb: rdb, log: log, integrityKeyFile: ""}
	c.loadScripts()

	if cfg.SSL {
		pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(pingCtx).Err(); err != nil {
			log.WithError(err).Error("redis: TLS ping failed; continuing fail-open")
		}
	}
	return c
}

// EnableSync sets the Redis stream for cross-DC synchronization.
func (c *Client) EnableSync(stream string) {
	c.syncStream = stream
}

// maybeSync appends a mutation to the sync stream if sync is enabled and the key
// is not local-only.
func (c *Client) maybeSync(ctx context.Context, op, key string, value interface{}, ttl time.Duration) {
	if c.syncStream == "" {
		return
	}

	// Skip local-only keys
	if strings.HasPrefix(key, "session:") || strings.HasPrefix(key, "lifespan:") ||
		strings.HasPrefix(key, "concurrent:") || strings.HasPrefix(key, "behavioral:burst:") {
		return
	}

	// Only sync security-critical keys for now (per PHASE_88 strategy)
	if !strings.HasPrefix(key, "ban:") && !strings.HasPrefix(key, "ja4:whitelist") &&
		!strings.HasPrefix(key, "ja4:blacklist") && key != "config:dial" {
		return
	}

	fields := map[string]interface{}{
		"op":        op,
		"key":       key,
		"value":     fmt.Sprintf("%v", value),
		"origin_ts": time.Now().UnixNano() / 1e6, // ms
	}
	if ttl > 0 {
		fields["ttl_ms"] = int64(ttl / time.Millisecond)
	}

	// Hot path: XAdd is non-blocking fire-and-forget in c.XAdd()
	c.XAdd(ctx, c.syncStream, fields)
}

// loadScripts loads the sliding-window Lua script via SCRIPT LOAD.
// Stores the SHA for later EVALSHA calls. Fails open on error.
func (c *Client) loadScripts() {
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	c.loadScriptsLocked()
}

// loadScriptsLocked assumes the caller holds c.scriptMu.Lock().
func (c *Client) loadScriptsLocked() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sha, err := c.rdb.ScriptLoad(ctx, SlidingWindowScript).Result()
	if err != nil {
		c.log.WithError(err).Warn("redis: failed to load sliding_window.lua; rate limiting unavailable")
		return
	}
	c.slidingWinSHA = sha
	c.log.WithField("sha", sha[:8]+"...").Debug("redis: sliding_window.lua loaded")
}

// Get retrieves a string value. Returns ("", nil) if key absent. Fails open.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	val, err := c.rdb.Get(ctx, key).Result()
	if err == goredis.Nil {
		observeOp("get", "ok")
		return "", nil
	}
	if err != nil {
		observeOp("get", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: GET failed")
		return "", nil // fail open
	}
	observeOp("get", "ok")
	return val, nil
}

// Set stores a string value with optional TTL. Fails open.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) {
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		observeOp("set", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: SET failed")
		return
	}
	observeOp("set", "ok")
	c.maybeSync(ctx, "set", key, value, ttl)
}

// SIsMember checks set membership. Returns false on error (fail open).
func (c *Client) SIsMember(ctx context.Context, key string, member interface{}) bool {
	ok, err := c.rdb.SIsMember(ctx, key, member).Result()
	if err != nil {
		observeOp("sismember", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: SISMEMBER failed")
		return false
	}
	observeOp("sismember", "ok")
	return ok
}

// SMembers retrieves all members of a set. Returns nil on error (fail open).
func (c *Client) SMembers(ctx context.Context, key string) []string {
	result, err := c.rdb.SMembers(ctx, key).Result()
	if err != nil {
		observeOp("smembers", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: SMEMBERS failed")
		return nil
	}
	observeOp("smembers", "ok")
	return result
}

// SAdd adds a member to a set. Fails open.
func (c *Client) SAdd(ctx context.Context, key string, member interface{}) {
	if err := c.rdb.SAdd(ctx, key, member).Err(); err != nil {
		observeOp("sadd", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: SADD failed")
		return
	}
	observeOp("sadd", "ok")
	c.maybeSync(ctx, "sadd", key, member, 0)
}

// SRem removes a member from a set. Fails open.
func (c *Client) SRem(ctx context.Context, key string, member interface{}) {
	if err := c.rdb.SRem(ctx, key, member).Err(); err != nil {
		observeOp("srem", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: SREM failed")
		return
	}
	observeOp("srem", "ok")

	// Tombstone logic for whitelists/blacklists (per PHASE_88)
	if key == "ja4:whitelist" || key == "ja4:blacklist" {
		tombstoneKey := key + ":removals"
		// Add to local removals set with 24h TTL
		if err := c.rdb.SAdd(ctx, tombstoneKey, member).Err(); err == nil {
			c.rdb.Expire(ctx, tombstoneKey, 24*time.Hour)
			// Sync the removal (the sync agent will apply it as SADD to :removals on peers)
			c.maybeSync(ctx, "sadd", tombstoneKey, member, 24*time.Hour)
		}
	} else {
		c.maybeSync(ctx, "srem", key, member, 0)
	}
}

// GetDial reads the config:dial key. Returns 0 on error (fail open — monitor mode).
func (c *Client) GetDial(ctx context.Context) int {
	val, err := c.rdb.Get(ctx, "config:dial").Result()
	if err == goredis.Nil {
		observeOp("get", "ok")
		return 0
	}
	if err != nil {
		observeOp("get", "error")
		c.log.WithError(err).Warn("redis: failed to read config:dial; defaulting to 0 (monitor)")
		return 0
	}
	observeOp("get", "ok")

	// JA4PROXY-2026-0040: Signed Dial (Control Plane Integrity)
	// If an integrity key is configured, verify the HMAC signature of the dial setting.
	if c.integrityKeyFile != "" {
		sig, err := c.rdb.Get(ctx, "config:dial:sig").Result()
		if err != nil {
			c.log.Warn("redis: config:dial:sig missing while integrity key is set; tampering suspected; defaulting to 0")
			return 0
		}

		key, err := os.ReadFile(c.integrityKeyFile)
		if err != nil {
			c.log.WithError(err).WithField("path", c.integrityKeyFile).Error("redis: failed to read integrity key file")
			return 0
		}

		mac := hmac.New(sha256.New, bytes.TrimSpace(key))
		mac.Write([]byte(val))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		if sig != expectedSig {
			c.log.WithFields(logrus.Fields{
				"val":      val,
				"sig":      sig,
				"expected": expectedSig,
			}).Warn("redis: config:dial signature mismatch; tampering suspected; defaulting to 0 (JA4PROXY-2026-0040)")
			return 0
		}
	}

	var dial int
	if _, err := fmt.Sscanf(val, "%d", &dial); err != nil {
		c.log.WithError(err).WithField("val", val).Warn("redis: config:dial parse failed; defaulting to 0 (monitor)")
		return 0
	}
	if dial < 0 {
		return 0
	}
	if dial > 100 {
		return 100
	}
	return dial
}
func (c *Client) SlidingWindowSHA() string {
	c.scriptMu.RLock()
	defer c.scriptMu.RUnlock()
	return c.slidingWinSHA
}

// SlidingWinSHAForTest is a test-only accessor. phase-201c.
func (c *Client) SlidingWinSHAForTest() string {
	c.scriptMu.RLock()
	defer c.scriptMu.RUnlock()
	return c.slidingWinSHA
}

// ZeroSlidingWinSHAForTest is a test-only mutator. phase-201c.
func (c *Client) ZeroSlidingWinSHAForTest() {
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	c.slidingWinSHA = ""
}

// HealthCheck pings Redis and reloads the sliding_window.lua script if needed.
// Fail-open: errors logged, metrics set, no panic. phase-201c.
func (c *Client) HealthCheck(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		metrics.RedisHealth.WithLabelValues("error").Set(1)
		metrics.RedisHealth.WithLabelValues("ok").Set(0)
		c.log.WithError(err).Warn("redis: health check ping failed")
		return
	}
	c.scriptMu.RLock()
	empty := c.slidingWinSHA == ""
	c.scriptMu.RUnlock()
	if empty {
		c.scriptMu.Lock()
		// Double-check under write lock to dedupe concurrent callers.
		if c.slidingWinSHA == "" {
			c.loadScriptsLocked()
			reloaded := c.slidingWinSHA != ""
			c.scriptMu.Unlock()
			if reloaded {
				metrics.RedisScriptReloadsTotal.WithLabelValues("ok").Inc()
			} else {
				metrics.RedisScriptReloadsTotal.WithLabelValues("error").Inc()
			}
		} else {
			c.scriptMu.Unlock()
		}
	}
	metrics.RedisHealth.WithLabelValues("ok").Set(1)
	metrics.RedisHealth.WithLabelValues("error").Set(0)
}

// Close shuts down the Redis connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Ping checks connectivity. Used for health checks.
func (c *Client) Ping(ctx context.Context) error {
	err := c.rdb.Ping(ctx).Err()
	if err != nil {
		observeOp("ping", "error")
	} else {
		observeOp("ping", "ok")
	}
	return err
}

// CountKeys returns the number of keys matching a glob pattern.
// Used for ban counting in health/deep endpoint. Returns 0 on error.
func (c *Client) CountKeys(ctx context.Context, pattern string) int {
	keys, err := c.rdb.Keys(ctx, pattern).Result()
	if err != nil {
		observeOp("keys", "error")
		c.log.WithError(err).WithField("pattern", pattern).Warn("redis: KEYS failed")
		return 0
	}
	observeOp("keys", "ok")
	return len(keys)
}

// SlidingWindowCount executes the sliding_window.lua EVALSHA.
// KEYS[1]=key, KEYS[2]=key+":ctr", ARGV[1]=now, ARGV[2]=window, ARGV[3]=ttl
// Returns 0 on error (fail open).
func (c *Client) SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int {
	c.scriptMu.RLock()
	sha := c.slidingWinSHA
	c.scriptMu.RUnlock()
	if sha == "" {
		return 0
	}
	now := float64(time.Now().UnixNano()) / 1e9
	result, err := c.rdb.EvalSha(ctx, sha,
		[]string{key, key + ":ctr"},
		now, window, ttl,
	).Int()
	if err != nil {
		observeOp("evalsha", "error")
		c.log.WithError(err).WithField("key", key).Debug("redis: EVALSHA failed")
		return 0
	}
	observeOp("evalsha", "ok")
	return result
}

// HGetAll retrieves all fields of a hash. Returns nil on error (fail open).
func (c *Client) HGetAll(ctx context.Context, key string) map[string]string {
	result, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		observeOp("hgetall", "error")
		c.log.WithError(err).WithField("key", key).Debug("redis: HGETALL failed")
		return nil
	}
	observeOp("hgetall", "ok")
	return result
}

// GetString retrieves a string value. Returns "" if absent or on error.
func (c *Client) GetString(ctx context.Context, key string) string {
	v, _ := c.Get(ctx, key)
	return v
}

// SetString stores a string value with TTL in seconds. Fails open.
func (c *Client) SetString(ctx context.Context, key, value string, ttlSeconds int) {
	c.Set(ctx, key, value, time.Duration(ttlSeconds)*time.Second)
}

// Exists returns true if the key exists. Returns false on error.
func (c *Client) Exists(ctx context.Context, key string) bool {
	n, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		observeOp("exists", "error")
		return false
	}
	observeOp("exists", "ok")
	return n > 0
}

// ZAdd adds a member to a sorted set. Fails open.
func (c *Client) ZAdd(ctx context.Context, key string, score float64, member string) {
	if err := c.rdb.ZAdd(ctx, key, goredis.Z{Score: score, Member: member}).Err(); err != nil {
		observeOp("zadd", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: ZADD failed")
		return
	}
	observeOp("zadd", "ok")
	c.maybeSync(ctx, "zadd", key, member, 0)
}

// ZRemRangeByScore removes members with scores between min and max. Fails open.
func (c *Client) ZRemRangeByScore(ctx context.Context, key string, min, max float64) {
	if err := c.rdb.ZRemRangeByScore(ctx, key, fmt.Sprintf("%f", min), fmt.Sprintf("%f", max)).Err(); err != nil {
		observeOp("zremrangebyscore", "error")
		c.log.WithError(err).WithField("key", key).Warn("redis: ZREMRANGEBYSCORE failed")
		return
	}
	observeOp("zremrangebyscore", "ok")
}

// ZRange returns members from start to stop index. Returns nil on error.
func (c *Client) ZRange(ctx context.Context, key string, start, stop int64) []string {
	result, err := c.rdb.ZRange(ctx, key, start, stop).Result()
	if err != nil {
		observeOp("zrange", "error")
		return nil
	}
	observeOp("zrange", "ok")
	return result
}

// ZCard returns the cardinality of a sorted set. Returns 0 on error.
func (c *Client) ZCard(ctx context.Context, key string) int64 {
	n, err := c.rdb.ZCard(ctx, key).Result()
	if err != nil {
		observeOp("zcard", "error")
		return 0
	}
	observeOp("zcard", "ok")
	return n
}

// ZRangeScores returns the scores (as float64) of members from start to stop. Returns nil on error.
func (c *Client) ZRangeScores(ctx context.Context, key string, start, stop int64) []float64 {
	result, err := c.rdb.ZRangeWithScores(ctx, key, start, stop).Result()
	if err != nil {
		// phase-63 review-fix N1: distinct label from plain ZRange so the
		// per-command panel can tell them apart on-call.
		observeOp("zrangewithscores", "error")
		return nil
	}
	observeOp("zrangewithscores", "ok")
	scores := make([]float64, len(result))
	for i, z := range result {
		scores[i] = z.Score
	}
	return scores
}

// XAdd appends a message to a Redis Stream. Fails open (errors are silently ignored
// since stream writes are fire-and-forget on the hot path).
func (c *Client) XAdd(ctx context.Context, stream string, values map[string]interface{}) {
	_ = c.XAddErr(ctx, stream, values)
}

// XAddErr is the error-returning variant of XAdd. The bounded XADD worker
// pool (cmd/proxy, JA4PROXY-2026-0031) needs the error so it can classify
// timeouts vs generic failures on the `ja4proxy_stream_event_write_errors_total`
// counter.
func (c *Client) XAddErr(ctx context.Context, stream string, values map[string]interface{}) error {
	if err := c.rdb.XAdd(ctx, &goredis.XAddArgs{
		Stream: stream,
		Values: values,
		MaxLen: 100000,
		Approx: true,
	}).Err(); err != nil {
		observeOp("xadd", "error")
		c.log.WithError(err).WithField("stream", stream).Debug("redis: XADD failed")
		return err
	}
	observeOp("xadd", "ok")
	return nil
}

// XGroupCreateMkStream creates a consumer group for a stream, creating the
// stream first if it does not exist.
func (c *Client) XGroupCreateMkStream(ctx context.Context, stream, group, start string) error {
	err := c.rdb.XGroupCreateMkStream(ctx, stream, group, start).Err()
	if err != nil && strings.Contains(err.Error(), "BUSYGROUP") {
		return nil // group already exists
	}
	return err
}

// XReadGroup reads messages from a stream using a consumer group.
func (c *Client) XReadGroup(ctx context.Context, args *goredis.XReadGroupArgs) ([]goredis.XStream, error) {
	return c.rdb.XReadGroup(ctx, args).Result()
}

// XAck acknowledges one or more messages in a consumer group.
func (c *Client) XAck(ctx context.Context, stream, group string, ids ...string) error {
	return c.rdb.XAck(ctx, stream, group, ids...).Err()
}

// SeedDialIfAbsent writes the dial value only if config:dial is not already set.
func (c *Client) SeedDialIfAbsent(ctx context.Context, dial int) {
	result, err := c.rdb.SetArgs(ctx, "config:dial", fmt.Sprintf("%d", dial), goredis.SetArgs{Mode: "NX"}).Result()
	if err != nil {
		observeOp("set", "error")
		c.log.WithError(err).Warn("redis: failed to seed config:dial")
		return
	}
	observeOp("set", "ok")
	if result == "OK" {
		c.log.WithField("dial", dial).Info("redis: seeded config:dial from config file")
	}
}

// MultiCheck performs a batch lookup of common security flags to reduce round-trips.
// Returns (dial, isBlacklisted, isWhitelisted).
func (c *Client) MultiCheck(ctx context.Context, ja4 string) (int, bool, bool) {
	pipe := c.rdb.Pipeline()
	dialCmd := pipe.Get(ctx, "config:dial")
	blackCmd := pipe.SIsMember(ctx, "blacklist", ja4)
	whiteCmd := pipe.SIsMember(ctx, "whitelist", ja4)
	_, _ = pipe.Exec(ctx)

	dial, _ := dialCmd.Int()
	isBlack, _ := blackCmd.Result()
	isWhite, _ := whiteCmd.Result()
	return dial, isBlack, isWhite
}
