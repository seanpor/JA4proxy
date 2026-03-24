package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// Client wraps go-redis and exposes the operations used by the pipeline.
// All methods fail open: errors are logged and a safe zero value is returned.
type Client struct {
	rdb           *goredis.Client
	log           *logrus.Logger
	slidingWinSHA string // EVALSHA hash for sliding_window.lua
}

// Config holds the Redis connection parameters.
type Config struct {
	Host     string
	Port     int
	DB       int
	Password string
	Timeout  time.Duration
}

// New creates a new Client and loads Lua scripts.
// Fails open: if the connection fails, the caller can still proceed with
// local-cache-only mode (all Redis ops will return zero values).
func New(cfg Config, log *logrus.Logger) *Client {
	if log == nil {
		log = logrus.New()
	}
	opts := &goredis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.Timeout,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
	}
	rdb := goredis.NewClient(opts)
	c := &Client{rdb: rdb, log: log}
	c.loadScripts()
	return c
}

// loadScripts loads the sliding-window Lua script via SCRIPT LOAD.
// Stores the SHA for later EVALSHA calls. Fails open on error.
func (c *Client) loadScripts() {
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
		return "", nil
	}
	if err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: GET failed")
		return "", nil // fail open
	}
	return val, nil
}

// Set stores a string value with optional TTL. Fails open.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) {
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: SET failed")
	}
}

// SIsMember checks set membership. Returns false on error (fail open).
func (c *Client) SIsMember(ctx context.Context, key string, member interface{}) bool {
	ok, err := c.rdb.SIsMember(ctx, key, member).Result()
	if err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: SISMEMBER failed")
		return false
	}
	return ok
}

// SMembers retrieves all members of a set. Returns nil on error (fail open).
func (c *Client) SMembers(ctx context.Context, key string) []string {
	result, err := c.rdb.SMembers(ctx, key).Result()
	if err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: SMEMBERS failed")
		return nil
	}
	return result
}

// SAdd adds a member to a set. Fails open.
func (c *Client) SAdd(ctx context.Context, key string, member interface{}) {
	if err := c.rdb.SAdd(ctx, key, member).Err(); err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: SADD failed")
	}
}

// SRem removes a member from a set. Fails open.
func (c *Client) SRem(ctx context.Context, key string, member interface{}) {
	if err := c.rdb.SRem(ctx, key, member).Err(); err != nil {
		c.log.WithError(err).WithField("key", key).Warn("redis: SREM failed")
	}
}

// GetDial reads the config:dial key. Returns 0 on error (fail open — monitor mode).
func (c *Client) GetDial(ctx context.Context) int {
	val, err := c.rdb.Get(ctx, "config:dial").Result()
	if err == goredis.Nil {
		return 0
	}
	if err != nil {
		c.log.WithError(err).Warn("redis: failed to read config:dial; defaulting to 0 (monitor)")
		return 0
	}
	var dial int
	if _, err := fmt.Sscanf(val, "%d", &dial); err != nil {
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

// SlidingWindowSHA returns the loaded EVALSHA for the sliding window script,
// or "" if the script was not loaded successfully.
func (c *Client) SlidingWindowSHA() string {
	return c.slidingWinSHA
}

// Close shuts down the Redis connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Ping checks connectivity. Used for health checks.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// SlidingWindowCount executes the sliding_window.lua EVALSHA.
// KEYS[1]=key, KEYS[2]=key+":ctr", ARGV[1]=now, ARGV[2]=window, ARGV[3]=ttl
// Returns 0 on error (fail open).
func (c *Client) SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int {
	if c.slidingWinSHA == "" {
		return 0
	}
	now := float64(time.Now().UnixNano()) / 1e9
	result, err := c.rdb.EvalSha(ctx, c.slidingWinSHA,
		[]string{key, key + ":ctr"},
		now, window, ttl,
	).Int()
	if err != nil {
		c.log.WithError(err).WithField("key", key).Debug("redis: EVALSHA failed")
		return 0
	}
	return result
}

// HGetAll retrieves all fields of a hash. Returns nil on error (fail open).
func (c *Client) HGetAll(ctx context.Context, key string) map[string]string {
	result, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		c.log.WithError(err).WithField("key", key).Debug("redis: HGETALL failed")
		return nil
	}
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
		return false
	}
	return n > 0
}

// ZAdd adds a member to a sorted set. Fails open.
func (c *Client) ZAdd(ctx context.Context, key string, score float64, member string) {
	c.rdb.ZAdd(ctx, key, goredis.Z{Score: score, Member: member})
}

// ZRemRangeByScore removes members with scores between min and max. Fails open.
func (c *Client) ZRemRangeByScore(ctx context.Context, key string, min, max float64) {
	c.rdb.ZRemRangeByScore(ctx, key, fmt.Sprintf("%f", min), fmt.Sprintf("%f", max))
}

// ZRange returns members from start to stop index. Returns nil on error.
func (c *Client) ZRange(ctx context.Context, key string, start, stop int64) []string {
	result, err := c.rdb.ZRange(ctx, key, start, stop).Result()
	if err != nil {
		return nil
	}
	return result
}

// ZCard returns the cardinality of a sorted set. Returns 0 on error.
func (c *Client) ZCard(ctx context.Context, key string) int64 {
	n, err := c.rdb.ZCard(ctx, key).Result()
	if err != nil {
		return 0
	}
	return n
}

// ZRangeScores returns the scores (as float64) of members from start to stop. Returns nil on error.
func (c *Client) ZRangeScores(ctx context.Context, key string, start, stop int64) []float64 {
	result, err := c.rdb.ZRangeWithScores(ctx, key, start, stop).Result()
	if err != nil {
		return nil
	}
	scores := make([]float64, len(result))
	for i, z := range result {
		scores[i] = z.Score
	}
	return scores
}

// SeedDialIfAbsent writes the dial value only if config:dial is not already set.
func (c *Client) SeedDialIfAbsent(ctx context.Context, dial int) {
	result, err := c.rdb.SetArgs(ctx, "config:dial", fmt.Sprintf("%d", dial), goredis.SetArgs{Mode: "NX"}).Result()
	if err != nil {
		c.log.WithError(err).Warn("redis: failed to seed config:dial")
		return
	}
	if result == "OK" {
		c.log.WithField("dial", dial).Info("redis: seeded config:dial from config file")
	}
}
