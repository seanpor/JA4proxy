// Package redis provides the Redis client, Lua scripts, and pub/sub subscriber
// for the JA4proxy Go proxy.
package redis

import (
	"os"
	"path/filepath"
	"runtime"
)

// SlidingWindowScript is the content of scripts/sliding_window.lua.
// Loaded once at startup via SCRIPT LOAD; called per-connection via EVALSHA.
// Content must be byte-identical to the Python version.
var SlidingWindowScript string

func init() {
	// Locate the repo root relative to this file at compile time.
	// In tests, __FILE__ resolves to the source path.
	_, filename, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	luaPath := filepath.Join(repoRoot, "scripts", "sliding_window.lua")

	data, err := os.ReadFile(luaPath)
	if err != nil {
		// Fallback: embed the canonical script inline so the binary works
		// even when scripts/ is absent (e.g. Docker runtime image).
		SlidingWindowScript = slidingWindowLua
		return
	}
	SlidingWindowScript = string(data)
}

// slidingWindowLua is the canonical sliding-window rate-limit script,
// embedded as a fallback when the file is not accessible at runtime.
// This must remain byte-identical to scripts/sliding_window.lua.
const slidingWindowLua = `-- sliding_window.lua
-- Atomic sliding-window rate tracker using Redis Sorted Sets.
--
-- Loaded on startup via SCRIPT LOAD, called per-connection via EVALSHA.
-- Never embed this script inline in production code paths.
--
-- KEYS[1]  — sorted set key for this (strategy, entity, window) tuple
-- KEYS[2]  — counter key for unique IDs within the same set
-- ARGV[1]  — current timestamp (float, seconds since epoch)
-- ARGV[2]  — window size in seconds (float)
-- ARGV[3]  — TTL in seconds for both keys (integer, for GDPR compliance)
--
-- Returns: integer count of connections within the window
--
-- Algorithm:
--   1. Atomically increment a counter to get a unique member ID.
--   2. Add this connection to the sorted set with score = timestamp.
--   3. Remove connections outside the window (score < now - window).
--   4. Count remaining members (= connections in window).
--   5. Set TTL on both keys (GDPR: minimal retention).

local key         = KEYS[1]
local counter_key = KEYS[2]
local now         = tonumber(ARGV[1])
local window      = tonumber(ARGV[2])
local ttl         = tonumber(ARGV[3])

-- Unique member ID: timestamp + monotonic counter prevents key collisions
-- when multiple connections arrive in the same millisecond
local counter   = redis.call('INCR', counter_key)
local unique_id = now .. ':' .. counter

-- Record this connection
redis.call('ZADD', key, now, unique_id)

-- Evict old entries outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count connections within the window
local count = redis.call('ZCARD', key)

-- GDPR compliance: ensure both keys expire
redis.call('EXPIRE', key, ttl)
redis.call('EXPIRE', counter_key, ttl)

return count
`
