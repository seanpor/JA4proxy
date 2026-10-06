package redis_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/seanpor/ja4proxy/internal/redis"
	"pgregory.net/rapid"
)

// INV-REDIS-001: Atomic Sliding Window Count
// Exec(N concurrent at t) => Count == N
func TestInvariant_Redis_AtomicSlidingWindowCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		defer rdb.Close()

		sha, err := rdb.ScriptLoad(context.Background(), redis.SlidingWindowScript).Result()
		if err != nil {
			t.Fatalf("ScriptLoad failed: %v", err)
		}

		numWorkers := rapid.IntRange(5, 30).Draw(t, "numWorkers")
		key := fmt.Sprintf("test-ip-%d", rapid.Int().Draw(t, "ipID"))
		counterKey := key + ":count"
		now := float64(time.Now().Unix())

		var wg sync.WaitGroup
		wg.Add(numWorkers)

		for i := 0; i < numWorkers; i++ {
			go func() {
				defer wg.Done()
				_, _ = rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, now, 60, 120).Result()
			}()
		}
		wg.Wait()

		res, err := rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, now, 60, 120).Result()
		if err != nil {
			t.Fatalf("EvalSha failed: %v", err)
		}

		count, ok := res.(int64)
		if !ok {
			t.Fatalf("Unexpected EvalSha return type: %T", res)
		}
		if count != int64(numWorkers+1) {
			t.Fatalf("Atomic window count mismatch: got %d, want %d", count, numWorkers+1)
		}
	})
}

// INV-REDIS-002: Timestamp Expiration
// forall t' >= t + W, Contribution(req_t, t') == 0
func TestInvariant_Redis_TimestampExpiration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		defer rdb.Close()

		sha, err := rdb.ScriptLoad(context.Background(), redis.SlidingWindowScript).Result()
		if err != nil {
			t.Fatalf("ScriptLoad failed: %v", err)
		}

		windowSec := rapid.IntRange(10, 60).Draw(t, "windowSec")
		key := fmt.Sprintf("exp-ip-%d", rapid.Int().Draw(t, "ipID"))
		counterKey := key + ":count"

		t0 := float64(1000.0)
		// Send request at t0
		_, err = rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, t0, windowSec, windowSec*2).Result()
		if err != nil {
			t.Fatalf("EvalSha failed at t0: %v", err)
		}

		// Fast forward past window: t' >= t0 + windowSec + 1
		t1 := t0 + float64(windowSec) + 1.0
		res, err := rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, t1, windowSec, windowSec*2).Result()
		if err != nil {
			t.Fatalf("EvalSha failed at t1: %v", err)
		}

		count := res.(int64)
		// Old request at t0 must have expired, so count at t1 is strictly 1 (only member at t1 remains)
		if count != 1 {
			t.Fatalf("Expired request contributed to count past window: got count %d, want 1", count)
		}
	})
}

// INV-REDIS-003: GDPR TTL Enforcement
// forall K in KeysWritten, TTL(K) <= ARGV[3]
func TestInvariant_Redis_GDPRTTLEnforcement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		defer rdb.Close()

		sha, err := rdb.ScriptLoad(context.Background(), redis.SlidingWindowScript).Result()
		if err != nil {
			t.Fatalf("ScriptLoad failed: %v", err)
		}

		ttlSec := rapid.IntRange(30, 300).Draw(t, "ttlSec")
		key := fmt.Sprintf("gdpr-ip-%d", rapid.Int().Draw(t, "ipID"))
		counterKey := key + ":count"
		now := float64(time.Now().Unix())

		_, err = rdb.EvalSha(context.Background(), sha, []string{key, counterKey}, now, 60, ttlSec).Result()
		if err != nil {
			t.Fatalf("EvalSha failed: %v", err)
		}

		ttlKey := mr.TTL(key)
		if ttlKey <= 0 || ttlKey > time.Duration(ttlSec)*time.Second {
			t.Fatalf("Key TTL violation: got %v, max allowed %v", ttlKey, time.Duration(ttlSec)*time.Second)
		}
	})
}

// INV-REDIS-004: Lua Script Embedded Parity
// Hash(scripts/) == Hash(internal/redis/scripts/)
func TestInvariant_Redis_ScriptEmbeddedParity(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	internalScriptPath := filepath.Join(filepath.Dir(filename), "scripts", "sliding_window.lua")
	rootDir := filepath.Join(filepath.Dir(filename), "..", "..")
	rootScriptPath := filepath.Join(rootDir, "scripts", "sliding_window.lua")

	internalData, err1 := os.ReadFile(internalScriptPath)
	rootData, err2 := os.ReadFile(rootScriptPath)

	if err1 != nil {
		t.Fatalf("Failed to read internal script at %s: %v", internalScriptPath, err1)
	}
	if err2 != nil {
		t.Fatalf("Failed to read root script at %s: %v", rootScriptPath, err2)
	}

	if !bytes.Equal(internalData, rootData) {
		t.Fatalf("Lua script parity violation: root scripts/sliding_window.lua does not match internal/redis/scripts/sliding_window.lua")
	}
}
