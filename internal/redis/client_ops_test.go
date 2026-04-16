package redis

// phase-104: Coverage tests for uncovered client operations.
// Covers: SMembers, SAdd, SRem, ZAdd, ZRange, ZCard, ZRangeScores,
// ZRemRangeByScore, GetString, SetString, HGetAll, Exists, CountKeys,
// SlidingWindowCount, SlidingWindowSHA, SeedDialIfAbsent, XAdd,
// XGroupCreateMkStream, XReadGroup, XAck, GetDial edge cases,
// EnableSync, maybeSync, Close.

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// --- Set Operations ---

func TestClient_SMembers(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Empty set returns empty slice (not nil from Redis perspective, but empty)
	members := c.SMembers(ctx, "emptyset")
	if len(members) != 0 {
		t.Errorf("SMembers empty: got %v, want empty", members)
	}

	// Add members and retrieve
	mr.SAdd("myset", "a", "b", "c")
	members = c.SMembers(ctx, "myset")
	if len(members) != 3 {
		t.Errorf("SMembers: got %d members, want 3", len(members))
	}
	found := map[string]bool{}
	for _, m := range members {
		found[m] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !found[want] {
			t.Errorf("SMembers: missing member %q", want)
		}
	}
}

func TestClient_SMembers_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close() // kill redis
	members := c.SMembers(context.Background(), "myset")
	if members != nil {
		t.Errorf("SMembers on down Redis: got %v, want nil (fail open)", members)
	}
}

func TestClient_SAdd(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.SAdd(ctx, "testset", "member1")
	c.SAdd(ctx, "testset", "member2")

	members, err := mr.Members("testset")
	if err != nil {
		t.Fatalf("mr.Members: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("SAdd: got %d members, want 2", len(members))
	}
}

func TestClient_SAdd_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic, just fail open
	c.SAdd(context.Background(), "testset", "member1")
}

func TestClient_SRem(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	mr.SAdd("testset", "a", "b", "c")
	c.SRem(ctx, "testset", "b")

	members, _ := mr.Members("testset")
	for _, m := range members {
		if m == "b" {
			t.Error("SRem: member 'b' should have been removed")
		}
	}
}

func TestClient_SRem_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic
	c.SRem(context.Background(), "testset", "member1")
}

func TestClient_SRem_Tombstone_Whitelist(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Add to whitelist then remove — should create tombstone
	c.SAdd(ctx, "ja4:whitelist", "fp_to_remove")
	c.SRem(ctx, "ja4:whitelist", "fp_to_remove")

	// Verify tombstone key exists
	ok, _ := mr.IsMember("ja4:whitelist:removals", "fp_to_remove")
	if !ok {
		t.Error("SRem whitelist: expected tombstone in ja4:whitelist:removals")
	}
}

func TestClient_SRem_Tombstone_Blacklist(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.SAdd(ctx, "ja4:blacklist", "badfp")
	c.SRem(ctx, "ja4:blacklist", "badfp")

	ok, _ := mr.IsMember("ja4:blacklist:removals", "badfp")
	if !ok {
		t.Error("SRem blacklist: expected tombstone in ja4:blacklist:removals")
	}
}

func TestClient_SRem_NoTombstone_RegularKey(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.SAdd(ctx, "regular:set", "item")
	c.SRem(ctx, "regular:set", "item")

	// Should not create a :removals key for non-whitelist/blacklist
	ok, _ := mr.IsMember("regular:set:removals", "item")
	if ok {
		t.Error("SRem regular key: should not create tombstone")
	}
}

// --- Sorted Set Operations ---

func TestClient_ZAdd(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.ZAdd(ctx, "zset1", 1.0, "a")
	c.ZAdd(ctx, "zset1", 2.0, "b")
	c.ZAdd(ctx, "zset1", 3.0, "c")

	members, err := mr.ZMembers("zset1")
	if err != nil {
		t.Fatalf("ZMembers: %v", err)
	}
	if len(members) != 3 {
		t.Errorf("ZAdd: got %d members, want 3", len(members))
	}
}

func TestClient_ZAdd_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	c.ZAdd(context.Background(), "zset1", 1.0, "a") // should not panic
}

func TestClient_ZRange(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.ZAdd(ctx, "zset1", 1.0, "a")
	c.ZAdd(ctx, "zset1", 2.0, "b")
	c.ZAdd(ctx, "zset1", 3.0, "c")

	result := c.ZRange(ctx, "zset1", 0, -1)
	if len(result) != 3 {
		t.Fatalf("ZRange: got %d members, want 3", len(result))
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("ZRange: got %v, want [a b c]", result)
	}

	// Partial range
	result = c.ZRange(ctx, "zset1", 0, 1)
	if len(result) != 2 {
		t.Errorf("ZRange partial: got %d members, want 2", len(result))
	}
}

func TestClient_ZRange_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	result := c.ZRange(context.Background(), "zset1", 0, -1)
	if result != nil {
		t.Errorf("ZRange on down Redis: got %v, want nil", result)
	}
}

func TestClient_ZCard(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Empty
	if n := c.ZCard(ctx, "zset_empty"); n != 0 {
		t.Errorf("ZCard empty: got %d, want 0", n)
	}

	c.ZAdd(ctx, "zset2", 1.0, "x")
	c.ZAdd(ctx, "zset2", 2.0, "y")

	if n := c.ZCard(ctx, "zset2"); n != 2 {
		t.Errorf("ZCard: got %d, want 2", n)
	}
}

func TestClient_ZCard_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	if n := c.ZCard(context.Background(), "zset2"); n != 0 {
		t.Errorf("ZCard on down Redis: got %d, want 0", n)
	}
}

func TestClient_ZRangeScores(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.ZAdd(ctx, "zs1", 10.5, "a")
	c.ZAdd(ctx, "zs1", 20.3, "b")
	c.ZAdd(ctx, "zs1", 30.7, "c")

	scores := c.ZRangeScores(ctx, "zs1", 0, -1)
	if len(scores) != 3 {
		t.Fatalf("ZRangeScores: got %d scores, want 3", len(scores))
	}
	if scores[0] != 10.5 || scores[1] != 20.3 || scores[2] != 30.7 {
		t.Errorf("ZRangeScores: got %v, want [10.5 20.3 30.7]", scores)
	}
}

func TestClient_ZRangeScores_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	scores := c.ZRangeScores(context.Background(), "zs1", 0, -1)
	if scores != nil {
		t.Errorf("ZRangeScores on down Redis: got %v, want nil", scores)
	}
}

func TestClient_ZRemRangeByScore(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.ZAdd(ctx, "zrr", 1.0, "old")
	c.ZAdd(ctx, "zrr", 5.0, "mid")
	c.ZAdd(ctx, "zrr", 10.0, "new")

	c.ZRemRangeByScore(ctx, "zrr", 0, 5.0)

	result := c.ZRange(ctx, "zrr", 0, -1)
	if len(result) != 1 || result[0] != "new" {
		t.Errorf("ZRemRangeByScore: got %v, want [new]", result)
	}
}

// --- String/Hash Operations ---

func TestClient_GetString(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Missing key
	if v := c.GetString(ctx, "nokey"); v != "" {
		t.Errorf("GetString missing: got %q, want empty", v)
	}

	c.Set(ctx, "strkey", "value123", 0)
	if v := c.GetString(ctx, "strkey"); v != "value123" {
		t.Errorf("GetString: got %q, want %q", v, "value123")
	}
}

func TestClient_GetString_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	if v := c.GetString(context.Background(), "k"); v != "" {
		t.Errorf("GetString on down Redis: got %q, want empty", v)
	}
}

func TestClient_SetString(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.SetString(ctx, "ss_key", "ss_val", 60)
	v, _ := c.Get(ctx, "ss_key")
	if v != "ss_val" {
		t.Errorf("SetString: got %q, want %q", v, "ss_val")
	}

	// Verify TTL was set (approximately)
	ttl := mr.TTL("ss_key")
	if ttl <= 0 || ttl > 61*time.Second {
		t.Errorf("SetString TTL: got %v, want ~60s", ttl)
	}
}

func TestClient_SetString_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic
	c.SetString(context.Background(), "k", "v", 60)
}

func TestClient_HGetAll(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Empty hash returns empty map
	result := c.HGetAll(ctx, "emptyhash")
	if result == nil || len(result) != 0 {
		t.Errorf("HGetAll empty: got %v, want empty map", result)
	}

	// Populate hash via miniredis
	mr.HSet("myhash", "f1", "v1")
	mr.HSet("myhash", "f2", "v2")

	result = c.HGetAll(ctx, "myhash")
	if len(result) != 2 {
		t.Fatalf("HGetAll: got %d fields, want 2", len(result))
	}
	if result["f1"] != "v1" || result["f2"] != "v2" {
		t.Errorf("HGetAll: got %v", result)
	}
}

func TestClient_HGetAll_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	result := c.HGetAll(context.Background(), "myhash")
	if result != nil {
		t.Errorf("HGetAll on down Redis: got %v, want nil", result)
	}
}

// --- Utility Functions ---

func TestClient_Exists(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	if c.Exists(ctx, "nokey") {
		t.Error("Exists: expected false for missing key")
	}

	c.Set(ctx, "yeskey", "val", 0)
	if !c.Exists(ctx, "yeskey") {
		t.Error("Exists: expected true for present key")
	}
}

func TestClient_Exists_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	if c.Exists(context.Background(), "k") {
		t.Error("Exists on down Redis: expected false (fail open)")
	}
}

func TestClient_CountKeys(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// No keys matching
	if n := c.CountKeys(ctx, "ban:*"); n != 0 {
		t.Errorf("CountKeys empty: got %d, want 0", n)
	}

	c.Set(ctx, "ban:1.1.1.1", "x", 0)
	c.Set(ctx, "ban:2.2.2.2", "x", 0)
	c.Set(ctx, "other:key", "x", 0)

	if n := c.CountKeys(ctx, "ban:*"); n != 2 {
		t.Errorf("CountKeys ban:*: got %d, want 2", n)
	}
}

func TestClient_CountKeys_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	if n := c.CountKeys(context.Background(), "ban:*"); n != 0 {
		t.Errorf("CountKeys on down Redis: got %d, want 0", n)
	}
}

func TestClient_SlidingWindowSHA(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	sha := c.SlidingWindowSHA()
	if sha == "" {
		t.Error("SlidingWindowSHA: expected non-empty after New()")
	}

	// Zero it and verify
	c.ZeroSlidingWinSHAForTest()
	if sha2 := c.SlidingWindowSHA(); sha2 != "" {
		t.Errorf("SlidingWindowSHA after zero: got %q, want empty", sha2)
	}
}

func TestClient_SlidingWindowCount(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Execute sliding window — should return count of 1
	count := c.SlidingWindowCount(ctx, "rate:test:1.2.3.4", 60, 120)
	if count != 1 {
		t.Errorf("SlidingWindowCount first call: got %d, want 1", count)
	}

	// Second call within the same window should return 2
	count = c.SlidingWindowCount(ctx, "rate:test:1.2.3.4", 60, 120)
	if count != 2 {
		t.Errorf("SlidingWindowCount second call: got %d, want 2", count)
	}
}

func TestClient_SlidingWindowCount_NoSHA(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	c.ZeroSlidingWinSHAForTest()
	count := c.SlidingWindowCount(context.Background(), "rate:test", 60, 120)
	if count != 0 {
		t.Errorf("SlidingWindowCount with no SHA: got %d, want 0", count)
	}
}

func TestClient_SlidingWindowCount_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close() // kill redis
	// SHA will have been loaded but redis is down — EVALSHA will fail
	count := c.SlidingWindowCount(context.Background(), "rate:test", 60, 120)
	if count != 0 {
		t.Errorf("SlidingWindowCount on down Redis: got %d, want 0", count)
	}
}

// --- Stream Operations ---

func TestClient_XAdd(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.XAdd(ctx, "teststream", map[string]interface{}{
		"key1": "val1",
		"key2": "val2",
	})

	msgs, err := mr.Stream("teststream")
	if err != nil {
		t.Fatalf("mr.Stream: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("XAdd: got %d messages, want 1", len(msgs))
	}
	v := streamValuesToMap(msgs[0].Values)
	if v["key1"] != "val1" || v["key2"] != "val2" {
		t.Errorf("XAdd values: got %v", v)
	}
}

func TestClient_XAdd_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic
	c.XAdd(context.Background(), "stream", map[string]interface{}{"k": "v"})
}

func TestClient_XGroupCreateMkStream(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Create group on non-existent stream — should create both
	err := c.XGroupCreateMkStream(ctx, "newstream", "mygroup", "0")
	if err != nil {
		t.Fatalf("XGroupCreateMkStream: %v", err)
	}

	// Creating the same group again should not error (BUSYGROUP handled)
	err = c.XGroupCreateMkStream(ctx, "newstream", "mygroup", "0")
	if err != nil {
		t.Errorf("XGroupCreateMkStream duplicate: got %v, want nil", err)
	}
}

func TestClient_XGroupCreateMkStream_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	err := c.XGroupCreateMkStream(context.Background(), "stream", "group", "0")
	if err == nil {
		t.Error("XGroupCreateMkStream on down Redis: expected error")
	}
}

func TestClient_XReadGroup(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	stream := "xrg_stream"
	group := "xrg_group"

	// Create group
	if err := c.XGroupCreateMkStream(ctx, stream, group, "0"); err != nil {
		t.Fatalf("XGroupCreateMkStream: %v", err)
	}

	// Add a message
	c.XAdd(ctx, stream, map[string]interface{}{"event": "test"})

	// Read it
	result, err := c.XReadGroup(ctx, &goredis.XReadGroupArgs{
		Group:    group,
		Consumer: "consumer1",
		Streams:  []string{stream, ">"},
		Count:    10,
		Block:    0,
	})
	if err != nil {
		t.Fatalf("XReadGroup: %v", err)
	}
	if len(result) != 1 || len(result[0].Messages) != 1 {
		t.Fatalf("XReadGroup: got %d streams, want 1 with 1 message", len(result))
	}
	if result[0].Messages[0].Values["event"] != "test" {
		t.Errorf("XReadGroup message: got %v", result[0].Messages[0].Values)
	}
}

func TestClient_XReadGroup_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	_, err := c.XReadGroup(context.Background(), &goredis.XReadGroupArgs{
		Group:    "g",
		Consumer: "c",
		Streams:  []string{"s", ">"},
	})
	if err == nil {
		t.Error("XReadGroup on down Redis: expected error")
	}
}

func TestClient_XAck(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	stream := "xack_stream"
	group := "xack_group"

	if err := c.XGroupCreateMkStream(ctx, stream, group, "0"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	c.XAdd(ctx, stream, map[string]interface{}{"data": "1"})

	// Read to get message ID
	result, err := c.XReadGroup(ctx, &goredis.XReadGroupArgs{
		Group:    group,
		Consumer: "c1",
		Streams:  []string{stream, ">"},
		Count:    10,
	})
	if err != nil || len(result) == 0 || len(result[0].Messages) == 0 {
		t.Fatalf("XReadGroup setup: %v (result: %v)", err, result)
	}

	msgID := result[0].Messages[0].ID
	err = c.XAck(ctx, stream, group, msgID)
	if err != nil {
		t.Errorf("XAck: %v", err)
	}
}

func TestClient_XAck_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	err := c.XAck(context.Background(), "s", "g", "0-0")
	if err == nil {
		t.Error("XAck on down Redis: expected error")
	}
}

// --- SeedDialIfAbsent ---

func TestClient_SeedDialIfAbsent(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Seed when absent
	c.SeedDialIfAbsent(ctx, 42)
	dial := c.GetDial(ctx)
	if dial != 42 {
		t.Errorf("SeedDialIfAbsent: got dial=%d, want 42", dial)
	}

	// Second seed should NOT overwrite
	c.SeedDialIfAbsent(ctx, 99)
	dial = c.GetDial(ctx)
	if dial != 42 {
		t.Errorf("SeedDialIfAbsent second call: got dial=%d, want 42 (should not overwrite)", dial)
	}
}

func TestClient_SeedDialIfAbsent_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic
	c.SeedDialIfAbsent(context.Background(), 50)
}

// --- GetDial edge cases ---

func TestClient_GetDial_Negative(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.Set(ctx, "config:dial", "-5", 0)
	dial := c.GetDial(ctx)
	if dial != 0 {
		t.Errorf("GetDial negative: got %d, want 0 (clamped)", dial)
	}
}

func TestClient_GetDial_Invalid(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.Set(ctx, "config:dial", "notanumber", 0)
	dial := c.GetDial(ctx)
	if dial != 0 {
		t.Errorf("GetDial invalid: got %d, want 0 (fail open)", dial)
	}
}

func TestClient_GetDial_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	dial := c.GetDial(context.Background())
	if dial != 0 {
		t.Errorf("GetDial on down Redis: got %d, want 0", dial)
	}
}

// --- EnableSync / maybeSync ---

func TestClient_EnableSync(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	c.EnableSync("sync:stream")
	if c.syncStream != "sync:stream" {
		t.Errorf("EnableSync: got %q, want %q", c.syncStream, "sync:stream")
	}
}

func TestClient_MaybeSync_SkipsLocalOnlyKeys(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	stream := "sync:test"
	c.EnableSync(stream)

	// These should NOT produce sync messages
	localKeys := []string{
		"session:1.2.3.4",
		"lifespan:abc",
		"concurrent:xyz",
		"behavioral:burst:test",
	}
	for _, key := range localKeys {
		c.Set(ctx, key, "val", 0)
	}

	msgs, _ := mr.Stream(stream)
	if len(msgs) != 0 {
		t.Errorf("maybeSync local-only keys: got %d messages, want 0", len(msgs))
	}
}

func TestClient_MaybeSync_SkipsNonSecurityKeys(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	stream := "sync:test2"
	c.EnableSync(stream)

	// Non-security, non-local key — should NOT sync
	c.Set(ctx, "score:1.2.3.4", "50", 0)

	msgs, _ := mr.Stream(stream)
	if len(msgs) != 0 {
		t.Errorf("maybeSync non-security key: got %d messages, want 0", len(msgs))
	}
}

func TestClient_MaybeSync_SyncsDialKey(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	stream := "sync:test3"
	c.EnableSync(stream)

	c.Set(ctx, "config:dial", "50", 0)

	msgs, _ := mr.Stream(stream)
	if len(msgs) != 1 {
		t.Fatalf("maybeSync config:dial: got %d messages, want 1", len(msgs))
	}
}

// --- Close ---

func TestClient_Close(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// --- Ping error path ---

func TestClient_Ping_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	if err := c.Ping(context.Background()); err == nil {
		t.Error("Ping on down Redis: expected error")
	}
}

// --- Set with TTL ---

func TestClient_Set_WithTTL(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()
	ctx := context.Background()

	c.Set(ctx, "ttlkey", "ttlval", 30*time.Second)
	v, _ := c.Get(ctx, "ttlkey")
	if v != "ttlval" {
		t.Errorf("Set with TTL: got %q, want %q", v, "ttlval")
	}
	ttl := mr.TTL("ttlkey")
	if ttl <= 0 || ttl > 31*time.Second {
		t.Errorf("Set TTL: got %v, want ~30s", ttl)
	}
}

func TestClient_Set_Error(t *testing.T) {
	c, mr := newTestClient(t)
	mr.Close()
	// Should not panic
	c.Set(context.Background(), "k", "v", 0)
}

// --- New with nil logger ---

func TestClient_New_NilLogger(t *testing.T) {
	c := New(Config{Host: "127.0.0.1", Port: 19999, Timeout: 100 * time.Millisecond}, nil)
	if c == nil {
		t.Fatal("New with nil logger: returned nil")
	}
	if c.log == nil {
		t.Error("New with nil logger: log field should be non-nil")
	}
}

// --- newFromOptions with nil logger ---

func TestClient_newFromOptions_NilLogger(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	c := newFromOptions(&goredis.Options{Addr: "127.0.0.1:19999"}, nil)
	if c == nil {
		t.Fatal("newFromOptions with nil logger: returned nil")
	}
	if c.log == nil {
		t.Error("newFromOptions with nil logger: log field should be non-nil")
	}
}
