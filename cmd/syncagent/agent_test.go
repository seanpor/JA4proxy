package main

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

func newTestAgent(t *testing.T) (*SyncAgent, *redis.Client, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{
		Host: mr.Host(),
		Port: mr.Server().Addr().Port,
	}, log)

	cfg := &config.Config{
		Sync: config.SyncAgentConfig{
			DCID: "dc-test",
		},
	}
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))
	return agent, rc, mr
}

func TestProcessInbound_Set(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "set",
		Key:   "ban:1.1.1.1",
		Value: "sync-test",
		TTLMS: 3600000,
	}

	agent.processInbound(event)

	val, err := mr.Get("ban:1.1.1.1")
	if err != nil {
		t.Errorf("expected key to be set: %v", err)
	}
	if val != "sync-test" {
		t.Errorf("got %s, want sync-test", val)
	}
	if mr.TTL("ban:1.1.1.1") <= 0 {
		t.Error("expected positive TTL")
	}
}

func TestProcessInbound_Tombstone(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	// Initial state: whitelist has the member
	mr.SAdd("ja4:whitelist", "fp1")

	// Inbound event: addition to removals set (tombstone for SREM)
	event := SyncEvent{
		Op:    "sadd",
		Key:   "ja4:whitelist:removals",
		Value: "fp1",
	}

	agent.processInbound(event)

	// Verify fp1 is removed from base set
	if ok, _ := mr.SIsMember("ja4:whitelist", "fp1"); ok {
		t.Error("fp1 should have been removed from ja4:whitelist")
	}

	// Verify fp1 is in removals set
	if ok, _ := mr.SIsMember("ja4:whitelist:removals", "fp1"); !ok {
		t.Error("fp1 should be in ja4:whitelist:removals")
	}
}

func TestProcessInbound_ZAdd(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "zadd",
		Key:   "test-zset",
		Value: "99.5",
	}

	agent.processInbound(event)

	// After bug fix: member is event.Value, not event.Key
	score, err := mr.ZScore("test-zset", "99.5")
	if err != nil {
		t.Errorf("ZScore failed: %v", err)
	}
	if score != 99.5 {
		t.Errorf("got %f, want 99.5", score)
	}
}
