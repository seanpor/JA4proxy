package main

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

func TestProcessInbound_KeyValidation(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)
	cfg := &config.Config{Sync: config.SyncAgentConfig{DCID: "dc-test"}}
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	tests := []struct {
		name    string
		event   SyncEvent
		allowed bool
	}{
		{"Allowed Ban", SyncEvent{Op: "set", Key: "ban:1.2.3.4", Value: "test"}, true},
		{"Allowed Whitelist", SyncEvent{Op: "sadd", Key: "ja4:whitelist", Value: "fp1"}, true},
		{"Allowed Whitelist Removals", SyncEvent{Op: "sadd", Key: "ja4:whitelist:removals", Value: "fp1"}, true},
		{"Forbidden Root", SyncEvent{Op: "set", Key: "root_password", Value: "hacked"}, false},
		{"Forbidden Config", SyncEvent{Op: "set", Key: "config:webhook_secret", Value: "stolen"}, false},
		{"Forbidden Admin", SyncEvent{Op: "sadd", Key: "admin_users", Value: "attacker"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent.processInbound(tt.event)
			
			if tt.allowed {
				// Check if it was applied
				if tt.event.Op == "set" {
					if val, _ := mr.Get(tt.event.Key); val != tt.event.Value {
						t.Errorf("Expected key %s to be set", tt.event.Key)
					}
				}
			} else {
				// Check if it was NOT applied
				if mr.Exists(tt.event.Key) {
					t.Errorf("Forbidden key %s was applied!", tt.event.Key)
				}
			}
		})
	}
}
