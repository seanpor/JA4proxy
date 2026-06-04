package main

import (
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

func TestHandleDialRPC_Bounds(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)
	cfg := &config.Config{Sync: config.SyncAgentConfig{DCID: "dc-test"}}
	_ = NewSyncAgent(cfg, rc, log.WithField("test", true))

	tests := []struct {
		dial    int
		allowed bool
	}{
		{0, true},
		{50, true},
		{100, true},
		{-1, false},
		{101, false},
		{200, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Dial_%d", tt.dial), func(t *testing.T) {
			if tt.dial < 0 || tt.dial > 100 {
				if tt.allowed {
					t.Errorf("Dial %d should be forbidden", tt.dial)
				}
			} else {
				if !tt.allowed {
					t.Errorf("Dial %d should be allowed", tt.dial)
				}
			}
		})
	}
}
