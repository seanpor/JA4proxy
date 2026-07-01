package redis

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNew_SentinelConfig(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	// Use a 1ms dial timeout so pool goroutines fail instantly when there is
	// no running Sentinel (avoids the test hanging on connection retries).
	cfg := Config{
		MasterName: "ja4proxy-primary",
		Sentinels:  []string{"127.0.0.1:26379", "127.0.0.1:26380"},
		Password:   "secret",
		DB:         0,
		Timeout:    1 * time.Millisecond,
	}

	c := New(cfg, log)
	if c == nil {
		t.Fatal("New returned nil for Sentinel config")
	}
	defer c.Close()
}

func TestNew_SingleNodeConfig(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	// Test standard single-node configuration
	cfg := Config{
		Host:    "127.0.0.1",
		Port:    6379,
		Timeout: 2 * time.Second,
	}

	c := New(cfg, log)
	if c == nil {
		t.Fatal("New returned nil for single-node config")
	}
	defer c.Close()
}
