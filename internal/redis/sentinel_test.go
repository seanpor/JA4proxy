package redis

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNew_SentinelConfig(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	// Test Sentinel configuration
	cfg := Config{
		MasterName: "ja4proxy-primary",
		Sentinels:  []string{"127.0.0.1:26379", "127.0.0.1:26380"},
		Password:   "secret",
		DB:         0,
		Timeout:    2 * time.Second,
	}

	c := New(cfg, log)
	if c == nil {
		t.Fatal("New returned nil for Sentinel config")
	}
	defer c.Close()

	// Since we can't easily inspect the internal go-redis client type/options
	// without reflection or export changes, we'll verify it doesn't panic
	// and handles the configuration.
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
