package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/tap"
)

// TestBuildBackends_PingSucceeds guards R-012's happy path: a reachable
// Redis logs "Redis connection verified" and returns real backends, no error.
func TestBuildBackends_PingSucceeds(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)

	cfg := runConfig{redisURL: "redis://" + mr.Addr() + "/0", enfCfg: tap.EnforcerConfig{}}
	store, enforcer, err := buildBackends(cfg, log)
	if err != nil {
		t.Fatalf("buildBackends: %v", err)
	}
	if store == nil || enforcer == nil {
		t.Fatal("expected non-nil store and enforcer")
	}
	if !strings.Contains(buf.String(), "Redis connection verified") {
		t.Errorf("expected a successful-ping log line; got: %s", buf.String())
	}
}

// TestBuildBackends_PingFailsWarnsButDoesNotError guards R-012's fail-open
// requirement: a Redis that can't be reached at startup must still return
// usable (if degraded) backends and no error -- a transient outage at
// startup must not prevent the sensor from at least passively classifying
// and logging traffic.
func TestBuildBackends_PingFailsWarnsButDoesNotError(t *testing.T) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	log.SetLevel(logrus.DebugLevel)

	// 127.0.0.1:1 is very unlikely to have anything listening, and the
	// startup Ping is bounded to 5s so this test doesn't hang.
	cfg := runConfig{redisURL: "redis://127.0.0.1:1/0", enfCfg: tap.EnforcerConfig{}}
	store, enforcer, err := buildBackends(cfg, log)
	if err != nil {
		t.Fatalf("buildBackends must not fail on an unreachable Redis (fail-open); got: %v", err)
	}
	if store == nil || enforcer == nil {
		t.Fatal("expected non-nil store and enforcer even with Redis unreachable")
	}
	if !strings.Contains(buf.String(), "Redis ping failed at startup") {
		t.Errorf("expected a ping-failure warning log line; got: %s", buf.String())
	}
}
