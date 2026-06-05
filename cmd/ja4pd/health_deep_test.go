package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/metrics"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

var onceMetrics sync.Once

func ensureMetricsRegistered() {
	onceMetrics.Do(func() {
		metrics.Register()
	})
}

func TestHealthDeep_ResponseSchema(t *testing.T) {
	ensureMetricsRegistered()

	// Start miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	// Seed config:dial
	mr.Set("config:dial", "25")

	// Create Redis client
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer rc.Close()

	// Create a minimal proxy instance
	p := &proxy{
		redis:       rc,
		activeConns: 42,
		cfg:         &config.Config{},
	}

	// Exercise the handler
	req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	w := httptest.NewRecorder()
	p.handleHealthDeep(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, w.Body.String())
	}

	// Verify all expected fields
	expectedFields := []string{
		"status",
		"redis_connected",
		"redis_latency_ms",
		"dial",
		"active_connections",
		"connections_total",
		"block_rate_pct",
		"active_bans",
		"cert_days_remaining",
	}

	for _, field := range expectedFields {
		if _, ok := resp[field]; !ok {
			t.Errorf("missing field: %s", field)
		}
	}

	// Verify values
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", resp["status"])
	}
	if resp["redis_connected"] != true {
		t.Errorf("expected redis_connected=true, got %v", resp["redis_connected"])
	}
	if resp["dial"].(float64) != 25 {
		t.Errorf("expected dial=25, got %v", resp["dial"])
	}
	if resp["active_connections"].(float64) != 42 {
		t.Errorf("expected active_connections=42, got %v", resp["active_connections"])
	}
}

func TestHealthDeep_RedisDown(t *testing.T) {
	ensureMetricsRegistered()

	// Create Redis client pointing at non-existent server
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    "127.0.0.1",
		Port:    1, // won't be listening
		Timeout: 100 * time.Millisecond,
	}, log)
	defer rc.Close()

	p := &proxy{
		redis:       rc,
		activeConns: 0,
		cfg:         &config.Config{},
	}

	// Phase 203e: anti-flap requires N=3 consecutive failures to flip status
	// from "degraded" to "error". Probe three times.
	var resp map[string]any
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		w := httptest.NewRecorder()
		p.handleHealthDeep(w, req)
		resp = nil
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
	}

	if resp["status"] != "error" {
		t.Errorf("expected status=error when Redis is down (after N=3 anti-flap failures), got %v", resp["status"])
	}
	if resp["redis_connected"] != false {
		t.Errorf("expected redis_connected=false, got %v", resp["redis_connected"])
	}
}

func TestMetricsSummary_DelegatesToHealthDeep(t *testing.T) {
	ensureMetricsRegistered()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	mr.Set("config:dial", "10")

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer rc.Close()

	p := &proxy{
		redis:       rc,
		activeConns: 5,
		cfg:         &config.Config{},
	}

	// Call both endpoints and verify they produce the same schema
	req1 := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/metrics/summary", nil)
	w1 := httptest.NewRecorder()
	w2 := httptest.NewRecorder()

	p.handleHealthDeep(w1, req1)
	p.handleMetricsSummary(w2, req2)

	var resp1, resp2 map[string]any
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	// Both should have the same keys
	for k := range resp1 {
		if _, ok := resp2[k]; !ok {
			t.Errorf("/metrics/summary missing field %q that /health/deep has", k)
		}
	}
	for k := range resp2 {
		if _, ok := resp1[k]; !ok {
			t.Errorf("/health/deep missing field %q that /metrics/summary has", k)
		}
	}
}
