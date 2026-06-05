package main

// Phase 203e — TDD red: integration tests for the extended /health/deep handler
// with component checks (tarpit, geoip) and anti-flap hysteresis.
//
// Contract (from docs/phases/PHASE_203.md sub-phase 203e):
//   - /health (liveness) is byte-for-byte unchanged — tested by assertion.
//   - /health/deep returns new fields: tarpit:{active,max,status}, geoip:{present,status}
//   - Anti-flap: 1 failure must NOT flip component status; 3 consecutive failures flip.
//   - HTTP 503 only when a CRITICAL component (redis, geoip if loaded) is unhealthy.
//   - Tarpit saturation → 200 with "degraded" warning, never 503.
//
// All these tests will FAIL against the pre-203e handler because the new
// fields don't exist yet. That's the correct red state.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

func newMiniRedisProxy(t *testing.T) (*proxy, *miniredis.Miniredis, func()) {
	t.Helper()
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	p := &proxy{
		redis:       rc,
		activeConns: 0,
		cfg:         &config.Config{},
		log:         log,
	}
	cleanup := func() {
		rc.Close()
		mr.Close()
	}
	return p, mr, cleanup
}

// /health must remain a tight Redis-or-die liveness probe.
// This test pins its exact response schema so 203e doesn't accidentally leak new fields here.
func TestHealth_Liveness_UnchangedByPhase203e(t *testing.T) {
	p, _, cleanup := newMiniRedisProxy(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/health returned %d; want 200", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// /health MUST have only {status, redis} — nothing else.
	allowed := map[string]bool{"status": true, "redis": true}
	for k := range resp {
		if !allowed[k] {
			t.Errorf("/health must not expose new field %q (that belongs on /health/deep)", k)
		}
	}
	if _, ok := resp["status"]; !ok {
		t.Error("/health missing 'status' field")
	}
	if _, ok := resp["redis"]; !ok {
		t.Error("/health missing 'redis' field")
	}
}

func TestHealthDeep_HasTarpitField(t *testing.T) {
	p, _, cleanup := newMiniRedisProxy(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	w := httptest.NewRecorder()
	p.handleHealthDeep(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	tarpit, ok := resp["tarpit"]
	if !ok {
		t.Fatal("/health/deep missing new 'tarpit' object (phase-203e)")
	}
	tobj, ok := tarpit.(map[string]any)
	if !ok {
		t.Fatalf("'tarpit' must be an object; got %T", tarpit)
	}
	for _, f := range []string{"active", "max", "status"} {
		if _, ok := tobj[f]; !ok {
			t.Errorf("tarpit object missing field %q", f)
		}
	}
}

func TestHealthDeep_HasGeoIPField_WhenLoaded(t *testing.T) {
	p, _, cleanup := newMiniRedisProxy(t)
	defer cleanup()
	// The proxy struct has a geoIP field (cmd/proxy/main.go:136). 203e must
	// expose a "geoip" object in /health/deep whose 'present' reflects whether
	// the reader is non-nil.
	req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	w := httptest.NewRecorder()
	p.handleHealthDeep(w, req)

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	geo, ok := resp["geoip"]
	if !ok {
		t.Fatal("/health/deep missing new 'geoip' object (phase-203e)")
	}
	gobj, ok := geo.(map[string]any)
	if !ok {
		t.Fatalf("'geoip' must be an object; got %T", geo)
	}
	if _, ok := gobj["present"]; !ok {
		t.Error("geoip object missing 'present' field")
	}
	if _, ok := gobj["status"]; !ok {
		t.Error("geoip object missing 'status' field")
	}
	// proxy.geoIP is nil in this test → present should be false, NOT crash.
	if gobj["present"] != false {
		t.Errorf("geoip.present = %v; want false when p.geoIP is nil", gobj["present"])
	}
}

func TestHealthDeep_TarpitSaturated_Returns200NotDegradedTo503(t *testing.T) {
	p, _, cleanup := newMiniRedisProxy(t)
	defer cleanup()
	// Simulate full tarpit. tarpitConcurrent == max should NOT produce 503.
	p.tarpitConcurrent = 1000 // arbitrary saturated number
	req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	w := httptest.NewRecorder()
	p.handleHealthDeep(w, req)

	if w.Code == http.StatusServiceUnavailable {
		t.Errorf("tarpit saturation must NOT return 503; got %d", w.Code)
	}
}

func TestHealthDeep_RedisSingleFailure_DoesNotFlipTo503(t *testing.T) {
	// Anti-flap contract: a single Redis probe failure must NOT mark the
	// endpoint as 503. It takes N=3 consecutive failures per the spec.
	//
	// Point proxy at a dead Redis so Ping fails.
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 100 * time.Millisecond,
	}, log)
	defer rc.Close()
	p := &proxy{
		redis:       rc,
		activeConns: 0,
		cfg:         &config.Config{},
		log:         log,
	}

	req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
	w := httptest.NewRecorder()
	p.handleHealthDeep(w, req)

	if w.Code == http.StatusServiceUnavailable {
		t.Errorf("single Redis failure must NOT flip /health/deep to 503 under anti-flap (N=3); got %d", w.Code)
	}
}

func TestHealthDeep_RedisThreeFailures_Flip503(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 100 * time.Millisecond,
	}, log)
	defer rc.Close()
	p := &proxy{
		redis:       rc,
		activeConns: 0,
		cfg:         &config.Config{},
		log:         log,
	}

	var lastCode int
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health/deep", nil)
		w := httptest.NewRecorder()
		p.handleHealthDeep(w, req)
		lastCode = w.Code
	}
	if lastCode != http.StatusServiceUnavailable {
		t.Errorf("after 3 consecutive Redis failures, /health/deep must return 503; got %d", lastCode)
	}
}
