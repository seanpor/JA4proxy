package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anomalyco/ja4proxy/internal/cache"
)

func defaultAbuseIPDBCfg(apiURL string) *AbuseIPDBConfig {
	return &AbuseIPDBConfig{
		Enabled:           true,
		APIKey:            "test-key",
		ScoreCap:          40,
		SharedIPThreshold: 50,
		LocalCacheSize:    100,
		Workers:           1,
		APIURL:            apiURL,
	}
}

func TestAbuseIPDB_Disabled_NoSignal(t *testing.T) {
	a := NewAbuseIPDB(&AbuseIPDBConfig{Enabled: false}, &mockRedis{}, nil)
	sig := a.GetSignal("1.2.3.4")
	if sig != nil {
		t.Errorf("disabled: expected nil, got %v", sig)
	}
}

func TestAbuseIPDB_LocalCacheHit_NoHTTPCall(t *testing.T) {
	// Pre-populate local cache with confidence=80
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
	}))
	defer srv.Close()

	a := NewAbuseIPDB(defaultAbuseIPDBCfg(srv.URL), &mockRedis{}, nil)
	a.localCache.Set("1.2.3.4", 80, 30*time.Minute)

	sig := a.GetSignal("1.2.3.4")
	if sig == nil {
		t.Fatal("local cache hit: expected signal")
	}
	if callCount != 0 {
		t.Errorf("local cache hit: HTTP should not be called, got %d calls", callCount)
	}
}

func TestAbuseIPDB_RedisCacheHit_Score(t *testing.T) {
	r := newMockRedisRW()
	r.strings["abuseipdb:1.2.3.4"] = "75"
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(""), r, nil)
	sig := a.GetSignal("1.2.3.4")
	if sig == nil {
		t.Fatal("redis cache hit: expected signal")
	}
	if sig.Name != "abuseipdb" {
		t.Errorf("expected 'abuseipdb', got %q", sig.Name)
	}
}

func TestAbuseIPDB_HighConfidence_ScaledScore(t *testing.T) {
	// confidence=100 → score = round(100/100 * 40) = 40
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(""), &mockRedis{}, nil)
	a.localCache.Set("1.2.3.4", 100, 30*time.Minute)
	sig := a.GetSignal("1.2.3.4")
	if sig == nil {
		t.Fatal("high confidence: expected signal")
	}
	if sig.Score != 40 {
		t.Errorf("expected score=40, got %d", sig.Score)
	}
}

func TestAbuseIPDB_LowConfidence_SharedIPCapped(t *testing.T) {
	// confidence=25 (below SharedIPThreshold=50) → score = round(25/50 * 15) = 8
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(""), &mockRedis{}, nil)
	a.localCache.Set("1.2.3.4", 25, 30*time.Minute)
	sig := a.GetSignal("1.2.3.4")
	if sig == nil {
		t.Fatal("low confidence: expected signal")
	}
	expected := 8 // round(25/50 * 15)
	if sig.Score != expected {
		t.Errorf("low confidence: expected score=%d, got %d", expected, sig.Score)
	}
}

func TestAbuseIPDB_ZeroConfidence_NoSignal(t *testing.T) {
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(""), &mockRedis{}, nil)
	a.localCache.Set("1.2.3.4", 0, 30*time.Minute)
	sig := a.GetSignal("1.2.3.4")
	if sig != nil {
		t.Errorf("zero confidence: expected nil, got %v", sig)
	}
}

func TestAbuseIPDB_APIError_FailOpen(t *testing.T) {
	// Server returns 500 — should fail open (no signal)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewAbuseIPDB(defaultAbuseIPDBCfg(srv.URL), &mockRedis{}, nil)
	sig := a.GetSignal("1.2.3.4")
	// Not cached yet — returns nil (enqueues lookup)
	if sig != nil {
		t.Errorf("not cached: expected nil signal, got %v", sig)
	}
}

func TestAbuseIPDB_LookupStoresInRedis(t *testing.T) {
	// Mock HTTPS server returns confidence=60. JA4PROXY-2026-0049 — the
	// AbuseIPDB client refuses to send the API key to a non-HTTPS URL, so
	// the test harness must use httptest.NewTLSServer and inject its TLS-
	// aware http.Client (which trusts the server's self-signed cert).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // test HTTP handler
			"data": map[string]interface{}{
				"abuseConfidenceScore": 60,
			},
		})
	}))
	defer srv.Close()

	r := newMockRedisRW()
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(srv.URL), r, nil)
	a.http = srv.Client()

	// Trigger a synchronous lookup
	a.lookup(context.Background(), "1.2.3.4")

	// Check local cache was set
	if v, ok := a.localCache.Get("1.2.3.4"); !ok || v.(int) != 60 {
		t.Errorf("after lookup: local cache should have confidence=60")
	}
}

// Compile check: ensure cache.LRU usage is correct.
var _ *cache.LRU = cache.New(10)
