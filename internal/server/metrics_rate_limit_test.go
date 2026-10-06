package server

// Regression test for JA4PROXY-2026-0026 — Unauthenticated Health/Metrics
// Endpoints Missing Rate Limiting (MEDIUM, CVSS 5.3).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestLimitedHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

func TestRegression_JA4PROXY_2026_0026_remote_is_throttled_after_burst(t *testing.T) {
	lim := NewMetricsRateLimiter(1.0 /* rps */, 3 /* burst */)
	h := MetricsRateLimitMiddleware(newTestLimitedHandler(), lim, nil)

	remote := "203.0.113.42:54321"

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("burst request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst request: want 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over-burst request must set Retry-After header")
	}
}

func TestRegression_JA4PROXY_2026_0026_loopback_is_never_throttled(t *testing.T) {
	lim := NewMetricsRateLimiter(1.0, 1)
	h := MetricsRateLimitMiddleware(newTestLimitedHandler(), lim, nil)

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "127.0.0.1:60000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("loopback request %d throttled: got %d", i+1, rec.Code)
		}
	}
}

func TestRegression_JA4PROXY_2026_0026_ipv6_loopback_exempt(t *testing.T) {
	lim := NewMetricsRateLimiter(1.0, 1)
	h := MetricsRateLimitMiddleware(newTestLimitedHandler(), lim, nil)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "[::1]:60000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ipv6 loopback request %d throttled: got %d", i+1, rec.Code)
		}
	}
}

func TestRegression_JA4PROXY_2026_0026_separate_ips_have_separate_buckets(t *testing.T) {
	lim := NewMetricsRateLimiter(1.0, 2)
	h := MetricsRateLimitMiddleware(newTestLimitedHandler(), lim, nil)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "198.51.100.10:1000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP-A burst: want 200, got %d", rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.10:1000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("IP-A over-burst: want 429, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "198.51.100.11:1000"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("IP-B first request (IP-A was throttled): want 200, got %d", rec.Code)
	}
}

func TestRegression_JA4PROXY_2026_0026_tokens_refill_over_time(t *testing.T) {
	lim := NewMetricsRateLimiter(100.0 /* 100 rps */, 1)
	remote := "203.0.113.99:2000"
	t0 := time.Unix(0, 0)

	if !lim.allow(remote, t0) {
		t.Fatalf("first request (burst=1) should be allowed")
	}
	if lim.allow(remote, t0) {
		t.Fatalf("second request at t0 should be over-limit")
	}
	if !lim.allow(remote, t0.Add(15*time.Millisecond)) {
		t.Fatalf("request after 15ms at 100rps should have refilled")
	}
}

func TestRegression_JA4PROXY_2026_0026_zero_rps_disables_limiter(t *testing.T) {
	lim := NewMetricsRateLimiter(0, 0)
	remote := "203.0.113.200:5000"
	for i := 0; i < 1000; i++ {
		if !lim.allow(remote, time.Now()) {
			t.Fatalf("zero-rps limiter must never throttle (iter %d)", i)
		}
	}
}

func TestRegression_JA4PROXY_2026_0026_nil_limiter_is_safe(t *testing.T) {
	var lim *MetricsRateLimiter
	if !lim.allow("203.0.113.250:6000", time.Now()) {
		t.Fatalf("nil limiter must not throttle")
	}
}

func TestRegression_JA4PROXY_2026_0026_bucket_map_capped(t *testing.T) {
	lim := NewMetricsRateLimiter(1.0, 1)
	lim.maxEntries = 8

	now := time.Unix(0, 0)
	for i := 0; i < 100; i++ {
		lim.allow(toIPPort(i), now.Add(time.Duration(i)*time.Microsecond))
	}
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if got := len(lim.bucket); got > lim.maxEntries {
		t.Fatalf("bucket map exceeded cap: %d > %d", got, lim.maxEntries)
	}
}

func toIPPort(i int) string {
	return formatIP(203, 0, 113, byte(i)) + ":1000"
}

func formatIP(a, b, c, d byte) string {
	buf := make([]byte, 0, 16)
	buf = appendDec(buf, a)
	buf = append(buf, '.')
	buf = appendDec(buf, b)
	buf = append(buf, '.')
	buf = appendDec(buf, c)
	buf = append(buf, '.')
	buf = appendDec(buf, d)
	return string(buf)
}

func appendDec(buf []byte, v byte) []byte {
	if v >= 100 {
		buf = append(buf, '0'+v/100)
	}
	if v >= 10 {
		buf = append(buf, '0'+(v/10)%10)
	}
	buf = append(buf, '0'+v%10)
	return buf
}
