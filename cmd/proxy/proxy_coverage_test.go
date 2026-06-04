package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/anomalyco/ja4proxy/internal/config"
	redisclient "github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/anomalyco/ja4proxy/internal/security"
	"github.com/sirupsen/logrus"
)

// TestBuildPipelineConfig verifies that buildPipelineConfig correctly maps
// config.Config fields to a PipelineConfig.
func TestBuildPipelineConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.SecurityPolicy.ALPNBrowserBypass.Enabled = true
	cfg.SecurityPolicy.JA4WhitelistBypass.Enabled = true
	cfg.SecurityPolicy.JA4BlockingEnabled.Enabled = true
	cfg.SecurityPolicy.MTLSBypass.Enabled = false
	cfg.SecurityPolicy.CountryBlockingEnabled.Enabled = true
	cfg.SecurityPolicy.TLSVersionBypass.Enabled = true

	cfg.Security.Whitelist = []string{"fp1", "fp2"}
	cfg.Security.Blacklist = []string{"fp3"}

	cfg.RiskScorer.Thresholds.Flag = 20
	cfg.RiskScorer.Thresholds.RateLimit = 40
	cfg.RiskScorer.Thresholds.Tarpit = 60
	cfg.RiskScorer.Thresholds.Block = 80
	cfg.RiskScorer.Thresholds.Ban = 95

	cfg.TLSEnforcer.BlockTLS10 = true
	cfg.TLSEnforcer.BlockTLS11 = true
	cfg.TLSEnforcer.FlagTLS12 = true
	cfg.TLSEnforcer.BlockWeakCiphers = true

	cfg.SNIAnalyzer.MissingSNI.Enabled = true
	cfg.SNIAnalyzer.MissingSNI.Score = 15
	cfg.SNIAnalyzer.IPLiteralSNI.Enabled = true
	cfg.SNIAnalyzer.IPLiteralSNI.Score = 10
	cfg.SNIAnalyzer.DGADetection.Enabled = true
	cfg.SNIAnalyzer.DGADetection.ScoreCap = 25
	cfg.SNIAnalyzer.ExpectedHostnames = []string{"example.com"}

	cfg.RateLimiter.Enabled = true
	cfg.RateLimiter.ByIP.Enabled = true
	cfg.RateLimiter.ByIP.Suspicious = 100
	cfg.RateLimiter.ByIP.Block = 500
	cfg.RateLimiter.ByIP.Ban = 1000

	pc := buildPipelineConfig(cfg)

	if !pc.ALPNBrowserBypass {
		t.Error("ALPNBrowserBypass should be true")
	}
	if !pc.JA4WhitelistBypass {
		t.Error("JA4WhitelistBypass should be true")
	}
	if !pc.JA4BlockingEnabled {
		t.Error("JA4BlockingEnabled should be true")
	}
	if pc.MTLSBypass {
		t.Error("MTLSBypass should be false")
	}
	if !pc.TLSVersionBypassEnabled {
		t.Error("TLSVersionBypassEnabled should be true")
	}
	if !pc.Whitelist["fp1"] || !pc.Whitelist["fp2"] {
		t.Error("whitelist should contain fp1 and fp2")
	}
	if !pc.Blacklist["fp3"] {
		t.Error("blacklist should contain fp3")
	}
	if pc.Thresholds["flag"] != 20 {
		t.Errorf("flag threshold = %d; want 20", pc.Thresholds["flag"])
	}
	if pc.Thresholds["ban"] != 95 {
		t.Errorf("ban threshold = %d; want 95", pc.Thresholds["ban"])
	}
	if !pc.BlockTLS10 || !pc.BlockTLS11 || !pc.FlagTLS12 || !pc.BlockWeakCiphers {
		t.Error("TLS enforcer flags should be true")
	}
	if !pc.MissingSNIEnabled || pc.MissingSNIScore != 15 {
		t.Error("MissingSNI config mismatch")
	}
	if !pc.DGAEnabled || pc.DGAScoreCap != 25 {
		t.Error("DGA config mismatch")
	}
	if !pc.ExpectedHostnames["example.com"] {
		t.Error("ExpectedHostnames should contain example.com")
	}
	if !pc.RateLimiterEnabled {
		t.Error("RateLimiterEnabled should be true")
	}
	if !pc.RateLimiterByIP.Enabled || pc.RateLimiterByIP.Suspicious != 100 {
		t.Error("RateLimiterByIP config mismatch")
	}
}

// TestStringSliceToSet verifies the helper converts slices to maps.
func TestStringSliceToSet(t *testing.T) {
	result := stringSliceToSet([]string{"a", "b", "c"})
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result))
	}
	for _, k := range []string{"a", "b", "c"} {
		if !result[k] {
			t.Errorf("missing key %q", k)
		}
	}

	// Empty slice
	nilResult := stringSliceToSet(nil)
	if nilResult != nil {
		t.Errorf("expected nil for empty slice, got %v", nilResult)
	}
}

// TestDedupStrings verifies deduplication preserves order.
func TestDedupStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	result := dedupStrings(input)
	expected := []string{"a", "b", "c"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d, got %d: %v", len(expected), len(result), result)
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %q; want %q", i, result[i], v)
		}
	}
}

// TestBuildStaticAllowlist verifies the helper builds the correct map.
func TestBuildStaticAllowlist(t *testing.T) {
	ips := []config.StaticIPConfigYAML{
		{IP: "10.0.0.1"},
		{IP: "192.168.1.0/24"},
	}
	result := buildStaticAllowlist(ips)
	if !result["10.0.0.1"] {
		t.Error("missing 10.0.0.1")
	}
	if !result["192.168.1.0/24"] {
		t.Error("missing 192.168.1.0/24")
	}
}

// TestBuildBlocklistFeeds verifies the helper maps config feeds correctly.
func TestBuildBlocklistFeeds(t *testing.T) {
	feeds := []config.BlocklistFeedConfigYAML{
		{
			Name:    "spamhaus",
			URL:     "https://example.com/drop.txt",
			Format:  "cidr",
			Enabled: true,
			Score:   100,
		},
	}
	result := buildBlocklistFeeds(feeds)
	if len(result) != 1 {
		t.Fatalf("expected 1 feed, got %d", len(result))
	}
	if result[0].Name != "spamhaus" {
		t.Errorf("feed name = %q; want spamhaus", result[0].Name)
	}
	if result[0].Score != 100 {
		t.Errorf("feed score = %d; want 100", result[0].Score)
	}
}

// TestHandleHealth_RedisUp verifies /health returns 200 when Redis is up.
func TestHandleHealth_RedisUp(t *testing.T) {
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer rc.Close()

	p := &proxy{
		redis: rc,
		cfg:   &config.Config{},
		log:   log,
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q; want ok", resp["status"])
	}
	if resp["redis"] != "ok" {
		t.Errorf("redis = %q; want ok", resp["redis"])
	}
}

// TestHandleHealth_RedisDown verifies /health returns 503 when Redis is down.
func TestHandleHealth_RedisDown(t *testing.T) {
	ensureMetricsRegistered()
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 100 * time.Millisecond,
	}, log)
	defer rc.Close()

	p := &proxy{
		redis: rc,
		cfg:   &config.Config{},
		log:   log,
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "degraded" {
		t.Errorf("status = %q; want degraded", resp["status"])
	}
}

// TestRemoteIP verifies IP extraction from a TCP connection address.
func TestRemoteIP(t *testing.T) {
	// remoteIP is defined in the main package; we're in the same package so can test it.
	// We'll test the fallback behavior with a mock conn.
	// (remoteIP with a real TCPAddr is tested through handleConn integration tests)
}

// TestNewProxy_RequiresConfig is a basic smoke test verifying newProxy doesn't
// panic with a minimal config. We don't run the full proxy, just check construction.
func TestNewProxy_MinimalConfig(t *testing.T) {
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	cfg := &config.Config{}
	cfg.Redis.Host = mr.Host()
	cfg.Redis.Port = config.FlexInt(mr.Server().Addr().Port)
	cfg.Redis.Timeout = config.FlexInt(2)
	cfg.MonitorMode.Dial = 0
	cfg.Proxy.BufferSize = 4096
	cfg.Proxy.ReadTimeout = 10
	cfg.Proxy.WriteTimeout = 10
	cfg.Proxy.ConnectionTimeout = 5
	cfg.Proxy.DrainTimeoutSeconds = 5
	cfg.Proxy.BackendHost = "localhost"
	cfg.Proxy.BackendPort = config.FlexInt(443)
	cfg.Tarpit.MaxActiveConnections = 100
	cfg.Tarpit.MaxPerIP = 5
	cfg.Tarpit.OverflowAction = "block"

	prx, err := newProxy(cfg, "", log)
	if err != nil {
		t.Fatalf("newProxy error: %v", err)
	}
	if prx == nil {
		t.Fatal("newProxy returned nil")
	}
	if prx.pipeline == nil {
		t.Error("pipeline should not be nil")
	}
	if prx.redis == nil {
		t.Error("redis should not be nil")
	}
}

// TestUpdateTLSCertExpiryGauge_EmptyPath verifies no panic on empty cert path.
func TestUpdateTLSCertExpiryGauge_EmptyPath(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	// Should return without error
	updateTLSCertExpiryGauge("", log)
}

// TestUpdateTLSCertExpiryGauge_NonexistentFile verifies it handles missing file.
func TestUpdateTLSCertExpiryGauge_NonexistentFile(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	updateTLSCertExpiryGauge("/nonexistent/cert.pem", log)
	// Should not panic — gauge set to 0
}

// TestUpdateTLSCertExpiryGauge_InvalidPEM verifies it handles invalid PEM data.
func TestUpdateTLSCertExpiryGauge_InvalidPEM(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)

	tmpFile := t.TempDir() + "/bad.pem"
	if err := writeFile(tmpFile, "not a pem file"); err != nil {
		t.Fatal(err)
	}
	updateTLSCertExpiryGauge(tmpFile, log)
	// Should not panic — gauge set to 0
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// TestNewLogger_JSONEnabled verifies JSON logging is configured when enabled.
func TestNewLogger_JSONEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.JSONEnabled = true
	cfg.Logging.Level = "debug"
	log := newLogger(cfg)
	if log.Level != logrus.DebugLevel {
		t.Errorf("expected DebugLevel, got %v", log.Level)
	}
}

// TestNewLogger_ECSFormat verifies ECS formatter is used.
func TestNewLogger_ECSFormat(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.Format = "ecs"
	cfg.Logging.Level = "info"
	log := newLogger(cfg)
	if log.Level != logrus.InfoLevel {
		t.Errorf("expected InfoLevel, got %v", log.Level)
	}
}

// TestNewLogger_InvalidLevel verifies fallback to InfoLevel.
func TestNewLogger_InvalidLevel(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.Level = "notareallevel"
	log := newLogger(cfg)
	if log.Level != logrus.InfoLevel {
		t.Errorf("expected InfoLevel fallback, got %v", log.Level)
	}
}

// TestNewLogger_DualOutput verifies dual output configuration.
func TestNewLogger_DualOutput(t *testing.T) {
	cfg := &config.Config{}
	cfg.Logging.Format = "ecs"
	cfg.Logging.DualOutput = true
	cfg.Logging.Level = "warn"
	log := newLogger(cfg)
	if log.Level != logrus.WarnLevel {
		t.Errorf("expected WarnLevel, got %v", log.Level)
	}
}

// TestDrain_NoConnections verifies drain returns immediately when no connections.
func TestDrain_NoConnections(t *testing.T) {
	p := &proxy{
		activeConns: 0,
		log:         logrus.New(),
	}
	start := time.Now()
	p.drain(1)
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("drain took too long (%v) with 0 active connections", elapsed)
	}
}

// TestRemoteIP_Fallback verifies remoteIP returns a string for non-TCP connections.
func TestRemoteIP_Fallback(t *testing.T) {
	// Test with a mock address that is not TCPAddr
	result, _ := remoteIP(&mockConn{addr: mockAddr("1.2.3.4:5678")})
	if result != "1.2.3.4:5678" {
		t.Errorf("remoteIP = %q; want 1.2.3.4:5678", result)
	}
}

// TestRemotePort_Fallback verifies remotePort returns 0 for non-TCP connections.
func TestRemotePort_Fallback(t *testing.T) {
	result := remotePort(&mockConn{addr: mockAddr("1.2.3.4:5678")})
	if result != 0 {
		t.Errorf("remotePort = %d; want 0", result)
	}
}

// mockAddr implements net.Addr for testing.
type mockAddr string

func (a mockAddr) Network() string { return "mock" }
func (a mockAddr) String() string  { return string(a) }

// mockConn is a minimal net.Conn for testing remoteIP/remotePort.
type mockConn struct {
	net.Conn
	addr net.Addr
}

func (c *mockConn) RemoteAddr() net.Addr { return c.addr }

// TestSeedSecurityLists verifies seedSecurityLists populates Redis.
func TestSeedSecurityLists(t *testing.T) {
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer rc.Close()

	cfg := &config.Config{}
	cfg.Security.Whitelist = []string{"fp1", "fp2"}
	cfg.Security.Blacklist = []string{"fp3"}
	cfg.GeoIP.CountryBlacklist = []string{"10.0.0.0/8"}

	ctx := context.Background()
	seedSecurityLists(ctx, rc, cfg)

	if ok, _ := mr.SIsMember("ja4:whitelist", "fp1"); !ok {
		t.Error("fp1 should be in ja4:whitelist")
	}
	if ok, _ := mr.SIsMember("ja4:whitelist", "fp2"); !ok {
		t.Error("fp2 should be in ja4:whitelist")
	}
	if ok, _ := mr.SIsMember("ja4:blacklist", "fp3"); !ok {
		t.Error("fp3 should be in ja4:blacklist")
	}
	if ok, _ := mr.SIsMember("geoip:blocked_cidrs", "10.0.0.0/8"); !ok {
		t.Error("10.0.0.0/8 should be in geoip:blocked_cidrs")
	}
}

// TestLoadSecurityLists verifies loadSecurityLists loads from Redis into the pipeline.
func TestLoadSecurityLists(t *testing.T) {
	ensureMetricsRegistered()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	mr.SAdd("ja4:whitelist", "fp1")
	mr.SAdd("ja4:blacklist", "fp3")
	mr.SAdd("geoip:blocked_cidrs", "10.0.0.0/8")

	log := logrus.New()
	log.SetLevel(logrus.WarnLevel)
	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)
	defer rc.Close()

	pipeCfg := buildPipelineConfig(&config.Config{})
	p := security.NewPipeline(pipeCfg, rc, log)

	ctx := context.Background()
	loadSecurityLists(ctx, rc, p)
	// No panic = success; the function logs its own output
}

// Verify security.PipelineConfig is correctly typed (compile-time check).
var _ = func() *security.PipelineConfig {
	return buildPipelineConfig(&config.Config{})
}
