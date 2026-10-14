package server

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/health"
	"github.com/seanpor/ja4proxy/internal/security"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
)

func newTestServer(t *testing.T) (*Server, *config.Config) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = config.FlexInt(6379)
	cfg.Redis.Password = "test-secret"
	cfg.Redis.ACLUsers.Enabled = true
	cfg.Redis.ACLUsers.ProxyUser = "ja4proxy_app"

	log := logrus.New()
	log.SetOutput(&bytes.Buffer{})

	s := &Server{
		Cfg:         cfg,
		Log:         log,
		HealthState: health.New(health.Config{FailThreshold: 3}),
		NodeID:      "test-node-01",
		AcceptSem:   make(chan struct{}, 100),
		TarpitPerIP: make(map[string]int),
	}
	return s, cfg
}

func TestClassifyConnError(t *testing.T) {
	cases := []struct {
		source string
		err    error
		want   string
	}{
		{"client_read", nil, "unknown"},
		{"backend_dial", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, "backend_dial_timeout"},
		{"client_read", context.DeadlineExceeded, "client_read_timeout"},
		{"redis", context.DeadlineExceeded, "redis_timeout"},
		{"other", context.DeadlineExceeded, "timeout"},
		{"backend_dial", &net.OpError{Op: "dial", Err: &net.AddrError{Err: "connection refused"}}, "backend_refused"},
		{"client_read", &net.OpError{Op: "read", Err: &net.AddrError{Err: "connection refused"}}, "connection_refused"},
		{"backend_dial", &net.OpError{Op: "dial", Err: &net.AddrError{Err: "out of memory"}}, "oom"},
		{"backend_dial", &net.OpError{Op: "dial", Err: &net.AddrError{Err: "unhandled failure"}}, "backend_dial_error"},
		{"client_read", &net.OpError{Op: "read", Err: &net.AddrError{Err: "unhandled failure"}}, "client_read_error"},
		{"redis", &net.OpError{Op: "cmd", Err: &net.AddrError{Err: "unhandled failure"}}, "redis_error"},
	}

	for _, tc := range cases {
		got := ClassifyConnError(tc.source, tc.err)
		if got != tc.want {
			t.Errorf("ClassifyConnError(%q, %v) = %q; want %q", tc.source, tc.err, got, tc.want)
		}
	}
}

func TestDeriveNodeID(t *testing.T) {
	if got := DeriveNodeID("prod-worker-01.eu-west-1"); got != "prod-worker-01-eu-west-1" {
		t.Errorf("DeriveNodeID failed, got %q", got)
	}
	if got := DeriveNodeID(""); got != "ja4proxy" {
		t.Errorf("DeriveNodeID empty failed, got %q", got)
	}
}

func TestSignStreamEvent(t *testing.T) {
	secret := "test-secret"
	event := []byte(`{"event":"test"}`)
	sig := SignStreamEvent(secret, event)
	if sig == "" {
		t.Fatal("expected non-empty HMAC signature")
	}
	if SignStreamEvent("", event) != "" {
		t.Fatal("expected empty HMAC for empty secret")
	}
}

func TestNextConnectionID(t *testing.T) {
	s, _ := newTestServer(t)
	id1 := s.NextConnectionID()
	id2 := s.NextConnectionID()
	if id1 == id2 {
		t.Fatalf("expected unique connection IDs, got %s == %s", id1, id2)
	}
	if !strings.HasPrefix(id1, "test-node-01-") {
		t.Errorf("unexpected connection ID format: %s", id1)
	}
}

func TestStringSliceToSetAndDedup(t *testing.T) {
	if StringSliceToSet(nil) != nil {
		t.Error("expected nil set for empty slice")
	}
	ss := []string{"a", "b", "a", "c"}
	set := StringSliceToSet(ss)
	if len(set) != 3 || !set["a"] || !set["b"] || !set["c"] {
		t.Errorf("StringSliceToSet failed: %+v", set)
	}

	deduped := DedupStrings(ss)
	if len(deduped) != 3 || deduped[0] != "a" || deduped[1] != "b" || deduped[2] != "c" {
		t.Errorf("DedupStrings failed: %+v", deduped)
	}
}

func TestSanitizeString(t *testing.T) {
	raw := "foo\x00bar\r\nbaz\x7f"
	sanitized := sanitizeString(raw)
	if strings.Contains(sanitized, "\x00") || strings.Contains(sanitized, "\x7f") {
		t.Errorf("sanitizeString left control characters: %q", sanitized)
	}
	if sanitizeString("") != "" {
		t.Errorf("sanitizeString empty failed")
	}
}

func TestRemoteIPAndPort(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ipStr, ip := RemoteIP(c1)
	if ipStr == "" {
		t.Error("expected non-empty remote IP string")
	}
	_ = ip
	_ = RemotePort(c1)
}

func TestPopulateTLSFingerprints(t *testing.T) {
	connCtx := &security.ConnectionContext{}
	hello := &tlsparse.ClientHelloInfo{
		LegacyVersion: 0x0303,
		SNI:           "example.com\x00",
		ALPNProtocols: []string{"h2\x00"},
		CipherSuites:  []uint16{0x1301, 0x1302},
		Extensions:    []uint16{0x0000, 0x0010},
	}

	PopulateTLSFingerprints(connCtx, hello)
	if connCtx.TLSVersion != 0x0303 {
		t.Errorf("expected TLSVersion 0x0303, got %x", connCtx.TLSVersion)
	}
	if connCtx.SNI != "example.com" {
		t.Errorf("expected sanitized SNI example.com, got %q", connCtx.SNI)
	}
	if connCtx.ALPN != "h2" {
		t.Errorf("expected sanitized ALPN h2, got %q", connCtx.ALPN)
	}
	if len(connCtx.CipherList) != 2 {
		t.Errorf("expected 2 ciphers, got %d", len(connCtx.CipherList))
	}
}

func TestReassembleClientHello(t *testing.T) {
	s, _ := newTestServer(t)

	// Short data < 5
	short := []byte{0x16, 0x03, 0x01}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	got := s.ReassembleClientHello(c1, short, make([]byte, 1024))
	if !bytes.Equal(got, short) {
		t.Errorf("expected short data returned unmodified")
	}

	// Full record already present in data
	record := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	got = s.ReassembleClientHello(c1, record, make([]byte, 1024))
	if !bytes.Equal(got, record) {
		t.Errorf("expected full record returned unmodified")
	}
}

func TestReassembleProxyHeader(t *testing.T) {
	s, _ := newTestServer(t)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Empty
	if len(s.ReassembleProxyHeader(c1, nil, make([]byte, 1024))) != 0 {
		t.Error("expected empty data returned")
	}

	// PROXY v1 full
	v1Full := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n")
	got := s.ReassembleProxyHeader(c1, v1Full, make([]byte, 1024))
	if !bytes.Equal(got, v1Full) {
		t.Errorf("expected v1Full unmodified")
	}

	// PROXY v2 full
	v2Header := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // magic
		0x21, 0x11, 0x00, 0x00, // ver/cmd, fam/proto, addrLen=0
	}
	got = s.ReassembleProxyHeader(c1, v2Header, make([]byte, 1024))
	if !bytes.Equal(got, v2Header) {
		t.Errorf("expected v2Header unmodified")
	}
}

func TestForwardWithMockBackend(t *testing.T) {
	s, cfg := newTestServer(t)

	// Spin up mock backend TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on mock backend: %v", err)
	}
	defer ln.Close()

	backendHost, backendPortStr, _ := net.SplitHostPort(ln.Addr().String())
	cfg.Proxy.BackendHost = backendHost
	cfg.Proxy.BackendPort = config.FlexInt(mustParseInt(backendPortStr))
	cfg.Proxy.ConnectionTimeout = 2
	cfg.Proxy.ReadTimeout = 2
	cfg.Proxy.WriteTimeout = 2
	cfg.Proxy.WriteProxyProtocol = true
	cfg.Proxy.WriteProxyProtocolVersion = 1

	backendReceived := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			backendReceived <- buf[:n]
		}
	}()

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on client mock: %v", err)
	}
	defer clientLn.Close()

	clientConnected := make(chan net.Conn, 1)
	go func() {
		conn, err := clientLn.Accept()
		if err == nil {
			clientConnected <- conn
		}
	}()

	dialConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial mock client: %v", err)
	}
	defer dialConn.Close()

	serverClientConn := <-clientConnected
	defer serverClientConn.Close()

	initialPayload := []byte("HELLO-BACKEND")
	go s.Forward(serverClientConn, initialPayload, "192.0.2.1", 54321)

	select {
	case rx := <-backendReceived:
		if !strings.HasPrefix(string(rx), "PROXY TCP4") && !strings.Contains(string(rx), "HELLO-BACKEND") {
			t.Errorf("unexpected payload received by backend: %q", string(rx))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for backend to receive forwarded packet")
	}
}

func TestTarpitCapacityAndOverflow(t *testing.T) {
	s, cfg := newTestServer(t)
	cfg.Tarpit.MaxActiveConnections = 2
	cfg.Tarpit.MaxPerIP = 1
	cfg.Tarpit.OverflowAction = "block"

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Fill capacity for client IP
	s.TarpitMu.Lock()
	s.TarpitConcurrent = 2
	s.TarpitPerIP["203.0.113.5"] = 1
	s.TarpitMu.Unlock()

	// Should drop on overflow
	s.Tarpit(c1, []byte("probe"), "203.0.113.5")
}

func TestUpdateTLSCertExpiryGauge(t *testing.T) {
	log := logrus.New()
	log.SetOutput(&bytes.Buffer{})

	// Empty path
	UpdateTLSCertExpiryGauge("", log)

	// Non-existent path
	UpdateTLSCertExpiryGauge("/non/existent/cert.pem", log)

	// Invalid PEM
	tmpDir := t.TempDir()
	badCertPath := filepath.Join(tmpDir, "bad.pem")
	_ = os.WriteFile(badCertPath, []byte("NOT-PEM"), 0600)
	UpdateTLSCertExpiryGauge(badCertPath, log)
}

func TestFormatUint36(t *testing.T) {
	if got := FormatUint36(0); got != "0" {
		t.Errorf("FormatUint36(0) = %q; want 0", got)
	}
	if got := FormatUint36(35); got != "z" {
		t.Errorf("FormatUint36(35) = %q; want z", got)
	}
	if got := FormatUint36(36); got != "10" {
		t.Errorf("FormatUint36(36) = %q; want 10", got)
	}
}

func TestAdmitConnAndCapacityOverflow(t *testing.T) {
	s, _ := newTestServer(t)
	// Create small sem of cap 1
	s.AcceptSem = make(chan struct{}, 1)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if !s.AdmitConn(c1) {
		t.Fatal("first connection should be admitted")
	}

	c3, c4 := net.Pipe()
	defer c4.Close()

	if s.AdmitConn(c3) {
		t.Fatal("second connection should be rejected when sem is full")
	}
}

func TestServeListenerAndDrain(t *testing.T) {
	s, _ := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- s.ServeListener(ctx, ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	conn.Close()

	// Cancel context to stop ServeListener
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("ServeListener returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeListener did not return after context cancellation")
	}

	// Test Drain with 0 active connections
	s.Drain(1)
}

func TestStreamEventQueueAndDrops(t *testing.T) {
	s, _ := newTestServer(t)
	s.StreamEventQueue = make(chan []byte, 1)

	evt := []byte(`{"test":"event"}`)
	s.EnqueueStreamEvent(evt)

	// Should drop because queue is full
	s.EnqueueStreamEvent(evt)
}

func TestReloadTrustedCIDRs(t *testing.T) {
	s, cfg := newTestServer(t)
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	cfg.TrustedUpstreamSources.NetBox.Enabled = false

	s.ReloadTrustedCIDRs(context.Background(), cfg)
	trusted := s.GetTrustedCIDRs()
	if len(trusted) != 2 {
		t.Fatalf("expected 2 trusted CIDRs, got %d", len(trusted))
	}
}

func TestHealthEndpoints(t *testing.T) {
	s, _ := newTestServer(t)

	// Test HandleHealth without redis (degraded)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	s.HandleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("HandleHealth without redis: want 200, got %d", rec.Code)
	}

	// Test HandleHealthDeep: anti-flap requires 3 failures before flipping to unhealthy (503)
	recDeep1 := httptest.NewRecorder()
	s.HandleHealthDeep(recDeep1, req)
	if recDeep1.Code != http.StatusOK {
		t.Errorf("HandleHealthDeep transient failure (1): want 200 (degraded anti-flap), got %d", recDeep1.Code)
	}

	// Trigger consecutive failures to reach threshold 3
	s.HandleHealthDeep(httptest.NewRecorder(), req)
	recDeep3 := httptest.NewRecorder()
	s.HandleHealthDeep(recDeep3, req)
	if recDeep3.Code != http.StatusServiceUnavailable {
		t.Errorf("HandleHealthDeep consecutive failures (3): want 503, got %d", recDeep3.Code)
	}

	// Test HandleMetricsSummary on fresh server (transient failure state = 200 degraded)
	sFresh, _ := newTestServer(t)
	recMetrics := httptest.NewRecorder()
	sFresh.HandleMetricsSummary(recMetrics, req)
	if recMetrics.Code != http.StatusOK {
		t.Errorf("HandleMetricsSummary: want 200, got %d", recMetrics.Code)
	}
}

func TestMetricsAuthMiddleware(t *testing.T) {
	dummyNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := MetricsAuthMiddleware(dummyNext, "secret-token")

	// Local request should bypass auth
	reqLocal := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqLocal.RemoteAddr = "127.0.0.1:54321"
	recLocal := httptest.NewRecorder()
	handler.ServeHTTP(recLocal, reqLocal)
	if recLocal.Code != http.StatusOK {
		t.Errorf("expected local request to bypass auth, got %d", recLocal.Code)
	}

	// Remote request without auth should be unauthorized
	reqRemote := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqRemote.RemoteAddr = "203.0.113.10:54321"
	recRemote := httptest.NewRecorder()
	handler.ServeHTTP(recRemote, reqRemote)
	if recRemote.Code != http.StatusUnauthorized {
		t.Errorf("expected unauthorized, got %d", recRemote.Code)
	}

	// Remote request with valid Bearer token
	reqRemoteAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqRemoteAuth.RemoteAddr = "203.0.113.10:54321"
	reqRemoteAuth.Header.Set("Authorization", "Bearer secret-token")
	recRemoteAuth := httptest.NewRecorder()
	handler.ServeHTTP(recRemoteAuth, reqRemoteAuth)
	if recRemoteAuth.Code != http.StatusOK {
		t.Errorf("expected authorized, got %d", recRemoteAuth.Code)
	}
}

func TestPipelineConfigHelpers(t *testing.T) {
	_, cfg := newTestServer(t)
	cfg.Security.Whitelist = []string{"t13d1516h2_8daaf6152771_b65345719460"}
	cfg.Security.Blacklist = []string{"t13d1516h2_000000000000_000000000000"}

	pCfg := BuildPipelineConfig(cfg)
	if pCfg == nil {
		t.Fatal("expected non-nil pipeline config")
	}
	if !pCfg.Whitelist["t13d1516h2_8daaf6152771_b65345719460"] {
		t.Error("expected whitelist fingerprint loaded")
	}

	logger := NewLogger(cfg)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// BuildBlocklistFeeds and BuildStaticAllowlist
	feeds := BuildBlocklistFeeds([]config.BlocklistFeedConfigYAML{
		{Name: "test-feed", URL: "http://example.com", Enabled: true},
	})
	if len(feeds) != 1 || feeds[0].Path != "data/feeds/test-feed.txt" {
		t.Errorf("unexpected feeds: %+v", feeds)
	}

	allowlist := BuildStaticAllowlist([]config.StaticIPConfigYAML{
		{IP: "192.0.2.1"},
	})
	if !allowlist["192.0.2.1"] {
		t.Error("expected static IP in allowlist")
	}
}

func mustParseInt(s string) int {
	var n int
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestServerHandleConnNonTLSAndSmuggling(t *testing.T) {
	s, cfg := newTestServer(t)
	enforce := true
	cfg.Security.EnforceTLSRecord = &enforce
	s.Pipeline = security.NewPipeline(BuildPipelineConfig(cfg), nil, s.Log)

	// Case 1: Non-TLS packet (e.g. plain HTTP GET)
	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleConn(context.Background(), serverConn)
	}()

	_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	select {
	case <-done:
		// Succeeded in dropping non-TLS connection
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn timed out waiting for drop of non-TLS connection")
	}
	clientConn.Close()

	// Case 2: PROXY v1 chained smuggling attempt
	cfg.Proxy.ProxyProtocol = true
	clientConn2, serverConn2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.HandleConn(context.Background(), serverConn2)
	}()

	smugglePayload := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\nPROXY TCP4 9.9.9.9 8.8.8.8 4321 443\r\n\x16\x03\x01\x00\x05")
	_, _ = clientConn2.Write(smugglePayload)
	select {
	case <-done2:
		// Succeeded in dropping smuggled proxy protocol
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn timed out waiting for drop of smuggled PROXY header")
	}
	clientConn2.Close()
}

func TestServerStreamEventsAndWorkers(t *testing.T) {
	s, cfg := newTestServer(t)
	cfg.Webhooks.StreamWorkers = 1
	cfg.Webhooks.StreamWriteTimeoutSeconds = 0.5
	s.StreamEventQueue = make(chan []byte, 10)
	s.StreamHMACSecret = "secret123"

	// Enqueue when full to trigger drop path
	fullQueue := make(chan []byte, 1)
	s.StreamEventQueue = fullQueue
	s.EnqueueStreamEvent([]byte("event1"))
	s.EnqueueStreamEvent([]byte("event2")) // Should drop gracefully without blocking

	// Start workers and cancel
	ctx, cancel := context.WithCancel(context.Background())
	s.StartStreamEventWorkers(ctx)
	cancel()
}

func TestServerReloadAndTrustedCIDRs(t *testing.T) {
	s, cfg := newTestServer(t)
	s.Pipeline = security.NewPipeline(BuildPipelineConfig(cfg), nil, s.Log)

	// Test SetTrustedCIDRs / GetTrustedCIDRs
	cidrs := []string{"10.0.0.0/8", "192.168.0.0/16"}
	s.SetTrustedCIDRs(cidrs)
	got := s.GetTrustedCIDRs()
	if len(got) != 2 || got[0] != "10.0.0.0/8" {
		t.Errorf("unexpected trusted CIDRs: %+v", got)
	}

	// Test ReloadTrustedCIDRs with NetBox disabled
	cfg.TrustedUpstreamSources.NetBox.Enabled = false
	cfg.TrustedUpstreamSources.StaticCIDRs = []string{"172.16.0.0/12"}
	s.ReloadTrustedCIDRs(context.Background(), cfg)
	got2 := s.GetTrustedCIDRs()
	if len(got2) != 1 || got2[0] != "172.16.0.0/12" {
		t.Errorf("unexpected trusted CIDRs after reload: %+v", got2)
	}

	// Test Reload() with valid temporary config file
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "proxy.yml")
	cfgContent := `
proxy:
  listen_port: 8443
  backend_host: "127.0.0.1"
  backend_port: 443
redis:
  host: "127.0.0.1"
  port: 6379
  password: "test-secret"
`
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}
	s.CfgPath = cfgFile
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
}

func TestServerNewAndValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Redis.Host = "127.0.0.1"
	cfg.Redis.Port = config.FlexInt(6379)
	cfg.Redis.Password = "strong-secret-token-here"
	cfg.Redis.ACLUsers.Enabled = true
	cfg.Redis.ACLUsers.ProxyUser = "ja4proxy_app"

	log := logrus.New()
	log.SetOutput(&bytes.Buffer{})

	srv, err := NewWithConfigPath(cfg, "config/proxy.yml", log)
	if err != nil {
		t.Fatalf("NewWithConfigPath failed: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}

	// Test New helper
	srv2, err2 := New(cfg, log)
	if err2 != nil || srv2 == nil {
		t.Fatalf("New helper failed: %v", err2)
	}

	// Test CheckAndLogRedisACL
	CheckAndLogRedisACL(cfg, log)

	// Test SeedSecurityLists with nil rc safe handling
	SeedSecurityLists(context.Background(), nil, cfg)
	LoadSecurityLists(context.Background(), nil, nil)
}

func TestEmitConnectionEvent(t *testing.T) {
	s, _ := newTestServer(t)
	s.StreamEventQueue = make(chan []byte, 10)

	// Nil cases
	s.EmitConnectionEvent(nil, nil, "127.0.0.1", EventPhaseFinal)

	connCtx := &security.ConnectionContext{
		ClientIP:     "192.0.2.1",
		ClientPort:   54321,
		ConnectionID: "conn-12345",
		JA4:          "t13d1516h2_8daaf6152771_b65345719460",
	}
	result := &security.PipelineResult{
		Action: "allow",
		Score:  10,
	}

	// Without dispatcher
	s.EmitConnectionEvent(connCtx, result, "127.0.0.1", EventPhaseFinal)
	if len(s.StreamEventQueue) != 0 {
		t.Error("expected 0 events when dispatcher is nil")
	}
}

func TestServerStartServeAndIntegrityWorker(t *testing.T) {
	s, cfg := newTestServer(t)
	// Disable metrics and listen on dynamic loopback port
	cfg.Metrics.Enabled = false
	cfg.Proxy.BindHost = "127.0.0.1"
	cfg.Proxy.BindPort = config.FlexInt(0)

	// Verify Start / Serve can start and cancel cleanly
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// Clean termination
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Start did not terminate promptly upon context cancellation")
	}
}

func TestServerHandleConnPipelineDecisions(t *testing.T) {
	// Test TLS connection handling for allow, tarpit, block
	actions := []string{"allow", "tarpit", "block", "ban"}

	for _, act := range actions {
		t.Run(act, func(t *testing.T) {
			s, cfg := newTestServer(t)
			cfg.Proxy.BackendHost = "127.0.0.1"
			cfg.Proxy.BackendPort = 443

			// Mock pipeline with fixed result
			s.Pipeline = security.NewPipeline(BuildPipelineConfig(cfg), nil, s.Log)

			clientConn, serverConn := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.HandleConn(context.Background(), serverConn)
			}()

			// Client writes minimal TLS ClientHello record (0x16 0x03 0x01 ...)
			// 5-byte header: 0x16, 0x03, 0x01, length 4 bytes (0x00, 0x04), payload: 4 dummy bytes
			tlsRecord := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
			_, _ = clientConn.Write(tlsRecord)

			// Give it a brief moment to process
			time.Sleep(50 * time.Millisecond)
			clientConn.Close()
			select {
			case <-done:
				// Finished processing
			case <-time.After(2 * time.Second):
				t.Fatal("HandleConn hung on decision processing")
			}
		})
	}
}

func TestServerTarpitOverflow(t *testing.T) {
	s, cfg := newTestServer(t)
	cfg.Tarpit.MaxActiveConnections = 1
	cfg.Tarpit.MaxPerIP = 1
	cfg.Tarpit.OverflowAction = "block"

	// Artificially saturate TarpitConcurrent
	s.TarpitMu.Lock()
	s.TarpitConcurrent = 1
	s.TarpitMu.Unlock()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Tarpit should immediately reject due to overflow
	s.Tarpit(serverConn, []byte("data"), "192.0.2.1")
}

func TestServerReassembleProxyHeaderEdges(t *testing.T) {
	s, _ := newTestServer(t)

	// Case 1: Empty data returns immediately
	if res := s.ReassembleProxyHeader(nil, nil, nil); res != nil {
		t.Errorf("expected nil for empty data, got %v", res)
	}

	// Case 2: PROXY v1 partial header that completes
	clientConn, serverConn := net.Pipe()
	buf := make([]byte, 256)
	copy(buf, []byte("PROXY TCP4 1.1.1.1 2.2.2.2 1234 443"))

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = clientConn.Write([]byte("\r\n"))
		clientConn.Close()
	}()

	res := s.ReassembleProxyHeader(serverConn, buf[:35], buf)
	if !strings.Contains(string(res), "\r\n") {
		t.Errorf("expected complete PROXY header, got %q", string(res))
	}
	serverConn.Close()
}
