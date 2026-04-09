// JA4proxy — Go TLS-aware passthrough security proxy.
//
// Reads config/proxy.yml, accepts TCP connections, parses TLS ClientHello
// without decrypting traffic, runs each connection through the security
// pipeline, and forwards allowed connections to the backend unchanged.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/anomalyco/ja4proxy/internal/config"
	jalogger "github.com/anomalyco/ja4proxy/internal/logging"
	"github.com/anomalyco/ja4proxy/internal/metrics"
	proxypkg "github.com/anomalyco/ja4proxy/internal/proxy"
	redisclient "github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/anomalyco/ja4proxy/internal/security"
	tlsparse "github.com/anomalyco/ja4proxy/internal/tls"
	webhook "github.com/anomalyco/ja4proxy/internal/webhook"
)

func main() {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config/proxy.yml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := newLogger(cfg)

	// Register Prometheus metrics (must be called once before any metric use)
	metrics.Register()

	// phase-63: emit TLS cert expiry timestamp gauge from JA4PROXY_TLS_CERT_FILE
	// (Phase 64 alerts on this gauge — see docs/phases/PHASE_63_notes.md).
	updateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), log)

	proxy, err := newProxy(cfg, log)
	if err != nil {
		log.WithError(err).Fatal("failed to initialise proxy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background workers
	proxy.pipeline.StartBackgroundWorkers(ctx)

	// Start pub/sub for config hot-reload and dynamic list updates
	go redisclient.NewPubSubHandler(proxy.redis, log, func() {
		if err := proxy.reload(); err != nil {
			log.WithError(err).Warn("config reload failed")
		}
	}, func() {
		loadSecurityLists(ctx, proxy.redis, proxy.pipeline)
		log.Info("security lists refreshed via pub/sub")
	}).Run(ctx)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go proxy.serve(ctx)

	// Start webhook dispatcher if enabled. phase-80.
	if cfg.Webhooks.Enabled && proxy.dispatcher != nil {
		go proxy.dispatcher.Run(ctx)
	}

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log.Info("SIGHUP received — reloading config")
			if err := proxy.reload(); err != nil {
				log.WithError(err).Warn("config reload failed")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.WithField("signal", sig).Info("shutdown signal received")
			cancel()
			proxy.drain(cfg.Proxy.DrainTimeoutSeconds)
			return
		}
	}
}

// ── Proxy ─────────────────────────────────────────────────────────────────

type proxy struct {
	cfg        *config.Config
	log        *logrus.Logger
	pipeline   *security.Pipeline
	redis      *redisclient.Client
	geoIP      *geoip2.Reader
	dispatcher *webhook.Dispatcher // phase-80: webhook event delivery

	activeConns int64 // atomic
	mu          sync.RWMutex

	// Tarpit self-protection
	tarpitConcurrent int
	tarpitPerIP      map[string]int
	tarpitMu         sync.Mutex
}

func newProxy(cfg *config.Config, log *logrus.Logger) (*proxy, error) {
	redisCfg := redisclient.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port.Int(),
		DB:       cfg.Redis.DB,
		Password: cfg.Redis.Password,
		Timeout:  time.Duration(cfg.Redis.Timeout.Int()) * time.Second,
	}
	rc := redisclient.New(redisCfg, log)

	pipelineCfg := buildPipelineConfig(cfg)
	p := security.NewPipeline(pipelineCfg, rc, log)

	// Seed Redis in the background so a slow/unavailable Redis does not block
	// the proxy from starting to accept connections (fail-open on startup).
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rc.SeedDialIfAbsent(ctx, cfg.MonitorMode.Dial)
		seedSecurityLists(ctx, rc, cfg)
		loadSecurityLists(ctx, rc, p)
	}()

	// Initialise webhook dispatcher (starts inactive if cfg.Webhooks.Enabled is false).
	// phase-80: build per-endpoint config; per-endpoint retry/timeout fields are
	// stored in WebhookEndpointConfig but DispatcherConfig holds global retry settings.
	// Use the first endpoint's settings as global defaults (or safe defaults if none set).
	endpoints := make([]webhook.WebhookEndpoint, len(cfg.Webhooks.Endpoints))
	var dispatchRetryAttempts int = 3
	var dispatchRetryBackoff float64 = 5.0
	var dispatchTimeout float64 = 30.0
	for i, e := range cfg.Webhooks.Endpoints {
		endpoints[i] = webhook.WebhookEndpoint{
			ID:     e.ID,
			URL:    e.URL,
			Secret: e.Secret,
			Events: e.Events,
		}
		if i == 0 {
			if e.RetryAttempts > 0 {
				dispatchRetryAttempts = e.RetryAttempts
			}
			if e.RetryBackoffSeconds > 0 {
				dispatchRetryBackoff = e.RetryBackoffSeconds
			}
			if e.TimeoutSeconds > 0 {
				dispatchTimeout = e.TimeoutSeconds
			}
		}
	}
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port.Int())
	dispatcherCfg := webhook.DispatcherConfig{
		Endpoints:      endpoints,
		StreamKey:      cfg.Webhooks.StreamKey,
		DLQStreamKey:   cfg.Webhooks.DLQKey,
		RetryAttempts:  dispatchRetryAttempts,
		RetryBackoff:   time.Duration(dispatchRetryBackoff * float64(time.Second)),
		TimeoutSeconds: dispatchTimeout,
	}
	disp, err := webhook.NewDispatcher(dispatcherCfg, redisAddr, log)
	if err != nil {
		log.WithError(err).Warn("proxy: webhook dispatcher init failed; webhooks disabled")
	}

	prx := &proxy{
		cfg:         cfg,
		log:         log,
		pipeline:    p,
		redis:       rc,
		dispatcher:  disp,
		tarpitPerIP: make(map[string]int),
	}

	// Open GeoIP DB if configured
	if cfg.GeoIP.DBPath != "" {
		if reader, err := geoip2.Open(cfg.GeoIP.DBPath); err == nil {
			prx.geoIP = reader
		} else {
			log.WithError(err).Warn("proxy: failed to open GeoIP DB; country lookup disabled")
		}
	}

	return prx, nil
}

func (p *proxy) serve(ctx context.Context) {
	// Start metrics/health HTTP server
	if p.cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/health", p.handleHealth)
			addr := fmt.Sprintf(":%d", p.cfg.Metrics.Port.Int())
			p.log.WithField("addr", addr).Info("proxy: metrics server listening")
			srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second}
			go func() {
				<-ctx.Done()
				if err := srv.Shutdown(context.Background()); err != nil {
					p.log.WithError(err).Warn("metrics server shutdown error")
				}
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				p.log.WithError(err).Warn("metrics server error")
			}
		}()
	}

	addr := fmt.Sprintf("%s:%d", p.cfg.Proxy.BindHost, p.cfg.Proxy.BindPort.Int())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.log.WithError(err).Fatal("failed to listen")
	}
	p.log.WithField("addr", addr).Info("proxy: listening")

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // clean shutdown
			default:
				p.log.WithError(err).Warn("proxy: accept error")
				continue
			}
		}
		atomic.AddInt64(&p.activeConns, 1)
		go p.handleConn(ctx, conn)
	}
}

func (p *proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	metrics.ActiveConnections.Inc()
	defer func() {
		metrics.ActiveConnections.Dec()
		atomic.AddInt64(&p.activeConns, -1)
		clientConn.Close()
	}()

	// Peek at first 5 bytes to detect TLS
	buf := make([]byte, p.cfg.Proxy.BufferSize)
	clientConn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.ReadTimeout) * time.Second))
	n, err := clientConn.Read(buf)
	clientConn.SetReadDeadline(time.Time{}) // clear deadline
	if err != nil || n == 0 {
		if err != nil {
			// phase-63: classify and record the error against the availability SLI.
			metrics.ConnectionErrorsTotal.WithLabelValues(classifyConnError(err)).Inc()
		}
		return
	}
	data := buf[:n]

	// Build ConnectionContext from TLS ClientHello
	connCtx := &security.ConnectionContext{
		ClientIP: remoteIP(clientConn),
	}

	// PROXY protocol: extract real client IP if behind HAProxy
	if p.cfg.Proxy.ProxyProtocol {
		if realIP, ok := proxypkg.ReadProxyProtocol(data); ok {
			connCtx.ClientIP = realIP
			// Advance past the PROXY header
			if idx := bytes.Index(data, []byte("\r\n")); idx >= 0 {
				data = data[idx+2:]
			}
		}
	}

	// GeoIP country lookup
	if p.geoIP != nil {
		if ip := net.ParseIP(connCtx.ClientIP); ip != nil {
			if record, err := p.geoIP.Country(ip); err == nil {
				connCtx.Country = record.Country.IsoCode
			}
		}
	}

	if n >= 5 && data[0] == 0x16 {
		if hello, err := tlsparse.ParseClientHello(data); err == nil {
			ja4 := tlsparse.ComputeJA4(hello)
			connCtx.JA4 = ja4
			connCtx.TLSVersion = int(hello.LegacyVersion)
			connCtx.SNI = hello.SNI
			if len(hello.ALPNProtocols) > 0 {
				connCtx.ALPN = hello.ALPNProtocols[0]
			}
			connCtx.CipherList = make([]int, len(hello.CipherSuites))
			for i, cs := range hello.CipherSuites {
				connCtx.CipherList[i] = int(cs)
			}
		} else {
			// phase-63: TLS parse failures contribute to the availability SLI.
			metrics.ConnectionErrorsTotal.WithLabelValues("tls_parse_error").Inc()
			p.log.WithError(err).Debug("proxy: TLS parse failed; scoring without JA4")
		}
	}

	// Run pipeline
	start := time.Now()
	result := p.pipeline.Process(ctx, connCtx)
	metrics.PipelineDurationSeconds.Observe(time.Since(start).Seconds())

	// Record metrics
	metrics.ConnectionsTotal.WithLabelValues(result.Action).Inc()
	metrics.RiskScore.Observe(float64(result.Score))
	if result.Bypassed {
		metrics.BypassTotal.WithLabelValues(result.BypassReason).Inc()
	}

	// Log every connection decision — required for SIEM visibility at all dial settings.
	// ECS formatter maps these fields to standard ECS field names.
	p.mu.RLock()
	backendHost := p.cfg.Proxy.BackendHost
	p.mu.RUnlock()
	p.log.WithFields(logrus.Fields{
		"client_ip":   connCtx.ClientIP,
		"ja4":         connCtx.JA4,
		"ja4x":        connCtx.JA4X,
		"action":      result.Action,
		"score":        result.Score,
		"sni":         connCtx.SNI,
		"alpn":        connCtx.ALPN,
		"country":     connCtx.Country,
		"tls_version": connCtx.TLSVersion,
		"ja4t":        connCtx.TCPJA4T,
		"dial":        result.Dial,
		"signals":     result.Signals,
		"dst_ip":      backendHost, // phase-80: destination for ECS field mapping
	}).Info("proxy: connection decision")

	// Publish ECS connection event to Redis Stream for webhook delivery.
	// Fire-and-forget: stream write must never block the hot path.  phase-80.
	if p.dispatcher != nil {
		go func() {
			ecsFields := map[string]interface{}{
				"@timestamp":                time.Now().UTC().Format(time.RFC3339Nano),
				"event.action":              result.Action,
				"event.risk_score":          result.Score,
				"source.ip":                 connCtx.ClientIP,
				"destination.ip":            backendHost,
				"destination.port":          443,
				"network.transport":         "tcp",
				"network.protocol":          "tls",
				"service.name":              "ja4proxy",
				"ja4proxy.fingerprint.ja4":  connCtx.JA4,
				"ja4proxy.sni":              connCtx.SNI,
				"ja4proxy.dial_setting":     result.Dial,
			}
			ecsJSON, err := json.Marshal(ecsFields)
			if err != nil {
				return
			}
			p.redis.XAdd(context.Background(), "events:connection",
				map[string]interface{}{"event": string(ecsJSON)})
		}()
	}

	// Execute action
	switch result.Action {
	case "allow", "flag", "rate_limit":
		p.forward(clientConn, data)
	case "tarpit":
		p.tarpit(clientConn, data, connCtx.ClientIP)
	case "block", "ban":
		// Force RST instead of clean FIN
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0)
		}
	}
}

func (p *proxy) forward(clientConn net.Conn, initialData []byte) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	backendAddr := net.JoinHostPort(cfg.Proxy.BackendHost, fmt.Sprintf("%d", cfg.Proxy.BackendPort.Int()))
	backendConn, err := net.DialTimeout("tcp", backendAddr,
		time.Duration(cfg.Proxy.ConnectionTimeout)*time.Second)
	if err != nil {
		// phase-63: backend dial failures degrade availability SLI.
		metrics.ConnectionErrorsTotal.WithLabelValues(classifyConnError(err)).Inc()
		p.log.WithError(err).WithField("backend", backendAddr).Warn("proxy: backend connect failed")
		return
	}
	defer backendConn.Close()

	// Send buffered initial data
	if _, err := backendConn.Write(initialData); err != nil {
		p.log.WithError(err).Warn("proxy: write initial data to backend failed")
		return
	}

	// Bidirectional copy
	done := make(chan struct{}, 2)
	copyConn := func(dst, src net.Conn) {
		buf := make([]byte, p.cfg.Proxy.BufferSize)
		for {
			src.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.ReadTimeout) * time.Second))
			n, err := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.WriteTimeout) * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}

	go copyConn(backendConn, clientConn)
	go copyConn(clientConn, backendConn)
	<-done
}

func (p *proxy) tarpit(clientConn net.Conn, data []byte, clientIP string) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	maxConcurrent := cfg.Tarpit.MaxActiveConnections
	maxPerIP := cfg.Tarpit.MaxPerIP
	overflowAction := cfg.Tarpit.OverflowAction

	acquired := false
	p.tarpitMu.Lock()
	overGlobal := p.tarpitConcurrent >= maxConcurrent
	overPerIP := p.tarpitPerIP[clientIP] >= maxPerIP
	if !overGlobal && !overPerIP {
		p.tarpitConcurrent++
		p.tarpitPerIP[clientIP]++
		metrics.TarpitConcurrent.Set(float64(p.tarpitConcurrent))
		acquired = true
	}
	p.tarpitMu.Unlock()

	if !acquired {
		metrics.TarpitOverflowTotal.WithLabelValues(overflowAction).Inc()
		p.log.WithFields(logrus.Fields{
			"ip":     clientIP,
			"action": overflowAction,
		}).Info("tarpit: capacity reached — executing overflow action")

		if overflowAction == "allow" {
			p.forward(clientConn, data)
		}
		// block/ban: return and let handleConn's defer close clientConn
		return
	}

	defer func() {
		p.tarpitMu.Lock()
		p.tarpitConcurrent--
		if p.tarpitConcurrent < 0 {
			p.tarpitConcurrent = 0
		}
		ipCount := p.tarpitPerIP[clientIP]
		if ipCount <= 1 {
			delete(p.tarpitPerIP, clientIP)
		} else {
			p.tarpitPerIP[clientIP] = ipCount - 1
		}
		metrics.TarpitConcurrent.Set(float64(p.tarpitConcurrent))
		p.tarpitMu.Unlock()
	}()

	tarpitAddr := net.JoinHostPort(cfg.Proxy.TarpitHost, fmt.Sprintf("%d", cfg.Proxy.TarpitPort.Int()))
	tarpitConn, err := net.DialTimeout("tcp", tarpitAddr, 5*time.Second)
	if err != nil {
		p.log.WithError(err).Debug("proxy: tarpit connect failed; closing connection")
		return
	}
	defer tarpitConn.Close()

	// Send buffered initial data
	if _, err := tarpitConn.Write(data); err != nil {
		p.log.WithError(err).Debug("proxy: write to tarpit failed")
		return
	}

	// Forward to tarpit — bidirectional copy
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		buf := make([]byte, 512)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyOne(tarpitConn, clientConn)
	go copyOne(clientConn, tarpitConn)
	<-done
}

func (p *proxy) reload() error {
	newCfg, err := config.Load("config/proxy.yml")
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg = newCfg
	p.mu.Unlock()
	metrics.ConfigReloadsTotal.Inc()
	// phase-63: refresh the TLS cert expiry gauge on every reload.
	updateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), p.log)
	p.log.Info("config reloaded")
	return nil
}

// handleHealth responds to HTTP health check requests.
func (p *proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	redisStatus := "ok"
	if err := p.redis.Ping(ctx); err != nil {
		redisStatus = "error"
	}
	status := "ok"
	if redisStatus != "ok" {
		status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": status, "redis": redisStatus}); err != nil {
		p.log.WithError(err).Warn("health: failed to encode response")
	}
}

func (p *proxy) drain(timeoutSeconds int) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&p.activeConns) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	remaining := atomic.LoadInt64(&p.activeConns)
	if remaining > 0 {
		p.log.WithField("remaining", remaining).Warn("drain timeout expired; forcing shutdown")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func remoteIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return conn.RemoteAddr().String()
}

func newLogger(cfg *config.Config) *logrus.Logger {
	log := logrus.New()
	// Always write to stdout so that Vector (stdin source) and Docker log drivers
	// receive structured log lines. logrus defaults to stderr which breaks pipelines.
	log.SetOutput(os.Stdout)
	useJSON := cfg.Logging.JSONEnabled || os.Getenv("ENVIRONMENT") == "production"
	if useJSON || cfg.Logging.Format == "ecs" {
		// Use ECS formatter when explicitly configured or when JSON+ecs format requested.
		log.SetFormatter(jalogger.NewECSLogrusFormatter(cfg.Logging.Format))
	}
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
	// phase-80: dual_output is Python-only. Log a warning if misconfigured.
	if cfg.Logging.DualOutput && cfg.Logging.Format == "ecs" {
		log.Warn("proxy: logging.dual_output=true is a Python-only feature; Go proxy emits ECS-only format")
	}
	return log
}

func buildPipelineConfig(cfg *config.Config) *security.PipelineConfig {
	whitelist := make(map[string]bool, len(cfg.Security.Whitelist))
	for _, fp := range cfg.Security.Whitelist {
		whitelist[fp] = true
	}
	blacklist := make(map[string]bool, len(cfg.Security.Blacklist))
	for _, fp := range cfg.Security.Blacklist {
		blacklist[fp] = true
	}
	thresholds := map[string]int{
		"flag":       cfg.RiskScorer.Thresholds.Flag,
		"rate_limit": cfg.RiskScorer.Thresholds.RateLimit,
		"tarpit":     cfg.RiskScorer.Thresholds.Tarpit,
		"block":      cfg.RiskScorer.Thresholds.Block,
		"ban":        cfg.RiskScorer.Thresholds.Ban,
	}
	expectedHostnames := stringSliceToSet(cfg.SNIAnalyzer.ExpectedHostnames)
	return &security.PipelineConfig{
		ALPNBrowserBypass:       cfg.SecurityPolicy.ALPNBrowserBypass.Enabled,
		JA4WhitelistBypass:      cfg.SecurityPolicy.JA4WhitelistBypass.Enabled,
		JA4BlacklistBypass:      cfg.SecurityPolicy.JA4BlacklistBypass.Enabled,
		MTLSBypass:              cfg.SecurityPolicy.MTLSBypass.Enabled,
		CountryBlacklistBypass:  cfg.SecurityPolicy.CountryBlacklistBypass.Enabled,
		Whitelist:               whitelist,
		WhitelistSuffs:          cfg.Security.WhitelistPatterns,
		Blacklist:               blacklist,
		Thresholds:              thresholds,
		TLSVersionBypassEnabled: cfg.SecurityPolicy.TLSVersionBypass.Enabled,
		BlockTLS10:              cfg.TLSEnforcer.BlockTLS10,
		BlockTLS11:              cfg.TLSEnforcer.BlockTLS11,
		FlagTLS12:               cfg.TLSEnforcer.FlagTLS12,
		BlockWeakCiphers:        cfg.TLSEnforcer.BlockWeakCiphers,
		MissingSNIEnabled:       cfg.SNIAnalyzer.MissingSNI.Enabled,
		MissingSNIScore:         cfg.SNIAnalyzer.MissingSNI.Score,
		IPLiteralSNIEnabled:     cfg.SNIAnalyzer.IPLiteralSNI.Enabled,
		IPLiteralSNIScore:       cfg.SNIAnalyzer.IPLiteralSNI.Score,
		DGAEnabled:              cfg.SNIAnalyzer.DGADetection.Enabled,
		DGAScoreCap:             cfg.SNIAnalyzer.DGADetection.ScoreCap,
		UnexpectedSNIEnabled:    cfg.SNIAnalyzer.UnexpectedSNI.Enabled,
		UnexpectedSNIScore:      cfg.SNIAnalyzer.UnexpectedSNI.Score,
		ExpectedHostnames:       expectedHostnames,
		// Rate limiter (Group 3)
		RateLimiterEnabled: cfg.RateLimiter.Enabled,
		RateLimiterByIP: security.StrategyConfig{
			Enabled:    cfg.RateLimiter.ByIP.Enabled,
			Suspicious: cfg.RateLimiter.ByIP.Suspicious,
			Block:      cfg.RateLimiter.ByIP.Block,
			Ban:        cfg.RateLimiter.ByIP.Ban,
			Window:     cfg.RateLimiter.ByIP.Window,
			TTL:        cfg.RateLimiter.ByIP.TTL,
		},
		RateLimiterByJA4: security.StrategyConfig{
			Enabled:    cfg.RateLimiter.ByJA4.Enabled,
			Suspicious: cfg.RateLimiter.ByJA4.Suspicious,
			Block:      cfg.RateLimiter.ByJA4.Block,
			Ban:        cfg.RateLimiter.ByJA4.Ban,
			Window:     cfg.RateLimiter.ByJA4.Window,
			TTL:        cfg.RateLimiter.ByJA4.TTL,
		},
		RateLimiterByIPJA4: security.StrategyConfig{
			Enabled:    cfg.RateLimiter.ByIPJA4.Enabled,
			Suspicious: cfg.RateLimiter.ByIPJA4.Suspicious,
			Block:      cfg.RateLimiter.ByIPJA4.Block,
			Ban:        cfg.RateLimiter.ByIPJA4.Ban,
			Window:     cfg.RateLimiter.ByIPJA4.Window,
			TTL:        cfg.RateLimiter.ByIPJA4.TTL,
		},
		// TCP analyzer (Group 3)
		TCPAnalyzerEnabled:                   cfg.TCPAnalyzer.Enabled,
		TCPAnalyzerSessionResumptionEnabled:  cfg.TCPAnalyzer.SessionResumptionEnabled,
		TCPAnalyzerMinConnectionsForSession:  cfg.TCPAnalyzer.MinConnectionsForSessionCheck,
		TCPAnalyzerShortLifespanEnabled:      cfg.TCPAnalyzer.ShortLifespanEnabled,
		TCPAnalyzerShortLifespanThresholdMS:  cfg.TCPAnalyzer.ShortLifespanThresholdMS,
		TCPAnalyzerConcurrencyEnabled:        cfg.TCPAnalyzer.ConcurrencyEnabled,
		TCPAnalyzerConcurrencyModerate:       cfg.TCPAnalyzer.ConcurrencyModerate,
		TCPAnalyzerConcurrencyHigh:           cfg.TCPAnalyzer.ConcurrencyHigh,
		TCPAnalyzerConcurrencySevere:         cfg.TCPAnalyzer.ConcurrencySevere,
		TCPAnalyzerReturnVisitorEnabled:      cfg.TCPAnalyzer.ReturnVisitorEnabled,
		TCPAnalyzerReturnVisitorMinDays:      cfg.TCPAnalyzer.ReturnVisitorMinDays,
		TCPAnalyzerReturnVisitorMinAllowRate: cfg.TCPAnalyzer.ReturnVisitorMinAllowRate,
		// ASN classifier (Group 4)
		ASNClassifierEnabled:            cfg.ASNClassifier.Enabled,
		ASNDBPath:                       cfg.ASNClassifier.MaxMindDBPath,
		TorExitListPath:                 cfg.ASNClassifier.TorExitList.DownloadURL, // Note: using URL as placeholder or path if local
		ASNClassifierDatacenterListPath: cfg.ASNClassifier.DatacenterListPath,
		DatacenterScore:                 cfg.ASNClassifier.RiskContributions.Datacenter,
		TorScore:                        cfg.ASNClassifier.RiskContributions.Tor,
		VPNScore:                        cfg.ASNClassifier.RiskContributions.VPN,
		UnknownScore:                    cfg.ASNClassifier.RiskContributions.Unknown,
		DatacenterOrgs:                  cfg.ASNClassifier.DatacenterOrgs,
		// DNS enrichment (Group 4)
		DNSEnrichmentEnabled: cfg.DNSEnrichment.Enabled,
		DNSEnrichmentWorkers: cfg.DNSEnrichment.WorkerCount,
		DNSNoPTRScore:        cfg.DNSEnrichment.FCrDNS.NoPTRScore,
		DNSFCrDNSFailedScore: cfg.DNSEnrichment.FCrDNS.FCrDNSFailedScore,
		DNSResidentialScore:  cfg.DNSEnrichment.FCrDNS.ResidentialScoreReduction,
		DNSTTL:               cfg.DNSEnrichment.TTLSeconds,
		// Blocklists (Group 4)
		BlocklistFeeds: buildBlocklistFeeds(cfg.Blocklists.Feeds),
		// Beaconing detector (Group 5)
		BeaconingEnabled:         cfg.Beaconing.Enabled,
		BeaconingScoreCap:        cfg.Beaconing.Score,
		BeaconingMinObservations: cfg.Beaconing.MinObservations,
		BeaconingShortWindowSec:  float64(cfg.Beaconing.ObservationWindowSeconds),
		BeaconingLongWindowSec:   float64(cfg.Beaconing.LongWindow.WindowSeconds),
		// AbuseIPDB (Group 5)
		AbuseIPDBEnabled:           cfg.AbuseIPDB.Enabled,
		AbuseIPDBAPIKey:            cfg.AbuseIPDB.APIKey,
		AbuseIPDBScoreCap:          cfg.AbuseIPDB.ScoreCap,
		AbuseIPDBSharedIPThreshold: cfg.AbuseIPDB.SharedIPThreshold,
		AbuseIPDBLocalCacheSize:    10000,
		AbuseIPDBWorkers:           cfg.AbuseIPDB.WorkerCount,
		AbuseIPDBAPIURL:            cfg.AbuseIPDB.APIURL,
		// RDAP enrichment (Group 5)
		RDAPEnabled:               cfg.RDAPEnrichment.Enabled,
		RDAPMinTriggerScore:       cfg.RDAPEnrichment.MinEnqueueScore,
		RDAPNewNetblockMaxAgeDays: cfg.RDAPEnrichment.NewNetblockFlagging.MaxAgeDays,
		RDAPNewNetblockScore:      cfg.RDAPEnrichment.NewNetblockFlagging.Score,
		RDAPKnownBadOrgScore:      cfg.RDAPEnrichment.OrgReputation.Score,
		RDAPBlockExpansionEnabled: cfg.RDAPEnrichment.BlockExpansion.Enabled,
		RDAPKnownBadOrgsPath:      cfg.RDAPEnrichment.KnownBadOrgsPath,
		// Static IP allowlist (Group 6)
		StaticIPAllowlistEnabled: cfg.SecurityPolicy.StaticIPAllowlist.Enabled && cfg.StaticAllowlist.Enabled,
		StaticIPAllowlist:        buildStaticAllowlist(cfg.StaticAllowlist.IPs),
		// Country blacklist (Group 6)
		CountryBlacklist: stringSliceToSet(cfg.GeoIP.CountryBlacklist),
		// JA4X configuration (Group 6)
		JA4XEnabled:        cfg.Fingerprinting.JA4X.Enabled,
		JA4XBlacklistScore: cfg.Fingerprinting.JA4X.BlacklistScore,
	}
}

func buildBlocklistFeeds(feeds []config.BlocklistFeedConfigYAML) []security.BlocklistFeedConfig {
	out := make([]security.BlocklistFeedConfig, len(feeds))
	for i, f := range feeds {
		out[i] = security.BlocklistFeedConfig{
			Name:                   f.Name,
			URL:                    f.URL,
			Format:                 f.Format,
			IsBypass:               f.IsBypass,
			Action:                 f.Action,
			Score:                  f.Score,
			RefreshIntervalSeconds: f.RefreshIntervalSeconds,
			Enabled:                f.Enabled,
		}
	}
	return out
}

func buildStaticAllowlist(ips []config.StaticIPConfigYAML) map[string]bool {
	out := make(map[string]bool, len(ips))
	for _, entry := range ips {
		out[entry.IP] = true
	}
	return out
}

// seedSecurityLists pre-populates Redis ja4:whitelist and ja4:blacklist from config.
func seedSecurityLists(ctx context.Context, rc *redisclient.Client, cfg *config.Config) {
	for _, fp := range cfg.Security.Whitelist {
		rc.SAdd(ctx, "ja4:whitelist", fp)
	}
	for _, fp := range cfg.Security.Blacklist {
		rc.SAdd(ctx, "ja4:blacklist", fp)
	}
	// Dynamic CIDR blocklist (from geoip.country_blacklist_cidrs or similar)
	// Parity with proxy.py _populate_security_lists
	for _, cidr := range cfg.GeoIP.CountryBlacklist {
		// Only seed if it looks like a CIDR
		if strings.Contains(cidr, "/") || strings.Contains(cidr, ".") || strings.Contains(cidr, ":") {
			rc.SAdd(ctx, "geoip:blocked_cidrs", cidr)
		}
	}
}

// loadSecurityLists fetches JA4 and CIDR lists from Redis and updates the Pipeline.
func loadSecurityLists(ctx context.Context, rc *redisclient.Client, p *security.Pipeline) {
	// Use a timeout for Redis operations
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	wlRaw := rc.SMembers(ctx, "ja4:whitelist")
	blRaw := rc.SMembers(ctx, "ja4:blacklist")
	cidrRaw := rc.SMembers(ctx, "geoip:blocked_cidrs")

	wl := make(map[string]bool, len(wlRaw))
	for _, fp := range wlRaw {
		wl[fp] = true
	}
	bl := make(map[string]bool, len(blRaw))
	for _, fp := range blRaw {
		bl[fp] = true
	}

	p.UpdateSets(wl, bl)
	p.UpdateDynamicCIDRs(cidrRaw)

	logrus.WithFields(logrus.Fields{
		"whitelist": len(wl),
		"blacklist": len(bl),
		"cidrs":     len(cidrRaw),
	}).Info("security lists loaded from Redis")
}

// ── Phase 63: SLO instrumentation helpers ─────────────────────────────────

// classifyConnError maps a connection-handler error to one of the five
// error_type label values used by ja4proxy_connection_errors_total.
func classifyConnError(err error) string {
	if err == nil {
		return "unknown"
	}
	s := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(s, "i/o timeout"), strings.Contains(s, "redis"):
		if strings.Contains(s, "redis") {
			return "redis_timeout"
		}
		return "redis_timeout"
	case strings.Contains(s, "tls"), strings.Contains(s, "handshake"), strings.Contains(s, "client hello"):
		return "tls_parse_error"
	case strings.Contains(s, "connection refused"), strings.Contains(s, "no route"):
		return "backend_refused"
	case strings.Contains(s, "out of memory"), strings.Contains(s, "cannot allocate"):
		return "oom"
	default:
		return "unknown"
	}
}

// updateTLSCertExpiryGauge reads the PEM-encoded certificate at the given path
// and sets ja4proxy_tls_cert_expiry_timestamp_seconds to the cert's NotAfter.
// Phase 63: invoked at startup and on every config reload. Phase 64 alerts on
// this gauge — see docs/phases/PHASE_63_notes.md.
func updateTLSCertExpiryGauge(certPath string, log *logrus.Logger) {
	if certPath == "" {
		return
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		log.WithError(err).WithField("path", certPath).Warn("phase-63: failed to read TLS cert for expiry gauge")
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.WithField("path", certPath).Warn("phase-63: TLS cert PEM decode failed")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).WithField("path", certPath).Warn("phase-63: x509 parse failed")
		return
	}
	metrics.TLSCertExpiryTimestampSeconds.Set(float64(cert.NotAfter.Unix()))
	log.WithFields(logrus.Fields{
		"path":      certPath,
		"not_after": cert.NotAfter.Format(time.RFC3339),
	}).Info("phase-63: TLS cert expiry gauge updated")
}

// stringSliceToSet converts a string slice to a set map.
func stringSliceToSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}
