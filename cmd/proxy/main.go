// JA4proxy — Go TLS-aware passthrough security proxy.
//
// Reads config/proxy.yml, accepts TCP connections, parses TLS ClientHello
// without decrypting traffic, runs each connection through the security
// pipeline, and forwards allowed connections to the backend unchanged.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/metrics"
	proxypkg "github.com/anomalyco/ja4proxy/internal/proxy"
	redisclient "github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/anomalyco/ja4proxy/internal/security"
	tlsparse "github.com/anomalyco/ja4proxy/internal/tls"
)

func main() {
	cfg, err := config.Load("config/proxy.yml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := newLogger(cfg)

	// Register Prometheus metrics (must be called once before any metric use)
	metrics.Register()

	proxy, err := newProxy(cfg, log)
	if err != nil {
		log.WithError(err).Fatal("failed to initialise proxy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background workers
	proxy.pipeline.StartBackgroundWorkers(ctx)

	// Start pub/sub for config hot-reload
	go redisclient.NewPubSubHandler(proxy.redis, log, func() {
		if err := proxy.reload(); err != nil {
			log.WithError(err).Warn("config reload failed")
		}
	}).Run(ctx)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go proxy.serve(ctx)

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
	cfg      *config.Config
	log      *logrus.Logger
	pipeline *security.Pipeline
	redis    *redisclient.Client
	geoIP    *geoip2.Reader

	activeConns int64 // atomic
	mu          sync.RWMutex
}

func newProxy(cfg *config.Config, log *logrus.Logger) (*proxy, error) {
	redisCfg := redisclient.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		DB:       cfg.Redis.DB,
		Password: cfg.Redis.Password,
		Timeout:  time.Duration(cfg.Redis.Timeout) * time.Second,
	}
	rc := redisclient.New(redisCfg, log)

	// Seed dial from config if not already set in Redis
	ctx := context.Background()
	rc.SeedDialIfAbsent(ctx, cfg.MonitorMode.Dial)

	pipelineCfg := buildPipelineConfig(cfg)
	p := security.NewPipeline(pipelineCfg, rc, log)

	prx := &proxy{
		cfg:      cfg,
		log:      log,
		pipeline: p,
		redis:    rc,
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
			addr := fmt.Sprintf(":%d", p.cfg.Metrics.Port)
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
	metrics.ConcurrentConnections.Inc()
	defer func() {
		metrics.ConcurrentConnections.Dec()
		atomic.AddInt64(&p.activeConns, -1)
		clientConn.Close()
	}()

	// Peek at first 5 bytes to detect TLS
	buf := make([]byte, p.cfg.Proxy.BufferSize)
	clientConn.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.ReadTimeout) * time.Second))
	n, err := clientConn.Read(buf)
	clientConn.SetReadDeadline(time.Time{}) // clear deadline
	if err != nil || n == 0 {
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
		} else {
			p.log.WithError(err).Debug("proxy: TLS parse failed; scoring without JA4")
		}
	}

	// Run pipeline
	result := p.pipeline.Process(ctx, connCtx)

	// Record metrics
	metrics.ConnectionsTotal.WithLabelValues(result.Action).Inc()
	metrics.RiskScore.Observe(float64(result.Score))
	if result.Bypassed {
		metrics.BypassTotal.WithLabelValues(result.BypassReason).Inc()
	}

	// Execute action
	switch result.Action {
	case "allow", "flag", "rate_limit":
		p.forward(clientConn, data)
	case "tarpit":
		p.tarpit(clientConn, data)
	case "block", "ban":
		// RST — just close (already deferred)
		p.log.WithFields(logrus.Fields{
			"ip":     connCtx.ClientIP,
			"ja4":    connCtx.JA4,
			"action": result.Action,
			"score":  result.Score,
		}).Info("proxy: blocked connection")
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

func (p *proxy) tarpit(clientConn net.Conn, _ []byte) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	tarpitAddr := net.JoinHostPort(cfg.Proxy.TarpitHost, fmt.Sprintf("%d", cfg.Proxy.TarpitPort.Int()))
	tarpitConn, err := net.DialTimeout("tcp", tarpitAddr, 2*time.Second)
	if err != nil {
		// Tarpit unavailable → just close (fail open to block rather than forward)
		p.log.WithError(err).Debug("proxy: tarpit connect failed; closing connection")
		return
	}
	defer tarpitConn.Close()

	// Forward to tarpit — same bidirectional copy
	buf := make([]byte, 512)
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		for {
			n, err := src.Read(buf)
			if n > 0 {
				dst.Write(buf[:n]) //nolint:errcheck
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
	if cfg.Logging.JSONEnabled || os.Getenv("ENVIRONMENT") == "production" {
		log.SetFormatter(&logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	}
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
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
	}
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
