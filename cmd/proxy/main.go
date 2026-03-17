// JA4proxy — Go TLS-aware passthrough security proxy.
//
// Reads config/proxy.yml, accepts TCP connections, parses TLS ClientHello
// without decrypting traffic, runs each connection through the security
// pipeline, and forwards allowed connections to the backend unchanged.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/anomalyco/ja4proxy/internal/config"
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

	proxy, err := newProxy(cfg, log)
	if err != nil {
		log.WithError(err).Fatal("failed to initialise proxy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	pipelineCfg := buildPipelineConfig(cfg)
	p := security.NewPipeline(pipelineCfg, rc, log)

	return &proxy{
		cfg:      cfg,
		log:      log,
		pipeline: p,
		redis:    rc,
	}, nil
}

func (p *proxy) serve(ctx context.Context) {
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
	defer func() {
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

	backendAddr := fmt.Sprintf("%s:%d", cfg.Proxy.BackendHost, cfg.Proxy.BackendPort.Int())
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

	tarpitAddr := fmt.Sprintf("%s:%d", cfg.Proxy.TarpitHost, cfg.Proxy.TarpitPort.Int())
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
	p.log.Info("config reloaded")
	return nil
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
