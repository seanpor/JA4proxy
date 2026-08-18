// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// JA4proxy — Go TLS-aware passthrough security proxy.
//
// Reads config/proxy.yml, accepts TCP connections, parses TLS ClientHello
// without decrypting traffic, runs each connection through the security
// pipeline, and forwards allowed connections to the backend unchanged.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/health"
	jalogger "github.com/seanpor/ja4proxy/internal/logging"
	"github.com/seanpor/ja4proxy/internal/metrics"
	proxypkg "github.com/seanpor/ja4proxy/internal/proxy"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/seanpor/ja4proxy/internal/security"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	webhook "github.com/seanpor/ja4proxy/internal/webhook"
)

// bufferPool recycles 32KB buffers to reduce GC pressure.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32768)
		return &b
	},
}

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
	log.WithFields(logrus.Fields{
		"version": config.Version,
		"built":   config.BuildDate,
		"commit":  config.GitCommit,
	}).Info("JA4proxy daemon starting")

	if os.Getenv("ENVIRONMENT") == "production" && os.Getenv("ALLOW_UNAUTH_REDIS") == "true" {
		log.Fatal("Insecure Redis config blocked in production")
	}

	// Register Prometheus metrics (must be called once before any metric use)
	metrics.Register()

	// phase-63: emit TLS cert expiry timestamp gauge from JA4PROXY_TLS_CERT_FILE
	// (Phase 64 alerts on this gauge — see docs/phases/PHASE_63_notes.md).
	updateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), log)

	proxy, err := newProxy(cfg, cfgPath, log)
	if err != nil {
		log.WithError(err).Fatal("failed to initialise proxy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background workers
	proxy.pipeline.StartBackgroundWorkers(ctx)

	// Start multi-DC monitoring (NTP drift)
	if cfg.Monitoring.Enabled {
		go metrics.StartNTPMonitor(ctx, cfg.Monitoring.NTPCheckIntervalSeconds, log)
	}

	// Start pub/sub for config hot-reload and dynamic list updates.
	// JA4PROXY-2026-0019 — wire HMAC secret so critical channels reject
	// unsigned messages when configured.
	pubsubHandler := redisclient.NewPubSubHandler(proxy.redis, log, func() {
		if err := proxy.reload(); err != nil {
			metrics.ConfigReloadFailuresTotal.Inc()
			log.WithError(err).Error("config reload failed")
		}
	}, func() {
		loadSecurityLists(ctx, proxy.redis, proxy.pipeline)
		log.Info("security lists refreshed via pub/sub")
	})
	pubsubHandler.SetHMACSecret(cfg.Redis.PubSubHMACSecret)
	go pubsubHandler.Run(ctx)

	// phase-201c: periodic Redis health check + auto script reload.
	// phase-209: recover from panic so the goroutine keeps running.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							metrics.HealthCheckPanicsTotal.Inc()
							log.WithField("panic", r).Error("health check panicked, continuing loop")
						}
					}()
					proxy.redis.HealthCheck(ctx)
				}()
			}
		}
	}()

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
				metrics.ConfigReloadFailuresTotal.Inc()
				log.WithError(err).Error("config reload failed")
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
	cfgPath    string // JA4PROXY-2026-0041: path used to Load cfg at startup; re-read on SIGHUP.
	log        *logrus.Logger
	pipeline   *security.Pipeline
	redis      *redisclient.Client
	geoIP      *geoip2.Reader
	dispatcher *webhook.Dispatcher // phase-80: webhook event delivery

	activeConns int64 // atomic
	mu          sync.RWMutex

	// JA4PROXY-2026-0012 — bounded semaphore for the Accept loop. Capacity
	// == cfg.Proxy.MaxConnections. Acquired non-blockingly before spawning
	// handleConn; if full, the connection is immediately closed and
	// metrics.ConnectionErrorsTotal{reason="accept_overflow"} is bumped.
	// Without this, a flood of half-open connections grows the goroutine
	// pool and per-connection 3x BufferSize allocations unboundedly —
	// 100K conns = 2.4GB of buffers alone at the 8KB default.
	acceptSem chan struct{}

	// Tarpit self-protection
	tarpitConcurrent int
	tarpitPerIP      map[string]int
	tarpitMu         sync.Mutex

	// Trusted upstream CIDRs merged from static config + NetBox (phase-94i2).
	trustedCIDRs   []string
	trustedCIDRsMu sync.RWMutex

	// Phase 203e — anti-flap state for /health/deep component checks.
	// Lazily initialised to tolerate test fixtures that build *proxy via
	// struct literals without calling newProxy().
	healthState *health.State

	// JA4PROXY-2026-0031 — bounded XADD event queue. Every connection
	// decision previously spawned an unbounded `go func() { XAdd(bg, ...) }()`
	// goroutine with no timeout. If Redis slowed down or a brief outage
	// pushed XADD latency into the seconds, goroutines (each holding a
	// JSON-marshalled event) accumulated without bound until the proxy
	// OOMed. We now enqueue the event into a fixed-capacity channel drained
	// by a small worker pool; when the queue is full we drop the event and
	// increment metrics.StreamEventDropsTotal instead of spawning a new
	// goroutine. The connection itself continues to be handled — only the
	// telemetry stream write is shed.
	streamEventQueue chan []byte

	// phase-826 — HMAC secret for signing stream events, and this instance's
	// identifier. Both are fixed at construction: the secret is a credential
	// (not hot-reloadable, like the Redis URL) and the node ID is derived from
	// the hostname, which does not change while the process runs.
	streamHMACSecret string
	nodeID           string
}

// JA4PROXY-2026-0041: cfgPath must match the path main() loaded `cfg`
// from, so reload() re-reads the same file on SIGHUP rather than
// silently falling back to "config/proxy.yml". Test code that
// constructs newProxy() directly may pass "" to skip the reload-safe
// round-trip, but production callers must supply the real path.
func newProxy(cfg *config.Config, cfgPath string, log *logrus.Logger) (*proxy, error) {
	// JA4PROXY-2026-0010 — refuse to start against a remote, unauthenticated
	// Redis. Ban lists, whitelists, and the dial setting are security state;
	// anyone who can reach an unauthenticated Redis can rewrite them.
	if err := config.ValidateRedisAuth(cfg); err != nil {
		return nil, err
	}
	// JA4PROXY-2026-0008 — refuse to start with an unauthenticated metrics
	// endpoint bound to a non-loopback interface. /metrics and /health/deep
	// leak operational state that makes reconnaissance trivial.
	if err := config.ValidateMetricsAccess(cfg); err != nil {
		return nil, err
	}
	// JA4PROXY-2026-0050 — check whether per-service Redis ACL users are
	// configured. When they are not and Redis is remote, emit a loud WARN
	// so the gap cannot be missed during deployment review. Never a
	// startup gate: flipping the default would break every deployment
	// that has not yet run scripts/redis-acl-setup.sh.
	checkAndLogRedisACL(cfg, log)
	// JA4PROXY-2026-0052 — refuse to start when acl_users.enabled is true
	// but acl_users.proxy_user is empty. Misconfiguration silently keeps
	// the proxy on the "default" user — exactly the state the operator
	// thought they were fixing.
	if err := config.ValidateRedisACLConsistency(cfg); err != nil {
		return nil, err
	}
	// JA4PROXY-2026-0052 — resolve effective Redis username. When ACLs are
	// enabled, acl_users.proxy_user takes precedence over the historical
	// redis.username field so operators do not have to set both in lockstep.
	redisUsername := config.ResolveRedisUsername(cfg)
	if log != nil {
		log.WithFields(logrus.Fields{
			"finding":  "JA4PROXY-2026-0052",
			"username": redisUsername,
			"acl_mode": config.CheckRedisACLStatus(cfg).String(),
		}).Info("Redis effective ACL username resolved")
	}
	redisCfg := redisclient.Config{
		Host:             cfg.Redis.Host,
		Port:             cfg.Redis.Port.Int(),
		MasterName:       cfg.Redis.MasterName,
		Sentinels:        cfg.Redis.Sentinels,
		DB:               cfg.Redis.DB,
		Password:         cfg.Redis.Password,
		Username:         redisUsername,
		SSL:              cfg.Redis.SSL,
		Timeout:          time.Duration(cfg.Redis.Timeout.Int()) * time.Second,
		IntegrityKeyFile: cfg.Sync.IntegrityKeyFile,
	}
	rc := redisclient.New(redisCfg, log)

	// Phase 88.2: Enable cross-DC sync capture
	if cfg.Sync.DCID != "" {
		syncStream := fmt.Sprintf("ja4proxy:dc:%s:sync:out", cfg.Sync.DCID)
		rc.EnableSync(syncStream)
	}

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
	// phase-100-C: each endpoint carries its own retry/backoff/timeout; the
	// DispatcherConfig holds safe global defaults used when per-endpoint values are zero.
	endpoints := make([]webhook.WebhookEndpoint, len(cfg.Webhooks.Endpoints))
	for i, e := range cfg.Webhooks.Endpoints {
		endpoints[i] = webhook.WebhookEndpoint{
			ID:                  e.ID,
			URL:                 e.URL,
			Secret:              e.Secret,
			Events:              e.Events,
			RetryAttempts:       e.RetryAttempts,
			RetryBackoffSeconds: e.RetryBackoffSeconds,
			TimeoutSeconds:      e.TimeoutSeconds,
		}
	}
	dispatcherCfg := webhook.DispatcherConfig{
		Endpoints:      endpoints,
		StreamKey:      cfg.Webhooks.StreamKey,
		DLQStreamKey:   cfg.Webhooks.DLQKey,
		RetryAttempts:  3, // global default; overridden per-endpoint
		RetryBackoff:   5 * time.Second,
		TimeoutSeconds: 30,
	}
	disp, err := webhook.NewDispatcher(dispatcherCfg, rc.Raw(), log)
	if err != nil {
		log.WithError(err).Warn("proxy: webhook dispatcher init failed; webhooks disabled")
	}

	// JA4PROXY-2026-0012 — cap simultaneous accept-loop goroutines. A zero
	// or negative MaxConnections would otherwise produce a zero-capacity
	// channel and block the proxy from serving any traffic; fall back to a
	// sane default so a misconfigured cap never turns into an availability
	// outage.
	maxConns := cfg.Proxy.MaxConnections
	if maxConns <= 0 {
		maxConns = 1000
	}
	prx := &proxy{
		cfg:         cfg,
		cfgPath:     cfgPath, // JA4PROXY-2026-0041: used by reload() on SIGHUP.
		log:         log,
		pipeline:    p,
		redis:       rc,
		dispatcher:  disp,
		tarpitPerIP: make(map[string]int),
		healthState: health.New(health.Config{FailThreshold: 3}),
		acceptSem:   make(chan struct{}, maxConns),
	}

	// JA4PROXY-2026-0031 — bounded XADD queue. Capacity bounds the number
	// of events buffered during a Redis slowdown; beyond this, drops are
	// counted rather than goroutines being unboundedly spawned.
	queueCap := cfg.Webhooks.StreamQueueCapacity
	if queueCap <= 0 {
		queueCap = 4096
	}
	prx.streamEventQueue = make(chan []byte, queueCap)

	// phase-826 — analytics event signing. An unsigned event is rejected by
	// the analytics node under its default hmac_required, so silently running
	// without a secret means emitting telemetry that is guaranteed to be
	// discarded. Warn loudly rather than let that look like "no traffic".
	prx.streamHMACSecret = cfg.Webhooks.StreamHMACSecret
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	prx.nodeID = deriveNodeID(hostname)
	if prx.streamHMACSecret == "" {
		log.Warn("proxy: webhooks.stream_hmac_secret is empty — connection events " +
			"are written unsigned and the analytics node will reject them unless " +
			"it runs with hmac_required=false. Intelligence findings will be empty.")
	}

	// phase-94i2: load trusted CIDRs from NetBox in the background (fail-open, non-blocking).
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		prx.reloadTrustedCIDRs(ctx, cfg)
	}()

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
	// JA4PROXY-2026-0031 — start the bounded XADD worker pool.
	p.startStreamEventWorkers(ctx)
	go p.startIntegrityWorker(ctx)

	// Phase 232b: heartbeat — SET proxy:heartbeat:{hostname} EX 90 every 60s.
	go func() {
		hostname, _ := os.Hostname()
		key := "proxy:heartbeat:" + hostname
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		// Write immediately so the management API sees a heartbeat on first poll.
		p.redis.Set(ctx, key, fmt.Sprintf("%d", time.Now().Unix()), 90*time.Second)
		for {
			select {
			case <-ctx.Done():
				// Best-effort cleanup: DEL so the management API detects
				// PROXY_DOWN within the next poll cycle (10s). Hard crash
				// (SIGKILL) leaves the key — TTL expiry handles that.
				p.redis.Raw().Del(context.Background(), key)
				return
			case <-t.C:
				p.redis.Set(ctx, key, fmt.Sprintf("%d", time.Now().Unix()), 90*time.Second)
			}
		}
	}()

	// Start metrics/health HTTP server
	if p.cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/health", p.handleHealth)
			mux.HandleFunc("/health/deep", p.handleHealthDeep)
			mux.HandleFunc("/metrics/summary", p.handleMetricsSummary)
			var handler http.Handler = mux
			if p.cfg.Metrics.RateLimitRPS > 0 {
				limiter := newMetricsRateLimiter(p.cfg.Metrics.RateLimitRPS, p.cfg.Metrics.RateLimitBurst)
				handler = metricsRateLimitMiddleware(handler, limiter, p.log)
			}
			handler = metricsAuthMiddleware(handler, p.cfg.Metrics.AuthToken)
			bindHost := p.cfg.Metrics.BindHost
			if bindHost == "" {
				bindHost = "127.0.0.1"
			}
			addr := fmt.Sprintf("%s:%d", bindHost, p.cfg.Metrics.Port.Int())
			p.log.WithField("addr", addr).Info("proxy: metrics server listening")
			srv := &http.Server{Addr: addr, Handler: handler, ReadTimeout: 10 * time.Second}
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
		if !p.admitConn(conn) {
			continue
		}
		atomic.AddInt64(&p.activeConns, 1)
		go func() {
			defer func() { <-p.acceptSem }()
			defer func() {
				if r := recover(); r != nil {
					p.log.WithField("panic", r).Error("handler recovered from panic")
					metrics.HandlerPanicsTotal.Inc()
				}
			}()
			p.handleConn(ctx, conn)
		}()
	}
}

// admitConn acquires a slot in the accept-loop semaphore (non-blocking). If
// the semaphore is full the connection is refused and closed immediately —
// the alternative is unbounded goroutine growth, since every half-open
// connection allocates 3x BufferSize and a handler goroutine.
// JA4PROXY-2026-0012.
func (p *proxy) admitConn(conn net.Conn) bool {
	select {
	case p.acceptSem <- struct{}{}:
		return true
	default:
		metrics.ConnectionErrorsTotal.WithLabelValues("accept_overflow").Inc()
		p.log.WithField("remote", conn.RemoteAddr().String()).
			Warn("proxy: accept-loop at capacity; dropping connection")
		_ = conn.Close()
		return false
	}
}

func (p *proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	t0, t1, t2, t3 := time.Now(), time.Now(), time.Now(), time.Now()
	_, _, _, _ = t0, t1, t2, t3
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()
	metrics.ActiveConnections.Inc()
	defer func() {
		metrics.ActiveConnections.Dec()
		atomic.AddInt64(&p.activeConns, -1)
		clientConn.Close()
	}()

	// Peek at first 5 bytes to detect TLS
	bp := bufferPool.Get().(*[]byte)
	buf := *bp
	defer bufferPool.Put(bp)
	// Errors are ignored: a SetReadDeadline failure means the conn is already
	// broken, so the following Read fails immediately anyway.
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Proxy.ReadTimeout) * time.Second))
	n, err := clientConn.Read(buf)
	t1 = time.Now()
	_ = clientConn.SetReadDeadline(time.Time{}) // clear deadline
	if err != nil || n == 0 {
		if err != nil {
			// phase-63: classify and record the error against the availability SLI.
			metrics.ConnectionErrorsTotal.WithLabelValues(classifyConnError("client_read", err)).Inc()
		}
		return
	}
	data := buf[:n]

	// Build ConnectionContext from TLS ClientHello
	ipStr, ipNet := remoteIP(clientConn)
	connCtx := &security.ConnectionContext{
		ClientIP:   ipStr,
		ParsedIP:   ipNet,
		ClientPort: remotePort(clientConn),
	}

	// PROXY protocol: always strip the header (v1 or v2) so it is never
	// forwarded to the backend. Only adopt the extracted client IP when the
	// source is in the trusted upstream CIDR list.
	//
	//   JA4PROXY-2026-0001 (spoof): before the always-strip fix, an untrusted
	//     source that sent a PROXY header used to have the header forwarded
	//     verbatim to the backend, which might then trust the attacker's
	//     claimed src IP. The header is now stripped in all cases; only
	//     trusted peers influence connCtx.ClientIP.
	//   JA4PROXY-2026-0002 (smuggling): a second PROXY header chained after
	//     the first is treated as a smuggling attempt (e.g. trusted HAProxy
	//     header followed by an attacker-injected one). The connection is
	//     closed.
	if cfg.Proxy.ProxyProtocol {
		socketIP, _ := remoteIP(clientConn)
		trusted := proxypkg.IsTrustedProxySourceCIDRs(socketIP, p.getTrustedCIDRs())
		stripped := false
		// Try v2 binary header first (HAProxy 2.x+, AWS NLB).
		if realIP, ok, hdrLen := proxypkg.ReadProxyProtocolV2WithLength(data); ok {
			if trusted {
				connCtx.ClientIP = realIP
				connCtx.ParsedIP = net.ParseIP(realIP)
			}
			data = data[hdrLen:]
			stripped = true
		} else if realIP, ok := proxypkg.ReadProxyProtocol(data); ok {
			// Fall back to v1 text header.
			if trusted {
				connCtx.ClientIP = realIP
				connCtx.ParsedIP = net.ParseIP(realIP)
			}
			if idx := bytes.Index(data, []byte("\r\n")); idx >= 0 {
				data = data[idx+2:]
				stripped = true
			}
		}
		if stripped {
			if !trusted {
				metrics.ProxyProtocolParserEvents.WithLabelValues("spoof_stripped").Inc()
				p.log.WithField("socket_ip", socketIP).Warn("proxy: stripped PROXY header from untrusted source (JA4PROXY-2026-0001)")
			}
			// JA4PROXY-2026-0002: detect chained PROXY header (smuggling).
			if _, ok, _ := proxypkg.ReadProxyProtocolV2WithLength(data); ok {
				metrics.ProxyProtocolParserEvents.WithLabelValues("smuggling_blocked").Inc()
				p.log.WithField("socket_ip", socketIP).Warn("proxy: PROXY header smuggling detected (v2 chained); closing (JA4PROXY-2026-0002)")
				return
			}
			if _, ok := proxypkg.ReadProxyProtocol(data); ok {
				metrics.ProxyProtocolParserEvents.WithLabelValues("smuggling_blocked").Inc()
				p.log.WithField("socket_ip", socketIP).Warn("proxy: PROXY header smuggling detected (v1 chained); closing (JA4PROXY-2026-0002)")
				return
			}
		}
	}

	// GeoIP country lookup
	if p.geoIP != nil {
		if ip := connCtx.ParsedIP; ip != nil {
			if record, err := p.geoIP.Country(ip); err == nil {
				connCtx.Country = record.Country.IsoCode
			}
		}
	}

	// JA4PROXY-2026-0011 — protocol lockdown. After PROXY strip the first
	// byte must be 0x16 (TLS Handshake content type). Anything else is a
	// non-TLS protocol on a TLS-aware listener (HTTP/SSH/etc.) or an
	// attempt to smuggle a second PROXY header; either way it must never
	// reach the pipeline's pre-parse fall-through that would otherwise
	// forward without a JA4. Operators who proxy non-TLS on this port can
	// disable the check with security.enforce_tls_record: false.
	if cfg.Security.ProtocolLockdownEnabled() && len(data) >= 1 && data[0] != 0x16 {
		metrics.ConnectionErrorsTotal.WithLabelValues("non_tls_dropped").Inc()
		p.log.WithFields(logrus.Fields{
			"client_ip":     connCtx.ClientIP,
			"first_byte":    fmt.Sprintf("0x%02x", data[0]),
			"bytes_sampled": len(data),
		}).Warn("proxy: non-TLS content type on TLS listener; dropping (JA4PROXY-2026-0011)")
		return
	}

	// JA4PROXY-2026-0003: length check was previously `n >= 5`, which used
	// the pre-PROXY-strip read count and could read past the end of `data`
	// after a stripped header. Use len(data) now that data has been
	// normalised.
	if len(data) >= 5 && data[0] == 0x16 {
		// JA4PROXY-2026-0003: if the first TCP segment only contains a
		// fragment of the ClientHello record, the first ParseClientHello
		// returns ErrTruncated and the connection would previously be
		// forwarded without a JA4 — defeating every JA4-based control.
		// Read additional bytes until we either have the full record or
		// hit a ceiling / the client stops sending.
		data = p.reassembleClientHello(clientConn, data, buf)
		if hello, err := tlsparse.ParseClientHello(data); err == nil {
			t2 = time.Now()
			// JA4PROXY-2026-0092: populateTLSFingerprints clones SNI/ALPN so
			// connCtx does not alias the pooled read buffer once it escapes to
			// the async scorer (see the helper's doc comment).
			populateTLSFingerprints(connCtx, hello)
		} else {
			// phase-63 (review fix B3): TLS parse failures are NOT availability
			// errors — the connection is still handled and reaches a policy
			// decision (scored without JA4). Counting it both here and in the
			// good term at ConnectionsTotal would double-count and bias the SLI
			// optimistically. Just log.
			p.log.WithError(err).Debug("proxy: TLS parse failed; scoring without JA4")
		}
	}

	// Run pipeline
	start := time.Now()
	result := p.pipeline.Process(ctx, connCtx)
	t3 = time.Now()
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
	backendHost := cfg.Proxy.BackendHost
	p.mu.RUnlock()
	traceFields := logrus.Fields{}
	if os.Getenv("JA4PROXY_FORENSIC") == "true" {
		traceFields["trace.accept_to_read_us"] = t1.Sub(t0).Microseconds()
		traceFields["trace.read_to_parse_us"] = t2.Sub(t1).Microseconds()
		traceFields["trace.parse_to_score_us"] = t3.Sub(t2).Microseconds()
		traceFields["trace.total_us"] = time.Since(t0).Microseconds()
	}
	p.log.WithFields(traceFields).WithFields(logrus.Fields{
		"client_ip":   connCtx.ClientIP,
		"ja4":         connCtx.JA4,
		"ja4x":        connCtx.JA4X,
		"action":      result.Action,
		"score":       result.Score,
		"sni":         connCtx.SNI,
		"alpn":        connCtx.ALPN,
		"country":     connCtx.Country,
		"tls_version": connCtx.TLSVersion,
		"ja4t":        connCtx.TCPJA4T,
		"dial":        result.Dial,
		"signals":     result.Signals,
		"reason":      result.BypassReason,
		"dst_ip":      backendHost, // phase-80: destination for ECS field mapping
		"src_port":    connCtx.ClientPort,
	}).Info("proxy: connection decision")

	// Publish ECS connection event to Redis Stream for webhook delivery.
	// JA4PROXY-2026-0031 — enqueue into a bounded channel drained by a
	// fixed worker pool instead of spawning an unbounded goroutine per
	// connection. Non-blocking send: if the queue is full (Redis is lagging
	// or down), drop the event and bump a counter. The connection itself
	// was already decided — losing the telemetry event is the correct
	// degradation under load.
	if p.dispatcher != nil {
		ecsFields := map[string]interface{}{
			"@timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
			"event.action":      result.Action,
			"event.risk_score":  result.Score,
			"source.ip":         connCtx.ClientIP,
			"source.port":       connCtx.ClientPort,
			"destination.ip":    backendHost,
			"destination.port":  443,
			"network.transport": "tcp",
			"network.protocol":  "tls",
			"service.name":      "ja4proxy",
			// phase-826: the analytics node attributes findings per proxy
			// instance, so a multi-node deployment can tell which node saw
			// what. Previously absent, which made its proxy_id validation
			// unsatisfiable.
			"ja4proxy.node_id":         p.nodeID,
			"ja4proxy.fingerprint.ja4": connCtx.JA4,
			"ja4proxy.sni":             connCtx.SNI,
			"ja4proxy.dial_setting":    result.Dial,
			// phase-827: the analytics node correlates findings across
			// dimensions — "45 IPs, one JA4" or "one JA4 across 12 countries"
			// is what makes a finding actionable, and none of it could be
			// computed because the event carried only IP, JA4 and SNI. These
			// are all already resolved on the connection; emitting them costs
			// nothing extra on the hot path.
			//
			// Empty values are still emitted rather than omitted, so the
			// consumer can distinguish "not collected" from "collected and
			// empty" (GeoIP absent vs. an IP with no country).
			"ja4proxy.alpn":             connCtx.ALPN,
			"ja4proxy.tls_version":      connCtx.TLSVersion,
			"client.geo.country_iso":    connCtx.Country,
			"ja4proxy.fingerprint.ja4x": connCtx.JA4X,
			"ja4proxy.fingerprint.ja4t": connCtx.TCPJA4T,
			"ja4proxy.bypass_reason":    result.BypassReason,
		}
		if ecsJSON, err := json.Marshal(ecsFields); err == nil {
			p.enqueueStreamEvent(ecsJSON)
		}
	}

	// Execute action
	switch result.Action {
	case "allow", "flag", "rate_limit":
		p.forward(clientConn, data, connCtx.ClientIP, connCtx.ClientPort)
	case "tarpit":
		p.tarpit(clientConn, data, connCtx.ClientIP)
	case "block", "ban":
		// Force RST instead of clean FIN
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
	}
}

// reassembleClientHello keeps reading from clientConn until `data` holds the
// complete TLS record whose length is encoded at bytes 3-4 (or until a hard
// ceiling is reached / the client sends no more). Fail-open: on any error or
// timeout we return whatever we have so far — the parser will decide.
//
// The caller passes `buf`, the full-capacity backing array that `data`
// already aliases (data == buf[:len(data)]). We extend data into buf's
// unused tail so we don't clobber the bytes already read.
//
// JA4PROXY-2026-0003 regression guard: previously a single Read() could land
// a truncated ClientHello, tlsparse.ParseClientHello returned ErrTruncated,
// and the connection was forwarded without a JA4.
func (p *proxy) reassembleClientHello(clientConn net.Conn, data, buf []byte) []byte {
	if len(data) < 5 {
		return data
	}

	// 1. Reassemble the first TLS record if it is incomplete.
	recordLen := int(data[3])<<8 | int(data[4])
	want := 5 + recordLen
	// JA4PROXY-2026-0063: cap the first-record read at 64KB so the
	// fragmentation loop has room to read subsequent records without
	// hitting the per-connection cap prematurely.
	const firstRecordCap = 65536
	if want > firstRecordCap {
		want = firstRecordCap
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	for len(data) < want {
		if time.Now().After(deadline) {
			break
		}
		_ = clientConn.SetReadDeadline(deadline)
		offset := len(data)
		if offset >= cap(buf) {
			break
		}
		end := want
		if end > cap(buf) {
			end = cap(buf)
		}
		m, err := clientConn.Read(buf[offset:end])
		if m > 0 {
			data = buf[:offset+m]
		}
		if err != nil {
			break
		}
	}

	// 2. JA4PROXY-2026-0003 extension: handle Handshake fragmentation across records.
	// If this is a ClientHello handshake, check if we need more records.
	if len(data) >= 9 && data[0] == 0x16 && data[5] == 0x01 {
		handshakeLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
		totalHandshakeWanted := 4 + handshakeLen
		currentHandshake := len(data) - 5

		// Per-connection cap to prevent OOM under fragmentation attack (F-004).
		// JA4PROXY-2026-0063: use this as the ONLY bound — the old hardCap
		// (16640) silently truncated large handshakes, allowing the bypass
		// to move to ~33KB instead of closing it.
		const maxReassemblyBytes = 65536

		// If the handshake spans multiple records, read them and append bodies.
		for currentHandshake < totalHandshakeWanted {
			if len(data) >= maxReassemblyBytes || time.Now().After(deadline) {
				break
			}

			_ = clientConn.SetReadDeadline(deadline)
			header := make([]byte, 5)
			if _, err := io.ReadFull(clientConn, header); err != nil {
				break
			}

			// Must be subsequent Handshake record (0x16)
			if header[0] != 0x16 {
				p.log.WithField("content_type", header[0]).
					Debug("reassembly: non-handshake record during fragment assembly")
				break
			}

			nextLen := int(header[3])<<8 | int(header[4])
			if nextLen == 0 || nextLen > 16384 {
				break
			}

			body := make([]byte, nextLen)
			if _, err := io.ReadFull(clientConn, body); err != nil {
				break
			}

			// JA4PROXY-2026-0063: prepend the 5-byte TLS record header so
			// ParseClientHello can detect multiple records and concatenate
			// their handshake payloads.
			data = append(data, header...)
			data = append(data, body...)
			currentHandshake += nextLen
		}

		// JA4PROXY-2026-0063: ParseClientHello now handles multi-record input
		// by concatenating handshake payloads. We pass the raw reassembled data
		// (multiple TLS records) directly to the parser, which detects and
		// concatenates them internally. No header update needed here.
	}

	_ = clientConn.SetReadDeadline(time.Time{})
	return data
}

func (p *proxy) forward(clientConn net.Conn, initialData []byte, srcIP string, srcPort int) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	backendAddr := net.JoinHostPort(cfg.Proxy.BackendHost, fmt.Sprintf("%d", cfg.Proxy.BackendPort.Int()))

	t3 := time.Now()
	backendConn, err := net.DialTimeout("tcp", backendAddr,
		time.Duration(cfg.Proxy.ConnectionTimeout)*time.Second)
	t6 := time.Now()
	if os.Getenv("JA4PROXY_FORENSIC") == "true" {
		_, lport, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err == nil {
			_, bp, _ := net.SplitHostPort(backendConn.LocalAddr().String())
			p.log.Warnf("TRACE [P] port=%s outbound=%s T3=%d T6=%d", lport, bp, t3.UnixNano(), t6.UnixNano())
		} else {
			p.log.Warnf("TRACE [P] port=%s T3=%d T6=%d", lport, t3.UnixNano(), t6.UnixNano())
		}
	}
	if err != nil {
		// phase-63: backend dial failures degrade availability SLI.
		metrics.ConnectionErrorsTotal.WithLabelValues(classifyConnError("backend_dial", err)).Inc()
		p.log.WithError(err).WithField("backend", backendAddr).Warn("proxy: backend connect failed")
		return
	}
	defer backendConn.Close()

	// phase-231a: optionally prepend a PROXY protocol header so the backend
	// learns the real client IP/port without JA4proxy decrypting TLS. Written
	// first, before the buffered ClientHello, so it is the very first thing the
	// backend reads. srcIP/srcPort are the already-resolved client (from a
	// trusted inbound PROXY header, else the socket peer); dst is the proxy's
	// own accept address.
	if cfg.Proxy.WriteProxyProtocol {
		var dstIP net.IP
		dstPort := 0
		if la, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
			dstIP = la.IP
			dstPort = la.Port
		}
		hdr := proxypkg.BuildBackendProxyHeader(cfg.Proxy.WriteProxyProtocolVersion, net.ParseIP(srcIP), srcPort, dstIP, dstPort)
		if _, err := backendConn.Write(hdr); err != nil {
			metrics.ConnectionErrorsTotal.WithLabelValues(classifyConnError("backend_proxy_header", err)).Inc()
			p.log.WithError(err).Warn("proxy: write PROXY header to backend failed")
			return
		}
	}

	// Send buffered initial data
	if _, err := backendConn.Write(initialData); err != nil {
		p.log.WithError(err).Warn("proxy: write initial data to backend failed")
		return
	}

	// Bidirectional copy. Two design constraints are held together here:
	//
	//   1. Throughput (phase-306, from PR #95): each direction borrows a 32KB
	//      buffer from bufferPool instead of allocating one per connection,
	//      which removes per-connection GC pressure under sustained load.
	//
	//   2. Idle-connection reaping (security): every read refreshes
	//      SetReadDeadline(ReadTimeout) and every write refreshes
	//      SetWriteDeadline(WriteTimeout). Without this a slowloris / idle-hold
	//      client would pin a goroutine *and* a pooled buffer indefinitely, and
	//      the operator-configured read_timeout / write_timeout knobs would be
	//      silently dead. io.CopyBuffer cannot do this — it sets no deadlines —
	//      so we keep an explicit copy loop. (PR #95 dropped this; phase-306
	//      restores it while keeping the buffer-pool win — the two do not
	//      conflict.)
	//
	// JA4PROXY-2026-0009 — both copy goroutines must finish before forward()
	// returns, otherwise the surviving one lingers with its (now-returned)
	// pooled buffer still reachable. Closing both conns when either direction
	// ends unblocks the peer's Read promptly so wg.Wait() returns without a
	// lingering goroutine.
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		bp := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bp)
		buf := *bp
		for {
			_ = src.SetReadDeadline(time.Now().Add(time.Duration(cfg.Proxy.ReadTimeout) * time.Second))
			n, rerr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(time.Duration(cfg.Proxy.WriteTimeout) * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}

	go cp(backendConn, clientConn)
	go cp(clientConn, backendConn)
	wg.Wait()
}

func (p *proxy) tarpit(clientConn net.Conn, data []byte, clientIP string) {
	p.mu.RLock()
	cfg := p.cfg
	p.mu.RUnlock()

	maxConcurrent := cfg.Tarpit.MaxActiveConnections
	maxPerIP := cfg.Tarpit.MaxPerIP
	overflowAction := cfg.Tarpit.OverflowAction
	if overflowAction == "" {
		overflowAction = "block"
	}

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
			p.forward(clientConn, data, clientIP, remotePort(clientConn))
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

	// JA4PROXY-2026-0013 — bound how long each Read can block so an attacker
	// cannot pin a tarpit slot by sending one byte and hanging. Inactivity
	// timeout applies to every Read; lifetime cap is a belt-and-braces hard
	// stop even for an actively-trickling client.
	inactivity := time.Duration(cfg.Tarpit.InactivityTimeoutSeconds) * time.Second
	lifetime := time.Duration(cfg.Tarpit.MaxLifetimeSeconds) * time.Second
	deadline := time.Now().Add(lifetime)
	if lifetime > 0 {
		_ = clientConn.SetDeadline(deadline)
		_ = tarpitConn.SetDeadline(deadline)
	}

	// Forward to tarpit — bidirectional copy
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		buf := make([]byte, 512)
		for {
			if inactivity > 0 {
				_ = src.SetReadDeadline(time.Now().Add(inactivity))
			}
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
	// JA4PROXY-2026-0009 — wait for both copy goroutines, closing conns
	// after the first returns so the second unblocks immediately.
	<-done
	_ = clientConn.Close()
	_ = tarpitConn.Close()
	<-done
}

func (p *proxy) reload() error {
	// JA4PROXY-2026-0041: re-read the exact path main() loaded from.
	// Previously this was hardcoded to "config/proxy.yml" and silently
	// diverged from CONFIG_PATH — a SIGHUP would then reload a DIFFERENT
	// file than the one the process was started against, loading stale
	// or wrong policy. Fall back only when the field is empty (test
	// fixtures that construct proxy via struct literals).
	cfgPath := p.cfgPath
	if cfgPath == "" {
		cfgPath = "config/proxy.yml"
	}
	newCfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	pipelineCfg := buildPipelineConfig(newCfg)
	// phase-248: Attack Mode can activate auto-escalation via Redis key.
	// attack_mode:escalate is set by the management API when Attack Mode activates
	// and deleted when it deactivates. The Phase 237 revert poller fires a
	// config:reload when the dial auto-reverts, which triggers this check.
	if p.redis.GetString(context.Background(), "attack_mode:escalate") == "1" {
		pipelineCfg.AutoEscalate.Enabled = true
	}
	// Phase 249: apply Redis override for datacenter policy (set by management UI).
	if raw := p.redis.GetString(context.Background(), "config:datacenter_policy"); raw != "" {
		var override config.DatacenterPolicyConfig
		if err := json.Unmarshal([]byte(raw), &override); err == nil {
			pipelineCfg.DatacenterPolicy = override
		}
	}
	p.pipeline.ReplaceConfig(pipelineCfg)
	p.mu.Lock()
	p.cfg = newCfg
	p.mu.Unlock()
	loadSecurityLists(context.Background(), p.redis, p.pipeline)
	metrics.ConfigReloadsTotal.Inc()
	updateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), p.log)
	p.reloadTrustedCIDRs(context.Background(), newCfg)
	p.log.Info("config reloaded")
	return nil
}

// reloadTrustedCIDRs fetches CIDRs from NetBox (if enabled), merges them with
// static_cidrs, and stores the result in p.trustedCIDRs. Fails open.
func (p *proxy) reloadTrustedCIDRs(ctx context.Context, cfg *config.Config) {
	sources := cfg.TrustedUpstreamSources
	if !sources.NetBox.Enabled {
		// NetBox disabled — use only static CIDRs.
		p.setTrustedCIDRs(sources.StaticCIDRs)
		p.log.Debug("netbox: disabled; using static CIDRs only")
		return
	}

	netboxCIDRs, err := config.LoadTrustedCIDRsFromNetBox(ctx, sources.NetBox.URL, sources.NetBox.Token, sources.NetBox.Tag)
	if err != nil {
		p.log.WithError(err).Warn("netbox: LoadTrustedCIDRsFromNetBox returned error")
		metrics.NetBoxCIDRsLoaded.WithLabelValues("error").Inc()
		// Fall back to static CIDRs only — fail-open.
		p.setTrustedCIDRs(sources.StaticCIDRs)
		return
	}

	if len(netboxCIDRs) == 0 {
		p.log.Warn("netbox: returned zero CIDRs; using static CIDRs only")
		metrics.NetBoxCIDRsLoaded.WithLabelValues("error").Inc()
		p.setTrustedCIDRs(sources.StaticCIDRs)
		return
	}

	// Merge: static_cidrs + netbox CIDRs, deduplicated.
	merged := dedupStrings(append(sources.StaticCIDRs, netboxCIDRs...))
	p.setTrustedCIDRs(merged)
	metrics.NetBoxCIDRsLoaded.WithLabelValues("ok").Inc()
	p.log.WithField("cidrs", len(merged)).Info("netbox: trusted CIDRs reloaded")
}

func (p *proxy) setTrustedCIDRs(cidrs []string) {
	p.trustedCIDRsMu.Lock()
	p.trustedCIDRs = cidrs
	p.trustedCIDRsMu.Unlock()
}

func (p *proxy) getTrustedCIDRs() []string {
	p.trustedCIDRsMu.RLock()
	defer p.trustedCIDRsMu.RUnlock()
	return append([]string(nil), p.trustedCIDRs...)
}

// metricsAuthMiddleware gates the metrics/health HTTP server.
//
// JA4PROXY-2026-0008: /metrics and /health/deep expose dial setting, ban
// rates, cert expiry, and active-connection counts — reconnaissance-grade
// intelligence that must not be world-readable.
//
// Policy:
//   - Requests from loopback (127.0.0.0/8, ::1) are always allowed. This is
//     the common case: Prometheus running as a sidecar on the same host.
//   - If an AuthToken is configured, remote requests must present a matching
//     bearer token in the Authorization header. Constant-time compare.
//   - If no AuthToken is configured, remote requests are refused with 403.
//     ValidateMetricsAccess would have already refused startup for a
//     non-loopback bind, so in practice this arm is only reached when the
//     bind is loopback but the request reached us through some other path.
func metricsAuthMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.MetricsRequestIsLocal(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) ||
			subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ja4proxy-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// metricsRateLimiter is a per-IP token-bucket for the observability endpoints.
//
// JA4PROXY-2026-0026 — /metrics, /health, /health/deep, and /metrics/summary
// were previously unthrottled. A compromised-token holder or a misconfigured
// scraper could spam these, each hit costing a Redis PING plus log/metric
// churn, and DoS the observability subsystem. The limiter enforces a
// configured RPS per remote IP with a small burst. Loopback is exempted so
// co-located Prometheus sidecars are never throttled. Over-limit callers get
// 429 with Retry-After set to one second and a small WARN log that cannot
// itself be turned into a flood because the log emission is also gated by
// the bucket.
type metricsRateLimiter struct {
	rps    float64
	burst  float64
	mu     sync.Mutex
	bucket map[string]*ipBucket
	// maxEntries caps the bucket map to prevent memory-growth via spoofed
	// source IPs. Oldest entries are evicted on insert when the cap is hit.
	maxEntries int
}

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newMetricsRateLimiter(rps float64, burst int) *metricsRateLimiter {
	b := float64(burst)
	if b <= 0 {
		b = rps * 2
	}
	return &metricsRateLimiter{
		rps:        rps,
		burst:      b,
		bucket:     make(map[string]*ipBucket),
		maxEntries: 4096,
	}
}

// allow returns true if remoteAddr has a token available, consuming one.
// remoteAddr is the RemoteAddr string (host:port) from http.Request.
func (l *metricsRateLimiter) allow(remoteAddr string, now time.Time) bool {
	if l == nil || l.rps <= 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bucket[host]
	if !ok {
		if len(l.bucket) >= l.maxEntries {
			// Evict the single oldest entry to bound memory.
			var oldestKey string
			var oldestTime time.Time
			for k, v := range l.bucket {
				if oldestKey == "" || v.lastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.lastSeen
				}
			}
			delete(l.bucket, oldestKey)
		}
		b = &ipBucket{tokens: l.burst, lastSeen: now}
		l.bucket[host] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rps
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
		}
		b.lastSeen = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

// signStreamEvent returns the hex HMAC-SHA256 of the raw event bytes, or ""
// when no secret is configured (signing disabled).
//
// phase-826. The signature deliberately covers the exact bytes written to the
// stream rather than a canonicalised re-encoding of the event object. The
// verifier is Python; making the check depend on Go's and Python's JSON
// encoders agreeing on key order, float formatting and unicode escaping would
// be a standing source of silent, traffic-dependent verification failures.
func signStreamEvent(secret string, event []byte) string {
	if secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(event)
	return hex.EncodeToString(m.Sum(nil))
}

// deriveNodeID returns a stable per-instance identifier for stream events,
// constrained to the analytics node's proxy_id schema (^[a-zA-Z0-9-]{1,32}$).
//
// phase-826. Hostname is the natural choice — under Docker and Kubernetes it
// is the container/pod name — but it can contain dots and underscores and can
// exceed 32 characters, any of which would fail the consumer's validation and
// silently drop every event from that node. Non-conforming characters become
// '-' and the result is truncated; an empty hostname falls back to a constant
// so the field is never absent.
func deriveNodeID(hostname string) string {
	out := make([]rune, 0, 32)
	for _, r := range hostname {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
		if len(out) == 32 {
			break
		}
	}
	if len(out) == 0 {
		return "ja4proxy"
	}
	return string(out)
}

// enqueueStreamEvent performs a non-blocking send onto the bounded XADD
// queue. If the queue is full, the event is dropped and a Prometheus
// counter is incremented. JA4PROXY-2026-0031.
func (p *proxy) enqueueStreamEvent(event []byte) {
	if p == nil || p.streamEventQueue == nil {
		return
	}
	select {
	case p.streamEventQueue <- event:
		metrics.StreamEventQueueDepth.Set(float64(len(p.streamEventQueue)))
	default:
		metrics.StreamEventDropsTotal.Inc()
	}
}

// startStreamEventWorkers starts a fixed pool of goroutines that drain the
// bounded XADD queue and publish to the Redis stream with a per-call
// timeout. JA4PROXY-2026-0031 — bounds both queue depth and per-write
// latency so a Redis slowdown cannot translate into unbounded goroutine
// or memory growth on the proxy.
func (p *proxy) startStreamEventWorkers(ctx context.Context) {
	if p.streamEventQueue == nil {
		return
	}
	workers := p.cfg.Webhooks.StreamWorkers
	if workers <= 0 {
		workers = 4
	}
	timeout := time.Duration(p.cfg.Webhooks.StreamWriteTimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	streamKey := p.cfg.Webhooks.StreamKey
	if streamKey == "" {
		streamKey = "events:connection"
	}
	for i := 0; i < workers; i++ {
		go p.streamEventWorker(ctx, streamKey, timeout)
	}
}

func (p *proxy) streamEventWorker(ctx context.Context, streamKey string, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-p.streamEventQueue:
			if !ok {
				return
			}
			metrics.StreamEventQueueDepth.Set(float64(len(p.streamEventQueue)))
			writeCtx, cancel := context.WithTimeout(ctx, timeout)
			values := map[string]interface{}{"event": string(event)}
			// phase-826: sign the bytes we are about to send, not a re-encoded
			// object — the verifier recomputes over the same raw string, so no
			// cross-language JSON canonicalisation is involved.
			if mac := signStreamEvent(p.streamHMACSecret, event); mac != "" {
				values["hmac"] = mac
			}
			err := p.redis.XAddErr(writeCtx, streamKey, values)
			cancel()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					metrics.StreamEventWriteErrorsTotal.WithLabelValues("timeout").Inc()
				} else {
					metrics.StreamEventWriteErrorsTotal.WithLabelValues("error").Inc()
				}
			}
		}
	}
}

func metricsRateLimitMiddleware(next http.Handler, limiter *metricsRateLimiter, log *logrus.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.MetricsRequestIsLocal(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		if !limiter.allow(r.RemoteAddr, time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// handleHealthDeep responds with comprehensive health data for monitoring integrations.
// Phase 86a — returns Redis state, proxy metrics, and certificate expiry info.
func (p *proxy) handleHealthDeep(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Phase 203e — lazy-init anti-flap state for struct-literal test harnesses.
	p.mu.Lock()
	if p.healthState == nil {
		p.healthState = health.New(health.Config{FailThreshold: 3})
	}
	hs := p.healthState
	p.mu.Unlock()

	// Redis connectivity
	redisOK := true
	redisLatencyMs := 0.0
	t0 := time.Now()
	if err := p.redis.Ping(ctx); err != nil {
		redisOK = false
		hs.RecordFailure("redis")
	} else {
		redisLatencyMs = float64(time.Since(t0).Microseconds()) / 1000.0
		hs.RecordSuccess("redis")
	}
	redisUnhealthy := hs.IsUnhealthy("redis")

	// Dial — read from Redis (management API writes here)
	dial := p.redis.GetDial(ctx)

	// Active bans (count keys matching pattern). phase-231a: the canonical ban
	// key is `ban:{ip}` (REDIS_SCHEMA); the old `ja4proxy:ban:*` prefix matched
	// nothing, so this gauge always read 0.
	activeBans := 0
	if redisOK {
		activeBans = p.redis.CountKeys(ctx, "ban:*")
	}

	// Connection counters — gather from Prometheus registry
	connTotal := 0.0
	blocksTotal := 0.0
	{
		mfs, gatherErr := prometheus.DefaultGatherer.Gather()
		if gatherErr == nil {
			for _, mf := range mfs {
				if mf.GetName() == "ja4proxy_connections_total" {
					for _, m := range mf.GetMetric() {
						val := m.GetCounter().GetValue()
						connTotal += val
						// Sum all blocking actions (B1 fix)
						for _, lp := range m.GetLabel() {
							if lp.GetName() == "action" {
								a := lp.GetValue()
								if a == "block" || a == "ban" || a == "tarpit" || a == "rate_limit" {
									blocksTotal += val
								}
							}
						}
					}
				}
			}
		}
	}

	// Cert expiry
	certTSVal := -1.0
	{
		mfs, gatherErr := prometheus.DefaultGatherer.Gather()
		if gatherErr == nil {
			for _, mf := range mfs {
				if mf.GetName() == "ja4proxy_tls_cert_expiry_timestamp_seconds" {
					for _, m := range mf.GetMetric() {
						certTSVal = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	var certDaysRemaining float64
	if certTSVal > 0 {
		certDaysRemaining = (certTSVal - float64(time.Now().Unix())) / 86400.0
		if certDaysRemaining < 0 {
			certDaysRemaining = 0
		}
	}

	// Block rate
	blockRatePct := 0.0
	if connTotal > 0 {
		blockRatePct = blocksTotal / connTotal * 100.0
	}

	// Phase 203e — tarpit component (always reported). Saturation is a
	// "degraded" warning, never 503.
	tarpitMax := 0
	if p.cfg != nil {
		tarpitMax = p.cfg.Tarpit.MaxActiveConnections
	}
	p.tarpitMu.Lock()
	tarpitActive := p.tarpitConcurrent
	p.tarpitMu.Unlock()
	tarpitStatus := "ok"
	if tarpitMax > 0 && tarpitActive >= tarpitMax {
		tarpitStatus = "degraded"
	}

	// Phase 203e — geoip component (reported only when Country lookup is
	// configured). present=false when p.geoIP is nil; status is always "ok"
	// in this revision since we do not probe the reader on the hot path.
	// Future work: active probe with anti-flap.
	geoIPPresent := p.geoIP != nil
	geoIPStatus := "ok"

	// Status determination
	status := "ok"
	if redisUnhealthy {
		status = "error"
	} else if !redisOK {
		// Transient blip under N=3 anti-flap — still reported but not fatal.
		status = "degraded"
	} else if redisLatencyMs > 50 {
		status = "degraded"
	} else if tarpitStatus == "degraded" {
		status = "degraded"
	}

	// HTTP status: 503 only when a CRITICAL component (redis) is unhealthy
	// under anti-flap. Tarpit saturation never escalates to 503.
	if redisUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"status":             status,
		"redis_connected":    redisOK,
		"redis_latency_ms":   math.Round(redisLatencyMs*100) / 100,
		"dial":               dial,
		"active_connections": atomic.LoadInt64(&p.activeConns),
		"connections_total":  int(connTotal),
		"block_rate_pct":     math.Round(blockRatePct*100) / 100,
		"active_bans":        activeBans,
		"tarpit": map[string]any{
			"active": tarpitActive,
			"max":    tarpitMax,
			"status": tarpitStatus,
		},
		"geoip": map[string]any{
			"present": geoIPPresent,
			"status":  geoIPStatus,
		},
	}
	if certTSVal > 0 {
		resp["cert_days_remaining"] = math.Round(certDaysRemaining*10) / 10
	} else {
		resp["cert_days_remaining"] = nil
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.log.WithError(err).Warn("health/deep: failed to encode response")
	}
}

// handleMetricsSummary is an alias for /health/deep.
// Exists so monitoring tools can poll a single endpoint named "metrics/summary".
func (p *proxy) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	p.handleHealthDeep(w, r)
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

func remoteIP(conn net.Conn) (string, net.IP) {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String(), addr.IP
	}
	s := conn.RemoteAddr().String()
	return s, net.ParseIP(s)
}

func remotePort(conn net.Conn) int {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// populateTLSFingerprints copies the parsed ClientHello fields into connCtx.
//
// JA4PROXY-2026-0092: tls.ParseClientHello returns SNI and ALPN as zero-copy
// strings that ALIAS the input buffer — which here is a sync.Pool buffer that
// handleConn returns to the pool as soon as it finishes. Because the pipeline
// runs in async mode by default, connCtx is enqueued on workChan and read by a
// scoring worker *after* handleConn returns; a later connection can by then have
// reused the buffer and overwritten those bytes. That corrupts the SNI/ALPN the
// async scorer sees (wrong scoring, missed h2/h1 browser bypass) and can bleed
// one connection's SNI hostname into another's logs. We therefore clone SNI and
// ALPN so connCtx owns them and no longer aliases the pooled buffer. JA4/JA4X
// are fmt.Sprintf-owned already; CipherList is copied by value.
func populateTLSFingerprints(connCtx *security.ConnectionContext, hello *tlsparse.ClientHelloInfo) {
	connCtx.JA4 = tlsparse.ComputeJA4(hello)
	connCtx.TLSVersion = int(hello.LegacyVersion)
	connCtx.SNI = strings.Clone(hello.SNI)
	if len(hello.ALPNProtocols) > 0 {
		connCtx.ALPN = strings.Clone(hello.ALPNProtocols[0])
	}
	connCtx.CipherList = make([]int, len(hello.CipherSuites))
	for i, cs := range hello.CipherSuites {
		connCtx.CipherList[i] = int(cs)
	}
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
	// phase-100-B: dual_output=true emits two JSON lines per log call — legacy first,
	// then ECS — to support operators migrating Loki dashboards to ECS without a
	// hard cutover.
	if cfg.Logging.DualOutput && cfg.Logging.Format == "ecs" {
		log.SetFormatter(&jalogger.DualFormatter{
			Legacy: &logrus.JSONFormatter{
				FieldMap: logrus.FieldMap{
					logrus.FieldKeyTime:  "timestamp",
					logrus.FieldKeyLevel: "level",
					logrus.FieldKeyMsg:   "message",
				},
			},
			ECS: jalogger.NewECSLogrusFormatter("ecs"),
		})
	}
	// JA4PROXY-2026-0048 — strip filesystem paths, Redis keys, and upstream
	// IP:port pairs from log fields when ENVIRONMENT=production.
	log.AddHook(jalogger.NewSensitiveFieldRedactor())
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
		JA4BlockingEnabled:      cfg.SecurityPolicy.JA4BlockingEnabled.Enabled,
		MTLSBypass:              cfg.SecurityPolicy.MTLSBypass.Enabled,
		CountryBlockingEnabled:  cfg.SecurityPolicy.CountryBlockingEnabled.Enabled,
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
		MaliciousSNIEnabled:     cfg.SNIAnalyzer.MaliciousSNI.Enabled,
		MaliciousSNIScore:       cfg.SNIAnalyzer.MaliciousSNI.Score,
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
		// Phase 203a — TAP-consumed JA4T OS mismatch.
		TapConsumerEnabled:          cfg.TapConsumer.Enabled,
		TapConsumerScore:            cfg.TapConsumer.SignalScore,
		TapConsumerRedisTimeout:     cfg.TapConsumer.RedisTimeoutMs,
		TapConsumerCacheTTL:         cfg.TapConsumer.CacheTTLSeconds,
		TapConsumerMaxAge:           cfg.TapConsumer.MaxAgeSeconds,
		TapConsumerNegativeCacheTTL: cfg.TapConsumer.NegativeCacheTTLSeconds,
		// Phase 316c — TAP-consumed JA4T blocklist.
		JA4TConsumerEnabled:          cfg.JA4TConsumer.Enabled,
		JA4TConsumerScore:            cfg.JA4TConsumer.SignalScore,
		JA4TConsumerRedisTimeout:     cfg.JA4TConsumer.RedisTimeoutMs,
		JA4TConsumerCacheTTL:         cfg.JA4TConsumer.CacheTTLSeconds,
		JA4TConsumerNegativeCacheTTL: cfg.JA4TConsumer.NegativeCacheTTLSeconds,
		JA4TBlocklist:                cfg.JA4TConsumer.Blocklist,
		AutoEscalate:                 cfg.AutoEscalate,     // phase-248
		DatacenterPolicy:             cfg.DatacenterPolicy, // phase-249
		// phase-515 — decision cache (ADR-003): per-client key + asymmetric TTLs.
		DecisionCacheAllowTTLSeconds: cfg.DecisionCache.AllowTTLSeconds,
		DecisionCacheBlockTTLSeconds: cfg.DecisionCache.BlockTTLSeconds,
		DecisionCacheMaxEntries:      cfg.DecisionCache.MaxEntries,
	}
}

// defaultBlocklistCacheDir is where downloaded feeds are cached for warm-start
// when a feed does not set an explicit path. phase-309 WP-6.
const defaultBlocklistCacheDir = "/var/lib/ja4proxy/blocklists"

func buildBlocklistFeeds(feeds []config.BlocklistFeedConfigYAML) []security.BlocklistFeedConfig {
	out := make([]security.BlocklistFeedConfig, len(feeds))
	for i, f := range feeds {
		path := f.Path
		// Derive a default cache path for downloadable feeds so they warm-start
		// after a restart without operators having to configure one.
		if path == "" && f.URL != "" {
			path = filepath.Join(defaultBlocklistCacheDir, f.Name+".txt")
		}
		out[i] = security.BlocklistFeedConfig{
			Name:                   f.Name,
			URL:                    f.URL,
			Format:                 f.Format,
			IsBypass:               f.IsBypass,
			Action:                 f.Action,
			Score:                  f.Score,
			RefreshIntervalSeconds: f.RefreshIntervalSeconds,
			Enabled:                f.Enabled,
			Path:                   path,
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

// classifyConnError maps a connection-handler error to one of the error_type
// checkAndLogRedisACL sets the ja4proxy_redis_acl_enabled gauge from the
// current config and, when per-service ACL users are disabled against a
// remote Redis, emits a structured WARN naming the finding id and how to
// fix it. Extracted from newProxy so the regression test can drive it
// directly without standing up the whole proxy lifecycle.
// JA4PROXY-2026-0050.
func checkAndLogRedisACL(cfg *config.Config, log *logrus.Logger) {
	aclStatus := config.CheckRedisACLStatus(cfg)
	if aclStatus == config.RedisACLEnabled {
		metrics.RedisACLEnabled.Set(1)
	} else {
		metrics.RedisACLEnabled.Set(0)
	}
	if aclStatus != config.RedisACLDisabledRemote || log == nil {
		return
	}
	host := ""
	if cfg != nil {
		host = cfg.Redis.Host
		if host == "" && len(cfg.Redis.Sentinels) > 0 {
			host = cfg.Redis.Sentinels[0]
		}
	}
	log.WithFields(logrus.Fields{
		"finding": "JA4PROXY-2026-0050",
		"host":    host,
		"status":  aclStatus.String(),
	}).Warn(
		"Redis ACL users disabled with a remote Redis target — the proxy " +
			"is connecting as the 'default' user which has full Redis " +
			"authority. Run scripts/redis-acl-setup.sh and set " +
			"redis.acl_users.enabled: true. See docs/security/findings.yaml " +
			"JA4PROXY-2026-0050.",
	)
}

// label values used by ja4proxy_connection_errors_total. The source argument
// disambiguates errors that look identical at the os/net layer but mean very
// different things — a "i/o timeout" on a client read is a normal idle close,
// on a backend dial is upstream overload, and on a Redis call is a Redis
// problem. Without the source we cannot tell on-call where to look first.
//
// Recognised sources: "client_read", "backend_dial", "redis".
func classifyConnError(source string, err error) string {
	if err == nil {
		return "unknown"
	}
	s := strings.ToLower(err.Error())

	// Source-specific connection-refused / no-route always wins over timeouts.
	if strings.Contains(s, "connection refused") || strings.Contains(s, "no route") {
		if source == "backend_dial" {
			return "backend_refused"
		}
		return "connection_refused"
	}
	if strings.Contains(s, "out of memory") || strings.Contains(s, "cannot allocate") {
		return "oom"
	}

	isTimeout := errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded")

	switch source {
	case "client_read":
		if isTimeout {
			return "client_read_timeout"
		}
		return "client_read_error"
	case "backend_dial":
		if isTimeout {
			return "backend_dial_timeout"
		}
		return "backend_dial_error"
	case "redis":
		if isTimeout {
			return "redis_timeout"
		}
		return "redis_error"
	default:
		if isTimeout {
			return "timeout"
		}
		return "unknown"
	}
}

// updateTLSCertExpiryGauge reads the PEM-encoded certificate at the given path
// and sets ja4proxy_tls_cert_expiry_timestamp_seconds to the cert's NotAfter.
// Phase 63: invoked at startup and on every config reload. Phase 64 alerts on
// this gauge — see docs/phases/PHASE_63_notes.md.
//
// Review-fix N3: on any read/parse failure the gauge is forced to 0 so the
// Phase 64 expiry alert (which tests "now() - gauge < N days") sees the
// failure as "missing data" instead of stale-good. Without this clear, a
// failed reload after cert rotation would silently keep the previous, valid
// NotAfter and the alert would never fire even though the proxy is broken.
func updateTLSCertExpiryGauge(certPath string, log *logrus.Logger) {
	if certPath == "" {
		return
	}
	pemBytes, err := os.ReadFile(certPath) // #nosec
	if err != nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
		log.WithError(err).WithField("path", certPath).Warn("phase-63: failed to read TLS cert for expiry gauge")
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
		log.WithField("path", certPath).Warn("phase-63: TLS cert PEM decode failed")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
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

// dedupStrings returns a deduplicated copy of the input slice, preserving
// the original order of first occurrence.
func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// startIntegrityWorker periodically verifies critical Redis state.
// JA4PROXY-2026-0046: Runtime Integrity Monitoring.
func (p *proxy) startIntegrityWorker(ctx context.Context) {
	p.log.Info("proxy: starting integrity worker (drift detection)")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Monitor dial setting drift. Signed Dial (Phase 124) already
			// prevents tampering, but this provides observability.
			dial := p.redis.GetDial(ctx)
			metrics.DialCurrent.Set(float64(dial))
		}
	}
}
