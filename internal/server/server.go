package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/health"
	"github.com/seanpor/ja4proxy/internal/metrics"
	proxypkg "github.com/seanpor/ja4proxy/internal/proxy"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/seanpor/ja4proxy/internal/security"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	webhook "github.com/seanpor/ja4proxy/internal/webhook"
)

type Server struct {
	Cfg        *config.Config
	CfgPath    string
	Log        *logrus.Logger
	Pipeline   *security.Pipeline
	Redis      *redisclient.Client
	GeoIP      *geoip2.Reader
	Dispatcher *webhook.Dispatcher

	ActiveConns int64
	Mu          sync.RWMutex

	AcceptSem chan struct{}

	TarpitConcurrent int
	TarpitPerIP      map[string]int
	TarpitMu         sync.Mutex

	TrustedCIDRs   []string
	TrustedCIDRsMu sync.RWMutex

	HealthState *health.State

	StreamEventQueue chan []byte
	StreamHMACSecret string
	NodeID           string
	ConnSeq          uint64

	// Lowercase field aliases for backwards compatibility with tests in package main
	cfg              *config.Config
	cfgPath          string
	log              *logrus.Logger
	pipeline         *security.Pipeline
	redis            *redisclient.Client
	geoIP            *geoip2.Reader
	dispatcher       *webhook.Dispatcher
	activeConns      int64
	acceptSem        chan struct{}
	tarpitPerIP      map[string]int
	trustedCIDRs     []string
	healthState      *health.State
	streamEventQueue chan []byte
	streamHMACSecret string
	nodeID           string
}

func New(cfg *config.Config, log *logrus.Logger) (*Server, error) {
	return NewWithConfigPath(cfg, "", log)
}

func NewWithConfigPath(cfg *config.Config, cfgPath string, log *logrus.Logger) (*Server, error) {
	if err := config.ValidateRedisAuth(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidateMetricsAccess(cfg); err != nil {
		return nil, err
	}
	CheckAndLogRedisACL(cfg, log)
	if err := config.ValidateRedisACLConsistency(cfg); err != nil {
		return nil, err
	}

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

	if cfg.Sync.DCID != "" {
		syncStream := fmt.Sprintf("ja4proxy:dc:%s:sync:out", cfg.Sync.DCID)
		rc.EnableSync(syncStream)
	}

	pipelineCfg := BuildPipelineConfig(cfg)
	p := security.NewPipeline(pipelineCfg, rc, log)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		SeedSecurityLists(ctx, rc, cfg)
		LoadSecurityLists(ctx, rc, p)
	}()

	maxConns := cfg.Proxy.MaxConnections
	if maxConns <= 0 {
		maxConns = 10000
	}

	var disp *webhook.Dispatcher
	if cfg.Webhooks.Enabled && rc != nil {
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
			RetryAttempts:  3,
			RetryBackoff:   5 * time.Second,
			TimeoutSeconds: 30,
		}
		var err error
		disp, err = webhook.NewDispatcher(dispatcherCfg, rc.Raw(), log)
		if err != nil && log != nil {
			log.WithError(err).Warn("proxy: webhook dispatcher init failed; webhooks disabled")
		}
	}

	queueCap := cfg.Webhooks.StreamQueueCapacity
	if queueCap <= 0 {
		queueCap = 4096
	}
	eventQueue := make(chan []byte, queueCap)
	hostname, _ := os.Hostname()
	derivedID := DeriveNodeID(hostname)

	srv := &Server{
		Cfg:              cfg,
		CfgPath:          cfgPath,
		Log:              log,
		Pipeline:         p,
		Redis:            rc,
		Dispatcher:       disp,
		AcceptSem:        make(chan struct{}, maxConns),
		TarpitPerIP:      make(map[string]int),
		TrustedCIDRs:     cfg.TrustedUpstreamSources.StaticCIDRs,
		HealthState:      health.New(health.Config{FailThreshold: 3}),
		StreamEventQueue: eventQueue,
		StreamHMACSecret: cfg.Webhooks.StreamHMACSecret,
		NodeID:           derivedID,

		// Sync lower-case fields
		cfg:              cfg,
		cfgPath:          cfgPath,
		log:              log,
		pipeline:         p,
		redis:            rc,
		dispatcher:       disp,
		acceptSem:        make(chan struct{}, maxConns),
		tarpitPerIP:      make(map[string]int),
		trustedCIDRs:     cfg.TrustedUpstreamSources.StaticCIDRs,
		healthState:      health.New(health.Config{FailThreshold: 3}),
		streamEventQueue: eventQueue,
		streamHMACSecret: cfg.Webhooks.StreamHMACSecret,
		nodeID:           derivedID,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.ReloadTrustedCIDRs(ctx, cfg)
	}()

	if cfg.GeoIP.DBPath != "" {
		if reader, err := geoip2.Open(cfg.GeoIP.DBPath); err == nil {
			srv.GeoIP = reader
			srv.geoIP = reader
		} else if log != nil {
			log.WithError(err).Warn("proxy: failed to open GeoIP DB; country lookup disabled")
		}
	}

	return srv, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.Serve(ctx)
	return nil
}

func (s *Server) Serve(ctx context.Context) {
	s.StartStreamEventWorkers(ctx)
	go s.StartIntegrityWorker(ctx)

	go func() {
		hostname, _ := os.Hostname()
		key := "proxy:heartbeat:" + hostname
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		s.Redis.Set(ctx, key, fmt.Sprintf("%d", time.Now().Unix()), 90*time.Second)
		for {
			select {
			case <-ctx.Done():
				s.Redis.Raw().Del(context.Background(), key)
				return
			case <-t.C:
				s.Redis.Set(ctx, key, fmt.Sprintf("%d", time.Now().Unix()), 90*time.Second)
			}
		}
	}()

	if s.Cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/health", s.HandleHealth)
			mux.HandleFunc("/health/deep", s.HandleHealthDeep)
			mux.HandleFunc("/metrics/summary", s.HandleMetricsSummary)
			var handler http.Handler = mux
			if s.Cfg.Metrics.RateLimitRPS > 0 {
				limiter := NewMetricsRateLimiter(s.Cfg.Metrics.RateLimitRPS, s.Cfg.Metrics.RateLimitBurst)
				handler = MetricsRateLimitMiddleware(handler, limiter, s.Log)
			}
			handler = MetricsAuthMiddleware(handler, s.Cfg.Metrics.AuthToken)
			bindHost := s.Cfg.Metrics.BindHost
			if bindHost == "" {
				bindHost = "127.0.0.1"
			}
			addr := fmt.Sprintf("%s:%d", bindHost, s.Cfg.Metrics.Port.Int())
			if s.Log != nil {
				s.Log.WithField("addr", addr).Info("proxy: metrics server listening")
			}
			srv := &http.Server{Addr: addr, Handler: handler, ReadTimeout: 10 * time.Second}
			go func() {
				<-ctx.Done()
				if err := srv.Shutdown(context.Background()); err != nil && s.Log != nil {
					s.Log.WithError(err).Warn("metrics server shutdown error")
				}
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed && s.Log != nil {
				s.Log.WithError(err).Warn("metrics server error")
			}
		}()
	}

	addr := fmt.Sprintf("%s:%d", s.Cfg.Proxy.BindHost, s.Cfg.Proxy.BindPort.Int())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if s.Log != nil {
			s.Log.WithError(err).Fatal("failed to listen")
		}
		return
	}
	if s.Log != nil {
		s.Log.WithField("addr", addr).Info("proxy: listening")
	}

	_ = s.ServeListener(ctx, ln)
}

func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if s.Log != nil {
					s.Log.WithError(err).Warn("proxy: accept error")
				}
				continue
			}
		}
		if !s.AdmitConn(conn) {
			continue
		}
		atomic.AddInt64(&s.ActiveConns, 1)
		atomic.AddInt64(&s.activeConns, 1)
		go func() {
			defer func() { <-s.AcceptSem }()
			defer func() {
				if r := recover(); r != nil {
					if s.Log != nil {
						s.Log.WithField("panic", r).Error("handler recovered from panic")
					}
					metrics.HandlerPanicsTotal.Inc()
				}
			}()
			s.HandleConn(ctx, conn)
		}()
	}
}

func (s *Server) AdmitConn(conn net.Conn) bool {
	select {
	case s.AcceptSem <- struct{}{}:
		return true
	default:
		metrics.ConnectionErrorsTotal.WithLabelValues("accept_overflow").Inc()
		if s.Log != nil {
			s.Log.WithField("remote", conn.RemoteAddr().String()).
				Warn("proxy: accept-loop at capacity; dropping connection")
		}
		_ = conn.Close()
		return false
	}
}



func (s *Server) HandleConn(ctx context.Context, clientConn net.Conn) {
	s.Mu.RLock()
	cfg := s.Cfg
	s.Mu.RUnlock()
	metrics.ActiveConnections.Inc()
	defer func() {
		metrics.ActiveConnections.Dec()
		atomic.AddInt64(&s.ActiveConns, -1)
		atomic.AddInt64(&s.activeConns, -1)
		clientConn.Close()
	}()

	bp := BufferPool.Get().(*[]byte)
	buf := *bp
	defer BufferPool.Put(bp)

	_ = clientConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Proxy.ReadTimeout) * time.Second))
	n, err := clientConn.Read(buf)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		if err != nil {
			metrics.ConnectionErrorsTotal.WithLabelValues(ClassifyConnError("client_read", err)).Inc()
		}
		return
	}
	data := buf[:n]

	ipStr, ipNet := RemoteIP(clientConn)
	connCtx := &security.ConnectionContext{
		ClientIP:     ipStr,
		ParsedIP:     ipNet,
		ClientPort:   RemotePort(clientConn),
		ConnectionID: s.NextConnectionID(),
	}

	if cfg.Proxy.ProxyProtocol {
		socketIP, _ := RemoteIP(clientConn)
		trusted := proxypkg.IsTrustedProxySourceCIDRs(socketIP, s.GetTrustedCIDRs())
		stripped := false
		if realIP, ok, hdrLen := proxypkg.ReadProxyProtocolV2WithLength(data); ok {
			if trusted {
				connCtx.ClientIP = realIP
				connCtx.ParsedIP = net.ParseIP(realIP)
			}
			metrics.ProxyProtocolParserEvents.WithLabelValues("spoof_stripped").Inc()
			data = data[hdrLen:]
			stripped = true
		} else if realIP, ok := proxypkg.ReadProxyProtocol(data); ok {
			if trusted {
				connCtx.ClientIP = realIP
				connCtx.ParsedIP = net.ParseIP(realIP)
			}
			metrics.ProxyProtocolParserEvents.WithLabelValues("spoof_stripped").Inc()
			if idx := strings.Index(string(data), "\r\n"); idx != -1 {
				data = data[idx+2:]
			}
			stripped = true
		}

		if stripped {
			if _, ok, _ := proxypkg.ReadProxyProtocolV2WithLength(data); ok {
				metrics.ProxyProtocolParserEvents.WithLabelValues("smuggling_blocked").Inc()
				metrics.ConnectionErrorsTotal.WithLabelValues("proxy_protocol_smuggling").Inc()
				if s.Log != nil {
					s.Log.WithField("remote", socketIP).Warn("proxy: chained PROXY v2 header rejected as smuggling attempt")
				}
				return
			}
			if _, ok := proxypkg.ReadProxyProtocol(data); ok {
				metrics.ProxyProtocolParserEvents.WithLabelValues("smuggling_blocked").Inc()
				metrics.ConnectionErrorsTotal.WithLabelValues("proxy_protocol_smuggling").Inc()
				if s.Log != nil {
					s.Log.WithField("remote", socketIP).Warn("proxy: chained PROXY v1 header rejected as smuggling attempt")
				}
				return
			}
		}
	}

	if len(data) == 0 {
		_ = clientConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Proxy.ReadTimeout) * time.Second))
		n, err := clientConn.Read(buf)
		_ = clientConn.SetReadDeadline(time.Time{})
		if err != nil || n == 0 {
			if err != nil {
				metrics.ConnectionErrorsTotal.WithLabelValues(ClassifyConnError("client_read_post_proxy_hdr", err)).Inc()
			}
			return
		}
		data = buf[:n]
	}

	if cfg.Security.ProtocolLockdownEnabled() && len(data) >= 1 && data[0] != 0x16 {
		metrics.ConnectionErrorsTotal.WithLabelValues("non_tls_dropped").Inc()
		if s.Log != nil {
			s.Log.WithFields(logrus.Fields{
				"client_ip":     connCtx.ClientIP,
				"first_byte":    fmt.Sprintf("0x%02x", data[0]),
				"bytes_sampled": len(data),
			}).Warn("proxy: non-TLS content type on TLS listener; dropping (JA4PROXY-2026-0011)")
		}
		return
	}

	data = s.ReassembleClientHello(clientConn, data, buf)

	if len(data) >= 5 && data[0] == 0x16 {
		helloInfo, parseErr := tlsparse.ParseClientHello(data)
		if parseErr == nil {
			PopulateTLSFingerprints(connCtx, helloInfo)
			if s.GeoIP != nil {
				if record, err := s.GeoIP.Country(connCtx.ParsedIP); err == nil {
					connCtx.Country = record.Country.IsoCode
				}
			}
		}
	}

	result := s.Pipeline.Process(ctx, connCtx)
	if s.Log != nil {
		s.Log.WithFields(logrus.Fields{
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
			"dst_ip":      cfg.Proxy.BackendHost,
			"src_port":    connCtx.ClientPort,
		}).Info("proxy: connection decision")
	}
	s.EmitConnectionEvent(connCtx, result, cfg.Proxy.BackendHost, EventPhaseFinal)

	switch result.Action {
	case "allow", "flag", "rate_limit":
		s.Forward(clientConn, data, connCtx.ClientIP, connCtx.ClientPort)
	case "tarpit":
		s.Tarpit(clientConn, data, connCtx.ClientIP)
	case "block", "ban":
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
	}
}

func (s *Server) Drain(timeoutSeconds int) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&s.ActiveConns) <= 0 && atomic.LoadInt64(&s.activeConns) <= 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	remaining := atomic.LoadInt64(&s.ActiveConns) + atomic.LoadInt64(&s.activeConns)
	if remaining > 0 && s.Log != nil {
		s.Log.WithField("remaining", remaining).Warn("drain timeout expired; forcing shutdown")
	}
}

func (s *Server) Reload() error {
	cfgPath := s.CfgPath
	if cfgPath == "" {
		cfgPath = "config/proxy.yml"
	}
	newCfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	pipelineCfg := BuildPipelineConfig(newCfg)
	if s.Redis != nil && s.Redis.GetString(context.Background(), "attack_mode:escalate") == "1" {
		pipelineCfg.AutoEscalate.Enabled = true
	}
	if s.Redis != nil {
		if raw := s.Redis.GetString(context.Background(), "config:datacenter_policy"); raw != "" {
			var override config.DatacenterPolicyConfig
			if err := json.Unmarshal([]byte(raw), &override); err == nil {
				pipelineCfg.DatacenterPolicy = override
			}
		}
	}
	s.Pipeline.ReplaceConfig(pipelineCfg)
	s.Mu.Lock()
	s.Cfg = newCfg
	s.cfg = newCfg
	s.Mu.Unlock()
	LoadSecurityLists(context.Background(), s.Redis, s.Pipeline)
	metrics.ConfigReloadsTotal.Inc()
	UpdateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), s.Log)
	s.ReloadTrustedCIDRs(context.Background(), newCfg)
	if s.Log != nil {
		s.Log.Info("config reloaded")
	}
	return nil
}

func (s *Server) ReloadTrustedCIDRs(ctx context.Context, cfg *config.Config) {
	sources := cfg.TrustedUpstreamSources
	if !sources.NetBox.Enabled {
		s.SetTrustedCIDRs(sources.StaticCIDRs)
		if s.Log != nil {
			s.Log.Debug("netbox: disabled; using static CIDRs only")
		}
		return
	}

	netboxCIDRs, err := config.LoadTrustedCIDRsFromNetBox(ctx, sources.NetBox.URL, sources.NetBox.Token, sources.NetBox.Tag)
	if err != nil {
		if s.Log != nil {
			s.Log.WithError(err).Warn("netbox: LoadTrustedCIDRsFromNetBox returned error")
		}
		metrics.NetBoxCIDRsLoaded.WithLabelValues("error").Inc()
		s.SetTrustedCIDRs(sources.StaticCIDRs)
		return
	}

	if len(netboxCIDRs) == 0 {
		if s.Log != nil {
			s.Log.Warn("netbox: returned zero CIDRs; using static CIDRs only")
		}
		metrics.NetBoxCIDRsLoaded.WithLabelValues("error").Inc()
		s.SetTrustedCIDRs(sources.StaticCIDRs)
		return
	}

	merged := DedupStrings(append(sources.StaticCIDRs, netboxCIDRs...))
	s.SetTrustedCIDRs(merged)
	metrics.NetBoxCIDRsLoaded.WithLabelValues("ok").Inc()

	if s.Log != nil {
		s.Log.WithFields(logrus.Fields{
			"static": len(sources.StaticCIDRs),
			"netbox": len(netboxCIDRs),
			"total":  len(merged),
		}).Info("netbox: trusted CIDRs reloaded successfully")
	}
}

func (s *Server) SetTrustedCIDRs(cidrs []string) {
	s.TrustedCIDRsMu.Lock()
	defer s.TrustedCIDRsMu.Unlock()
	s.TrustedCIDRs = cidrs
	s.trustedCIDRs = cidrs
}

func (s *Server) GetTrustedCIDRs() []string {
	s.TrustedCIDRsMu.RLock()
	defer s.TrustedCIDRsMu.RUnlock()
	out := make([]string, len(s.TrustedCIDRs))
	copy(out, s.TrustedCIDRs)
	return out
}
