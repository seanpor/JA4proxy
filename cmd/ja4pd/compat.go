// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/health"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/seanpor/ja4proxy/internal/security"
	"github.com/seanpor/ja4proxy/internal/server"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
)

type proxy struct {
	*server.Server
	cfg              *config.Config
	cfgPath          string
	log              *logrus.Logger
	pipeline         *security.Pipeline
	redis            *redisclient.Client
	activeConns      int64
	acceptSem        chan struct{}
	tarpitConcurrent int
	tarpitPerIP      map[string]int
	tarpitMu         sync.Mutex
	trustedCIDRs     []string
	trustedCIDRsMu   sync.RWMutex
	healthState      *health.State
	streamEventQueue chan []byte
	streamHMACSecret string
	mu               sync.RWMutex
}

func newProxy(cfg *config.Config, cfgPath string, log *logrus.Logger) (*proxy, error) {
	srv, err := server.NewWithConfigPath(cfg, cfgPath, log)
	if err != nil {
		return nil, err
	}
	p := &proxy{
		Server:           srv,
		cfg:              srv.Cfg,
		cfgPath:          srv.CfgPath,
		log:              srv.Log,
		pipeline:         srv.Pipeline,
		redis:            srv.Redis,
		acceptSem:        srv.AcceptSem,
		tarpitConcurrent: srv.TarpitConcurrent,
		tarpitPerIP:      srv.TarpitPerIP,
		trustedCIDRs:     srv.TrustedCIDRs,
	}
	return p, nil
}

func (p *proxy) syncServerConfig() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Server == nil {
		p.Server = &server.Server{
			Cfg:              p.cfg,
			CfgPath:          p.cfgPath,
			Log:              p.log,
			Pipeline:         p.pipeline,
			Redis:            p.redis,
			AcceptSem:        p.acceptSem,
			TrustedCIDRs:     p.trustedCIDRs,
			StreamEventQueue: p.streamEventQueue,
			StreamHMACSecret: p.streamHMACSecret,
			ActiveConns:      atomic.LoadInt64(&p.activeConns),
		}
	} else {
		if p.cfg != nil {
			p.Cfg = p.cfg
		}
		if p.log != nil {
			p.Log = p.log
		}
		if p.pipeline != nil {
			p.Pipeline = p.pipeline
		}
		if p.redis != nil {
			p.Redis = p.redis
		}
		if p.acceptSem != nil {
			p.AcceptSem = p.acceptSem
		}
		if p.cfgPath != "" {
			p.CfgPath = p.cfgPath
		}
		if p.streamEventQueue != nil {
			p.StreamEventQueue = p.streamEventQueue
		}
		if p.streamHMACSecret != "" {
			p.StreamHMACSecret = p.streamHMACSecret
		}
		if atomic.LoadInt64(&p.activeConns) > 0 {
			atomic.StoreInt64(&p.ActiveConns, atomic.LoadInt64(&p.activeConns))
		}
	}
}

func (p *proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	p.syncServerConfig()
	p.HandleConn(ctx, clientConn)
}

func (p *proxy) admitConn(conn net.Conn) bool {
	p.syncServerConfig()
	return p.AdmitConn(conn)
}

func (p *proxy) forward(clientConn net.Conn, initialData []byte, srcIP string, srcPort int) {
	p.syncServerConfig()
	p.Forward(clientConn, initialData, srcIP, srcPort)
}

func (p *proxy) tarpit(clientConn net.Conn, data []byte, clientIP string) {
	p.syncServerConfig()
	p.Tarpit(clientConn, data, clientIP)
}

func (p *proxy) drain(timeoutSeconds int) {
	if p == nil {
		return
	}
	p.syncServerConfig()
	if p.Server != nil {
		deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
		for time.Now().Before(deadline) {
			conns := atomic.LoadInt64(&p.activeConns)
			atomic.StoreInt64(&p.ActiveConns, conns)
			if conns <= 0 && atomic.LoadInt64(&p.ActiveConns) <= 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		p.Drain(timeoutSeconds)
		atomic.StoreInt64(&p.activeConns, atomic.LoadInt64(&p.ActiveConns))
	}
}

func (p *proxy) reload() error {
	p.syncServerConfig()
	err := p.Reload()
	if err == nil {
		p.cfg = p.Cfg
	}
	return err
}

func (p *proxy) serve(ctx context.Context) {
	p.syncServerConfig()
	p.Serve(ctx)
}

func (p *proxy) setTrustedCIDRs(cidrs []string) {
	if p.Server != nil {
		p.SetTrustedCIDRs(cidrs)
	}
	p.trustedCIDRsMu.Lock()
	defer p.trustedCIDRsMu.Unlock()
	p.trustedCIDRs = cidrs
}

func (p *proxy) getTrustedCIDRs() []string {
	if p.Server != nil {
		return p.GetTrustedCIDRs()
	}
	p.trustedCIDRsMu.RLock()
	defer p.trustedCIDRsMu.RUnlock()
	out := make([]string, len(p.trustedCIDRs))
	copy(out, p.trustedCIDRs)
	return out
}

func (p *proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	p.syncServerConfig()
	p.HandleHealth(w, r)
}

func (p *proxy) handleHealthDeep(w http.ResponseWriter, r *http.Request) {
	p.syncServerConfig()
	p.HandleHealthDeep(w, r)
}

func (p *proxy) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	p.syncServerConfig()
	p.HandleMetricsSummary(w, r)
}

func (p *proxy) reloadTrustedCIDRs(ctx context.Context, cfg *config.Config) {
	p.syncServerConfig()
	p.ReloadTrustedCIDRs(ctx, cfg)
}

func buildPipelineConfig(cfg *config.Config) *security.PipelineConfig {
	return server.BuildPipelineConfig(cfg)
}

func loadSecurityLists(ctx context.Context, rc *redisclient.Client, p *security.Pipeline) {
	server.LoadSecurityLists(ctx, rc, p)
}

func remoteIP(conn net.Conn) (string, net.IP) {
	return server.RemoteIP(conn)
}

func remotePort(conn net.Conn) int {
	return server.RemotePort(conn)
}

func updateTLSCertExpiryGauge(certPath string, log *logrus.Logger) {
	server.UpdateTLSCertExpiryGauge(certPath, log)
}

func metricsAuthMiddleware(next http.Handler, token string) http.Handler {
	return server.MetricsAuthMiddleware(next, token)
}

func (p *proxy) enqueueStreamEvent(event []byte) {
	if p == nil {
		return
	}
	p.syncServerConfig()
	if p.Server != nil {
		if p.streamEventQueue != nil {
			p.StreamEventQueue = p.streamEventQueue
		}
		p.EnqueueStreamEvent(event)
	}
}

func (p *proxy) streamEventWorker(ctx context.Context, streamKey string, timeout time.Duration) {
	if p == nil {
		return
	}
	p.syncServerConfig()
	if p.Server != nil {
		p.StreamEventWorker(ctx, streamKey, timeout)
	}
}

func stringSliceToSet(ss []string) map[string]bool {
	return server.StringSliceToSet(ss)
}

func dedupStrings(ss []string) []string {
	return server.DedupStrings(ss)
}

func buildStaticAllowlist(ips []config.StaticIPConfigYAML) map[string]bool {
	return server.BuildStaticAllowlist(ips)
}

func buildBlocklistFeeds(feeds []config.BlocklistFeedConfigYAML) []security.BlocklistFeedConfig {
	return server.BuildBlocklistFeeds(feeds)
}

func newLogger(cfg *config.Config) *logrus.Logger {
	return server.NewLogger(cfg)
}

func (p *proxy) reassembleClientHello(clientConn net.Conn, data, buf []byte) []byte {
	p.syncServerConfig()
	if p.Server != nil {
		return p.ReassembleClientHello(clientConn, data, buf)
	}
	return data
}

func (p *proxy) startStreamEventWorkers(ctx context.Context) {
	p.syncServerConfig()
	if p.Server != nil {
		p.StartStreamEventWorkers(ctx)
	}
}

func (p *proxy) startIntegrityWorker(ctx context.Context) {
	p.syncServerConfig()
	if p.Server != nil {
		p.StartIntegrityWorker(ctx)
	}
}

func seedSecurityLists(ctx context.Context, rc *redisclient.Client, cfg *config.Config) {
	server.SeedSecurityLists(ctx, rc, cfg)
}

func populateTLSFingerprints(connCtx *security.ConnectionContext, hello *tlsparse.ClientHelloInfo) {
	server.PopulateTLSFingerprints(connCtx, hello)
}

func checkAndLogRedisACL(cfg *config.Config, log *logrus.Logger) {
	server.CheckAndLogRedisACL(cfg, log)
}

func classifyConnError(source string, err error) string {
	return server.ClassifyConnError(source, err)
}
