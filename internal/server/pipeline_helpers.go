package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	jalogger "github.com/seanpor/ja4proxy/internal/logging"
	"github.com/seanpor/ja4proxy/internal/metrics"
	redisclient "github.com/seanpor/ja4proxy/internal/redis"
	"github.com/seanpor/ja4proxy/internal/security"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
)

func NewLogger(cfg *config.Config) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	useJSON := cfg.Logging.JSONEnabled || os.Getenv("ENVIRONMENT") == "production"
	if useJSON || cfg.Logging.Format == "ecs" {
		log.SetFormatter(jalogger.NewECSLogrusFormatter(cfg.Logging.Format))
	}
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
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
	return log
}

func BuildPipelineConfig(cfg *config.Config) *security.PipelineConfig {
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
	expectedHostnames := StringSliceToSet(cfg.SNIAnalyzer.ExpectedHostnames)
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

		TCPAnalyzerEnabled:                   cfg.TCPAnalyzer.Enabled,
		TCPAnalyzerSessionResumptionEnabled: cfg.TCPAnalyzer.SessionResumptionEnabled,
		TCPAnalyzerMinConnectionsForSession: cfg.TCPAnalyzer.MinConnectionsForSessionCheck,
		TCPAnalyzerShortLifespanEnabled:     cfg.TCPAnalyzer.ShortLifespanEnabled,
		TCPAnalyzerShortLifespanThresholdMS: cfg.TCPAnalyzer.ShortLifespanThresholdMS,
		TCPAnalyzerConcurrencyEnabled:       cfg.TCPAnalyzer.ConcurrencyEnabled,
		TCPAnalyzerConcurrencyModerate:      cfg.TCPAnalyzer.ConcurrencyModerate,
		TCPAnalyzerConcurrencyHigh:          cfg.TCPAnalyzer.ConcurrencyHigh,
		TCPAnalyzerConcurrencySevere:        cfg.TCPAnalyzer.ConcurrencySevere,
		TCPAnalyzerReturnVisitorEnabled:     cfg.TCPAnalyzer.ReturnVisitorEnabled,
		TCPAnalyzerReturnVisitorMinDays:     cfg.TCPAnalyzer.ReturnVisitorMinDays,
	}
}

func SeedSecurityLists(ctx context.Context, rc *redisclient.Client, cfg *config.Config) {
	if rc == nil {
		return
	}
	for _, fp := range cfg.Security.Whitelist {
		rc.SAdd(ctx, "ja4:whitelist", fp)
	}
	for _, fp := range cfg.Security.Blacklist {
		rc.SAdd(ctx, "ja4:blacklist", fp)
	}
	for _, cidr := range cfg.GeoIP.CountryBlacklist {
		if strings.Contains(cidr, "/") || strings.Contains(cidr, ".") || strings.Contains(cidr, ":") {
			rc.SAdd(ctx, "geoip:blocked_cidrs", cidr)
		}
	}
}

func LoadSecurityLists(ctx context.Context, rc *redisclient.Client, p *security.Pipeline) {
	if rc == nil || p == nil {
		return
	}
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

func CheckAndLogRedisACL(cfg *config.Config, log *logrus.Logger) {
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

func ClassifyConnError(source string, err error) string {
	if err == nil {
		return "unknown"
	}
	s := strings.ToLower(err.Error())

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

func UpdateTLSCertExpiryGauge(certPath string, log *logrus.Logger) {
	if certPath == "" {
		return
	}
	pemBytes, err := os.ReadFile(certPath) // #nosec
	if err != nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
		if log != nil {
			log.WithError(err).WithField("path", certPath).Warn("phase-63: failed to read TLS cert for expiry gauge")
		}
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
		if log != nil {
			log.WithField("path", certPath).Warn("phase-63: TLS cert PEM decode failed")
		}
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		metrics.TLSCertExpiryTimestampSeconds.Set(0)
		if log != nil {
			log.WithError(err).WithField("path", certPath).Warn("phase-63: x509 parse failed")
		}
		return
	}
	metrics.TLSCertExpiryTimestampSeconds.Set(float64(cert.NotAfter.Unix()))
	if log != nil {
		log.WithFields(logrus.Fields{
			"path":      certPath,
			"not_after": cert.NotAfter.Format(time.RFC3339),
		}).Info("phase-63: TLS cert expiry gauge updated")
	}
}

func StringSliceToSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func DedupStrings(ss []string) []string {
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

func RemoteIP(conn net.Conn) (string, net.IP) {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String(), addr.IP
	}
	s := conn.RemoteAddr().String()
	return s, net.ParseIP(s)
}

func RemotePort(conn net.Conn) int {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

func PopulateTLSFingerprints(connCtx *security.ConnectionContext, hello *tlsparse.ClientHelloInfo) {
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

func BuildBlocklistFeeds(feeds []config.BlocklistFeedConfigYAML) []security.BlocklistFeedConfig {
	out := make([]security.BlocklistFeedConfig, len(feeds))
	for i, f := range feeds {
		path := f.Path
		if path == "" && f.Name != "" {
			path = "data/feeds/" + f.Name + ".txt"
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

func BuildStaticAllowlist(ips []config.StaticIPConfigYAML) map[string]bool {
	out := make(map[string]bool, len(ips))
	for _, entry := range ips {
		out[entry.IP] = true
	}
	return out
}

