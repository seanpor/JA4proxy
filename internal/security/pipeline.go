package security

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
)

// RedisReader is the Redis interface used by the pipeline and signal modules.
// Using an interface makes unit testing straightforward.
type RedisReader interface {
	GetDial(ctx context.Context) int
	SIsMember(ctx context.Context, key string, member interface{}) bool
	SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int
	HGetAll(ctx context.Context, key string) map[string]string
	GetString(ctx context.Context, key string) string
}

// Pipeline orchestrates the JA4proxy connection decision flow:
//  1. Bypass checks (short-circuit)
//  2. Signal collection
//  3. Composite scoring (RiskScorer)
//  4. Action decision (ActionDecider + dial)
//
// Fail open: any module error is logged; a zero/neutral signal is used instead.
type Pipeline struct {
	cfg         *PipelineConfig
	scorer      *RiskScorer
	decider     *ActionDecider
	redis       RedisReader
	log         *logrus.Logger
	tlsEnforcer *TLSEnforcer
	sniAnalyzer *SNIAnalyzer
}

// PipelineConfig holds the pipeline's toggleable bypass flags and list sets.
type PipelineConfig struct {
	// Bypass toggles (from security_policy in proxy.yml)
	ALPNBrowserBypass      bool
	JA4WhitelistBypass     bool
	JA4BlacklistBypass     bool
	MTLSBypass             bool
	CountryBlacklistBypass bool

	// JA4 lists (from security.whitelist / security.blacklist)
	Whitelist      map[string]bool
	WhitelistSuffs []string // pattern suffixes for ALPN-based bypass
	Blacklist      map[string]bool

	// Scoring thresholds (from risk_scorer.thresholds)
	Thresholds map[string]int

	// TLS enforcement (Group 2)
	TLSVersionBypassEnabled bool
	BlockTLS10              bool
	BlockTLS11              bool
	FlagTLS12               bool
	BlockWeakCiphers        bool

	// SNI analysis (Group 2)
	MissingSNIEnabled    bool
	MissingSNIScore      int
	IPLiteralSNIEnabled  bool
	IPLiteralSNIScore    int
	DGAEnabled           bool
	DGAScoreCap          int
	UnexpectedSNIEnabled bool
	UnexpectedSNIScore   int
	ExpectedHostnames    map[string]bool
}

// NewPipeline creates a Pipeline ready to process connections.
func NewPipeline(cfg *PipelineConfig, redis RedisReader, log *logrus.Logger) *Pipeline {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &PipelineConfig{}
	}
	p := &Pipeline{
		cfg:     cfg,
		scorer:  NewRiskScorer(cfg.Thresholds),
		decider: NewActionDecider(cfg.Thresholds),
		redis:   redis,
		log:     log,
	}
	p.tlsEnforcer = NewTLSEnforcer(buildTLSEnforcerConfig(cfg), log)
	p.sniAnalyzer = NewSNIAnalyzer(buildSNIAnalyzerConfig(cfg), log)
	return p
}

// Process runs a connection through the full pipeline and returns the result.
// It never panics; all module errors are caught and logged.
func (p *Pipeline) Process(ctx context.Context, conn *ConnectionContext) *PipelineResult {
	// ── 1. BYPASS CHECKS ──────────────────────────────────────────────────
	if bypass, reason := p.checkBypasses(conn); bypass {
		p.log.WithFields(logrus.Fields{
			"ip":     conn.ClientIP,
			"ja4":    conn.JA4,
			"bypass": reason,
		}).Debug("pipeline: bypass")
		return &PipelineResult{
			Action:       "allow",
			Bypassed:     true,
			BypassReason: reason,
		}
	}

	// Check hard-blocks before scoring
	if block, reason := p.checkHardBlocks(conn); block {
		p.log.WithFields(logrus.Fields{
			"ip":     conn.ClientIP,
			"ja4":    conn.JA4,
			"reason": reason,
		}).Debug("pipeline: hard block")
		return &PipelineResult{
			Action:       "block",
			Bypassed:     false,
			BypassReason: reason,
			Score:        100,
		}
	}

	// ── 2. DIAL (fetch once — cheap Redis GET) ────────────────────────────
	dial := 0
	if p.redis != nil {
		dial = p.redis.GetDial(ctx)
	}

	// ── 3. SIGNAL COLLECTION ─────────────────────────────────────────────
	var signals []RiskSignal

	// TLS enforcement (hard block check first)
	if tlsSigs, hardBlock := p.tlsEnforcer.Check(uint16(conn.TLSVersion), uint16s(conn.CipherList)); hardBlock {
		return &PipelineResult{Action: "block", Score: 100, BypassReason: "tls_enforcement"}
	} else {
		signals = append(signals, tlsSigs...)
	}

	// SNI analysis
	signals = append(signals, p.sniAnalyzer.Analyze(conn.SNI)...)

	// ── 4. COMPOSITE SCORING ─────────────────────────────────────────────
	assessment := p.scorer.Score(signals)

	// ── 5. ACTION DECISION ───────────────────────────────────────────────
	action := p.decider.Decide(assessment.TotalScore, dial)

	// Build counterfactuals for monitor-mode logging
	var counterfactuals map[int]string
	if dial == 0 {
		counterfactuals = p.decider.Counterfactuals(assessment.TotalScore, []int{25, 50, 75, 100})
	}

	p.log.WithFields(logrus.Fields{
		"ip":     conn.ClientIP,
		"ja4":    conn.JA4,
		"score":  assessment.TotalScore,
		"dial":   dial,
		"action": action,
	}).Debug("pipeline: decision")

	return &PipelineResult{
		Action:          action,
		Score:           assessment.TotalScore,
		Signals:         assessment.Signals,
		Dial:            dial,
		Counterfactuals: counterfactuals,
	}
}

// checkBypasses returns (true, reason) if the connection matches an ALLOW bypass.
func (p *Pipeline) checkBypasses(conn *ConnectionContext) (bool, string) {
	// ALPN browser bypass: h2 or h1 → always allow
	if p.cfg.ALPNBrowserBypass && (conn.ALPN == "h2" || conn.ALPN == "h1") {
		return true, "alpn_browser"
	}

	// JA4 whitelist bypass
	if p.cfg.JA4WhitelistBypass && conn.JA4 != "" {
		if p.cfg.Whitelist[conn.JA4] {
			return true, "ja4_whitelist"
		}
		// Pattern match: whitelist_patterns are ALPN suffix patterns
		for _, pat := range p.cfg.WhitelistSuffs {
			if strings.HasSuffix(conn.JA4, pat) || strings.Contains(conn.JA4, pat) {
				return true, "ja4_whitelist_pattern"
			}
		}
	}

	// mTLS bypass: valid client cert
	if p.cfg.MTLSBypass && conn.HasValidClientCert {
		return true, "mtls"
	}

	return false, ""
}

// checkHardBlocks returns (true, reason) if the connection must be blocked immediately.
func (p *Pipeline) checkHardBlocks(conn *ConnectionContext) (bool, string) {
	// JA4 blacklist
	if p.cfg.JA4BlacklistBypass && conn.JA4 != "" && p.cfg.Blacklist[conn.JA4] {
		return true, "ja4_blacklist"
	}

	return false, ""
}

// buildTLSEnforcerConfig creates a TLSEnforcerConfig from the pipeline config.
func buildTLSEnforcerConfig(cfg *PipelineConfig) *TLSEnforcerConfig {
	return &TLSEnforcerConfig{
		TLSVersionBypassEnabled: cfg.TLSVersionBypassEnabled,
		BlockTLS10:              cfg.BlockTLS10,
		BlockTLS11:              cfg.BlockTLS11,
		FlagTLS12:               cfg.FlagTLS12,
		BlockWeakCiphers:        cfg.BlockWeakCiphers,
	}
}

// buildSNIAnalyzerConfig creates an SNIAnalyzerConfig from the pipeline config.
func buildSNIAnalyzerConfig(cfg *PipelineConfig) *SNIAnalyzerConfig {
	return &SNIAnalyzerConfig{
		MissingSNIEnabled:    cfg.MissingSNIEnabled,
		MissingSNIScore:      defaultInt(cfg.MissingSNIScore, 30),
		IPLiteralSNIEnabled:  cfg.IPLiteralSNIEnabled,
		IPLiteralSNIScore:    defaultInt(cfg.IPLiteralSNIScore, 25),
		DGAEnabled:           cfg.DGAEnabled,
		DGAScoreCap:          defaultInt(cfg.DGAScoreCap, 40),
		UnexpectedSNIEnabled: cfg.UnexpectedSNIEnabled,
		UnexpectedSNIScore:   defaultInt(cfg.UnexpectedSNIScore, 15),
		ExpectedHostnames:    cfg.ExpectedHostnames,
	}
}

// defaultInt returns v if non-zero, otherwise def.
func defaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// uint16s converts []int to []uint16. CipherList in ConnectionContext is []int.
func uint16s(in []int) []uint16 {
	out := make([]uint16, len(in))
	for i, v := range in {
		out[i] = uint16(v)
	}
	return out
}
