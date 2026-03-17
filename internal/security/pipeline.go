package security

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
)

// RedisReader is the minimal Redis interface used by the pipeline.
// Using an interface makes unit testing straightforward.
type RedisReader interface {
	GetDial(ctx context.Context) int
	SIsMember(ctx context.Context, key string, member interface{}) bool
}

// Pipeline orchestrates the JA4proxy connection decision flow:
//  1. Bypass checks (short-circuit)
//  2. Signal collection
//  3. Composite scoring (RiskScorer)
//  4. Action decision (ActionDecider + dial)
//
// Fail open: any module error is logged; a zero/neutral signal is used instead.
type Pipeline struct {
	cfg     *PipelineConfig
	scorer  *RiskScorer
	decider *ActionDecider
	redis   RedisReader
	log     *logrus.Logger
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
}

// NewPipeline creates a Pipeline ready to process connections.
func NewPipeline(cfg *PipelineConfig, redis RedisReader, log *logrus.Logger) *Pipeline {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &PipelineConfig{}
	}
	return &Pipeline{
		cfg:     cfg,
		scorer:  NewRiskScorer(cfg.Thresholds),
		decider: NewActionDecider(cfg.Thresholds),
		redis:   redis,
		log:     log,
	}
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
	// Signal modules are stubs in Phase 15; the architecture is wired here
	// so that future phases can add signals without touching the pipeline.
	var signals []RiskSignal // populated by signal modules below (future phases)

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
