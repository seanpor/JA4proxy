package security

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/metrics"
	ja4tls "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// RedisReader is the Redis interface used by the pipeline and signal modules.
// Using an interface makes unit testing straightforward.
type RedisReader interface {
	GetDial(ctx context.Context) int
	SIsMember(ctx context.Context, key string, member interface{}) bool
	SlidingWindowCount(ctx context.Context, key string, window float64, ttl int) int
	HGetAll(ctx context.Context, key string) map[string]string
	GetString(ctx context.Context, key string) string
	SetString(ctx context.Context, key, value string, ttlSeconds int)
	Exists(ctx context.Context, key string) bool
	Ping(ctx context.Context) error
	ZAdd(ctx context.Context, key string, score float64, member string)
	ZRemRangeByScore(ctx context.Context, key string, min, max float64)
	ZRange(ctx context.Context, key string, start, stop int64) []string
	ZCard(ctx context.Context, key string) int64
	ZRangeScores(ctx context.Context, key string, start, stop int64) []float64
	// phase-248: offense counter needs these atomic operations.
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	CountKeys(ctx context.Context, pattern string) int
}

// Pipeline orchestrates the JA4proxy connection decision flow:
//  1. Bypass checks (short-circuit)
//  2. Signal collection
//  3. Composite scoring (RiskScorer)
//  4. Action decision (ActionDecider + dial)
//
// Fail open: any module error is logged; a zero/neutral signal is used instead.
// beaconingJob is a unit of work for the bounded beaconing worker.
type beaconingJob struct {
	ctx    context.Context
	conn   *ConnectionContext
	action string
}

type auditJob struct {
	ctx          context.Context
	ip           string
	currentScore int
}

const (
	beaconingJobBuf = 256
	auditJobBuf     = 256
)

type Pipeline struct {
	cfg            *PipelineConfig
	cache          *DecisionCache
	workChan       chan *ConnectionContext
	Sync           bool
	scorer         *RiskScorer
	decider        *ActionDecider
	redis          RedisReader
	log            *logrus.Logger
	tlsEnforcer    *TLSEnforcer
	sniAnalyzer    *SNIAnalyzer
	rateLimiter    *RateLimiter
	tcpAnalyzer    *TCPAnalyzer
	asnClassifier  *ASNClassifier
	dnsEnrichment  *DNSEnrichment
	blocklists     *BlocklistManager
	feedDownloader *FeedDownloader
	beaconing      *BeaconingDetector
	abuseipdb      *AbuseIPDB
	rdap           *RDAPEnricher
	tapConsumer    *TapConsumer    // phase-203a
	ja4tConsumer   *JA4TConsumer   // phase-316c
	offenseCounter *OffenseCounter // phase-248

	// Bounded beaconing worker (F-002)
	beaconingJobs chan beaconingJob

	// Bounded audit worker — prevents unbounded goroutine growth on slow Redis
	auditJobs chan auditJob

	// JA4 lists (dynamic, synchronized with Redis)
	Whitelist   map[string]bool
	Blacklist   map[string]bool
	dynamicCIDR cidranger.Ranger

	// JA4X lists (dynamic, synchronized with Redis)
	JA4XWhitelist map[string]bool
	JA4XBlacklist map[string]bool

	mu sync.RWMutex
}

// PipelineConfig holds the pipeline's toggleable bypass flags and list sets.
type PipelineConfig struct {
	// Bypass toggles (from security_policy in proxy.yml)
	ALPNBrowserBypass      bool
	JA4WhitelistBypass     bool
	JA4BlockingEnabled     bool
	MTLSBypass             bool
	CountryBlockingEnabled bool

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
	MaliciousSNIEnabled  bool
	UnexpectedSNIScore   int
	MaliciousSNIScore    int
	ExpectedHostnames    map[string]bool

	// Rate limiter (Group 3)
	RateLimiterEnabled bool
	RateLimiterByIP    StrategyConfig
	RateLimiterByJA4   StrategyConfig
	RateLimiterByIPJA4 StrategyConfig

	// TCP analyzer (Group 3)
	TCPAnalyzerEnabled                   bool
	TCPAnalyzerSessionResumptionEnabled  bool
	TCPAnalyzerMinConnectionsForSession  int
	TCPAnalyzerShortLifespanEnabled      bool
	TCPAnalyzerShortLifespanThresholdMS  int
	TCPAnalyzerConcurrencyEnabled        bool
	TCPAnalyzerConcurrencyModerate       int
	TCPAnalyzerConcurrencyHigh           int
	TCPAnalyzerConcurrencySevere         int
	TCPAnalyzerReturnVisitorEnabled      bool
	TCPAnalyzerReturnVisitorMinDays      int
	TCPAnalyzerReturnVisitorMinAllowRate float64

	// ASN classifier (Group 4)
	ASNClassifierEnabled            bool
	ASNDBPath                       string
	TorExitListPath                 string
	ASNClassifierDatacenterListPath string
	DatacenterScore                 int
	TorScore                        int
	VPNScore                        int
	UnknownScore                    int
	DatacenterASNs                  map[uint]bool
	DatacenterOrgs                  []string

	// DNS enrichment (Group 4)
	DNSEnrichmentEnabled bool
	DNSEnrichmentWorkers int
	DNSNoPTRScore        int
	DNSFCrDNSFailedScore int
	DNSResidentialScore  int
	DNSTTL               int

	// Blocklists (Group 4)
	BlocklistFeeds []BlocklistFeedConfig

	// Beaconing detector (Group 5)
	BeaconingEnabled         bool
	BeaconingScoreCap        int
	BeaconingMinObservations int
	BeaconingShortWindowSec  float64
	BeaconingLongWindowSec   float64

	// AbuseIPDB (Group 5)
	AbuseIPDBEnabled           bool
	AbuseIPDBAPIKey            string
	AbuseIPDBScoreCap          int
	AbuseIPDBSharedIPThreshold int
	AbuseIPDBLocalCacheSize    int
	AbuseIPDBWorkers           int
	AbuseIPDBAPIURL            string

	// RDAP enrichment (Group 5)
	RDAPEnabled               bool
	RDAPMinTriggerScore       int
	RDAPNewNetblockMaxAgeDays int
	RDAPNewNetblockScore      int
	RDAPKnownBadOrgScore      int
	RDAPRequireKnownBadOrg    bool
	RDAPBlockExpansionEnabled bool
	RDAPKnownBadOrgsPath      string

	// Static IP allowlist (Group 6)
	StaticIPAllowlistEnabled bool
	StaticIPAllowlist        map[string]bool

	// Country blacklist (Group 6)
	CountryBlacklist map[string]bool

	// JA4X configuration (Group 6)
	JA4XEnabled         bool
	JA4XWhitelistBypass bool
	JA4XBlockingEnabled bool
	JA4XBlacklistScore  int

	// Phase 203a — TAP-consumed JA4T OS mismatch signal.
	TapConsumerEnabled      bool
	TapConsumerScore        int
	TapConsumerRedisTimeout int // milliseconds
	TapConsumerCacheTTL     int // seconds
	TapConsumerMaxAge       int // seconds

	// Phase 316c — TAP-consumed JA4T blocklist signal.
	JA4TConsumerEnabled      bool
	JA4TConsumerScore        int
	JA4TConsumerRedisTimeout int      // milliseconds
	JA4TConsumerCacheTTL     int      // seconds
	JA4TBlocklist            []string // JA4T fingerprints that raise the signal

	// Phase 248 — Auto-escalating IP defense.
	AutoEscalate config.AutoEscalateConfig
	// Phase 249 — Datacenter ASN policy.
	DatacenterPolicy config.DatacenterPolicyConfig
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
		cfg:       cfg,
		scorer:    NewRiskScorer(cfg.Thresholds),
		decider:   NewActionDecider(cfg.Thresholds),
		redis:     redis,
		log:       log,
		Whitelist: cfg.Whitelist,
		Blacklist: cfg.Blacklist,
		cache:     NewDecisionCache(10000),
		// phase-306 (from PR #95): deeper async-scoring queue so accept bursts
		// are absorbed rather than dropped/blocked. Drained by a fixed pool of
		// scoring workers (see StartBackgroundWorkers).
		workChan: make(chan *ConnectionContext, 20000),
	}
	p.tlsEnforcer = NewTLSEnforcer(buildTLSEnforcerConfig(cfg), log)
	p.sniAnalyzer = NewSNIAnalyzer(buildSNIAnalyzerConfig(cfg), log)
	p.rateLimiter = NewRateLimiter(buildRateLimiterConfig(cfg), redis, log)
	p.tcpAnalyzer = NewTCPAnalyzer(buildTCPAnalyzerConfig(cfg), redis, log)
	p.asnClassifier = NewASNClassifier(buildASNClassifierConfig(cfg), log)
	p.dnsEnrichment = NewDNSEnrichment(buildDNSEnrichmentConfig(cfg), redis, log)
	p.blocklists = NewBlocklistManager(buildBlocklistConfig(cfg), log)
	p.feedDownloader = NewFeedDownloader(cfg.BlocklistFeeds, p.blocklists, log)
	p.beaconing = NewBeaconingDetector(buildBeaconingConfig(cfg), redis, log)
	p.abuseipdb = NewAbuseIPDB(buildAbuseIPDBConfig(cfg), redis, log)
	p.rdap = NewRDAPEnricher(buildRDAPConfig(cfg), redis, log)
	p.tapConsumer = NewTapConsumer(buildTapConsumerConfig(cfg), redisReaderGetter{redis}, log)    // phase-203a
	p.ja4tConsumer = NewJA4TConsumer(buildJA4TConsumerConfig(cfg), redisReaderGetter{redis}, log) // phase-316c
	if cfg.AutoEscalate.Enabled {
		p.offenseCounter = NewOffenseCounter(redis, &cfg.AutoEscalate, log)
	}
	p.beaconingJobs = make(chan beaconingJob, beaconingJobBuf)
	p.auditJobs = make(chan auditJob, auditJobBuf)
	go p.beaconingWorker()
	go p.auditWorker()
	return p
}

func (p *Pipeline) ReplaceConfig(cfg *PipelineConfig) {
	if cfg == nil {
		cfg = &PipelineConfig{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	p.Whitelist = cfg.Whitelist
	p.Blacklist = cfg.Blacklist
	p.scorer = NewRiskScorer(cfg.Thresholds)
	p.decider = NewActionDecider(cfg.Thresholds)
	p.tlsEnforcer = NewTLSEnforcer(buildTLSEnforcerConfig(cfg), p.log)
	p.sniAnalyzer = NewSNIAnalyzer(buildSNIAnalyzerConfig(cfg), p.log)
	p.rateLimiter = NewRateLimiter(buildRateLimiterConfig(cfg), p.redis, p.log)
	p.tcpAnalyzer = NewTCPAnalyzer(buildTCPAnalyzerConfig(cfg), p.redis, p.log)
	p.asnClassifier = NewASNClassifier(buildASNClassifierConfig(cfg), p.log)
	p.dnsEnrichment = NewDNSEnrichment(buildDNSEnrichmentConfig(cfg), p.redis, p.log)
	p.blocklists = NewBlocklistManager(buildBlocklistConfig(cfg), p.log)
	p.feedDownloader = NewFeedDownloader(cfg.BlocklistFeeds, p.blocklists, p.log)
	p.beaconing = NewBeaconingDetector(buildBeaconingConfig(cfg), p.redis, p.log)
	p.abuseipdb = NewAbuseIPDB(buildAbuseIPDBConfig(cfg), p.redis, p.log)
	p.rdap = NewRDAPEnricher(buildRDAPConfig(cfg), p.redis, p.log)
	p.tapConsumer = NewTapConsumer(buildTapConsumerConfig(cfg), redisReaderGetter{p.redis}, p.log)
	p.ja4tConsumer = NewJA4TConsumer(buildJA4TConsumerConfig(cfg), redisReaderGetter{p.redis}, p.log)
	if cfg.AutoEscalate.Enabled {
		p.offenseCounter = NewOffenseCounter(p.redis, &cfg.AutoEscalate, p.log)
	} else {
		p.offenseCounter = nil
	}
}

// redisReaderGetter adapts RedisReader (which uses GetString) to the narrow
// redisGetter interface expected by TapConsumer. Fail-open: GetString's
// underlying implementation already swallows errors.
type redisReaderGetter struct{ r RedisReader }

func (g redisReaderGetter) Get(ctx context.Context, key string) (string, error) {
	if g.r == nil {
		return "", nil
	}
	return g.r.GetString(ctx, key), nil
}

// buildTapConsumerConfig builds a TapConsumerConfig from the pipeline config.
func buildTapConsumerConfig(cfg *PipelineConfig) *TapConsumerConfig {
	return &TapConsumerConfig{
		Enabled:      cfg.TapConsumerEnabled,
		SignalScore:  cfg.TapConsumerScore,
		RedisTimeout: durationMillis(cfg.TapConsumerRedisTimeout, 50),
		CacheTTL:     durationSeconds(cfg.TapConsumerCacheTTL, 60),
		MaxAge:       durationSeconds(cfg.TapConsumerMaxAge, 300),
	}
}

// buildJA4TConsumerConfig builds a JA4TConsumerConfig from the pipeline config.
// The blocklist slice is materialised into a set for O(1) lookups on the hot path.
func buildJA4TConsumerConfig(cfg *PipelineConfig) *JA4TConsumerConfig {
	blocklist := make(map[string]bool, len(cfg.JA4TBlocklist))
	for _, j := range cfg.JA4TBlocklist {
		if j != "" {
			blocklist[j] = true
		}
	}
	return &JA4TConsumerConfig{
		Enabled:      cfg.JA4TConsumerEnabled,
		SignalScore:  cfg.JA4TConsumerScore,
		RedisTimeout: durationMillis(cfg.JA4TConsumerRedisTimeout, 50),
		CacheTTL:     durationSeconds(cfg.JA4TConsumerCacheTTL, 60),
		Blocklist:    blocklist,
	}
}

func durationMillis(ms, def int) time.Duration {
	if ms <= 0 {
		ms = def
	}
	return time.Duration(ms) * time.Millisecond
}

func durationSeconds(s, def int) time.Duration {
	if s <= 0 {
		s = def
	}
	return time.Duration(s) * time.Second
}

// beaconingWorker processes beaconing jobs from the bounded channel (F-002).
// Runs in a single goroutine — the channel buffer absorbs bursts and
// non-blocking sends prevent the pipeline from blocking on a saturated worker.
func (p *Pipeline) beaconingWorker() {
	for job := range p.beaconingJobs {
		p.beaconing.MaybeRecord(job.ctx, job.conn, job.action)
	}
}

// auditWorker processes mesh drift audit jobs from a bounded channel.
// Prevents unbounded goroutine growth when Redis is slow.
// The goroutine lifetime is tied to the process — the Pipeline is never
// shut down, so the channel is never closed. This is intentional: the
// process exits on SIGINT/SIGTERM, and adding a Stop() method would
// require plumbing shutdown through the entire call chain for no benefit.
func (p *Pipeline) auditWorker() {
	for job := range p.auditJobs {
		p.auditDecision(job.ctx, job.ip, job.currentScore)
	}
}

// asyncScoringWorkers is the fixed fan-out of goroutines draining workChan.
// phase-306 (from PR #95): a single scoring goroutine bottlenecks throughput on
// a multi-core box. This is a *bounded* pool (a fixed constant, not scaled by
// request volume) so it cannot become a resource-exhaustion vector itself.
const asyncScoringWorkers = 32

// StartBackgroundWorkers starts all async background workers.
func (p *Pipeline) StartBackgroundWorkers(ctx context.Context) {
	for i := 0; i < asyncScoringWorkers; i++ {
		go p.runAsyncScoringLoop(ctx)
	}
	p.dnsEnrichment.Start(ctx)
	p.abuseipdb.Start(ctx)
	p.rdap.Start(ctx)
	p.feedDownloader.Start(ctx) // phase-309 WP-6: periodic blocklist feed refresh
}

// Process runs a connection through the full pipeline and returns the result.
// It never panics; all module errors are caught and logged.
func (p *Pipeline) Process(ctx context.Context, conn *ConnectionContext) *PipelineResult {
	if conn.JA4 != "" {
		if res, hit := p.cache.Get(conn.JA4); hit {
			return res
		}
	}
	if block, reason := p.checkHardBlocks(conn); block {
		return &PipelineResult{Action: "block", Score: 100, BypassReason: reason}
	}
	if p.Sync {
		return p.processInternal(ctx, conn)
	}
	select {
	case p.workChan <- conn:
	default:
		// JA4PROXY-2026-0073: track workChan saturation for operational visibility.
		metrics.WorkChanDroppedTotal.Inc()
	}
	return &PipelineResult{Action: "allow", Score: 0}
}

func (p *Pipeline) processInternal(ctx context.Context, conn *ConnectionContext) *PipelineResult {

	// ── 1. HARD BLOCKS (Blacklists, etc.)
	if block, reason := p.checkHardBlocks(conn); block {
		if p.log.IsLevelEnabled(logrus.DebugLevel) {
			p.log.WithFields(logrus.Fields{
				"ip":     conn.ClientIP,
				"ja4":    conn.JA4,
				"reason": reason,
			}).Debug("pipeline: hard block")
		}
		return &PipelineResult{
			Action:       "block",
			Bypassed:     false,
			BypassReason: reason,
			Score:        100,
		}
	}

	// Extract JA4X from client certificate if not already set
	if conn.JA4X == "" && len(conn.ClientCertificate) > 0 {
		conn.JA4X = ja4tls.ExtractJA4X(conn.ClientCertificate)
	}

	// Blocklist check (hard block — before dial fetch). JA4PROXY-2026-0037:
	// Check() is called exactly once; the previous version called it here
	// and again during signal collection, so a PubSub-driven blocklist
	// update between the two calls could cause a hard-block decision and
	// a soft-signal decision to disagree on the same connection.
	startBL := time.Now()
	blSigs, blHardBlock := p.blocklists.Check(conn.ParsedIP)
	p.measure("blocklist", startBL)
	if blHardBlock {
		return &PipelineResult{Action: "block", Score: 100, BypassReason: "blocklist"}
	}

	// ── 1b. MANUAL BAN (phase-231a) ───────────────────────────────────────────
	// An operator ban (`ban:{ip}` in Redis, written by the management API /
	// `ja4p block`) is a hard block evaluated here — before the dial is fetched —
	// so it takes effect immediately, even in monitor mode (dial=0), exactly like
	// the static blocklist above. Canonical key `ban:{ip}` (REDIS_SCHEMA).
	// Fail-open: Exists() returns false on any Redis error, so an outage never
	// starts blocking legitimate traffic.
	if p.redis != nil && conn.ClientIP != "" {
		if p.redis.Exists(ctx, "ban:"+conn.ClientIP) {
			return &PipelineResult{Action: "block", Score: 100, BypassReason: "manual_ban"}
		}
	}

	// ── 2. BYPASS CHECKS (Whitelists, etc.) ──────────────────────────────────────────────────
	if bypass, reason := p.checkBypasses(conn); bypass {
		if p.log.IsLevelEnabled(logrus.DebugLevel) {
			p.log.WithFields(logrus.Fields{
				"ip":     conn.ClientIP,
				"ja4":    conn.JA4,
				"bypass": reason,
			}).Debug("pipeline: bypass")
		}
		return &PipelineResult{
			Action:       "allow",
			Bypassed:     true,
			BypassReason: reason,
		}
	}
	// ── 2. DIAL (fetch once — cheap Redis GET) ────────────────────────────
	dial := 0
	if p.redis != nil {
		dial = p.redis.GetDial(ctx)
	}

	// ── 3. SIGNAL COLLECTION ─────────────────────────────────────────────
	var signals []RiskSignal

	// Blocklist scored signals (from the single Check() above).
	signals = append(signals, blSigs...)

	// TLS enforcement (hard block check first). Hoist the conversion to its own
	// line so the #nosec attaches to it — a trailing #nosec after `{` binds to
	// the block, not the finding, and is silently ignored.
	tlsVer := uint16(conn.TLSVersion) // #nosec G115 -- TLS version is always in uint16 range
	if tlsSigs, hardBlock := p.tlsEnforcer.Check(tlsVer, uint16s(conn.CipherList)); hardBlock {
		return &PipelineResult{Action: "block", Score: 100, BypassReason: "tls_enforcement"}
	} else {
		signals = append(signals, tlsSigs...)
	}

	// Phase 203b — JA4 prefix vs negotiated TLS version mismatch.
	if conn.JA4 != "" {
		if sig := p.tlsEnforcer.CheckJA4TLSMismatch(conn.JA4, tlsVer); sig != nil {
			signals = append(signals, *sig)
		}
	}

	// Phase 203a — TAP-consumed OS mismatch. Fail-open; disabled by default.
	if sig := p.tapConsumer.GetSignal(ctx, conn.ClientIP, conn.JA4); sig != nil {
		signals = append(signals, *sig)
	}

	// Phase 316c — TAP-consumed JA4T blocklist. Fail-open; disabled and
	// empty-blocklist by default, so silent until an operator opts in.
	if sig := p.ja4tConsumer.GetSignal(ctx, conn.ClientIP); sig != nil {
		signals = append(signals, *sig)
	}

	// JA4X blacklist signal (non-hard-block case)
	p.mu.RLock()
	ja4xEnabled := p.cfg.JA4XEnabled
	ja4xBlockingEnabled := p.cfg.JA4XBlockingEnabled
	ja4xBlacklist := p.JA4XBlacklist
	blacklistScore := p.cfg.JA4XBlacklistScore
	p.mu.RUnlock()
	if conn.JA4X != "" && ja4xEnabled && !ja4xBlockingEnabled {
		if blacklistScore == 0 {
			blacklistScore = 80
		}
		if ja4xBlacklist[conn.JA4X] {
			signals = append(signals, RiskSignal{
				Name:   "ja4x_blacklist",
				Score:  blacklistScore,
				Reason: "JA4X fingerprint in blacklist",
			})
		}
	}

	// SNI analysis
	startSNI := time.Now()
	signals = append(signals, p.sniAnalyzer.Analyze(conn.SNI)...)
	p.measure("sni", startSNI)

	// Rate limiter
	startRL := time.Now()
	rlSignals := p.rateLimiter.Check(ctx, conn.ClientIP, conn.JA4)
	signals = append(signals, rlSignals...)
	p.measure("rate_limiter", startRL)

	// Auto-escalation (phase-248): if rate limiter fired, increment offense counter.
	if len(rlSignals) > 0 && p.offenseCounter != nil {
		count, _ := p.offenseCounter.Increment(ctx, conn.ClientIP)
		if escalated, _ := p.offenseCounter.EscalatedAction(ctx, conn.ClientIP); escalated != "" {
			p.log.WithFields(logrus.Fields{
				"event.action":             "offense_escalation",
				"client.ip":                conn.ClientIP,
				"offense.count":            count,
				"offense.escalated_action": escalated,
			}).Warn("offense escalation")
			metrics.OffenseEscalationsTotal.WithLabelValues(escalated).Inc()
			if escalated == "ban" {
				banKey := fmt.Sprintf("ban:%s", conn.ClientIP)
				reason := fmt.Sprintf(
					`{"reason":"auto_escalation","offense_count":%d,"auto":true}`, count)
				p.redis.SetString(ctx, banKey, reason, p.cfg.AutoEscalate.BanHours*3600)
			}
			return &PipelineResult{Action: escalated, Score: 100, BypassReason: "auto_escalation"}
		}
	}

	// TCP analyzer
	startTCP := time.Now()
	signals = append(signals, p.tcpAnalyzer.Analyze(ctx, conn)...)
	p.measure("tcp_analyzer", startTCP)

	// ASN classification
	startASN := time.Now()
	signals = append(signals, p.asnClassifier.Classify(conn.ClientIP)...)
	p.measure("asn", startASN)

	// Datacenter policy enforcement (Phase 249) — runs immediately after ASN classification.
	// ASN data is not available at bypass-check time, so this lives here.
	// When action is "score" (default), the block is skipped entirely.
	if dc := p.cfg.DatacenterPolicy; dc.Action == "tarpit" || dc.Action == "block" {
		if isDatacenter, asn := p.asnClassifier.IsDatacenter(conn.ClientIP); isDatacenter {
			excepted := false
			for _, exASN := range dc.Exceptions {
				if uint32(exASN) == asn { //nolint:gosec // ASN numbers are IANA-defined 32-bit values; config type is uint for yaml convenience
					excepted = true
					break
				}
			}
			if !excepted {
				if dc.LogActions {
					p.log.WithFields(logrus.Fields{
						"event.action":           "datacenter_policy",
						"client.ip":              conn.ClientIP,
						"network.asn":            asn,
						"ja4proxy.policy.action": dc.Action,
					}).Warn("datacenter policy applied")
				}
				metrics.DatacenterPolicyActionsTotal.WithLabelValues(dc.Action, "false").Inc()
				return &PipelineResult{
					Action:       dc.Action,
					Score:        100,
					BypassReason: "datacenter_policy",
				}
			}
			// Excepted ASN — log and continue to scorer.
			metrics.DatacenterPolicyActionsTotal.WithLabelValues(dc.Action, "true").Inc()
		}
	}

	// DNS enrichment (cached result; lookup happens async)
	var sig *RiskSignal
	startDNS := time.Now()
	sig = p.dnsEnrichment.GetSignal(ctx, conn)
	p.measure("dns", startDNS)
	if sig != nil {
		signals = append(signals, *sig)
	}

	// Beaconing detection
	startBeac := time.Now()
	sig = p.beaconing.GetSignal(ctx, conn)
	p.measure("beaconing", startBeac)
	if sig != nil {
		signals = append(signals, *sig)
	}

	// AbuseIPDB
	startAbuse := time.Now()
	sig = p.abuseipdb.GetSignal(conn.ClientIP)
	p.measure("abuseipdb", startAbuse)
	if sig != nil {
		signals = append(signals, *sig)
	}

	// RDAP — needs interim score to decide whether to enqueue
	interimAssessment := p.scorer.Score(signals)
	startRDAP := time.Now()
	signals = append(signals, p.rdap.GetSignals(ctx, conn, interimAssessment.TotalScore)...)
	p.measure("rdap", startRDAP)

	// Analytics signals
	startAnal := time.Now()
	signals = append(signals, GetAnalyticsSignals(ctx, p.redis, conn.ClientIP, p.log)...)
	p.measure("analytics", startAnal)

	// ── 4. COMPOSITE SCORING ─────────────────────────────────────────────
	assessment := p.scorer.Score(signals)

	// Mesh Drift Detection (async, bounded worker pool)
	if assessment.TotalScore > 0 {
		select {
		case p.auditJobs <- auditJob{ctx: ctx, ip: conn.ClientIP, currentScore: assessment.TotalScore}:
		default:
			metrics.AuditJobsDroppedTotal.Inc()
		}
	}

	// ── 5. ACTION DECISION ───────────────────────────────────────────────
	action := p.decider.Decide(assessment.TotalScore, dial)

	// Record beaconing timestamp (bounded worker, F-002)
	select {
	case p.beaconingJobs <- beaconingJob{ctx: ctx, conn: conn, action: action}:
	default:
		// Worker saturated — drop rather than block the pipeline
	}

	// Build counterfactuals for monitor-mode logging
	var counterfactuals map[int]string
	if dial == 0 {
		counterfactuals = p.decider.Counterfactuals(assessment.TotalScore, []int{25, 50, 75, 100})
	}

	if p.log.IsLevelEnabled(logrus.DebugLevel) {
		p.log.WithFields(logrus.Fields{
			"ip":     conn.ClientIP,
			"ja4":    conn.JA4,
			"score":  assessment.TotalScore,
			"dial":   dial,
			"action": action,
		}).Debug("pipeline: decision")
	}

	return &PipelineResult{
		Action:          action,
		Score:           assessment.TotalScore,
		Signals:         assessment.Signals,
		Dial:            dial,
		Counterfactuals: counterfactuals,
	}
}

// UpdateSets replaces in-process JA4 maps. Called on startup and pub/sub update.
func (p *Pipeline) UpdateSets(whitelist, blacklist map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Whitelist = whitelist
	p.Blacklist = blacklist
}

// UpdateJA4XSets replaces in-process JA4X maps. Called on startup and pub/sub update.
func (p *Pipeline) UpdateJA4XSets(whitelist, blacklist map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.JA4XWhitelist = whitelist
	p.JA4XBlacklist = blacklist
}

// UpdateDynamicCIDRs replaces the in-process CIDR blocklist.
func (p *Pipeline) UpdateDynamicCIDRs(cidrs []string) {
	ranger := cidranger.NewPCTrieRanger()
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			// Handle plain IPs
			ip := net.ParseIP(c)
			if ip != nil {
				mask := 32
				if ip.To4() == nil {
					mask = 128
				}
				_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", c, mask))
			}
		}
		if network != nil {
			_ = ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dynamicCIDR = ranger
}

// checkBypasses returns (true, reason) if the connection matches an ALLOW bypass.
func (p *Pipeline) checkBypasses(conn *ConnectionContext) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// ALPN browser bypass: h2 or h1 → always allow
	if p.cfg.ALPNBrowserBypass && (conn.ALPN == "h2" || conn.ALPN == "h1") {
		return true, "alpn_browser"
	}

	// JA4 whitelist bypass
	if p.cfg.JA4WhitelistBypass && conn.JA4 != "" {
		if p.Whitelist[conn.JA4] {
			return true, "ja4_whitelist"
		}
		// Pattern match: whitelist_patterns are ALPN suffix patterns
		for _, pat := range p.cfg.WhitelistSuffs {
			if strings.HasSuffix(conn.JA4, pat) || strings.Contains(conn.JA4, pat) {
				return true, "ja4_whitelist_pattern"
			}
		}
	}

	// JA4X whitelist bypass
	if p.cfg.JA4XWhitelistBypass && conn.JA4X != "" && p.cfg.JA4XEnabled {
		if p.JA4XWhitelist[conn.JA4X] {
			return true, "ja4x_whitelist"
		}
	}

	// mTLS bypass: valid client cert
	if p.cfg.MTLSBypass && conn.HasValidClientCert {
		return true, "mtls"
	}

	// Static IP allowlist bypass
	if p.cfg.StaticIPAllowlistEnabled && p.cfg.StaticIPAllowlist[conn.ClientIP] {
		return true, "static_ip"
	}

	return false, ""
}

// checkHardBlocks returns (true, reason) if the connection must be blocked immediately.
func (p *Pipeline) checkHardBlocks(conn *ConnectionContext) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// JA4 blacklist
	if p.cfg.JA4BlockingEnabled && conn.JA4 != "" && p.Blacklist[conn.JA4] {
		return true, "ja4_blacklist"
	}

	// JA4X blacklist
	if p.cfg.JA4XBlockingEnabled && conn.JA4X != "" && p.cfg.JA4XEnabled {
		if p.JA4XBlacklist[conn.JA4X] {
			return true, "ja4x_blacklist"
		}
	}

	// Country blacklist
	if p.cfg.CountryBlockingEnabled && conn.Country != "" && p.cfg.CountryBlacklist[conn.Country] {
		return true, "country_blacklist"
	}

	// Dynamic CIDR blocklist
	if p.dynamicCIDR != nil {
		ip := net.ParseIP(conn.ClientIP)
		if ip != nil {
			if contains, err := p.dynamicCIDR.Contains(ip); err == nil && contains {
				return true, "dynamic_cidr"
			}
		}
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
		MaliciousSNIEnabled:  cfg.MaliciousSNIEnabled,
		MaliciousSNIScore:    defaultInt(cfg.MaliciousSNIScore, 100),
		ExpectedHostnames:    cfg.ExpectedHostnames,
	}
}

// buildBeaconingConfig creates a BeaconingConfig from the pipeline config.
func buildBeaconingConfig(cfg *PipelineConfig) *BeaconingConfig {
	return &BeaconingConfig{
		Enabled:         cfg.BeaconingEnabled,
		ScoreCap:        cfg.BeaconingScoreCap,
		MinObservations: cfg.BeaconingMinObservations,
		ShortWindowSec:  cfg.BeaconingShortWindowSec,
		LongWindowSec:   cfg.BeaconingLongWindowSec,
	}
}

// buildAbuseIPDBConfig creates an AbuseIPDBConfig from the pipeline config.
func buildAbuseIPDBConfig(cfg *PipelineConfig) *AbuseIPDBConfig {
	return &AbuseIPDBConfig{
		Enabled:           cfg.AbuseIPDBEnabled,
		APIKey:            cfg.AbuseIPDBAPIKey,
		ScoreCap:          cfg.AbuseIPDBScoreCap,
		SharedIPThreshold: cfg.AbuseIPDBSharedIPThreshold,
		LocalCacheSize:    cfg.AbuseIPDBLocalCacheSize,
		Workers:           cfg.AbuseIPDBWorkers,
		APIURL:            cfg.AbuseIPDBAPIURL,
	}
}

// buildRDAPConfig creates an RDAPConfig from the pipeline config.
func buildRDAPConfig(cfg *PipelineConfig) *RDAPConfig {
	return &RDAPConfig{
		Enabled:               cfg.RDAPEnabled,
		MinTriggerScore:       cfg.RDAPMinTriggerScore,
		NewNetblockMaxAgeDays: cfg.RDAPNewNetblockMaxAgeDays,
		NewNetblockScore:      cfg.RDAPNewNetblockScore,
		KnownBadOrgScore:      cfg.RDAPKnownBadOrgScore,
		RequireKnownBadOrg:    cfg.RDAPRequireKnownBadOrg,
		BlockExpansionEnabled: cfg.RDAPBlockExpansionEnabled,
		KnownBadOrgsPath:      cfg.RDAPKnownBadOrgsPath,
	}
}

// buildASNClassifierConfig creates an ASNClassifierConfig from the pipeline config.
func buildASNClassifierConfig(cfg *PipelineConfig) *ASNClassifierConfig {
	return &ASNClassifierConfig{
		Enabled:            cfg.ASNClassifierEnabled,
		DBPath:             cfg.ASNDBPath,
		TorExitListPath:    cfg.TorExitListPath,
		DatacenterListPath: cfg.ASNClassifierDatacenterListPath,
		DatacenterScore:    cfg.DatacenterScore,
		TorScore:           cfg.TorScore,
		VPNScore:           cfg.VPNScore,
		UnknownScore:       cfg.UnknownScore,
		DatacenterASNs:     cfg.DatacenterASNs,
		DatacenterOrgs:     cfg.DatacenterOrgs,
	}
}

// buildDNSEnrichmentConfig creates a DNSEnrichmentConfig from the pipeline config.
func buildDNSEnrichmentConfig(cfg *PipelineConfig) *DNSEnrichmentConfig {
	return &DNSEnrichmentConfig{
		Enabled:           cfg.DNSEnrichmentEnabled,
		Workers:           cfg.DNSEnrichmentWorkers,
		NoPTRScore:        cfg.DNSNoPTRScore,
		FCrDNSFailedScore: cfg.DNSFCrDNSFailedScore,
		ResidentialScore:  cfg.DNSResidentialScore,
		TTL:               cfg.DNSTTL,
	}
}

// buildBlocklistConfig creates a BlocklistConfig from the pipeline config.
func buildBlocklistConfig(cfg *PipelineConfig) *BlocklistConfig {
	return &BlocklistConfig{
		Feeds: cfg.BlocklistFeeds,
	}
}

// buildRateLimiterConfig creates a RateLimiterConfig from the pipeline config.
func buildRateLimiterConfig(cfg *PipelineConfig) *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled: cfg.RateLimiterEnabled,
		ByIP:    cfg.RateLimiterByIP,
		ByJA4:   cfg.RateLimiterByJA4,
		ByIPJA4: cfg.RateLimiterByIPJA4,
	}
}

// buildTCPAnalyzerConfig creates a TCPAnalyzerConfig from the pipeline config.
func buildTCPAnalyzerConfig(cfg *PipelineConfig) *TCPAnalyzerConfig {
	return &TCPAnalyzerConfig{
		Enabled:                       cfg.TCPAnalyzerEnabled,
		SessionResumptionEnabled:      cfg.TCPAnalyzerSessionResumptionEnabled,
		MinConnectionsForSessionCheck: cfg.TCPAnalyzerMinConnectionsForSession,
		ShortLifespanEnabled:          cfg.TCPAnalyzerShortLifespanEnabled,
		ShortLifespanThresholdMS:      cfg.TCPAnalyzerShortLifespanThresholdMS,
		ConcurrencyEnabled:            cfg.TCPAnalyzerConcurrencyEnabled,
		ConcurrencyModerate:           cfg.TCPAnalyzerConcurrencyModerate,
		ConcurrencyHigh:               cfg.TCPAnalyzerConcurrencyHigh,
		ConcurrencySevere:             cfg.TCPAnalyzerConcurrencySevere,
		ReturnVisitorEnabled:          cfg.TCPAnalyzerReturnVisitorEnabled,
		ReturnVisitorMinDays:          cfg.TCPAnalyzerReturnVisitorMinDays,
		ReturnVisitorMinAllowRate:     cfg.TCPAnalyzerReturnVisitorMinAllowRate,
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
		out[i] = uint16(v) // #nosec G115 // cipher suite IDs are uint16 by TLS spec
	}
	return out
}

func (p *Pipeline) measure(name string, start time.Time) {
	metrics.SignalLatencySeconds.WithLabelValues(name).Observe(time.Since(start).Seconds())
}

func (p *Pipeline) auditDecision(ctx context.Context, ip string, currentScore int) {
	if p.redis == nil {
		return
	}
	key := "audit:last_score:" + ip
	lastScoreStr := p.redis.GetString(ctx, key)
	if lastScoreStr != "" {
		var lastScore int
		_, _ = fmt.Sscanf(lastScoreStr, "%d", &lastScore)
		diff := currentScore - lastScore
		if diff < 0 {
			diff = -diff
		}
		if diff > 20 { // 20 point threshold for "drift"
			metrics.SignalDriftTotal.WithLabelValues("mesh", "score_divergence").Inc()
			p.log.WithFields(logrus.Fields{
				"ip":            ip,
				"current_score": currentScore,
				"last_score":    lastScore,
			}).Warn("pipeline: score drift detected across mesh")
		}
	}
	p.redis.SetString(ctx, key, fmt.Sprintf("%d", currentScore), 300)
}

func (p *Pipeline) runAsyncScoringLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case conn := <-p.workChan:
					result := p.processInternal(ctx, conn)
					p.cache.Set(conn.JA4, result)
				default:
					return
				}
			}
		case conn := <-p.workChan:
			result := p.processInternal(ctx, conn)
			p.cache.Set(conn.JA4, result)
		}
	}
}
