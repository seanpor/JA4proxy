package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// RDAPConfig configures RDAP enrichment.
type RDAPConfig struct {
	Enabled               bool
	MinTriggerScore       int     // default 75
	NewNetblockMaxAgeDays int     // default 90
	NewNetblockScore      int     // default 20
	KnownBadOrgScore      int     // default 45
	RequireKnownBadOrg    bool    // default true
	BlockExpansionEnabled bool
	KnownBadOrgs          map[string]bool // loaded from config
}

type rdapJob struct {
	ip    string
	score int
	alpn  string
}

// RDAPEnricher enriches connections with RDAP netblock data.
type RDAPEnricher struct {
	cfg   *RDAPConfig
	redis RedisReader
	http  *http.Client
	queue chan rdapJob
	log   *logrus.Logger
}

// NewRDAPEnricher creates an RDAPEnricher.
func NewRDAPEnricher(cfg *RDAPConfig, redis RedisReader, log *logrus.Logger) *RDAPEnricher {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &RDAPConfig{}
	}
	return &RDAPEnricher{
		cfg:   cfg,
		redis: redis,
		http:  &http.Client{Timeout: 10 * time.Second},
		queue: make(chan rdapJob, 500),
		log:   log,
	}
}

// Start launches the background worker goroutine.
func (r *RDAPEnricher) Start(ctx context.Context) {
	go r.worker(ctx)
}

func (r *RDAPEnricher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.queue:
			r.enrich(ctx, job)
		}
	}
}

// GetSignals returns RDAP-based risk signals from cached data.
// Enqueues a lookup if the score is above the trigger threshold.
func (r *RDAPEnricher) GetSignals(ctx context.Context, conn *ConnectionContext, triggerScore int) []RiskSignal {
	if !r.cfg.Enabled {
		return nil
	}
	key := fmt.Sprintf("rdap:%s", conn.ClientIP)
	data := r.redis.HGetAll(ctx, key)
	if len(data) == 0 {
		// Enqueue lookup if score is interesting
		minScore := r.cfg.MinTriggerScore
		if minScore == 0 {
			minScore = 75
		}
		if triggerScore >= minScore {
			select {
			case r.queue <- rdapJob{ip: conn.ClientIP, score: triggerScore, alpn: conn.ALPN}:
			default:
			}
		}
		return nil
	}
	var signals []RiskSignal
	org := data["org"]
	// Known bad org check
	if org != "" && r.cfg.KnownBadOrgs[strings.ToLower(org)] {
		score := r.cfg.KnownBadOrgScore
		if score == 0 {
			score = 45
		}
		signals = append(signals, RiskSignal{
			Name:   "rdap_known_bad_org",
			Score:  score,
			Reason: fmt.Sprintf("org '%s' in known-bad list", org),
			Weight: 1.0,
		})
	}
	// New netblock check
	if registered := data["registered_date"]; registered != "" {
		regTime, err := time.Parse("2006-01-02", registered)
		maxAge := r.cfg.NewNetblockMaxAgeDays
		if maxAge == 0 {
			maxAge = 90
		}
		if err == nil && time.Since(regTime).Hours() < float64(maxAge)*24 {
			score := r.cfg.NewNetblockScore
			if score == 0 {
				score = 20
			}
			signals = append(signals, RiskSignal{
				Name:   "rdap_new_netblock",
				Score:  score,
				Reason: "netblock registered recently",
				Weight: 1.0,
			})
		}
	}
	return signals
}

func (r *RDAPEnricher) enrich(ctx context.Context, job rdapJob) {
	// Simple RDAP lookup via ARIN (a full implementation would use IANA bootstrap)
	url := fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", job.ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	resp, err := r.http.Do(req)
	if err != nil {
		r.log.WithError(err).WithField("ip", job.ip).Debug("rdap: lookup failed")
		return
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}
	// Extract org name
	org := ""
	if name, ok := result["name"].(string); ok {
		org = name
	}
	// Block expansion
	if r.cfg.BlockExpansionEnabled && job.alpn != "h2" && job.alpn != "h1" {
		r.maybeExpandBlock(ctx, job.ip, org, job.score)
	}
	_ = org
}

func (r *RDAPEnricher) maybeExpandBlock(ctx context.Context, ip, org string, score int) {
	minScore := r.cfg.MinTriggerScore
	if minScore == 0 {
		minScore = 75
	}
	if score < minScore {
		return
	}
	if r.cfg.RequireKnownBadOrg && !r.cfg.KnownBadOrgs[strings.ToLower(org)] {
		return
	}
	// Derive /24 (IPv4) or /48 (IPv6) CIDR
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return
	}
	var cidr string
	if parsed.To4() != nil {
		mask := net.CIDRMask(24, 32)
		cidr = fmt.Sprintf("%s/24", parsed.Mask(mask).String())
	} else {
		mask := net.CIDRMask(48, 128)
		cidr = fmt.Sprintf("%s/48", parsed.Mask(mask).String())
	}
	r.redis.SetString(ctx, fmt.Sprintf("ban_cidr:%s", cidr), "1", 86400*7)
}
