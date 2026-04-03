package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
)

// RDAPConfig configures RDAP enrichment.
type RDAPConfig struct {
	Enabled               bool
	MinTriggerScore       int
	NewNetblockMaxAgeDays int
	NewNetblockScore      int
	KnownBadOrgScore      int
	RequireKnownBadOrg    bool
	BlockExpansionEnabled bool
	KnownBadOrgsPath      string
	KnownBadOrgs          []KnownBadOrgEntry
}

// KnownBadOrgEntry represents an entry in known_bad_orgs.yml
type KnownBadOrgEntry struct {
	Handle string `yaml:"handle"`
	Name   string `yaml:"name"`
	Reason string `yaml:"reason"`
	Score  int    `yaml:"score"`
}

type knownBadOrgsYAML struct {
	Orgs []KnownBadOrgEntry `yaml:"orgs"`
}

// rdapResult matches the JSON schema stored in Redis by both Python and Go.
type rdapResult struct {
	Netblock         string  `json:"netblock"`
	OrgName          string  `json:"org_name"`
	OrgHandle        string  `json:"org_handle"`
	ASN              string  `json:"asn"`
	Country          string  `json:"country"`
	RegistrationDate string  `json:"registration_date"`
	FetchedAt        float64 `json:"fetched_at"`
	IsUnknown        bool    `json:"is_unknown"`
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

	// Load known-bad orgs if path provided
	if cfg.KnownBadOrgsPath != "" {
		if data, err := os.ReadFile(cfg.KnownBadOrgsPath); err == nil {
			var kbo knownBadOrgsYAML
			if err := yaml.Unmarshal(data, &kbo); err == nil {
				cfg.KnownBadOrgs = kbo.Orgs
				log.WithField("count", len(kbo.Orgs)).Info("rdap: loaded known-bad orgs")
			} else {
				log.WithError(err).Warn("rdap: failed to parse known-bad orgs YAML")
			}
		}
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
	// Python uses rdap:ip:{ip}, Go used rdap:{ip}. Aligning to Python.
	key := fmt.Sprintf("rdap:ip:%s", conn.ClientIP)
	val := r.redis.GetString(ctx, key)
	if val == "" {
		// Enqueue lookup if score is interesting
		minScore := r.cfg.MinTriggerScore
		if minScore == 0 {
			minScore = 20 // Standard default from proxy.yml
		}
		if triggerScore >= minScore {
			select {
			case r.queue <- rdapJob{ip: conn.ClientIP, score: triggerScore, alpn: conn.ALPN}:
			default:
			}
		}
		return nil
	}

	var res rdapResult
	if err := json.Unmarshal([]byte(val), &res); err != nil {
		r.log.WithError(err).Warn("rdap: failed to unmarshal result from Redis")
		return nil
	}

	if res.IsUnknown {
		return nil
	}

	var signals []RiskSignal

	// Known bad org check
	if isMatch, entry := r.checkKnownBad(res.OrgHandle, res.OrgName); isMatch {
		score := entry.Score
		if score == 0 {
			score = r.cfg.KnownBadOrgScore
			if score == 0 {
				score = 45
			}
		}
		signals = append(signals, RiskSignal{
			Name:   "rdap_known_bad_org",
			Score:  score,
			Reason: fmt.Sprintf("Known bad org: %s (%s)", res.OrgName, entry.Reason),
			Weight: 1.0,
		})
	}

	// New netblock check
	if res.RegistrationDate != "" {
		regTime, err := time.Parse("2006-01-02", res.RegistrationDate)
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
				Reason: fmt.Sprintf("Netblock registered %d days ago", int(time.Since(regTime).Hours()/24)),
				Weight: 1.0,
			})
		}
	}
	return signals
}

func (r *RDAPEnricher) checkKnownBad(handle, name string) (bool, *KnownBadOrgEntry) {
	if len(r.cfg.KnownBadOrgs) == 0 {
		return false, nil
	}
	handleLower := strings.ToLower(handle)
	nameLower := strings.ToLower(name)

	for _, entry := range r.cfg.KnownBadOrgs {
		if entry.Handle != "" && strings.ToLower(entry.Handle) == handleLower {
			return true, &entry
		}
		if entry.Name != "" && strings.Contains(nameLower, strings.ToLower(entry.Name)) {
			return true, &entry
		}
	}
	return false, nil
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
	handle := ""
	if h, ok := result["handle"].(string); ok {
		handle = h
	}

	// Block expansion
	if r.cfg.BlockExpansionEnabled && job.alpn != "h2" && job.alpn != "h1" {
		r.maybeExpandBlock(ctx, job.ip, handle, org, job.score)
	}
}

func (r *RDAPEnricher) maybeExpandBlock(ctx context.Context, ip, handle, org string, score int) {
	minScore := r.cfg.MinTriggerScore
	if minScore == 0 {
		minScore = 75
	}
	if score < minScore {
		return
	}
	isMatch, _ := r.checkKnownBad(handle, org)
	if r.cfg.RequireKnownBadOrg && !isMatch {
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
