package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/cache"
	"github.com/seanpor/ja4proxy/internal/metrics"
)

// ErrAbuseIPDBNonHTTPS is returned when lookup() refuses to send the API
// key to a non-HTTPS URL. JA4PROXY-2026-0049 — the API key is a long-lived
// credential scoped to a per-account abuse-check quota; sending it over
// plaintext HTTP exposes it to any on-path observer and burns the
// operator's quota or exfiltrates attacker-controlled scoring data.
var ErrAbuseIPDBNonHTTPS = errors.New("abuseipdb: refusing to send API key over non-HTTPS URL")

// AbuseIPDBConfig configures the AbuseIPDB integration.
type AbuseIPDBConfig struct {
	Enabled           bool
	APIKey            string
	ScoreCap          int    // default 40
	SharedIPThreshold int    // default 50
	LocalCacheSize    int    // default 10000
	Workers           int    // default 2
	APIURL            string // default "https://api.abuseipdb.com/api/v2/check"
}

// AbuseIPDB queries the AbuseIPDB API to score IPs by abuse confidence.
type AbuseIPDB struct {
	cfg        *AbuseIPDBConfig
	localCache *cache.LRU
	redis      RedisReader
	http       *http.Client
	queue      chan string
	log        *logrus.Logger
}

// NewAbuseIPDB creates an AbuseIPDB instance.
func NewAbuseIPDB(cfg *AbuseIPDBConfig, redis RedisReader, log *logrus.Logger) *AbuseIPDB {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &AbuseIPDBConfig{}
	}
	cacheSize := cfg.LocalCacheSize
	if cacheSize == 0 {
		cacheSize = 10000
	}
	// JA4PROXY-2026-0049 — refuse to follow redirects. The AbuseIPDB v2 API
	// never 3xx-redirects in normal operation; a redirect under our
	// configured URL means either a routing accident or an active attacker
	// trying to harvest the Key header onto a host they control. Return
	// ErrUseLastResponse so the redirect body is visible (for debug) but
	// the request is not retried against the new Location.
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &AbuseIPDB{
		cfg:        cfg,
		localCache: cache.New(cacheSize),
		redis:      redis,
		http:       httpClient,
		queue:      make(chan string, 1000),
		log:        log,
	}
}

// Start launches background workers for async API lookups.
func (a *AbuseIPDB) Start(ctx context.Context) {
	workers := a.cfg.Workers
	if workers == 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		go a.worker(ctx)
	}
}

func (a *AbuseIPDB) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-a.queue:
			a.lookup(ctx, ip)
		}
	}
}

func (a *AbuseIPDB) computeScore(confidence int) int {
	cap := a.cfg.ScoreCap
	if cap == 0 {
		cap = 40
	}
	threshold := a.cfg.SharedIPThreshold
	if threshold == 0 {
		threshold = 50
	}
	if confidence >= threshold {
		return int(math.Round(float64(confidence) / 100.0 * float64(cap)))
	}
	return int(math.Round(float64(confidence) / float64(threshold) * 15))
}

// GetSignal returns a risk signal if the IP has an AbuseIPDB confidence score.
// Returns nil if disabled, not cached, or score is zero.
func (a *AbuseIPDB) GetSignal(clientIP string) *RiskSignal {
	if !a.cfg.Enabled {
		return nil
	}
	// Check local cache
	if v, ok := a.localCache.Get(clientIP); ok {
		confidence := v.(int)
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("hit").Inc()
		score := a.computeScore(confidence)
		if score <= 0 {
			return nil
		}
		return &RiskSignal{
			Name:   "abuseipdb",
			Score:  score,
			Reason: fmt.Sprintf("AbuseIPDB confidence %d%%", confidence),
			Weight: 1.0,
		}
	}
	// Check Redis cache
	if a.redis == nil {
		// Not cached — enqueue lookup
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("miss").Inc()
		select {
		case a.queue <- clientIP:
		default:
		}
		return nil
	}
	redisKey := fmt.Sprintf("abuseipdb:%s", clientIP)
	cached := a.redis.GetString(context.Background(), redisKey)
	if cached != "" {
		confidence, err := strconv.Atoi(cached)
		if err == nil {
			metrics.AbuseIPDBLookupsTotal.WithLabelValues("hit").Inc()
			a.localCache.Set(clientIP, confidence, 30*time.Minute)
			score := a.computeScore(confidence)
			if score <= 0 {
				return nil
			}
			return &RiskSignal{
				Name:   "abuseipdb",
				Score:  score,
				Reason: fmt.Sprintf("AbuseIPDB confidence %d%%", confidence),
				Weight: 1.0,
			}
		}
	}
	// Not cached — enqueue lookup
	metrics.AbuseIPDBLookupsTotal.WithLabelValues("miss").Inc()
	select {
	case a.queue <- clientIP:
	default:
	}
	return nil
}

func (a *AbuseIPDB) lookup(ctx context.Context, ip string) {
	if a.cfg.APIKey == "" {
		return
	}
	apiURL := a.cfg.APIURL
	if apiURL == "" {
		apiURL = "https://api.abuseipdb.com/api/v2/check"
	}
	// JA4PROXY-2026-0049 — refuse to send the API key over plaintext HTTP.
	// Parse the URL once and hard-require an https:// scheme; a misconfigured
	// api_url (or a downgrade attack against a config source) must not
	// translate into credential exfiltration.
	if !isHTTPSURL(apiURL) {
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("error").Inc()
		a.log.WithField("scheme", schemeOf(apiURL)).Warn(
			"abuseipdb: refusing to send API key over non-HTTPS URL (JA4PROXY-2026-0049)")
		return
	}
	// Query-escape the IP to prevent an attacker-controlled client-address
	// from injecting additional URL parameters. IPv6 colons and brackets
	// all have to survive; url.Values.Encode is the canonical fix.
	qs := url.Values{}
	qs.Set("ipAddress", ip)
	qs.Set("maxAgeInDays", "30")
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"?"+qs.Encode(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Key", a.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("error").Inc()
		// The Key header must never appear in any log emission. WithError
		// is safe — Go's *url.Error redacts the URL userinfo but not custom
		// headers; we defensively log only the scrubbed URL host and ip.
		a.log.WithError(err).WithField("ip", ip).Debug("abuseipdb: API call failed")
		return
	}
	defer resp.Body.Close()
	// JA4PROXY-2026-0049 — if the API ever 3xx-redirects, CheckRedirect
	// returned ErrUseLastResponse so we see the 3xx body here. Treat it as
	// an error and DO NOT retry against the Location — the Key header
	// must only be sent to the originally-configured HTTPS host.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("error").Inc()
		a.log.WithField("status", resp.StatusCode).Warn(
			"abuseipdb: refusing to follow 3xx redirect — API key never leaves original host")
		return
	}
	var result struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		metrics.AbuseIPDBLookupsTotal.WithLabelValues("error").Inc()
		return
	}
	confidence := result.Data.AbuseConfidenceScore
	a.localCache.Set(ip, confidence, 30*time.Minute)
	a.redis.SetString(ctx, fmt.Sprintf("abuseipdb:%s", ip), strconv.Itoa(confidence), 86400)
}

// isHTTPSURL returns true only for fully-qualified https:// URLs — case
// insensitive on the scheme. Empty or malformed URLs return false so the
// caller refuses to send credentials.
func isHTTPSURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}

// schemeOf returns the lowercased scheme or "<invalid>" for malformed URLs.
// Used only for logging — never returns anything derived from the API key.
func schemeOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "<invalid>"
	}
	if parsed.Scheme == "" {
		return "<empty>"
	}
	return strings.ToLower(parsed.Scheme)
}
