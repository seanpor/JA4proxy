package security

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/anomalyco/ja4proxy/internal/cache"
)

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
	return &AbuseIPDB{
		cfg:        cfg,
		localCache: cache.New(cacheSize),
		redis:      redis,
		http:       &http.Client{Timeout: 5 * time.Second},
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
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"?ipAddress="+ip+"&maxAgeInDays=30", nil)
	if err != nil {
		return
	}
	req.Header.Set("Key", a.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		a.log.WithError(err).WithField("ip", ip).Debug("abuseipdb: API call failed")
		return
	}
	defer resp.Body.Close()
	var result struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}
	confidence := result.Data.AbuseConfidenceScore
	a.localCache.Set(ip, confidence, 30*time.Minute)
	a.redis.SetString(ctx, fmt.Sprintf("abuseipdb:%s", ip), strconv.Itoa(confidence), 86400)
}
