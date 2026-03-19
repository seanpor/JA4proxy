package security

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

// DNSEnrichmentConfig configures DNS PTR/FCrDNS enrichment.
type DNSEnrichmentConfig struct {
	Enabled           bool
	Workers           int // default 4
	NoPTRScore        int // default 15
	FCrDNSFailedScore int // default 20
	ResidentialScore  int // default -10 (negative — reduces risk)
	TTL               int // default 3600
}

// RedisWriter adds write operations needed by enrichment modules.
// Since SetString is already in RedisReader, this is an alias for RedisReader.
type RedisWriter interface {
	RedisReader
}

// DNSEnrichment performs async PTR lookups and caches results in Redis.
// Port of src/security/dns_enrichment.py.
type DNSEnrichment struct {
	cfg   *DNSEnrichmentConfig
	redis RedisWriter
	log   *logrus.Logger
	queue chan string
}

// NewDNSEnrichment creates a DNSEnrichment with the given configuration.
func NewDNSEnrichment(cfg *DNSEnrichmentConfig, redis RedisWriter, log *logrus.Logger) *DNSEnrichment {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &DNSEnrichmentConfig{}
	}
	return &DNSEnrichment{
		cfg:   cfg,
		redis: redis,
		log:   log,
		queue: make(chan string, 1000),
	}
}

// Start launches worker goroutines. Call once at startup.
func (d *DNSEnrichment) Start(ctx context.Context) {
	workers := d.cfg.Workers
	if workers == 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		go d.worker(ctx)
	}
}

func (d *DNSEnrichment) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-d.queue:
			d.enrich(ctx, ip)
		}
	}
}

func (d *DNSEnrichment) enrich(ctx context.Context, clientIP string) {
	ttl := d.cfg.TTL
	if ttl == 0 {
		ttl = 3600
	}
	key := fmt.Sprintf("dns:fcrdns:%s", clientIP)

	// PTR lookup
	names, err := net.LookupAddr(clientIP)
	if err != nil || len(names) == 0 {
		d.redis.SetString(ctx, key, "no_ptr", ttl)
		return
	}

	hostname := strings.TrimSuffix(names[0], ".")

	// FCrDNS: forward lookup must resolve back to the same IP
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		d.redis.SetString(ctx, key, "fcrdns_failed", ttl)
		return
	}

	confirmed := false
	for _, addr := range addrs {
		if addr == clientIP {
			confirmed = true
			break
		}
	}
	if !confirmed {
		d.redis.SetString(ctx, key, "fcrdns_failed", ttl)
		return
	}

	// Classify: check if hostname looks residential
	lower := strings.ToLower(hostname)
	residentialPatterns := []string{"dsl", "cable", "fiber", "adsl", "broadband", "dynamic", "home", "residential", "pool", "dhcp"}
	isResidential := false
	for _, pat := range residentialPatterns {
		if strings.Contains(lower, pat) {
			isResidential = true
			break
		}
	}
	if isResidential {
		d.redis.SetString(ctx, key, "confirmed_residential", ttl)
	} else if strings.Contains(lower, "datacenter") || strings.Contains(lower, "cloud") || strings.Contains(lower, "hosting") {
		d.redis.SetString(ctx, key, "confirmed_datacenter", ttl)
	} else {
		d.redis.SetString(ctx, key, "confirmed_unknown", ttl)
	}
}

// GetSignal returns the cached DNS risk signal for the connection's IP.
// If no cached result, enqueues a lookup and returns nil.
// Never blocks; browser traffic (h2/h1) is never enqueued.
func (d *DNSEnrichment) GetSignal(ctx context.Context, conn *ConnectionContext) *RiskSignal {
	if !d.cfg.Enabled {
		return nil
	}

	key := fmt.Sprintf("dns:fcrdns:%s", conn.ClientIP)
	cached := d.redis.GetString(ctx, key)

	noPTRScore := d.cfg.NoPTRScore
	if noPTRScore == 0 {
		noPTRScore = 15
	}
	fcrdnsScore := d.cfg.FCrDNSFailedScore
	if fcrdnsScore == 0 {
		fcrdnsScore = 20
	}
	residentialScore := d.cfg.ResidentialScore
	if residentialScore == 0 {
		residentialScore = -10
	}

	switch cached {
	case "no_ptr":
		return &RiskSignal{Name: "no_ptr", Score: noPTRScore, Reason: "no PTR record", Weight: 1.0}
	case "fcrdns_failed":
		return &RiskSignal{Name: "fcrdns_failed", Score: fcrdnsScore, Reason: "FCrDNS verification failed", Weight: 1.0}
	case "confirmed_residential":
		return &RiskSignal{Name: "residential_ptr", Score: residentialScore, Reason: "confirmed residential PTR", Weight: 1.0}
	case "confirmed_datacenter", "confirmed_unknown":
		return nil // no additional signal
	default:
		// Not cached: enqueue lookup (skip browser traffic)
		if conn.ALPN != "h2" && conn.ALPN != "h1" {
			select {
			case d.queue <- conn.ClientIP:
			default: // queue full, skip silently
			}
		}
		return nil
	}
}
