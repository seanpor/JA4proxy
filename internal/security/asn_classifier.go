package security

import (
	"net"
	"os"
	"strings"

	"github.com/oschwald/geoip2-golang"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
)

// ASNClassifierConfig configures ASN-based risk classification.
type ASNClassifierConfig struct {
	Enabled            bool
	DBPath             string
	TorExitListPath    string
	DatacenterListPath string
	DatacenterScore    int // default 20
	TorScore           int // default 40
	VPNScore           int // default 10
	UnknownScore       int // default 5
	DatacenterASNs     map[uint]bool
	DatacenterOrgs     []string
}

// datacenterListYAML matches the schema of config/asn_datacenter_list.yml
type datacenterListYAML struct {
	ASNS map[uint]string `yaml:"asns"`
	Orgs []string        `yaml:"orgs"`
}

// ASNClassifier classifies IPs by ASN: datacenter, Tor, VPN, or residential.
type ASNClassifier struct {
	db       *geoip2.Reader
	torExits map[string]bool
	cfg      *ASNClassifierConfig
	log      *logrus.Logger
	// lookupFn is used in tests to inject mock results
	lookupFn func(ip net.IP) (asnNum uint, orgName string, err error)
}

// vpnPatterns are case-insensitive substrings that identify VPN ASNs.
var vpnPatterns = []string{
	"vpn", "proxy", "tunnel", "anonymiz", "hide",
	"private internet", "nordvpn", "expressvpn", "surfshark",
}

// NewASNClassifier creates a classifier. If DBPath doesn't exist, returns a
// no-op classifier (fail open — no signals).
func NewASNClassifier(cfg *ASNClassifierConfig, log *logrus.Logger) *ASNClassifier {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &ASNClassifierConfig{}
	}
	c := &ASNClassifier{cfg: cfg, log: log, torExits: make(map[string]bool)}

	// Load datacenter list if path provided
	if cfg.DatacenterListPath != "" {
		if data, err := os.ReadFile(cfg.DatacenterListPath); err == nil {
			var dl datacenterListYAML
			if err := yaml.Unmarshal(data, &dl); err == nil {
				if cfg.DatacenterASNs == nil {
					cfg.DatacenterASNs = make(map[uint]bool)
				}
				for asn := range dl.ASNS {
					cfg.DatacenterASNs[asn] = true
				}
				cfg.DatacenterOrgs = append(cfg.DatacenterOrgs, dl.Orgs...)
				log.WithFields(logrus.Fields{
					"asns": len(dl.ASNS),
					"orgs": len(dl.Orgs),
				}).Info("asn_classifier: loaded datacenter list")
			} else {
				log.WithError(err).Warn("asn_classifier: failed to parse datacenter list YAML")
			}
		}
	}

	// Load MaxMind DB
	if cfg.DBPath != "" {
		if _, err := os.Stat(cfg.DBPath); err == nil {
			db, err := geoip2.Open(cfg.DBPath)
			if err != nil {
				log.WithError(err).Warn("asn_classifier: failed to open GeoLite2-ASN DB; signals disabled")
			} else {
				c.db = db
			}
		}
	}

	// Load Tor exit list
	if cfg.TorExitListPath != "" {
		if data, err := os.ReadFile(cfg.TorExitListPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					c.torExits[line] = true
				}
			}
			metrics.TorExitListEntries.Set(float64(len(c.torExits)))
		}
	}

	// Default lookup function uses the real DB
	c.lookupFn = func(ip net.IP) (uint, string, error) {
		if c.db == nil {
			return 0, "", nil
		}
		record, err := c.db.ASN(ip)
		if err != nil {
			return 0, "", err
		}
		return uint(record.AutonomousSystemNumber), record.AutonomousSystemOrganization, nil
	}

	return c
}

// Classify returns risk signals for the given IP address.
// Returns empty slice if DB absent or IP lookup fails (fail open).
func (c *ASNClassifier) Classify(clientIP string) []RiskSignal {
	if !c.cfg.Enabled {
		return nil
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	// Check Tor exit list first
	if c.torExits[clientIP] {
		metrics.ASNClassificationTotal.WithLabelValues("tor").Inc()
		score := c.cfg.TorScore
		if score == 0 {
			score = 40
		}
		return []RiskSignal{{
			Name:   "asn_tor",
			Score:  score,
			Reason: "IP is a known Tor exit node",
			Weight: 1.0,
		}}
	}

	asnNum, orgName, err := c.lookupFn(ip)
	if err != nil {
		c.log.WithError(err).WithField("ip", clientIP).Debug("asn_classifier: lookup failed")
		return nil
	}

	if orgName == "" && asnNum == 0 {
		return nil // DB absent
	}

	if orgName == "" {
		metrics.ASNClassificationTotal.WithLabelValues("unknown").Inc()
		score := c.cfg.UnknownScore
		if score == 0 {
			score = 5
		}
		return []RiskSignal{{
			Name:   "asn_unknown",
			Score:  score,
			Reason: "ASN lookup returned empty org name",
			Weight: 1.0,
		}}
	}

	lowerOrg := strings.ToLower(orgName)

	// Datacenter check
	if c.cfg.DatacenterASNs[asnNum] {
		metrics.ASNClassificationTotal.WithLabelValues("datacenter").Inc()
		score := c.cfg.DatacenterScore
		if score == 0 {
			score = 20
		}
		return []RiskSignal{{
			Name:   "asn_datacenter",
			Score:  score,
			Reason: "IP belongs to a known datacenter ASN",
			Weight: 1.0,
		}}
	}
	for _, pat := range c.cfg.DatacenterOrgs {
		if strings.Contains(lowerOrg, strings.ToLower(pat)) {
			metrics.ASNClassificationTotal.WithLabelValues("datacenter").Inc()
			score := c.cfg.DatacenterScore
			if score == 0 {
				score = 20
			}
			return []RiskSignal{{
				Name:   "asn_datacenter",
				Score:  score,
				Reason: "IP org name matches datacenter pattern",
				Weight: 1.0,
			}}
		}
	}

	// VPN check
	for _, pat := range vpnPatterns {
		if strings.Contains(lowerOrg, pat) {
			metrics.ASNClassificationTotal.WithLabelValues("vpn").Inc()
			score := c.cfg.VPNScore
			if score == 0 {
				score = 10
			}
			return []RiskSignal{{
				Name:   "asn_vpn",
				Score:  score,
				Reason: "IP org name matches VPN pattern",
				Weight: 1.0,
			}}
		}
	}

	metrics.ASNClassificationTotal.WithLabelValues("residential").Inc()
	return nil // residential / mobile / unknown-benign
}
