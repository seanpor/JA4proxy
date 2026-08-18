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
				log.WithError(err).Warn("asn_classifier: failed to open GeoLite2-ASN DB; country blocking and ASN enrichment disabled")
			} else {
				c.db = db
			}
		} else {
			log.WithField("path", cfg.DBPath).Warn(
				"asn_classifier: GeoIP database not found — country blocking and ASN enrichment disabled. " +
					"Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data or run: make update-geoip")
		}
	} else {
		log.Warn(
			"asn_classifier: no GeoIP database configured — country blocking and ASN enrichment disabled. " +
				"See docs/operations/EMERGENCY_DEPLOY.md for setup instructions")
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
	signals, _, _ := c.ClassifyAndLookup(clientIP)
	return signals
}

// ClassifyAndLookup returns the risk signals for clientIP along with the ASN
// number and organisation name the lookup resolved, so the caller can record
// the provenance of the connection rather than only its score.
//
// phase-827: the classifier resolved both values on every connection and then
// discarded them, keeping only a signal. That left the analytics node unable to
// tell a consumer ISP /24 from a hosting provider /24 — the single strongest
// provenance discriminator available, already computed on the hot path and
// thrown away. See docs/reference/GOOD_TRAFFIC_PROFILE.md §5-6.
//
// Returning them from the existing traversal rather than exposing a separate
// lookup keeps this at one DB read per connection; Classify remains as a
// wrapper so existing callers are unaffected.
//
// The ASN and org are returned WHENEVER the lookup succeeds, including on the
// paths that produce no signal at all (residential/mobile — the common case for
// legitimate traffic, and precisely the case worth being able to identify).
func (c *ASNClassifier) ClassifyAndLookup(clientIP string) ([]RiskSignal, uint32, string) {
	if !c.cfg.Enabled {
		return nil, 0, ""
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, 0, ""
	}

	// Check Tor exit list first
	if c.torExits[clientIP] {
		metrics.ASNClassificationTotal.WithLabelValues("tor").Inc()
		score := c.cfg.TorScore
		if score == 0 {
			score = 40
		}
		// Deliberately no ASN: the Tor list short-circuits before any DB read,
		// so reporting an ASN here would be an invention.
		return []RiskSignal{{
			Name:   "asn_tor",
			Score:  score,
			Reason: "IP is a known Tor exit node",
			Weight: 1.0,
		}}, 0, ""
	}

	asnNum, orgName, err := c.lookupFn(ip)
	if err != nil {
		c.log.WithError(err).WithField("ip", clientIP).Debug("asn_classifier: lookup failed")
		return nil, 0, ""
	}

	if orgName == "" && asnNum == 0 {
		return nil, 0, "" // DB absent
	}

	//nolint:gosec // ASN numbers are IANA-defined 32-bit values; safe to narrow from uint
	asn32 := uint32(asnNum)

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
		}}, asn32, orgName
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
		}}, asn32, orgName
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
			}}, asn32, orgName
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
			}}, asn32, orgName
		}
	}

	metrics.ASNClassificationTotal.WithLabelValues("residential").Inc()
	return nil, asn32, orgName // residential / mobile / unknown-benign
}

// IsDatacenter returns (true, asn) if clientIP belongs to a known datacenter ASN.
// Uses the same in-memory map as Classify — O(1), no Redis call.
func (c *ASNClassifier) IsDatacenter(clientIP string) (bool, uint32) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, 0
	}
	asnNum, orgName, err := c.lookupFn(ip)
	if err != nil || (asnNum == 0 && orgName == "") {
		return false, 0
	}
	if c.cfg.DatacenterASNs[asnNum] {
		return true, uint32(asnNum) //nolint:gosec // ASN numbers are IANA-defined 32-bit values; safe to narrow from uint
	}
	lowerOrg := strings.ToLower(orgName)
	for _, pat := range c.cfg.DatacenterOrgs {
		if strings.Contains(lowerOrg, strings.ToLower(pat)) {
			return true, uint32(asnNum) //nolint:gosec // ASN numbers are IANA-defined 32-bit values; safe to narrow from uint
		}
	}
	return false, 0
}
