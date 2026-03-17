package security

import (
	"errors"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

// newTestASNClassifier creates a classifier with an injected lookup function.
func newTestASNClassifier(cfg *ASNClassifierConfig, lookupFn func(net.IP) (uint, string, error)) *ASNClassifier {
	c := &ASNClassifier{cfg: cfg, log: logrus.New(), torExits: make(map[string]bool)}
	c.lookupFn = lookupFn
	return c
}

func defaultASNCfg() *ASNClassifierConfig {
	return &ASNClassifierConfig{
		Enabled:         true,
		DatacenterScore: 20,
		TorScore:        40,
		VPNScore:        10,
		UnknownScore:    5,
		DatacenterASNs:  map[uint]bool{16509: true}, // AWS
		DatacenterOrgs:  []string{"amazon", "google", "microsoft", "digitalocean"},
	}
}

func TestASNClassifier_NoDB_NoSignal(t *testing.T) {
	cfg := defaultASNCfg()
	cfg.Enabled = false
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 16509, "AMAZON-02", nil
	})
	sigs := c.Classify("1.2.3.4")
	if len(sigs) != 0 {
		t.Errorf("disabled: expected no signals, got %d", len(sigs))
	}
}

func TestASNClassifier_TorIP_Signal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 0, "Some ISP", nil
	})
	c.torExits["1.2.3.4"] = true
	sigs := c.Classify("1.2.3.4")
	if len(sigs) == 0 {
		t.Fatal("Tor IP: expected signal")
	}
	if sigs[0].Name != "asn_tor" {
		t.Errorf("expected 'asn_tor', got %q", sigs[0].Name)
	}
}

func TestASNClassifier_DatacenterASN_Signal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 16509, "AMAZON-02", nil // ASN 16509 is in DatacenterASNs
	})
	sigs := c.Classify("54.239.28.85")
	if len(sigs) == 0 {
		t.Fatal("datacenter ASN: expected signal")
	}
	if sigs[0].Name != "asn_datacenter" {
		t.Errorf("expected 'asn_datacenter', got %q", sigs[0].Name)
	}
}

func TestASNClassifier_DatacenterOrg_Signal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 99999, "DigitalOcean LLC", nil // org pattern match
	})
	sigs := c.Classify("192.0.2.1")
	if len(sigs) == 0 {
		t.Fatal("datacenter org: expected signal")
	}
	if sigs[0].Name != "asn_datacenter" {
		t.Errorf("expected 'asn_datacenter', got %q", sigs[0].Name)
	}
}

func TestASNClassifier_VPNOrg_Signal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 12345, "NordVPN Networks", nil
	})
	sigs := c.Classify("1.2.3.5")
	if len(sigs) == 0 {
		t.Fatal("VPN org: expected signal")
	}
	if sigs[0].Name != "asn_vpn" {
		t.Errorf("expected 'asn_vpn', got %q", sigs[0].Name)
	}
}

func TestASNClassifier_ResidentialOrg_NoSignal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 7922, "Comcast Cable Communications LLC", nil
	})
	sigs := c.Classify("1.2.3.6")
	if len(sigs) != 0 {
		t.Errorf("residential org: expected no signals, got %v", sigs)
	}
}

func TestASNClassifier_UnknownOrg_Signal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 99998, "", nil // empty org name → unknown signal
	})
	sigs := c.Classify("1.2.3.7")
	if len(sigs) == 0 {
		t.Fatal("unknown org: expected signal")
	}
	if sigs[0].Name != "asn_unknown" {
		t.Errorf("expected 'asn_unknown', got %q", sigs[0].Name)
	}
}

func TestASNClassifier_LookupError_NoSignal(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 0, "", errors.New("lookup failed")
	})
	sigs := c.Classify("1.2.3.8")
	if len(sigs) != 0 {
		t.Errorf("lookup error: expected no signals (fail open), got %d", len(sigs))
	}
}
