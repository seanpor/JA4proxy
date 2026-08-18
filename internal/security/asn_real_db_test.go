package security

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

// Phase 827 — verify a REAL, installed GeoLite2-ASN database actually resolves.
//
// Every other ASN test injects lookupFn, which is right for testing logic but
// means the whole suite passes with no database installed at all — exactly the
// state this repo was in, where asn_classifier.enabled was true, the .mmdb did
// not exist, and three scoring signals were silently dead.
//
// This test skips when the database is absent (CI has no MaxMind licence), so
// it cannot break the build. When the file IS present it proves the real thing
// works end to end: the file opens, lookups resolve, and the classifier
// produces the datacenter signal for datacenter space.
//
// A CSV download placed at this path would fail here rather than degrade
// silently to "DB absent" — which is the mistake worth catching, since the two
// formats are offered side by side on MaxMind's download page.

const realASNDB = "../../config/GeoLite2-ASN.mmdb"

func skipWithoutRealDB(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(realASNDB); err != nil {
		t.Skip("GeoLite2-ASN.mmdb not installed — see docs/runbooks/geoip_databases.md")
	}
}

func realClassifier(t *testing.T) *ASNClassifier {
	t.Helper()
	skipWithoutRealDB(t)
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	c := NewASNClassifier(&ASNClassifierConfig{
		Enabled:         true,
		DBPath:          realASNDB,
		DatacenterScore: 20,
		VPNScore:        10,
		UnknownScore:    5,
		TorScore:        40,
		DatacenterASNs:  map[uint]bool{16509: true, 15169: true},
		DatacenterOrgs:  []string{"amazon", "google", "cloudflare"},
	}, log)
	if c.db == nil {
		t.Fatal("database file exists but did not open — wrong format? " +
			"MaxMind offer CSV and .mmdb; only .mmdb works here")
	}
	return c
}

func TestRealASNDatabase_ResolvesWellKnownAddresses(t *testing.T) {
	c := realClassifier(t)

	cases := []struct {
		ip      string
		wantASN uint32
		wantOrg string
	}{
		{"8.8.8.8", 15169, "GOOGLE"},
		{"1.1.1.1", 13335, "CLOUDFLARENET"},
	}
	for _, tc := range cases {
		_, asn, org := c.ClassifyAndLookup(tc.ip)
		if asn != tc.wantASN {
			t.Errorf("%s: ASN = %d, want %d", tc.ip, asn, tc.wantASN)
		}
		if org == "" {
			t.Errorf("%s: organisation is empty — the event would carry no provenance", tc.ip)
		}
		t.Logf("%s -> AS%d %s", tc.ip, asn, org)
	}
}

func TestRealASNDatabase_ProducesDatacenterSignal(t *testing.T) {
	c := realClassifier(t)

	signals, asn, org := c.ClassifyAndLookup("8.8.8.8")
	if len(signals) != 1 || signals[0].Name != "asn_datacenter" {
		t.Fatalf("signals = %+v, want one asn_datacenter (AS%d %s)", signals, asn, org)
	}
	if signals[0].Score != 20 {
		t.Errorf("score = %d, want 20", signals[0].Score)
	}
}

func TestRealASNDatabase_PrivateSpaceHasNoProvenanceButDoesNotError(t *testing.T) {
	// RFC1918 is not in the database. This must read as "no data", not as a
	// failure, and must never invent an ASN — every container-to-container
	// connection in the POC stack lands here.
	c := realClassifier(t)
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1"} {
		signals, asn, org := c.ClassifyAndLookup(ip)
		if asn != 0 || org != "" {
			t.Errorf("%s: got AS%d %q, want no provenance for private space", ip, asn, org)
		}
		if len(signals) != 0 {
			t.Errorf("%s: private space produced signals %+v", ip, signals)
		}
	}
}
