package security

import (
	"context"
	"errors"
	"net"
	"testing"
)

// Phase 827 — the ASN and organisation must reach the connection event.
//
// WHY THIS EXISTS
// ---------------
// ASNClassifier resolved the ASN number and organisation name on every
// connection and then threw both away, keeping only a risk signal. The
// analytics node therefore could not tell a consumer ISP /24 from a hosting
// provider /24, and src/analytics/correlation.py declared `asn` and `asn_org`
// dimensions that nothing on earth could populate.
//
// That gap has teeth. The reference deployment serves an Irish web form, so its
// legitimate users arrive from CGNAT'd consumer ISPs where many unrelated
// people share one address — a shape indistinguishable from a scan on volume
// alone. Provenance is the discriminator, and it was being computed and
// discarded. See docs/reference/GOOD_TRAFFIC_PROFILE.md §5-6.
//
// The residential case below is the load-bearing one: it produces NO risk
// signal, so a naive implementation that only records provenance alongside a
// signal would leave exactly the traffic we most need to identify unlabelled.

func residentialLookup(asn uint, org string) func(net.IP) (uint, string, error) {
	return func(net.IP) (uint, string, error) { return asn, org, nil }
}

func TestClassifyAndLookup_ResidentialReturnsProvenanceDespiteNoSignal(t *testing.T) {
	// AS15502 / Vodafone Ireland — a real consumer ISP, the good-traffic case.
	c := newTestASNClassifier(defaultASNCfg(), residentialLookup(15502, "Vodafone Ireland"))

	signals, asn, org := c.ClassifyAndLookup("86.40.7.11")

	if len(signals) != 0 {
		t.Fatalf("residential IP must produce no risk signal, got %d: %+v", len(signals), signals)
	}
	if asn != 15502 {
		t.Errorf("ASN not reported for residential IP: got %d, want 15502 — "+
			"provenance must be recorded even when there is no signal, or the "+
			"legitimate traffic we most need to identify stays unlabelled", asn)
	}
	if org != "Vodafone Ireland" {
		t.Errorf("org = %q, want %q", org, "Vodafone Ireland")
	}
}

func TestClassifyAndLookup_ProvenanceAccompaniesEverySignallingPath(t *testing.T) {
	cases := []struct {
		name       string
		asn        uint
		org        string
		wantSignal string
	}{
		{"datacenter_by_asn", 16509, "Amazon", "asn_datacenter"},
		{"datacenter_by_org", 64512, "DigitalOcean LLC", "asn_datacenter"},
		{"vpn", 64513, "NordVPN", "asn_vpn"},
		{"unknown_org", 64514, "", "asn_unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestASNClassifier(defaultASNCfg(), residentialLookup(tc.asn, tc.org))
			signals, asn, org := c.ClassifyAndLookup("203.0.113.9")

			if len(signals) != 1 || signals[0].Name != tc.wantSignal {
				t.Fatalf("signals = %+v, want one %s", signals, tc.wantSignal)
			}
			if asn != uint32(tc.asn) {
				t.Errorf("ASN = %d, want %d", asn, tc.asn)
			}
			if org != tc.org {
				t.Errorf("org = %q, want %q", org, tc.org)
			}
		})
	}
}

// Absence must remain distinguishable from a real answer — never defaulted to
// a guess. A fabricated ASN would be worse than none: it would let an operator
// act on provenance that was never observed.
func TestClassifyAndLookup_FailsOpenWithoutInventingProvenance(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *ASNClassifierConfig
		lookup  func(net.IP) (uint, string, error)
		clientI string
	}{
		{"disabled", &ASNClassifierConfig{Enabled: false}, residentialLookup(15502, "Vodafone"), "86.40.7.11"},
		{"unparseable_ip", defaultASNCfg(), residentialLookup(15502, "Vodafone"), "not-an-ip"},
		{"lookup_error", defaultASNCfg(), func(net.IP) (uint, string, error) {
			return 0, "", errors.New("db read failed")
		}, "86.40.7.11"},
		{"db_absent", defaultASNCfg(), residentialLookup(0, ""), "86.40.7.11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestASNClassifier(tc.cfg, tc.lookup)
			_, asn, org := c.ClassifyAndLookup(tc.clientI)
			if asn != 0 || org != "" {
				t.Errorf("got ASN=%d org=%q, want zero values — an unavailable "+
					"lookup must not be reported as a result", asn, org)
			}
		})
	}
}

// The Tor list short-circuits before any DB read, so there is genuinely
// nothing to report. Asserted explicitly so a later "improvement" that fills
// these in from a second lookup is a deliberate choice, not an accident.
func TestClassifyAndLookup_TorPathReportsNoProvenance(t *testing.T) {
	c := newTestASNClassifier(defaultASNCfg(), residentialLookup(15502, "Vodafone Ireland"))
	c.torExits["203.0.113.7"] = true

	signals, asn, org := c.ClassifyAndLookup("203.0.113.7")
	if len(signals) != 1 || signals[0].Name != "asn_tor" {
		t.Fatalf("signals = %+v, want one asn_tor", signals)
	}
	if asn != 0 || org != "" {
		t.Errorf("got ASN=%d org=%q; the Tor path never reads the DB", asn, org)
	}
}

// Classify is now a wrapper. Its callers and their tests must be unaffected.
func TestClassify_WrapperMatchesClassifyAndLookup(t *testing.T) {
	for _, tc := range []struct {
		asn uint
		org string
	}{
		{16509, "Amazon"}, {15502, "Vodafone Ireland"}, {64513, "NordVPN"}, {0, ""},
	} {
		c := newTestASNClassifier(defaultASNCfg(), residentialLookup(tc.asn, tc.org))
		want, _, _ := c.ClassifyAndLookup("203.0.113.9")
		got := c.Classify("203.0.113.9")

		if len(got) != len(want) {
			t.Fatalf("asn=%d org=%q: Classify returned %d signals, ClassifyAndLookup %d",
				tc.asn, tc.org, len(got), len(want))
		}
		for i := range got {
			if got[i].Name != want[i].Name || got[i].Score != want[i].Score {
				t.Errorf("asn=%d: signal %d differs: %+v vs %+v", tc.asn, i, got[i], want[i])
			}
		}
	}
}

// The plumbing that actually matters: Process must leave the provenance on the
// ConnectionContext, because that struct is what cmd/ja4pd marshals into the
// ECS connection event. A classifier that resolves the ASN correctly is worth
// nothing if the value never leaves the classifier — which was the bug.
func TestPipeline_ProcessRecordsASNProvenanceOnContext(t *testing.T) {
	p := NewPipeline(&PipelineConfig{
		Whitelist: map[string]bool{},
		Blacklist: map[string]bool{},
	}, &mockRedis{dial: 100}, nil)
	p.Sync = true
	p.asnClassifier = newTestASNClassifier(
		defaultASNCfg(), residentialLookup(15502, "Vodafone Ireland"),
	)

	conn := &ConnectionContext{
		ParsedIP: net.ParseIP("86.40.7.11"),
		ClientIP: "86.40.7.11",
		JA4:      "t13d1516h2_8daaf6152771_b0da82dd1658",
	}
	p.Process(context.Background(), conn)

	if conn.ASN != 15502 {
		t.Errorf("conn.ASN = %d, want 15502 — the pipeline resolved it and "+
			"dropped it, so the connection event carries no provenance", conn.ASN)
	}
	if conn.ASNOrg != "Vodafone Ireland" {
		t.Errorf("conn.ASNOrg = %q, want %q", conn.ASNOrg, "Vodafone Ireland")
	}
}

// The bug the tests above missed, and why they missed it.
//
// TestPipeline_ProcessRecordsASNProvenanceOnContext sets Pipeline.Sync, which
// runs processInternal inline. Production does NOT: Process() enqueues to
// workChan and returns immediately, and cmd/ja4pd marshals the ECS event from
// the ConnectionContext as soon as Process() returns. Setting conn.ASN inside
// processInternal therefore happened on a worker goroutine AFTER the event had
// already been written, so client.as.number was 0 on every event in production
// while the whole suite passed.
//
// Found by reading a live event off events:connection, not by testing. These
// pin the ordering so it cannot regress.

func TestPipeline_ASNProvenanceIsSetOnTheAsyncPath(t *testing.T) {
	p := NewPipeline(&PipelineConfig{
		Whitelist: map[string]bool{},
		Blacklist: map[string]bool{},
	}, &mockRedis{dial: 100}, nil)
	p.Sync = false // production default — the mode that was broken
	p.asnClassifier = newTestASNClassifier(
		defaultASNCfg(), residentialLookup(15502, "Vodafone Ireland"),
	)

	conn := &ConnectionContext{
		ParsedIP: net.ParseIP("86.40.7.11"),
		ClientIP: "86.40.7.11",
		JA4:      "t13d1516h2_8daaf6152771_b0da82dd1658",
	}
	// No wait, no sleep: the value must be present the instant Process returns,
	// because that is when the caller builds the event.
	p.Process(context.Background(), conn)

	if conn.ASN != 15502 || conn.ASNOrg != "Vodafone Ireland" {
		t.Fatalf("got AS%d %q immediately after Process() on the async path; "+
			"the ECS event is marshalled at exactly this moment, so anything "+
			"resolved later never reaches it", conn.ASN, conn.ASNOrg)
	}
}

// Provenance must survive the early returns too — each one skips
// processInternal completely.
func TestPipeline_ASNProvenanceSurvivesEarlyReturns(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Pipeline, *ConnectionContext)
	}{
		{"hard_block_blacklisted_ja4", func(p *Pipeline, c *ConnectionContext) {
			p.cfg.Blacklist = map[string]bool{c.JA4: true}
			p.cfg.JA4BlockingEnabled = true
		}},
		{"manual_ban", func(p *Pipeline, c *ConnectionContext) {
			p.redis = &mockRedis{dial: 100, data: map[string]string{
				"ban:" + c.ClientIP: "manual",
			}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPipeline(&PipelineConfig{
				Whitelist: map[string]bool{},
				Blacklist: map[string]bool{},
			}, &mockRedis{dial: 100}, nil)
			p.asnClassifier = newTestASNClassifier(
				defaultASNCfg(), residentialLookup(16509, "Amazon"),
			)
			conn := &ConnectionContext{
				ParsedIP: net.ParseIP("203.0.113.9"),
				ClientIP: "203.0.113.9",
				JA4:      "t13d091100_f91f431d341e_8e6e362c5eac",
			}
			tc.setup(p, conn)

			p.Process(context.Background(), conn)

			if conn.ASN != 16509 {
				t.Errorf("ASN = %d, want 16509 — a blocked connection is the "+
					"case an operator most wants provenance for", conn.ASN)
			}
		})
	}
}
