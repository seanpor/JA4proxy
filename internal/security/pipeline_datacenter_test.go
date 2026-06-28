package security

import (
	"context"
	"net"
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
)

// mockLookupFn creates an ASNClassifier with a fixed lookup result.
func newDCClassifier(asnNum uint, orgName string, datacenterASNs map[uint]bool, orgs []string) *ASNClassifier {
	if datacenterASNs == nil {
		datacenterASNs = map[uint]bool{}
	}
	cfg := &ASNClassifierConfig{
		Enabled:        true,
		DatacenterASNs: datacenterASNs,
		DatacenterOrgs: orgs,
	}
	c := NewASNClassifier(cfg, nil)
	c.lookupFn = func(_ net.IP) (uint, string, error) {
		return asnNum, orgName, nil
	}
	return c
}

// ── IsDatacenter tests ────────────────────────────────────────────────────────

func TestASNClassifier_IsDatacenter_True(t *testing.T) {
	c := newDCClassifier(16509, "Amazon AWS", map[uint]bool{16509: true}, nil)
	ok, asn := c.IsDatacenter("1.2.3.4")
	if !ok {
		t.Error("want IsDatacenter=true for known datacenter ASN")
	}
	if asn != 16509 {
		t.Errorf("want asn=16509, got %d", asn)
	}
}

func TestASNClassifier_IsDatacenter_False(t *testing.T) {
	c := newDCClassifier(15169, "Google", map[uint]bool{16509: true}, nil)
	ok, _ := c.IsDatacenter("8.8.8.8")
	if ok {
		t.Error("want IsDatacenter=false for non-datacenter ASN")
	}
}

func TestASNClassifier_IsDatacenter_OrgMatch(t *testing.T) {
	c := newDCClassifier(14061, "DigitalOcean, LLC", nil, []string{"DigitalOcean"})
	ok, _ := c.IsDatacenter("1.2.3.4")
	if !ok {
		t.Error("want IsDatacenter=true when org matches DatacenterOrgs")
	}
}

func TestASNClassifier_IsDatacenter_InvalidIP(t *testing.T) {
	cfg := &ASNClassifierConfig{Enabled: true}
	c := NewASNClassifier(cfg, nil)
	ok, asn := c.IsDatacenter("not-an-ip")
	if ok || asn != 0 {
		t.Errorf("invalid IP: want (false,0), got (%v,%d)", ok, asn)
	}
}

func TestASNClassifier_IsDatacenter_NilDB(t *testing.T) {
	// No DB, lookupFn returns (0, "", nil) — not datacenter.
	cfg := &ASNClassifierConfig{Enabled: true, DatacenterASNs: map[uint]bool{}}
	c := NewASNClassifier(cfg, nil)
	// lookupFn defaults to real DB which is nil here — should return false, not panic.
	ok, _ := c.IsDatacenter("10.0.0.1")
	if ok {
		t.Error("no DB should return IsDatacenter=false")
	}
}

// ── Pipeline datacenter policy tests ─────────────────────────────────────────

// dcTestPipeline builds a pipeline with an injected ASN classifier that
// marks all IPs as belonging to asnNum.
func dcTestPipeline(t *testing.T, action string, exceptions []uint, asnNum uint) *Pipeline {
	t.Helper()
	r := &mockRedis{}
	cfg := &PipelineConfig{
		Whitelist: map[string]bool{},
		Blacklist: map[string]bool{},
		DatacenterPolicy: config.DatacenterPolicyConfig{
			Action:     action,
			Exceptions: exceptions,
			LogActions: false,
		},
	}
	p := NewPipeline(cfg, r, nil)
	// Inject classifier that always says "this IP is datacenter ASN asnNum".
	p.asnClassifier = newDCClassifier(asnNum, "TestDC Corp", map[uint]bool{asnNum: true}, nil)
	return p
}

func TestDatacenterPolicy_ScoreAction_PassesThrough(t *testing.T) {
	// action=score → datacenter IP flows to scorer, no early return.
	p := dcTestPipeline(t, "score", nil, 16509)
	conn := &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result != nil && result.BypassReason == "datacenter_policy" {
		t.Error("score action must not trigger datacenter_policy early return")
	}
}

func TestDatacenterPolicy_TarpitAction_EarlyReturn(t *testing.T) {
	// action=tarpit → datacenter IP returns "tarpit" before scorer.
	p := dcTestPipeline(t, "tarpit", nil, 16509)
	conn := &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result == nil {
		t.Fatal("expected PipelineResult, got nil")
	}
	if result.Action != "tarpit" {
		t.Errorf("want action=tarpit, got %q", result.Action)
	}
	if result.BypassReason != "datacenter_policy" {
		t.Errorf("want BypassReason=datacenter_policy, got %q", result.BypassReason)
	}
}

func TestDatacenterPolicy_BlockAction_EarlyReturn(t *testing.T) {
	// action=block → datacenter IP returns "block" before scorer.
	p := dcTestPipeline(t, "block", nil, 16509)
	conn := &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result == nil {
		t.Fatal("expected PipelineResult, got nil")
	}
	if result.Action != "block" {
		t.Errorf("want action=block, got %q", result.Action)
	}
}

func TestDatacenterPolicy_ExceptionASN_PassesThrough(t *testing.T) {
	// action=block, but 16509 is in exceptions → scored normally.
	p := dcTestPipeline(t, "block", []uint{16509}, 16509)
	conn := &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result != nil && result.BypassReason == "datacenter_policy" {
		t.Error("excepted ASN must not be blocked by datacenter policy")
	}
}

func TestDatacenterPolicy_NonDatacenterIP_Unaffected(t *testing.T) {
	// Non-datacenter IP with action=block → no early return from datacenter policy.
	r := &mockRedis{}
	cfg := &PipelineConfig{
		Whitelist: map[string]bool{},
		Blacklist: map[string]bool{},
		DatacenterPolicy: config.DatacenterPolicyConfig{
			Action:     "block",
			Exceptions: nil,
			LogActions: false,
		},
	}
	p := NewPipeline(cfg, r, nil)
	// Inject classifier that returns residential ASN (not in datacenter list).
	p.asnClassifier = newDCClassifier(15169, "Google", map[uint]bool{}, nil)
	conn := &ConnectionContext{ClientIP: "8.8.8.8", JA4: "t13d190900"}
	result := p.processInternal(context.Background(), conn)
	if result != nil && result.BypassReason == "datacenter_policy" {
		t.Error("non-datacenter IP must not be affected by datacenter policy")
	}
}

func TestDatacenterPolicy_ReplaceConfig_UpdatesPolicy(t *testing.T) {
	// ReplaceConfig swaps the datacenter policy atomically.
	// ReplaceConfig rebuilds the ASNClassifier from config, so we re-inject
	// the mock lookup after each swap.
	p := dcTestPipeline(t, "score", nil, 16509)
	conn := &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d190900"}

	// Initially score — no early return.
	r1 := p.processInternal(context.Background(), conn)
	if r1 != nil && r1.BypassReason == "datacenter_policy" {
		t.Error("initial score action should not block")
	}

	// Swap to tarpit; re-inject the mock classifier so IsDatacenter still works.
	newCfg := *p.cfg
	newCfg.DatacenterPolicy = config.DatacenterPolicyConfig{
		Action: "tarpit", Exceptions: nil, LogActions: false,
	}
	p.ReplaceConfig(&newCfg)
	p.asnClassifier = newDCClassifier(16509, "Amazon AWS", map[uint]bool{16509: true}, nil)

	r2 := p.processInternal(context.Background(), conn)
	if r2 == nil || r2.Action != "tarpit" {
		t.Errorf("after ReplaceConfig to tarpit, want action=tarpit, got %v", r2)
	}
}
