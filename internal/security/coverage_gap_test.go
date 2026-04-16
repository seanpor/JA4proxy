package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// ─── AbuseIPDB: Start, worker, lookup ──────────────────────────────────────

func TestAbuseIPDB_Start_WorkerProcessesQueue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"abuseConfidenceScore": 42},
		})
	}))
	defer srv.Close()

	redis := newMockRedisRW()
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(srv.URL), redis, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)

	// Enqueue an IP
	a.queue <- "10.0.0.1"
	// Wait briefly for the worker to process
	time.Sleep(100 * time.Millisecond)

	if v, ok := a.localCache.Get("10.0.0.1"); !ok || v.(int) != 42 {
		t.Errorf("worker should have cached confidence=42, got %v, ok=%v", v, ok)
	}
	cancel()
}

func TestAbuseIPDB_Worker_CancelStops(t *testing.T) {
	a := NewAbuseIPDB(&AbuseIPDBConfig{Enabled: true, Workers: 1}, &mockRedis{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	a.Start(ctx)
	cancel()
	// Worker should exit cleanly without hanging
	time.Sleep(50 * time.Millisecond)
}

func TestAbuseIPDB_Lookup_NoAPIKey_Noop(t *testing.T) {
	a := NewAbuseIPDB(&AbuseIPDBConfig{Enabled: true, APIKey: ""}, &mockRedis{}, nil)
	a.lookup(context.Background(), "1.2.3.4")
	// Should return immediately without error
	if _, ok := a.localCache.Get("1.2.3.4"); ok {
		t.Error("no API key: should not cache anything")
	}
}

func TestAbuseIPDB_Lookup_BadJSON_FailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	redis := newMockRedisRW()
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(srv.URL), redis, nil)
	a.lookup(context.Background(), "1.2.3.4")
	if _, ok := a.localCache.Get("1.2.3.4"); ok {
		t.Error("bad JSON: should not cache anything")
	}
}

func TestAbuseIPDB_Lookup_HTTPError_FailOpen(t *testing.T) {
	// Use an invalid URL that will cause a connection error
	redis := newMockRedisRW()
	cfg := defaultAbuseIPDBCfg("http://127.0.0.1:1")
	a := NewAbuseIPDB(cfg, redis, nil)
	a.lookup(context.Background(), "1.2.3.4")
	if _, ok := a.localCache.Get("1.2.3.4"); ok {
		t.Error("HTTP error: should not cache anything")
	}
}

func TestAbuseIPDB_Lookup_DefaultAPIURL(t *testing.T) {
	// When APIURL is empty, it should use the default
	redis := newMockRedisRW()
	cfg := &AbuseIPDBConfig{Enabled: true, APIKey: "test-key", APIURL: ""}
	a := NewAbuseIPDB(cfg, redis, nil)
	// Cancel context immediately so the request fails fast
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.lookup(ctx, "1.2.3.4")
	// Just verifying no panic
}

func TestAbuseIPDB_GetSignal_NoRedis_EnqueuesLookup(t *testing.T) {
	a := NewAbuseIPDB(&AbuseIPDBConfig{Enabled: true}, nil, nil)
	sig := a.GetSignal("1.2.3.4")
	if sig != nil {
		t.Error("no redis, not cached: expected nil signal")
	}
	select {
	case ip := <-a.queue:
		if ip != "1.2.3.4" {
			t.Errorf("enqueued %q, want 1.2.3.4", ip)
		}
	default:
		t.Error("expected IP to be enqueued")
	}
}

func TestAbuseIPDB_GetSignal_RedisCacheInvalidValue(t *testing.T) {
	r := newMockRedisRW()
	r.strings["abuseipdb:1.2.3.4"] = "not-a-number"
	a := NewAbuseIPDB(defaultAbuseIPDBCfg(""), r, nil)
	sig := a.GetSignal("1.2.3.4")
	// Should fall through to enqueue
	if sig != nil {
		t.Error("invalid redis value: expected nil signal")
	}
}

func TestAbuseIPDB_ComputeScore_DefaultCap(t *testing.T) {
	a := NewAbuseIPDB(&AbuseIPDBConfig{}, &mockRedis{}, nil)
	// ScoreCap=0 defaults to 40, SharedIPThreshold=0 defaults to 50
	score := a.computeScore(100)
	if score != 40 {
		t.Errorf("default cap: expected 40, got %d", score)
	}
}

// ─── DNS Enrichment: Start, worker, enrich ─────────────────────────────────

func TestDNSEnrichment_Start_WorkerExitsOnCancel(t *testing.T) {
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), newMockRedisRW(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	cancel()
	time.Sleep(50 * time.Millisecond)
	// No hang = pass
}

func TestDNSEnrichment_GetSignal_CachedDatacenter_NoSignal(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "confirmed_datacenter"
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"})
	if sig != nil {
		t.Errorf("confirmed_datacenter: expected nil (no additional signal), got %v", sig)
	}
}

func TestDNSEnrichment_GetSignal_CachedUnknown_NoSignal(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "confirmed_unknown"
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"})
	if sig != nil {
		t.Errorf("confirmed_unknown: expected nil, got %v", sig)
	}
}

func TestDNSEnrichment_GetSignal_QueueFull_Drops(t *testing.T) {
	r := newMockRedisRW()
	cfg := defaultDNSEnrichmentCfg()
	d := NewDNSEnrichment(cfg, r, nil)
	// Fill the queue
	for i := 0; i < 1000; i++ {
		select {
		case d.queue <- "fill":
		default:
		}
	}
	// Now try to enqueue another
	sig := d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", ALPN: "tls"})
	if sig != nil {
		t.Error("queue full: expected nil signal")
	}
}

func TestDNSEnrichment_GetSignal_H1ALPN_NeverEnqueued(t *testing.T) {
	r := newMockRedisRW()
	d := NewDNSEnrichment(defaultDNSEnrichmentCfg(), r, nil)
	d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", ALPN: "h1"})
	select {
	case <-d.queue:
		t.Error("h1 ALPN: should not enqueue")
	default:
	}
}

func TestDNSEnrichment_GetSignal_DefaultScores(t *testing.T) {
	r := newMockRedisRW()
	r.strings["dns:fcrdns:1.2.3.4"] = "no_ptr"
	// Use zero values to trigger defaults
	d := NewDNSEnrichment(&DNSEnrichmentConfig{Enabled: true}, r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"})
	if sig == nil {
		t.Fatal("expected signal for no_ptr")
	}
	if sig.Score != 15 { // default NoPTRScore
		t.Errorf("expected default score 15, got %d", sig.Score)
	}
}

// ─── RDAP: Start, worker, enrich, maybeExpandBlock ─────────────────────────

func TestRDAP_Start_WorkerExitsOnCancel(t *testing.T) {
	r := NewRDAPEnricher(defaultRDAPCfg(), &mockRedis{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestRDAP_Enrich_HTTPError_FailOpen(t *testing.T) {
	cfg := defaultRDAPCfg()
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	// Use cancelled context for fast failure
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.enrich(ctx, rdapJob{ip: "1.2.3.4", score: 80})
	// Should not panic
}

func TestRDAP_Enrich_WithBlockExpansion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":   "evil hosting",
			"handle": "EVIL-1",
		})
	}))
	defer srv.Close()

	redis := newMockRedisRW()
	cfg := &RDAPConfig{
		Enabled:               true,
		BlockExpansionEnabled: true,
		MinTriggerScore:       50,
		RequireKnownBadOrg:    false,
		KnownBadOrgs: []KnownBadOrgEntry{
			{Name: "evil hosting", Score: 45, Reason: "bulletproof"},
		},
	}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.http = srv.Client()
	// Override the HTTP URL by adjusting the transport
	origURL := srv.URL
	r.http = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &rewriteTransport{base: http.DefaultTransport, url: origURL},
	}
	r.enrich(context.Background(), rdapJob{ip: "1.2.3.4", score: 80, alpn: "tls"})

	// Check that ban_cidr was set
	if _, ok := redis.setValues["ban_cidr:1.2.3.0/24"]; !ok {
		t.Error("expected ban_cidr to be set for /24")
	}
}

// rewriteTransport rewrites requests to the test server URL.
type rewriteTransport struct {
	base http.RoundTripper
	url  string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	parsed, _ := http.NewRequest(req.Method, t.url+req.URL.Path, req.Body)
	newReq.URL = parsed.URL
	return t.base.RoundTrip(newReq)
}

func TestRDAP_MaybeExpandBlock_BelowScore_Noop(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{
		Enabled:            true,
		MinTriggerScore:    75,
		RequireKnownBadOrg: false,
	}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.maybeExpandBlock(context.Background(), "1.2.3.4", "", "", 50)
	if len(redis.setValues) != 0 {
		t.Error("below score threshold: should not expand block")
	}
}

func TestRDAP_MaybeExpandBlock_RequireKnownBad_NoMatch(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{
		Enabled:            true,
		MinTriggerScore:    50,
		RequireKnownBadOrg: true,
		KnownBadOrgs:      []KnownBadOrgEntry{{Name: "evil hosting"}},
	}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.maybeExpandBlock(context.Background(), "1.2.3.4", "GOOD-1", "Good Corp", 80)
	if len(redis.setValues) != 0 {
		t.Error("require known bad but no match: should not expand")
	}
}

func TestRDAP_MaybeExpandBlock_IPv4(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{
		Enabled:            true,
		MinTriggerScore:    50,
		RequireKnownBadOrg: false,
	}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.maybeExpandBlock(context.Background(), "192.168.1.100", "", "", 80)
	if _, ok := redis.setValues["ban_cidr:192.168.1.0/24"]; !ok {
		t.Error("expected IPv4 /24 ban_cidr")
	}
}

func TestRDAP_MaybeExpandBlock_IPv6(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{
		Enabled:            true,
		MinTriggerScore:    50,
		RequireKnownBadOrg: false,
	}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.maybeExpandBlock(context.Background(), "2001:db8:1234:5678::1", "", "", 80)
	found := false
	for k := range redis.setValues {
		if k == "ban_cidr:2001:db8:1234::/48" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected IPv6 /48 ban_cidr, got keys: %v", redis.setValues)
	}
}

func TestRDAP_MaybeExpandBlock_InvalidIP_Noop(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{Enabled: true, MinTriggerScore: 50, RequireKnownBadOrg: false}
	r := NewRDAPEnricher(cfg, redis, nil)
	r.maybeExpandBlock(context.Background(), "not-an-ip", "", "", 80)
	if len(redis.setValues) != 0 {
		t.Error("invalid IP: should not expand")
	}
}

func TestRDAP_MaybeExpandBlock_DefaultMinScore(t *testing.T) {
	redis := newMockRedisRW()
	cfg := &RDAPConfig{Enabled: true, MinTriggerScore: 0, RequireKnownBadOrg: false}
	r := NewRDAPEnricher(cfg, redis, nil)
	// Default minScore is 75; score=76 should trigger
	r.maybeExpandBlock(context.Background(), "1.2.3.4", "", "", 76)
	if _, ok := redis.setValues["ban_cidr:1.2.3.0/24"]; !ok {
		t.Error("default min score 75, score 76: should expand")
	}
}

func TestRDAP_NewRDAPEnricher_LoadKnownBadOrgsFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "known_bad_orgs_*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("orgs:\n  - handle: BAD-1\n    name: Bad Corp\n    reason: bulletproof\n    score: 50\n")
	tmpFile.Close()

	cfg := &RDAPConfig{KnownBadOrgsPath: tmpFile.Name()}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	if len(r.cfg.KnownBadOrgs) != 1 {
		t.Errorf("expected 1 known bad org, got %d", len(r.cfg.KnownBadOrgs))
	}
}

func TestRDAP_NewRDAPEnricher_BadYAMLPath(t *testing.T) {
	cfg := &RDAPConfig{KnownBadOrgsPath: "/nonexistent/file.yml"}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	if len(r.cfg.KnownBadOrgs) != 0 {
		t.Error("nonexistent file: should have zero known bad orgs")
	}
}

func TestRDAP_NewRDAPEnricher_InvalidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bad_yaml_*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not: [valid: yaml: {{{{")
	tmpFile.Close()

	cfg := &RDAPConfig{KnownBadOrgsPath: tmpFile.Name()}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	if len(r.cfg.KnownBadOrgs) != 0 {
		t.Error("invalid YAML: should have zero known bad orgs")
	}
}

func TestRDAP_GetSignals_IsUnknown_NoSignals(t *testing.T) {
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": `{"is_unknown": true}`,
		},
	}
	r := NewRDAPEnricher(defaultRDAPCfg(), mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"}, 80)
	if len(sigs) != 0 {
		t.Errorf("is_unknown=true: expected no signals, got %d", len(sigs))
	}
}

func TestRDAP_GetSignals_BadJSON_NoSignals(t *testing.T) {
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": `not json`,
		},
	}
	r := NewRDAPEnricher(defaultRDAPCfg(), mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"}, 80)
	if len(sigs) != 0 {
		t.Errorf("bad JSON: expected no signals, got %d", len(sigs))
	}
}

func TestRDAP_GetSignals_DefaultMinTriggerScore(t *testing.T) {
	cfg := &RDAPConfig{Enabled: true, MinTriggerScore: 0}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	// Default MinTriggerScore is 20; trigger=25 should enqueue
	r.GetSignals(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"}, 25)
	select {
	case job := <-r.queue:
		if job.ip != "1.2.3.4" {
			t.Errorf("expected 1.2.3.4, got %s", job.ip)
		}
	default:
		t.Error("score above default threshold: should enqueue")
	}
}

func TestRDAP_GetSignals_KnownBadOrg_DefaultScore(t *testing.T) {
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": `{"org_name": "evil hosting", "org_handle": "EVIL-1", "is_unknown": false}`,
		},
	}
	cfg := &RDAPConfig{
		Enabled:          true,
		KnownBadOrgScore: 0, // Should default to 45
		KnownBadOrgs: []KnownBadOrgEntry{
			{Name: "evil hosting", Score: 0, Reason: "bulletproof"}, // entry score 0 -> default
		},
	}
	r := NewRDAPEnricher(cfg, mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4"}, 80)
	if len(sigs) == 0 {
		t.Fatal("expected known bad org signal")
	}
	if sigs[0].Score != 45 {
		t.Errorf("expected default score 45, got %d", sigs[0].Score)
	}
}

func TestRDAP_CheckKnownBad_ByHandle(t *testing.T) {
	cfg := &RDAPConfig{
		KnownBadOrgs: []KnownBadOrgEntry{
			{Handle: "EVIL-1", Name: "", Reason: "bulletproof"},
		},
	}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	match, entry := r.checkKnownBad("EVIL-1", "some org")
	if !match {
		t.Error("expected match by handle")
	}
	if entry == nil {
		t.Error("expected non-nil entry")
	}
}

func TestRDAP_CheckKnownBad_NoOrgs(t *testing.T) {
	cfg := &RDAPConfig{KnownBadOrgs: nil}
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	match, _ := r.checkKnownBad("ANY", "Any Org")
	if match {
		t.Error("no orgs configured: should not match")
	}
}

// ─── Pipeline: UpdateSets, UpdateDynamicCIDRs, StartBackgroundWorkers ──────

func TestPipeline_UpdateSets(t *testing.T) {
	p := newTestPipeline(0)
	newWhitelist := map[string]bool{"newja4": true}
	newBlacklist := map[string]bool{"badja4": true}
	p.UpdateSets(newWhitelist, newBlacklist)
	if !p.Whitelist["newja4"] {
		t.Error("whitelist not updated")
	}
	if !p.Blacklist["badja4"] {
		t.Error("blacklist not updated")
	}
}

func TestPipeline_UpdateDynamicCIDRs(t *testing.T) {
	p := newTestPipeline(0)
	p.UpdateDynamicCIDRs([]string{"10.0.0.0/8", "2001:db8::/32"})

	// Test IPv4 match
	p.mu.RLock()
	ip4 := net.ParseIP("10.1.2.3")
	contains4, _ := p.dynamicCIDR.Contains(ip4)
	p.mu.RUnlock()
	if !contains4 {
		t.Error("10.1.2.3 should be in dynamic CIDR 10.0.0.0/8")
	}

	// Test IPv6 match
	p.mu.RLock()
	ip6 := net.ParseIP("2001:db8::1")
	contains6, _ := p.dynamicCIDR.Contains(ip6)
	p.mu.RUnlock()
	if !contains6 {
		t.Error("2001:db8::1 should be in dynamic CIDR 2001:db8::/32")
	}
}

func TestPipeline_UpdateDynamicCIDRs_PlainIPs(t *testing.T) {
	p := newTestPipeline(0)
	p.UpdateDynamicCIDRs([]string{"1.2.3.4", "2001:db8::1"})

	p.mu.RLock()
	ip4 := net.ParseIP("1.2.3.4")
	c4, _ := p.dynamicCIDR.Contains(ip4)
	ip6 := net.ParseIP("2001:db8::1")
	c6, _ := p.dynamicCIDR.Contains(ip6)
	p.mu.RUnlock()

	if !c4 {
		t.Error("plain IPv4 should be in dynamic CIDR as /32")
	}
	if !c6 {
		t.Error("plain IPv6 should be in dynamic CIDR as /128")
	}
}

func TestPipeline_UpdateDynamicCIDRs_InvalidEntries(t *testing.T) {
	p := newTestPipeline(0)
	// Should not panic on invalid entries
	p.UpdateDynamicCIDRs([]string{"not-a-cidr", "also-invalid", "10.0.0.0/8"})

	p.mu.RLock()
	ip := net.ParseIP("10.1.2.3")
	c, _ := p.dynamicCIDR.Contains(ip)
	p.mu.RUnlock()
	if !c {
		t.Error("valid CIDR should still be loaded despite invalid entries")
	}
}

func TestPipeline_StartBackgroundWorkers(t *testing.T) {
	p := newTestPipeline(0)
	ctx, cancel := context.WithCancel(context.Background())
	p.StartBackgroundWorkers(ctx)
	cancel()
	time.Sleep(50 * time.Millisecond)
	// No panic or hang = pass
}

func TestPipeline_CheckHardBlocks_DynamicCIDR(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4BlacklistBypass: true,
		Whitelist:          map[string]bool{},
		Blacklist:          map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	p.UpdateDynamicCIDRs([]string{"192.168.0.0/16"})

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "192.168.1.1",
		JA4:      "t13d000000_000000000000_000000000000",
	})
	if result.Action != "block" {
		t.Errorf("dynamic CIDR: action=%q, want 'block'", result.Action)
	}
	if result.BypassReason != "dynamic_cidr" {
		t.Errorf("expected 'dynamic_cidr', got %q", result.BypassReason)
	}
}

func TestPipeline_CheckHardBlocks_CountryBlacklist(t *testing.T) {
	cfg := &PipelineConfig{
		CountryBlacklistBypass: true,
		CountryBlacklist:       map[string]bool{"XX": true},
		Whitelist:              map[string]bool{},
		Blacklist:              map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		Country:  "XX",
	})
	if result.Action != "block" || result.BypassReason != "country_blacklist" {
		t.Errorf("country blacklist: action=%q reason=%q", result.Action, result.BypassReason)
	}
}

func TestPipeline_CheckBypasses_StaticIPAllowlist(t *testing.T) {
	cfg := &PipelineConfig{
		StaticIPAllowlistEnabled: true,
		StaticIPAllowlist:        map[string]bool{"10.0.0.1": true},
		Whitelist:                map[string]bool{},
		Blacklist:                map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "10.0.0.1",
	})
	if !result.Bypassed || result.BypassReason != "static_ip" {
		t.Errorf("static IP allowlist: bypassed=%v reason=%q", result.Bypassed, result.BypassReason)
	}
}

func TestPipeline_CheckBypasses_WhitelistPattern(t *testing.T) {
	cfg := &PipelineConfig{
		JA4WhitelistBypass: true,
		WhitelistSuffs:     []string{"h2_suffix"},
		Whitelist:          map[string]bool{},
		Blacklist:          map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4:      "t13d1516h2_suffix",
	})
	if !result.Bypassed || result.BypassReason != "ja4_whitelist_pattern" {
		t.Errorf("whitelist pattern: bypassed=%v reason=%q", result.Bypassed, result.BypassReason)
	}
}

func TestPipeline_CheckHardBlocks_JA4XBlacklist(t *testing.T) {
	cfg := &PipelineConfig{
		JA4XBlacklistBypass: true,
		JA4XEnabled:         true,
		Whitelist:           map[string]bool{},
		Blacklist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	p.UpdateJA4XSets(nil, map[string]bool{"badx509": true})

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "badx509",
	})
	if result.Action != "block" || result.BypassReason != "ja4x_blacklist" {
		t.Errorf("JA4X blacklist: action=%q reason=%q", result.Action, result.BypassReason)
	}
}

func TestPipeline_CheckBypasses_JA4XWhitelist(t *testing.T) {
	cfg := &PipelineConfig{
		JA4XWhitelistBypass: true,
		JA4XEnabled:         true,
		Whitelist:           map[string]bool{},
		Blacklist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	p.UpdateJA4XSets(map[string]bool{"goodx509": true}, nil)

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "goodx509",
	})
	if !result.Bypassed || result.BypassReason != "ja4x_whitelist" {
		t.Errorf("JA4X whitelist: bypassed=%v reason=%q", result.Bypassed, result.BypassReason)
	}
}

// ─── deriveSubnet ──────────────────────────────────────────────────────────

func TestDeriveSubnet_IPv6(t *testing.T) {
	subnet := deriveSubnet("2001:db8:1234:5678::1")
	if subnet == "" {
		t.Fatal("expected non-empty subnet for IPv6")
	}
	expected := "2001:db8:1234::/48"
	if subnet != expected {
		t.Errorf("deriveSubnet IPv6: got %q, want %q", subnet, expected)
	}
}

func TestDeriveSubnet_InvalidIP(t *testing.T) {
	subnet := deriveSubnet("not-an-ip")
	if subnet != "" {
		t.Errorf("invalid IP: expected empty, got %q", subnet)
	}
}

func TestDeriveSubnet_IPv4(t *testing.T) {
	subnet := deriveSubnet("192.168.1.100")
	if subnet != "192.168.1.0/24" {
		t.Errorf("expected 192.168.1.0/24, got %q", subnet)
	}
}

// ─── ASN Classifier: NewASNClassifier constructor paths ────────────────────

func TestNewASNClassifier_NilConfig(t *testing.T) {
	c := NewASNClassifier(nil, nil)
	if c == nil {
		t.Fatal("NewASNClassifier(nil) should not return nil")
	}
}

func TestNewASNClassifier_LoadTorExitList(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "tor_exits_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("# comment\n1.2.3.4\n5.6.7.8\n\n")
	tmpFile.Close()

	cfg := &ASNClassifierConfig{
		Enabled:         true,
		TorExitListPath: tmpFile.Name(),
	}
	c := NewASNClassifier(cfg, nil)
	if !c.torExits["1.2.3.4"] {
		t.Error("1.2.3.4 should be in tor exits")
	}
	if !c.torExits["5.6.7.8"] {
		t.Error("5.6.7.8 should be in tor exits")
	}
	if c.torExits["# comment"] {
		t.Error("comments should be excluded")
	}
}

func TestNewASNClassifier_LoadDatacenterList(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "dc_list_*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("asns:\n  16509: AWS\n  15169: Google\norgs:\n  - amazon\n  - google\n")
	tmpFile.Close()

	cfg := &ASNClassifierConfig{
		Enabled:            true,
		DatacenterListPath: tmpFile.Name(),
	}
	c := NewASNClassifier(cfg, nil)
	if !c.cfg.DatacenterASNs[16509] {
		t.Error("ASN 16509 should be in datacenter ASNs")
	}
	if !c.cfg.DatacenterASNs[15169] {
		t.Error("ASN 15169 should be in datacenter ASNs")
	}
}

func TestNewASNClassifier_BadDatacenterListYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bad_dc_*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not: [valid: yaml: {{{{")
	tmpFile.Close()

	cfg := &ASNClassifierConfig{
		Enabled:            true,
		DatacenterListPath: tmpFile.Name(),
	}
	c := NewASNClassifier(cfg, nil)
	// Should not panic; should have no datacenter ASNs
	if c == nil {
		t.Fatal("should not return nil on bad YAML")
	}
}

func TestNewASNClassifier_NonexistentDBPath(t *testing.T) {
	cfg := &ASNClassifierConfig{
		Enabled: true,
		DBPath:  "/nonexistent/db.mmdb",
	}
	c := NewASNClassifier(cfg, nil)
	if c.db != nil {
		t.Error("nonexistent DB: db should be nil")
	}
}

func TestNewASNClassifier_InvalidIP(t *testing.T) {
	cfg := defaultASNCfg()
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 0, "", nil
	})
	sigs := c.Classify("not-an-ip")
	if len(sigs) != 0 {
		t.Errorf("invalid IP: expected no signals, got %d", len(sigs))
	}
}

func TestASNClassifier_Classify_DefaultScores(t *testing.T) {
	// Zero-value scores should trigger defaults
	cfg := &ASNClassifierConfig{
		Enabled:        true,
		DatacenterASNs: map[uint]bool{100: true},
	}
	c := newTestASNClassifier(cfg, func(ip net.IP) (uint, string, error) {
		return 100, "Some DC", nil
	})
	sigs := c.Classify("1.2.3.4")
	if len(sigs) == 0 {
		t.Fatal("expected signal")
	}
	if sigs[0].Score != 20 {
		t.Errorf("expected default datacenter score 20, got %d", sigs[0].Score)
	}
}

// ─── mTLS: NewMTLSVerifier with valid CA + Verify ──────────────────────────

func TestMTLSVerifier_ValidCACert_VerifiesSignedCert(t *testing.T) {
	// Generate a self-signed CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Write CA PEM to temp file
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	tmpFile, err := os.CreateTemp("", "test_ca_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(caPEM)
	tmpFile.Close()

	v := NewMTLSVerifier(tmpFile.Name())
	if v.pool == nil {
		t.Fatal("CA pool should be loaded")
	}

	// Generate a client cert signed by the CA
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with DER
	if !v.Verify(clientDER) {
		t.Error("valid DER cert signed by CA should verify")
	}

	// Verify with PEM
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	if !v.Verify(clientPEM) {
		t.Error("valid PEM cert signed by CA should verify")
	}
}

func TestMTLSVerifier_NonexistentFile(t *testing.T) {
	v := NewMTLSVerifier("/nonexistent/file.pem")
	if v.pool != nil {
		t.Error("nonexistent file: pool should be nil")
	}
	if v.Verify([]byte("anything")) {
		t.Error("no pool: should not verify")
	}
}

func TestMTLSVerifier_InvalidPEMContent(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bad_pem_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not a PEM file")
	tmpFile.Close()

	v := NewMTLSVerifier(tmpFile.Name())
	// Pool will be created but empty (no valid certs added)
	if v.Verify([]byte("anything")) {
		t.Error("bad PEM: should not verify anything")
	}
}

func TestMTLSVerifier_UntrustedCert(t *testing.T) {
	// Generate CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	tmpFile, _ := os.CreateTemp("", "test_ca2_*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(caPEM)
	tmpFile.Close()

	v := NewMTLSVerifier(tmpFile.Name())

	// Generate a self-signed cert (NOT signed by the loaded CA)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Untrusted"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)

	if v.Verify(otherDER) {
		t.Error("untrusted cert: should not verify")
	}
}

func TestMTLSVerifier_Verify_BadPEMBlock(t *testing.T) {
	// Generate a valid CA first so pool is non-nil
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	tmpFile, _ := os.CreateTemp("", "ca_*.pem")
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(caPEM)
	tmpFile.Close()
	v := NewMTLSVerifier(tmpFile.Name())

	// Not valid DER, and pem.Decode returns nil block
	if v.Verify([]byte("garbage data not DER not PEM")) {
		t.Error("garbage: should return false")
	}
}

// ─── Blocklists: additional coverage ───────────────────────────────────────

func TestBlocklists_NilConfig(t *testing.T) {
	m := NewBlocklistManager(nil, nil)
	sigs, hardBlock := m.Check("1.2.3.4")
	if hardBlock || len(sigs) != 0 {
		t.Error("nil config: expected no block and no signals")
	}
}

func TestBlocklists_PlainIP_InFeed(t *testing.T) {
	// Feed file has plain IPs (no CIDR), should auto-add /32
	path := writeTempBlocklist(t, "1.2.3.4\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "plain_ip", Enabled: true, Path: path, Action: "signal", Score: 25},
		},
	}, nil)
	sigs, _ := m.Check("1.2.3.4")
	if len(sigs) == 0 {
		t.Error("plain IP: expected signal")
	}
}

func TestBlocklists_IPv6PlainIP_InFeed(t *testing.T) {
	path := writeTempBlocklist(t, "2001:db8::1\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "ipv6_plain", Enabled: true, Path: path, Action: "signal", Score: 20},
		},
	}, nil)
	sigs, _ := m.Check("2001:db8::1")
	if len(sigs) == 0 {
		t.Error("IPv6 plain IP: expected signal")
	}
}

func TestBlocklists_CommentedAndBlankLines_Skipped(t *testing.T) {
	path := writeTempBlocklist(t, "# This is a comment\n; Also a comment\n\n10.0.0.0/8\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "comments", Enabled: true, Path: path, IsBypass: true, Action: "block"},
		},
	}, nil)
	_, hardBlock := m.Check("10.1.2.3")
	if !hardBlock {
		t.Error("valid CIDR after comments: expected hard block")
	}
}

func TestBlocklists_InvalidCIDR_Skipped(t *testing.T) {
	path := writeTempBlocklist(t, "not-a-cidr\n10.0.0.0/8\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "mixed", Enabled: true, Path: path, IsBypass: true, Action: "block"},
		},
	}, nil)
	_, hardBlock := m.Check("10.1.2.3")
	if !hardBlock {
		t.Error("valid CIDR should still match after invalid lines")
	}
}

func TestBlocklists_MissingFile_Skipped(t *testing.T) {
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "missing", Enabled: true, Path: "/nonexistent/file.txt", IsBypass: true, Action: "block"},
		},
	}, nil)
	_, hardBlock := m.Check("1.2.3.4")
	if hardBlock {
		t.Error("missing file: should not block")
	}
}

func TestBlocklists_InvalidIP_NoBlock(t *testing.T) {
	path := writeTempBlocklist(t, "10.0.0.0/8\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "test", Enabled: true, Path: path, IsBypass: true, Action: "block"},
		},
	}, nil)
	_, hardBlock := m.Check("not-an-ip")
	if hardBlock {
		t.Error("invalid IP: should not block")
	}
}

// ─── Beaconing: MaybeRecord edge cases ─────────────────────────────────────

func TestBeaconing_MaybeRecord_BanSkipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234"}, "ban")
	if len(mock.zadded) != 0 {
		t.Error("ban action: MaybeRecord should not record")
	}
}

func TestBeaconing_MaybeRecord_H2Skipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234", ALPN: "h2"}, "allow")
	if len(mock.zadded) != 0 {
		t.Error("h2 ALPN: MaybeRecord should not record")
	}
}

func TestBeaconing_MaybeRecord_H1Skipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234", ALPN: "h1"}, "allow")
	if len(mock.zadded) != 0 {
		t.Error("h1 ALPN: MaybeRecord should not record")
	}
}

func TestBeaconing_MaybeRecord_EmptyJA4_Skipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	d := NewBeaconingDetector(defaultBeaconingCfg(), mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: ""}, "allow")
	if len(mock.zadded) != 0 {
		t.Error("empty JA4: MaybeRecord should not record")
	}
}

func TestBeaconing_MaybeRecord_NilRedis_Skipped(t *testing.T) {
	d := NewBeaconingDetector(defaultBeaconingCfg(), nil, nil)
	// Should not panic
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234"}, "allow")
}

func TestBeaconing_MaybeRecord_Disabled_Skipped(t *testing.T) {
	mock := &mockRedisBeacon{scores: map[string][]float64{}, zadded: map[string][]float64{}}
	cfg := defaultBeaconingCfg()
	cfg.Enabled = false
	d := NewBeaconingDetector(cfg, mock, nil)
	d.MaybeRecord(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234"}, "allow")
	if len(mock.zadded) != 0 {
		t.Error("disabled: MaybeRecord should not record")
	}
}

func TestBeaconing_GetSignal_NilRedis(t *testing.T) {
	d := NewBeaconingDetector(defaultBeaconingCfg(), nil, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{ClientIP: "1.2.3.4", JA4: "t13d1234"})
	if sig != nil {
		t.Error("nil redis: expected nil signal")
	}
}

// ─── Pipeline: redisReaderGetter ───────────────────────────────────────────

func TestRedisReaderGetter_NilRedis(t *testing.T) {
	g := redisReaderGetter{r: nil}
	val, err := g.Get(context.Background(), "key")
	if err != nil || val != "" {
		t.Errorf("nil redis: expected empty string, got %q err=%v", val, err)
	}
}

func TestRedisReaderGetter_WithRedis(t *testing.T) {
	r := newMockRedisRW()
	r.strings["testkey"] = "testval"
	g := redisReaderGetter{r: r}
	val, err := g.Get(context.Background(), "testkey")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if val != "testval" {
		t.Errorf("expected 'testval', got %q", val)
	}
}

// ─── Pipeline: durationMillis, durationSeconds, defaultInt ─────────────────

func TestDurationMillis(t *testing.T) {
	if d := durationMillis(100, 50); d != 100*time.Millisecond {
		t.Errorf("expected 100ms, got %v", d)
	}
	if d := durationMillis(0, 50); d != 50*time.Millisecond {
		t.Errorf("expected 50ms default, got %v", d)
	}
	if d := durationMillis(-1, 50); d != 50*time.Millisecond {
		t.Errorf("expected 50ms default for negative, got %v", d)
	}
}

func TestDurationSeconds(t *testing.T) {
	if d := durationSeconds(10, 5); d != 10*time.Second {
		t.Errorf("expected 10s, got %v", d)
	}
	if d := durationSeconds(0, 5); d != 5*time.Second {
		t.Errorf("expected 5s default, got %v", d)
	}
}

func TestDefaultInt(t *testing.T) {
	if v := defaultInt(0, 42); v != 42 {
		t.Errorf("defaultInt(0,42) = %d, want 42", v)
	}
	if v := defaultInt(10, 42); v != 10 {
		t.Errorf("defaultInt(10,42) = %d, want 10", v)
	}
}

func TestUint16s(t *testing.T) {
	in := []int{0x0301, 0x0303}
	out := uint16s(in)
	if len(out) != 2 || out[0] != 0x0301 || out[1] != 0x0303 {
		t.Errorf("uint16s: got %v", out)
	}
	// Empty input
	empty := uint16s(nil)
	if len(empty) != 0 {
		t.Error("expected empty slice for nil input")
	}
}

// ─── Pipeline: Process with JA4X blacklist signal (not hard-block) ─────────

func TestPipeline_JA4XBlacklistSignal_NonBypass(t *testing.T) {
	cfg := &PipelineConfig{
		JA4XEnabled:         true,
		JA4XBlacklistBypass: false, // Not a hard-block bypass; signal only
		JA4XBlacklistScore:  50,
		Whitelist:           map[string]bool{},
		Blacklist:           map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 100}, nil)
	p.UpdateJA4XSets(nil, map[string]bool{"badcert": true})

	result := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4",
		JA4X:     "badcert",
	})
	// Should not hard-block (JA4XBlacklistBypass=false), but signal should be present
	found := false
	for _, s := range result.Signals {
		if s.Name == "ja4x_blacklist" {
			found = true
			if s.Score != 50 {
				t.Errorf("expected ja4x_blacklist score=50, got %d", s.Score)
			}
		}
	}
	if !found {
		t.Error("expected ja4x_blacklist signal in pipeline result")
	}
}
