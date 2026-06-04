package security

import (
	"net"
	"context"
	"fmt"
	"testing"
	"time"
)

func defaultRDAPCfg() *RDAPConfig {
	return &RDAPConfig{
		Enabled:               true,
		MinTriggerScore:       75,
		NewNetblockMaxAgeDays: 90,
		NewNetblockScore:      20,
		KnownBadOrgScore:      45,
		RequireKnownBadOrg:    true,
		KnownBadOrgs: []KnownBadOrgEntry{
			{Name: "evil hosting", Score: 45, Reason: "bulletproof"},
		},
	}
}

func TestRDAP_Disabled_NoSignals(t *testing.T) {
	cfg := defaultRDAPCfg()
	cfg.Enabled = false
	r := NewRDAPEnricher(cfg, &mockRedis{}, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 80)
	if len(sigs) != 0 {
		t.Errorf("disabled: expected no signals, got %d", len(sigs))
	}
}

func TestRDAP_NoCachedData_EnqueuesAboveThreshold(t *testing.T) {
	r := NewRDAPEnricher(defaultRDAPCfg(), &mockRedis{}, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 80)
	if len(sigs) != 0 {
		t.Errorf("no cached data: expected no signals, got %d", len(sigs))
	}
	// Job should be enqueued
	select {
	case job := <-r.queue:
		if job.ip != "1.2.3.4" {
			t.Errorf("enqueued IP = %q, want '1.2.3.4'", job.ip)
		}
	default:
		t.Error("expected job to be enqueued for high score")
	}
}

func TestRDAP_NoCachedData_BelowThreshold_NotEnqueued(t *testing.T) {
	r := NewRDAPEnricher(defaultRDAPCfg(), &mockRedis{}, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 30)
	if len(sigs) != 0 {
		t.Errorf("below threshold: expected no signals, got %d", len(sigs))
	}
	select {
	case job := <-r.queue:
		t.Errorf("below threshold: job should not be enqueued, got %+v", job)
	default:
		// Expected
	}
}

func TestRDAP_KnownBadOrg_Signal(t *testing.T) {
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": `{"org_name": "evil hosting", "org_handle": "EVIL-1", "is_unknown": false}`,
		},
	}
	r := NewRDAPEnricher(defaultRDAPCfg(), mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 80)
	if len(sigs) == 0 {
		t.Fatal("known bad org: expected signal")
	}
	if sigs[0].Name != "rdap_known_bad_org" {
		t.Errorf("expected 'rdap_known_bad_org', got %q", sigs[0].Name)
	}
}

func TestRDAP_NewNetblock_Signal(t *testing.T) {
	recentDate := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": fmt.Sprintf(`{"org_name": "some org", "registration_date": "%s", "is_unknown": false}`, recentDate),
		},
	}
	cfg := defaultRDAPCfg()
	cfg.RequireKnownBadOrg = false
	r := NewRDAPEnricher(cfg, mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 80)
	if len(sigs) == 0 {
		t.Fatal("new netblock: expected signal")
	}
	found := false
	for _, s := range sigs {
		if s.Name == "rdap_new_netblock" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'rdap_new_netblock' signal, got %v", sigs)
	}
}

func TestRDAP_OldNetblock_NoSignal(t *testing.T) {
	oldDate := time.Now().AddDate(-2, 0, 0).Format("2006-01-02")
	mock := &mockRedisKV{
		strings: map[string]string{
			"rdap:ip:1.2.3.4": fmt.Sprintf(`{"org_name": "some org", "registration_date": "%s", "is_unknown": false}`, oldDate),
		},
	}
	cfg := defaultRDAPCfg()
	cfg.RequireKnownBadOrg = false
	r := NewRDAPEnricher(cfg, mock, nil)
	sigs := r.GetSignals(context.Background(), &ConnectionContext{ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4"}, 80)
	if len(sigs) != 0 {
		t.Errorf("old netblock: expected no signals, got %v", sigs)
	}
}
