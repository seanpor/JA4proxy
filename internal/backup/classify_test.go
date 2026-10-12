package backup

import "testing"

func TestClassifyKey(t *testing.T) {
	block := []string{"ban:1.2.3.4", "ban:2001:db8::1", "ban_cidr:10.0.0.0/8", "ip:blacklist", "ja4:blacklist", "config:dial"}
	allow := []string{"ip:whitelist", "ja4:whitelist", "fp:os:ip:1.2.3.4", "fp:ip:1.2.3.4", "management:audit_log", "management:policy_audit", "beacon:suspects", "blocklist:spamhaus"}
	for _, k := range block {
		if ClassifyKey(k) != ClassBlock {
			t.Errorf("ClassifyKey(%q) = allow, want block", k)
		}
	}
	for _, k := range allow {
		if ClassifyKey(k) != ClassAllow {
			t.Errorf("ClassifyKey(%q) = block, want allow", k)
		}
	}
}

func TestSubjectIP(t *testing.T) {
	cases := []struct {
		key    string
		wantIP string
		isSubj bool
	}{
		{"ban:1.2.3.4", "1.2.3.4", true},
		{"ban:2001:db8::1", "2001:db8::1", true},
		{"ban:2001:DB8::0:1", "2001:db8::1", true}, // canonicalised
		{"fp:os:ip:9.9.9.9", "9.9.9.9", true},
		{"fp:ja4t:ip:9.9.9.9", "9.9.9.9", true},
		{"fp:ban_intent:ip:9.9.9.9", "9.9.9.9", true},
		{"fp:ip:9.9.9.9", "9.9.9.9", true},
		{"beacon:1.2.3.4:t13d1516h2_8daaf6152771_b186095e22b6", "1.2.3.4", true},
		{"beacon:2001:db8::1:t13d1516h2_8daaf6152771_b186095e22b6", "2001:db8::1", true},
		{"session:10.0.0.1", "10.0.0.1", true},
		{"concurrent:10.0.0.2", "10.0.0.2", true},
		{"return_visitor:10.0.0.3", "10.0.0.3", true},
		{"dns:fcrdns:10.0.0.4", "10.0.0.4", true},
		{"audit:last_score:10.0.0.5", "10.0.0.5", true},
		{"rdap:ip:10.0.0.6", "10.0.0.6", true},
		{"abuseipdb:10.0.0.7", "10.0.0.7", true},
		{"ratelimit:ip:10.0.0.8", "10.0.0.8", true},
		{"ratelimit:ip_ja4:10.0.0.9:t13d1516h2", "10.0.0.9", true},
		{"offense:10.0.0.10", "10.0.0.10", true},
		{"beacon:suspects", "", false},     // not a per-IP key
		{"ban_cidr:10.0.0.0/8", "", false}, // a CIDR, not a subject
		{"config:dial", "", false},
		{"ip:blacklist", "", false},
		{"ban:not-an-ip", "", false},
	}
	for _, c := range cases {
		gotIP, gotSubj := SubjectIP(c.key)
		if gotSubj != c.isSubj || gotIP != c.wantIP {
			t.Errorf("SubjectIP(%q) = (%q,%v), want (%q,%v)", c.key, gotIP, gotSubj, c.wantIP, c.isSubj)
		}
	}
}
