package security

// Phase 203b — TDD red: ja4_tls_mismatch signal.
// Contract: (*TLSEnforcer).CheckJA4TLSMismatch(ja4 string, actualTLSVersion uint16) *RiskSignal
//   - nil on match or unparsable JA4 (fail open)
//   - *RiskSignal{Name:"ja4_tls_mismatch", Score:35, Weight:1.0} on mismatch
// JA4 prefix → TLS version: t13→0x0304, t12→0x0303, t11→0x0302, t10→0x0301, s30→0x0300.

import "testing"

func TestCheckJA4TLSMismatch_Match_ReturnsNil(t *testing.T) {
	e := NewTLSEnforcer(&TLSEnforcerConfig{}, nil)
	cases := []struct {
		name string
		ja4  string
		tlsV uint16
	}{
		{"t13_tls13", "t13d1516h2_aabbccddeeff_aabbccddeeff", 0x0304},
		{"t12_tls12", "t12d1516h2_aabbccddeeff_aabbccddeeff", 0x0303},
		{"t11_tls11", "t11d1516h2_aabbccddeeff_aabbccddeeff", 0x0302},
		{"t10_tls10", "t10d1516h2_aabbccddeeff_aabbccddeeff", 0x0301},
		{"s30_sslv3", "s30d1516h2_aabbccddeeff_aabbccddeeff", 0x0300},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := e.CheckJA4TLSMismatch(tc.ja4, tc.tlsV)
			if got != nil {
				t.Errorf("expected nil on match; got %+v", got)
			}
		})
	}
}

func TestCheckJA4TLSMismatch_Mismatch_ReturnsSignal(t *testing.T) {
	e := NewTLSEnforcer(&TLSEnforcerConfig{}, nil)
	cases := []struct {
		name string
		ja4  string
		tlsV uint16
	}{
		{"t13_claims13_actual12", "t13d1516h2_aabbccddeeff_aabbccddeeff", 0x0303},
		{"t12_claims12_actual11", "t12d1516h2_aabbccddeeff_aabbccddeeff", 0x0302},
		{"t10_claims10_actual_sslv3", "t10d1516h2_aabbccddeeff_aabbccddeeff", 0x0300},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sig := e.CheckJA4TLSMismatch(tc.ja4, tc.tlsV)
			if sig == nil {
				t.Fatal("expected signal on mismatch; got nil")
			}
			if sig.Name != "ja4_tls_mismatch" {
				t.Errorf("Name = %q; want %q", sig.Name, "ja4_tls_mismatch")
			}
			if sig.Score != 35 {
				t.Errorf("Score = %d; want 35", sig.Score)
			}
			if sig.Weight != 1.0 {
				t.Errorf("Weight = %v; want 1.0", sig.Weight)
			}
		})
	}
}

// TestCheckJA4TLSMismatch_ZeroTLSVersion_FailsOpen pins the invariant
// documented in PHASE_203.md close-out: a zero-valued negotiated version
// means the proxy never observed a completed handshake, so the check must
// fail open. This prevents spurious signals on mid-parse / malformed paths.
func TestCheckJA4TLSMismatch_ZeroTLSVersion_FailsOpen(t *testing.T) {
	e := NewTLSEnforcer(&TLSEnforcerConfig{}, nil)
	// All known JA4 prefixes must return nil when actualTLSVersion == 0.
	ja4s := []string{
		"t13d1516h2_aabbccddeeff_aabbccddeeff",
		"t12d1516h2_aabbccddeeff_aabbccddeeff",
		"t11d1516h2_aabbccddeeff_aabbccddeeff",
		"t10d1516h2_aabbccddeeff_aabbccddeeff",
		"s30d1516h2_aabbccddeeff_aabbccddeeff",
	}
	for _, ja4 := range ja4s {
		ja4 := ja4
		t.Run(ja4[:3], func(t *testing.T) {
			if got := e.CheckJA4TLSMismatch(ja4, 0); got != nil {
				t.Errorf("actualTLSVersion==0 must fail open for prefix %q; got %+v", ja4[:3], got)
			}
		})
	}
}

func TestCheckJA4TLSMismatch_Malformed_FailsOpen(t *testing.T) {
	e := NewTLSEnforcer(&TLSEnforcerConfig{}, nil)
	cases := []struct {
		name string
		ja4  string
		tlsV uint16
	}{
		{"empty", "", 0x0303},
		{"one_char", "x", 0x0303},
		{"two_chars", "t1", 0x0303},
		{"unknown_prefix", "abcd1516h2_aabbccddeeff_aabbccddeeff", 0x0303},
		{"unknown_version_digits", "t99d1516h2_aabbccddeeff_aabbccddeeff", 0x0303},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := e.CheckJA4TLSMismatch(tc.ja4, tc.tlsV)
			if got != nil {
				t.Errorf("malformed/unknown JA4 must fail open (nil); got %+v", got)
			}
		})
	}
}
