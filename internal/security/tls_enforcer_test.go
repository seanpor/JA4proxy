package security

import "testing"

func newTLSEnforcer(cfg *TLSEnforcerConfig) *TLSEnforcer {
	return NewTLSEnforcer(cfg, nil)
}

func TestTLSEnforcer_SSLv3_AlwaysHardBlock(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{})
	sigs, hard := e.Check(0x0300, nil)
	if !hard {
		t.Error("SSLv3 must always hard block")
	}
	if len(sigs) != 0 {
		t.Error("SSLv3 hard block must return no signals")
	}
}

func TestTLSEnforcer_TLS10_HardBlock_WhenBypassEnabled(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		TLSVersionBypassEnabled: true,
		BlockTLS10:              true,
	})
	sigs, hard := e.Check(0x0301, nil)
	if !hard {
		t.Error("TLS 1.0 should hard block when bypass enabled and BlockTLS10=true")
	}
	if len(sigs) != 0 {
		t.Error("hard block must return no signals")
	}
}

func TestTLSEnforcer_TLS10_Signal_WhenBypassDisabled(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		TLSVersionBypassEnabled: false,
	})
	sigs, hard := e.Check(0x0301, nil)
	if hard {
		t.Error("TLS 1.0 should not hard block when bypass disabled")
	}
	if len(sigs) != 1 {
		t.Errorf("expected 1 signal, got %d", len(sigs))
		return
	}
	if sigs[0].Name != "tls_version" {
		t.Errorf("signal name = %q; want 'tls_version'", sigs[0].Name)
	}
	if sigs[0].Score != 40 {
		t.Errorf("signal score = %d; want 40", sigs[0].Score)
	}
}

func TestTLSEnforcer_TLS11_HardBlock_WhenBypassEnabled(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		TLSVersionBypassEnabled: true,
		BlockTLS11:              true,
	})
	sigs, hard := e.Check(0x0302, nil)
	if !hard {
		t.Error("TLS 1.1 should hard block when bypass enabled and BlockTLS11=true")
	}
	if len(sigs) != 0 {
		t.Error("hard block must return no signals")
	}
}

func TestTLSEnforcer_TLS12_FlaggedWhenEnabled(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		FlagTLS12: true,
	})
	sigs, hard := e.Check(0x0303, nil)
	if hard {
		t.Error("TLS 1.2 should not hard block when only flagging")
	}
	if len(sigs) != 1 {
		t.Errorf("expected 1 signal, got %d", len(sigs))
		return
	}
	if sigs[0].Name != "tls_12" {
		t.Errorf("signal name = %q; want 'tls_12'", sigs[0].Name)
	}
	if sigs[0].Score != 10 {
		t.Errorf("signal score = %d; want 10", sigs[0].Score)
	}
}

func TestTLSEnforcer_TLS13_NoSignal(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{})
	sigs, hard := e.Check(0x0304, nil) // TLS 1.3
	if hard {
		t.Error("TLS 1.3 should not hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("TLS 1.3 should produce no signals, got %d", len(sigs))
	}
}

func TestTLSEnforcer_WeakCipher_Signal_WhenNotBlocking(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		BlockWeakCiphers: false,
	})
	sigs, hard := e.Check(0x0304, []uint16{0x0005}) // RC4_128_SHA
	if hard {
		t.Error("weak cipher should not hard block when BlockWeakCiphers=false")
	}
	if len(sigs) != 1 {
		t.Errorf("expected 1 signal, got %d", len(sigs))
		return
	}
	if sigs[0].Name != "weak_cipher" {
		t.Errorf("signal name = %q; want 'weak_cipher'", sigs[0].Name)
	}
	if sigs[0].Score != 20 {
		t.Errorf("signal score = %d; want 20", sigs[0].Score)
	}
}

func TestTLSEnforcer_WeakCipher_HardBlock_WhenBlockEnabled(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		BlockWeakCiphers: true,
	})
	sigs, hard := e.Check(0x0304, []uint16{0x0005}) // RC4_128_SHA
	if !hard {
		t.Error("weak cipher should hard block when BlockWeakCiphers=true")
	}
	if len(sigs) != 0 {
		t.Error("hard block must return no signals")
	}
}

func TestTLSEnforcer_NoWeakCiphers_NoSignal(t *testing.T) {
	e := newTLSEnforcer(&TLSEnforcerConfig{
		BlockWeakCiphers: false,
	})
	sigs, hard := e.Check(0x0304, []uint16{0x1301, 0x1302}) // TLS 1.3 suites
	if hard {
		t.Error("strong ciphers should not hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("strong ciphers should produce no signals, got %d", len(sigs))
	}
}
