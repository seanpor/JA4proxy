package security

import (
	"testing"
)

func TestMTLSVerifier_EmptyPEMPath_AlwaysFalse(t *testing.T) {
	v := NewMTLSVerifier("")
	if v.Verify([]byte("anything")) {
		t.Error("empty PEM path: Verify should always return false")
	}
}

func TestMTLSVerifier_InvalidCert_ReturnsFalse(t *testing.T) {
	v := NewMTLSVerifier("")
	if v.Verify([]byte("not a certificate")) {
		t.Error("invalid cert: Verify should return false")
	}
}

func TestMTLSVerifier_NilCert_ReturnsFalse(t *testing.T) {
	v := NewMTLSVerifier("")
	if v.Verify(nil) {
		t.Error("nil cert: Verify should return false")
	}
}
