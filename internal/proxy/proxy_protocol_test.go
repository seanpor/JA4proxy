package proxy

import (
	"testing"
)

func TestProxyProtocol_TCP4_Valid(t *testing.T) {
	buf := []byte("PROXY TCP4 192.168.1.1 10.0.0.1 54321 443\r\nGARBAGE")
	ip, ok := ReadProxyProtocol(buf)
	if !ok {
		t.Fatal("TCP4: expected ok=true")
	}
	if ip != "192.168.1.1" {
		t.Errorf("TCP4: expected '192.168.1.1', got %q", ip)
	}
}

func TestProxyProtocol_TCP6_Valid(t *testing.T) {
	buf := []byte("PROXY TCP6 2001:db8::1 ::1 54321 443\r\nGARBAGE")
	ip, ok := ReadProxyProtocol(buf)
	if !ok {
		t.Fatal("TCP6: expected ok=true")
	}
	if ip != "2001:db8::1" {
		t.Errorf("TCP6: expected '2001:db8::1', got %q", ip)
	}
}

func TestProxyProtocol_UNKNOWN_ReturnsFalse(t *testing.T) {
	buf := []byte("PROXY UNKNOWN 0.0.0.0 0.0.0.0 0 0\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("UNKNOWN: expected ok=false")
	}
}

func TestProxyProtocol_NotProxyHeader_ReturnsFalse(t *testing.T) {
	buf := []byte("\x16\x03\x01\x00\x01\x00\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("TLS header: expected ok=false")
	}
}

func TestProxyProtocol_Truncated_ReturnsFalse(t *testing.T) {
	buf := []byte("PROXY TCP4 192.168.1.1")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("truncated: expected ok=false")
	}
}

func TestProxyProtocol_InvalidIP_ReturnsFalse(t *testing.T) {
	buf := []byte("PROXY TCP4 not-an-ip 10.0.0.1 12345 443\r\n")
	_, ok := ReadProxyProtocol(buf)
	if ok {
		t.Error("invalid IP: expected ok=false")
	}
}
