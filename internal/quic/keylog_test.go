package quic

import (
	"strings"
	"testing"
)

func TestKeyLog_ParseLine(t *testing.T) {
	kl := &KeyLog{entries: make(map[string]*keyLogEntry)}

	line := "QUIC_SECRET QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET 0102030405060708"
	if err := kl.parseLine(line); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret := kl.GetSecret("QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET")
	if secret == nil {
		t.Fatal("expected secret to be set")
	}
	if len(secret) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(secret))
	}
}

func TestKeyLog_ParseLine_WithIVs(t *testing.T) {
	kl := &KeyLog{entries: make(map[string]*keyLogEntry)}

	line := "QUIC_SECRET QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET 01020304 05060708 090a0b0c"
	if err := kl.parseLine(line); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entry := kl.entries["QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
	if entry == nil {
		t.Fatal("expected entry to be set")
	}
	if len(entry.ClientIV) != 4 {
		t.Fatalf("expected client IV 4 bytes, got %d", len(entry.ClientIV))
	}
	if len(entry.ServerIV) != 4 {
		t.Fatalf("expected server IV 4 bytes, got %d", len(entry.ServerIV))
	}
}

func TestKeyLog_ParseLine_Malformed(t *testing.T) {
	kl := &KeyLog{entries: make(map[string]*keyLogEntry)}

	// Too few fields
	if err := kl.parseLine("QUIC_SECRET"); err == nil {
		t.Fatal("expected error for too few fields")
	}

	// Invalid hex
	if err := kl.parseLine("QUIC_SECRET label zzzz"); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestKeyLog_NewKeyLog(t *testing.T) {
	input := `# Comment line
QUIC_SECRET QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET 0102030405060708

QUIC_SECRET QUIC_SECRET_SERVER_HANDSHAKE_TRAFFIC_SECRET 0a0b0c0d0e0f1011
`
	kl, err := NewKeyLog(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !kl.HasKeys() {
		t.Fatal("expected keys to be loaded")
	}
	if kl.GetSecret("QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET") == nil {
		t.Fatal("expected client secret")
	}
	if kl.GetSecret("QUIC_SECRET_SERVER_HANDSHAKE_TRAFFIC_SECRET") == nil {
		t.Fatal("expected server secret")
	}
}

func TestKeyLog_GetSecret_NotFound(t *testing.T) {
	kl := &KeyLog{entries: make(map[string]*keyLogEntry)}
	if kl.GetSecret("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent label")
	}
}

func TestKeyLog_Nil(t *testing.T) {
	var kl *KeyLog
	if kl.HasKeys() {
		t.Fatal("expected false for nil KeyLog")
	}
	if kl.GetSecret("test") != nil {
		t.Fatal("expected nil for nil KeyLog")
	}
}

func TestDeriveInitialKey(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	secret := []byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}

	key, iv, err := DeriveInitialKey(dcid, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("expected 16-byte key, got %d", len(key))
	}
	if len(iv) != 12 {
		t.Fatalf("expected 12-byte IV, got %d", len(iv))
	}
}

func TestDeriveInitialKey_EmptySecret(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	_, _, err := DeriveInitialKey(dcid, []byte{})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}
