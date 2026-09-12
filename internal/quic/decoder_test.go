package quic

import (
	"testing"
	"time"
)

func TestDecoder_ActiveCount(t *testing.T) {
	d := NewDecoder(nil)
	if d.ActiveCount() != 0 {
		t.Fatalf("expected 0, got %d", d.ActiveCount())
	}
}

func TestDecoder_HasKeys(t *testing.T) {
	d := NewDecoder(nil)
	if d.HasKeys() {
		t.Fatal("expected false when no key log")
	}

	d2 := NewDecoder(&KeyLog{entries: make(map[string]*keyLogEntry)})
	if d2.HasKeys() {
		t.Fatal("expected false when key log has no entries")
	}

	d3 := NewDecoder(&KeyLog{entries: map[string]*keyLogEntry{"test": {Secret: []byte{1, 2, 3}}}})
	if !d3.HasKeys() {
		t.Fatal("expected true when key log has entries")
	}
}

func TestDecoder_FlushEvicted(t *testing.T) {
	d := NewDecoder(nil)
	key := connIDKey([]byte{0x01, 0x02, 0x03, 0x04})
	d.active[key] = &Handshake{
		Version:  Version1,
		DCID:     []byte{0x01, 0x02, 0x03, 0x04},
		LastSeen: time.Now().Add(-HandshakeTTL - time.Second),
		Seen:     1,
	}
	if d.ActiveCount() != 1 {
		t.Fatalf("expected 1, got %d", d.ActiveCount())
	}
	d.FlushEvicted()
	if d.ActiveCount() != 0 {
		t.Fatalf("expected 0 after flush, got %d", d.ActiveCount())
	}
}

func TestConnIDKey(t *testing.T) {
	id := []byte{0x01, 0x02, 0x03}
	key := connIDKey(id)
	if key[0] != 0x01 || key[1] != 0x02 || key[2] != 0x03 {
		t.Fatal("connIDKey did not copy bytes correctly")
	}
}
