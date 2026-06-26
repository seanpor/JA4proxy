package quic

import (
	"testing"
)

func TestParseCRYPTOFrames_SingleFrame(t *testing.T) {
	// Single CRYPTO frame with type=0x06, offset=0, length=4, data=[1,2,3,4]
	payload := []byte{
		0x06,       // type: CRYPTO
		0x00,       // offset: 0
		0x04,       // length: 4
		0x01, 0x02, 0x03, 0x04, // data
	}

	result, err := ParseCRYPTOFrames(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(result))
	}
	if result[0] != 1 || result[3] != 4 {
		t.Fatal("data mismatch")
	}
}

func TestParseCRYPTOFrames_MultipleFrames(t *testing.T) {
	// Two CRYPTO frames
	payload := []byte{
		0x06,       // type: CRYPTO
		0x00,       // offset: 0
		0x02,       // length: 2
		0x01, 0x02, // data
		0x06,       // type: CRYPTO
		0x02,       // offset: 2
		0x02,       // length: 2
		0x03, 0x04, // data
	}

	result, err := ParseCRYPTOFrames(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(result))
	}
	if result[2] != 3 || result[3] != 4 {
		t.Fatal("data mismatch")
	}
}

func TestParseCRYPTOFrames_OutOfOrder(t *testing.T) {
	// Two CRYPTO frames out of order
	payload := []byte{
		0x06,       // type: CRYPTO
		0x02,       // offset: 2
		0x02,       // length: 2
		0x03, 0x04, // data
		0x06,       // type: CRYPTO
		0x00,       // offset: 0
		0x02,       // length: 2
		0x01, 0x02, // data
	}

	result, err := ParseCRYPTOFrames(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(result))
	}
	if result[0] != 1 || result[1] != 2 || result[2] != 3 || result[3] != 4 {
		t.Fatal("data mismatch")
	}
}

func TestParseCRYPTOFrames_NoFrames(t *testing.T) {
	// Only non-CRYPTO frames
	payload := []byte{
		0x00,       // type: PADDING
		0x06, 0x01, // ACK frame
	}

	_, err := ParseCRYPTOFrames(payload)
	if err == nil {
		t.Fatal("expected error for no CRYPTO frames")
	}
}

func TestParseCRYPTOFrames_Truncated(t *testing.T) {
	// CRYPTO frame with length exceeding payload
	payload := []byte{
		0x06, // type: CRYPTO
		0x00, // offset: 0
		0x10, // length: 16
		0x01, 0x02, 0x03, 0x04, // only 4 bytes of data
	}

	_, err := ParseCRYPTOFrames(payload)
	if err == nil {
		t.Fatal("expected error for truncated CRYPTO frame")
	}
}

func TestWrapInTLSRecord(t *testing.T) {
	handshake := []byte{0x01, 0x02, 0x03, 0x04}
	record := WrapInTLSRecord(handshake)

	if len(record) != 9 {
		t.Fatalf("expected 9 bytes, got %d", len(record))
	}
	if record[0] != 0x16 {
		t.Fatalf("expected content type 0x16, got 0x%02x", record[0])
	}
	if record[1] != 0x03 || record[2] != 0x01 {
		t.Fatal("expected legacy record version 0x0301")
	}
	if record[3] != 0x00 || record[4] != 0x04 {
		t.Fatal("expected length 4")
	}
	if record[5] != 1 || record[8] != 4 {
		t.Fatal("data mismatch")
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint64
		length   int
	}{
		{"1-byte", []byte{0x05}, 5, 1},
		{"2-byte", []byte{0x40, 0x01}, 1, 2},
		{"4-byte", []byte{0x80, 0x00, 0x01, 0x00}, 256, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, n := readVarint(tt.data)
			if n != tt.length {
				t.Fatalf("expected length %d, got %d", tt.length, n)
			}
			if val != tt.expected {
				t.Fatalf("expected %d, got %d", tt.expected, val)
			}
		})
	}
}

func TestDefragment(t *testing.T) {
	frags := []fragment{
		{offset: 4, data: []byte{5, 6}},
		{offset: 0, data: []byte{1, 2}},
		{offset: 2, data: []byte{3, 4}},
	}

	result, err := defragment(frags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(result))
	}
	for i := 0; i < 6; i++ {
		if result[i] != byte(i+1) {
			t.Fatalf("byte %d: expected %d, got %d", i, i+1, result[i])
		}
	}
}

func TestDefragment_Empty(t *testing.T) {
	_, err := defragment(nil)
	if err == nil {
		t.Fatal("expected error for empty fragments")
	}
}
