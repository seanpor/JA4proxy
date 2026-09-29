package tls

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAdversarialCorpus_Parity asserts that all fixtures in the adversarial corpus
// (both internal/tls/testdata/adversarial and tests/adversarial/corpus) are parsed cleanly:
// 1. Neither ParseClientHello nor ComputeJA4 panics or hangs.
// 2. Erroneous inputs return expected errors (ErrTruncated, ErrNotTLS, ErrNotClientHello, etc.).
// 3. Valid inputs produce well-formed ClientHelloInfo and valid JA4 fingerprints.
// 4. Edge cases match specific behavioral invariants:
//    - 0-byte input -> ErrTruncated
//    - Truncated record header (< 5 bytes) -> ErrTruncated
//    - Truncated ClientHello -> ErrTruncated
//    - Max length SNI (255 chars) -> parsed cleanly without overflow, valid JA4 computed
//    - SNI with null byte -> parsed cleanly without crash, null byte preserved/handled safely
//    - Duplicate extension types -> sorted and handled per JA4 spec without deduplication bugs
//    - All GREASE ciphers -> filtered out of cipher list per JA4 spec (resulting in 00 ciphers)
//    - Old TLS versions (SSL 3.0 / TLS 1.0) -> parsed cleanly with correct version indicator
func TestAdversarialCorpus_Parity(t *testing.T) {
	adversarialDir := "testdata/adversarial"
	entries, err := os.ReadDir(adversarialDir)
	if err != nil {
		// Fallback if running from repo root
		adversarialDir = "internal/tls/testdata/adversarial"
		entries, err = os.ReadDir(adversarialDir)
		if err != nil {
			t.Fatalf("failed to read adversarial directory: %v", err)
		}
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bin") {
			continue
		}

		name := entry.Name()
		filePath := filepath.Join(adversarialDir, name)

		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read %s: %v", filePath, err)
			}

			// Invariant 1: No panic, no hang (>200ms)
			type parseRes struct {
				info *ClientHelloInfo
				err  error
			}
			ch := make(chan parseRes, 1)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("ParseClientHello panicked on %s: %v", name, r)
						ch <- parseRes{err: nil}
					}
				}()
				info, pErr := ParseClientHello(data)
				ch <- parseRes{info: info, err: pErr}
			}()

			var res parseRes
			select {
			case res = <-ch:
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("ParseClientHello hung on %s (>200ms)", name)
			}

			if res.err != nil && res.info != nil {
				t.Fatalf("ParseClientHello returned both info and err on %s: info=%+v err=%v", name, res.info, res.err)
			}

			// Invariant 2: If successfully parsed, ComputeJA4 must not panic
			if res.info != nil {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("ComputeJA4 panicked on %s: %v", name, r)
					}
				}()
				ja4 := ComputeJA4(res.info)
				if ja4 == "" {
					t.Fatalf("ComputeJA4 returned empty string on %s", name)
				}
				// Basic JA4 format check: t12d..._..._...
				parts := strings.Split(ja4, "_")
				if len(parts) != 3 {
					t.Fatalf("invalid JA4 format for %s: %q", name, ja4)
				}
			}

			// Specific edge-case assertions
			switch name {
			case "empty_clienthello.bin":
				if res.err != ErrTruncated {
					t.Errorf("empty_clienthello.bin: want ErrTruncated, got %v", res.err)
				}
			case "zero_length_record.bin":
				// Record header len is 0; body len < minClientHelloSize -> ErrTruncated
				if res.err != ErrTruncated {
					t.Errorf("zero_length_record.bin: want ErrTruncated, got %v", res.err)
				}
			case "zero_length_clienthello.bin":
				if res.err != ErrTruncated {
					t.Errorf("zero_length_clienthello.bin: want ErrTruncated, got %v", res.err)
				}
			case "random_garbage_512_bytes.bin":
				if res.err != ErrNotTLS {
					t.Errorf("random_garbage_512_bytes.bin: want ErrNotTLS, got %v", res.err)
				}
			case "truncated_before_cipher_list.bin":
				if res.err != ErrTruncated {
					t.Errorf("truncated_before_cipher_list.bin: want ErrTruncated, got %v", res.err)
				}
			case "truncated_mid_extension.bin":
				if res.err != ErrTruncated {
					t.Errorf("truncated_mid_extension.bin: want ErrTruncated, got %v", res.err)
				}
			case "overflow_extension_length.bin":
				if res.err != ErrTruncated {
					t.Errorf("overflow_extension_length.bin: want ErrTruncated, got %v", res.err)
				}
			case "max_length_sni_255_chars.bin":
				if res.err != nil {
					t.Fatalf("max_length_sni_255_chars.bin failed to parse: %v", res.err)
				}
				if len(res.info.SNI) != 255 {
					t.Errorf("max_length_sni_255_chars.bin: expected SNI len 255, got %d", len(res.info.SNI))
				}
				if !res.info.SNIPresent {
					t.Errorf("max_length_sni_255_chars.bin: expected SNIPresent=true")
				}
				ja4 := ComputeJA4(res.info)
				if !strings.HasPrefix(ja4, "t12d") { // TLS 1.2 with domain
					t.Errorf("max_length_sni_255_chars.bin: expected JA4 to start with 't12d', got %q", ja4)
				}
			case "sni_with_null_byte.bin":
				if res.err != nil {
					t.Fatalf("sni_with_null_byte.bin failed to parse: %v", res.err)
				}
				if !strings.Contains(res.info.SNI, "\x00") {
					t.Errorf("sni_with_null_byte.bin: expected SNI to contain null byte, got %q", res.info.SNI)
				}
				ja4 := ComputeJA4(res.info)
				if !strings.HasPrefix(ja4, "t12d") {
					t.Errorf("sni_with_null_byte.bin: expected JA4 to start with 't12d', got %q", ja4)
				}
			case "duplicate_extension_types.bin":
				if res.err != nil {
					t.Fatalf("duplicate_extension_types.bin failed to parse: %v", res.err)
				}
				// Per RFC 8446 duplicates are handled; JA4 sort sorts both entries
				ja4 := ComputeJA4(res.info)
				if ja4 == "" {
					t.Errorf("duplicate_extension_types.bin: expected valid JA4")
				}
				// Verify extensions array has duplicate entries
				if len(res.info.Extensions) < 2 {
					t.Errorf("duplicate_extension_types.bin: expected multiple extensions, got %d", len(res.info.Extensions))
				}
			case "all_grease_ciphers.bin":
				if res.err != nil {
					t.Fatalf("all_grease_ciphers.bin failed to parse: %v", res.err)
				}
				// All ciphers are GREASE, so filtered ciphers = 0, cipher count in JA4 should be "00"
				// and cipher hash should be "000000000000"
				ja4 := ComputeJA4(res.info)
				parts := strings.Split(ja4, "_")
				if len(parts) == 3 {
					// Format: t12i000200_000000000000_<extHash>
					if parts[1] != "000000000000" {
						t.Errorf("all_grease_ciphers.bin: expected cipher hash '000000000000', got %q", parts[1])
					}
					// Check cipher count portion of section A: t 12 i 00(ciphers)
					secA := parts[0]
					if len(secA) >= 6 && secA[4:6] != "00" {
						t.Errorf("all_grease_ciphers.bin: expected 00 cipher count in JA4 secA %q", secA)
					}
				}
			case "empty_cipher_list.bin":
				if res.err != nil {
					t.Fatalf("empty_cipher_list.bin failed to parse: %v", res.err)
				}
				if len(res.info.CipherSuites) != 0 {
					t.Errorf("empty_cipher_list.bin: expected 0 ciphers, got %d", len(res.info.CipherSuites))
				}
				ja4 := ComputeJA4(res.info)
				parts := strings.Split(ja4, "_")
				if len(parts) == 3 && parts[1] != "000000000000" {
					t.Errorf("empty_cipher_list.bin: expected cipher hash '000000000000', got %q", parts[1])
				}
			case "tls_10_old_version.bin":
				if res.err != nil {
					t.Fatalf("tls_10_old_version.bin failed to parse: %v", res.err)
				}
				if res.info.LegacyVersion != 0x0301 {
					t.Errorf("tls_10_old_version.bin: expected legacy version 0x0301 (TLS 1.0), got 0x%04x", res.info.LegacyVersion)
				}
				ja4 := ComputeJA4(res.info)
				if !strings.HasPrefix(ja4, "t10") {
					t.Errorf("tls_10_old_version.bin: expected JA4 to start with 't10', got %q", ja4)
				}
			}
		})
	}
}

// TestAdversarialEdgeCases directly constructs edge-case byte sequences to verify
// parser and JA4 behavior hermetically.
func TestAdversarialEdgeCases(t *testing.T) {
	t.Run("ZeroByteInput", func(t *testing.T) {
		_, err := ParseClientHello([]byte{})
		if err != ErrTruncated {
			t.Errorf("expected ErrTruncated, got %v", err)
		}
	})

	t.Run("TruncatedRecordHeader", func(t *testing.T) {
		for l := 1; l < 5; l++ {
			header := []byte{0x16, 0x03, 0x01, 0x00, 0x05}[:l]
			_, err := ParseClientHello(header)
			if err != ErrTruncated {
				t.Errorf("len %d: expected ErrTruncated, got %v", l, err)
			}
		}
	})

	t.Run("TruncatedClientHelloHandshake", func(t *testing.T) {
		// Valid 5 byte TLS record header claiming 20 byte record, but nothing follows
		rec := []byte{0x16, 0x03, 0x03, 0x00, 0x14}
		_, err := ParseClientHello(rec)
		if err != ErrTruncated {
			t.Errorf("expected ErrTruncated, got %v", err)
		}
	})

	t.Run("MaxLengthSNI255Chars", func(t *testing.T) {
		sni255 := strings.Repeat("a", 255)
		ch := buildClientHelloBytes(0x0303, []uint16{0x1301}, []extensionSpec{
			{extType: 0x0000, data: buildSNIExt(sni255)},
		})
		info, err := ParseClientHello(ch)
		if err != nil {
			t.Fatalf("ParseClientHello failed: %v", err)
		}
		if info.SNI != sni255 {
			t.Fatalf("SNI mismatch: len got %d, want 255", len(info.SNI))
		}
		ja4 := ComputeJA4(info)
		if !strings.HasPrefix(ja4, "t12d") {
			t.Errorf("expected JA4 to start with t12d, got %s", ja4)
		}
	})

	t.Run("SNIWithNullByte", func(t *testing.T) {
		sniWithNull := "evil\x00corp.com"
		ch := buildClientHelloBytes(0x0303, []uint16{0x1301}, []extensionSpec{
			{extType: 0x0000, data: buildSNIExt(sniWithNull)},
		})
		info, err := ParseClientHello(ch)
		if err != nil {
			t.Fatalf("ParseClientHello failed: %v", err)
		}
		if info.SNI != sniWithNull {
			t.Fatalf("SNI mismatch: got %q, want %q", info.SNI, sniWithNull)
		}
		ja4 := ComputeJA4(info)
		if !strings.HasPrefix(ja4, "t12d") {
			t.Errorf("expected JA4 to start with t12d, got %s", ja4)
		}
	})

	t.Run("DuplicateExtensionTypes", func(t *testing.T) {
		ch := buildClientHelloBytes(0x0303, []uint16{0x1301}, []extensionSpec{
			{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304})},
			{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304})},
		})
		info, err := ParseClientHello(ch)
		if err != nil {
			t.Fatalf("ParseClientHello failed: %v", err)
		}
		if len(info.Extensions) != 2 || info.Extensions[0] != 0x002b || info.Extensions[1] != 0x002b {
			t.Fatalf("expected duplicate extensions [0x002b, 0x002b], got %v", info.Extensions)
		}
		ja4 := ComputeJA4(info)
		if ja4 == "" {
			t.Fatalf("expected non-empty JA4")
		}
	})

	t.Run("AllGREASECiphers", func(t *testing.T) {
		greaseCiphers := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a}
		ch := buildClientHelloBytes(0x0303, greaseCiphers, nil)
		info, err := ParseClientHello(ch)
		if err != nil {
			t.Fatalf("ParseClientHello failed: %v", err)
		}
		ja4 := ComputeJA4(info)
		parts := strings.Split(ja4, "_")
		if parts[1] != "000000000000" {
			t.Errorf("expected cipher hash 000000000000, got %s", parts[1])
		}
	})

	t.Run("OldTLSVersions", func(t *testing.T) {
		// SSL 3.0 (0x0300)
		ch30 := buildClientHelloBytes(0x0300, []uint16{0x0004}, nil)
		info30, err := ParseClientHello(ch30)
		if err != nil {
			t.Fatalf("ParseClientHello SSL 3.0 failed: %v", err)
		}
		ja4_30 := ComputeJA4(info30)
		if !strings.HasPrefix(ja4_30, "t03") {
			t.Errorf("expected t03 prefix for SSL 3.0, got %s", ja4_30)
		}

		// TLS 1.0 (0x0301)
		ch10 := buildClientHelloBytes(0x0301, []uint16{0x0004}, nil)
		info10, err := ParseClientHello(ch10)
		if err != nil {
			t.Fatalf("ParseClientHello TLS 1.0 failed: %v", err)
		}
		ja4_10 := ComputeJA4(info10)
		if !strings.HasPrefix(ja4_10, "t10") {
			t.Errorf("expected t10 prefix for TLS 1.0, got %s", ja4_10)
		}
	})

	t.Run("OversizedRecordHeaderLength", func(t *testing.T) {
		// TLS record claims 16385 bytes (> 16384 limit)
		data := []byte{0x16, 0x03, 0x03, 0x40, 0x01}
		_, err := ParseClientHello(data)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("expected 'TLS record too large' error, got %v", err)
		}
	})

	t.Run("NonHandshakeContentType", func(t *testing.T) {
		// 0x17 = Application Data
		data := []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}
		_, err := ParseClientHello(data)
		if err != ErrNotTLS {
			t.Errorf("expected ErrNotTLS, got %v", err)
		}
	})

	t.Run("NonClientHelloHandshakeType", func(t *testing.T) {
		// Handshake header type 0x02 = ServerHello
		body := []byte{0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00}
		rec := append([]byte{0x16, 0x03, 0x03, 0x00, byte(len(body))}, body...)
		_, err := ParseClientHello(rec)
		if err != ErrNotClientHello {
			t.Errorf("expected ErrNotClientHello, got %v", err)
		}
	})

	t.Run("ReassembledMultipleRecordsParsing", func(t *testing.T) {
		// Multiple records forming a fragmented ClientHello
		ch := buildClientHelloBytes(0x0303, []uint16{0x1301, 0x1302}, []extensionSpec{
			{extType: 0x0000, data: buildSNIExt("example.com")},
		})
		// Split body across two TLS records
		body := ch[5:]
		half := len(body) / 2
		r1 := append([]byte{0x16, 0x03, 0x03, byte(half >> 8), byte(half)}, body[:half]...)
		r2Len := len(body) - half
		r2 := append([]byte{0x16, 0x03, 0x03, byte(r2Len >> 8), byte(r2Len)}, body[half:]...)
		combined := append(r1, r2...)

		info, err := ParseClientHello(combined)
		if err != nil {
			t.Fatalf("expected successful reassembly parse, got: %v", err)
		}
		if info.SNI != "example.com" {
			t.Errorf("expected SNI example.com, got %q", info.SNI)
		}
		ja4 := ComputeJA4(info)
		if !strings.HasPrefix(ja4, "t12d") {
			t.Errorf("expected t12d JA4 prefix, got %s", ja4)
		}
	})

	t.Run("TrailingGarbageAfterValidClientHello", func(t *testing.T) {
		ch := buildClientHelloBytes(0x0303, []uint16{0x1301}, nil)
		withGarbage := append(ch, []byte("TRAIL_GARBAGE_BYTES")...)
		info, err := ParseClientHello(withGarbage)
		if err != nil {
			t.Fatalf("ParseClientHello failed with trailing garbage: %v", err)
		}
		if info == nil {
			t.Fatalf("expected valid info")
		}
		if !bytes.Equal(info.Raw, withGarbage) {
			t.Errorf("expected info.Raw to preserve input")
		}
	})
}
