package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildSyntheticClientHello constructs a minimal but valid TLS ClientHello
// binary that ParseClientHello can parse. It includes:
//   - TLS record header (content type 0x16, version TLS 1.0, length)
//   - Handshake header (type 0x01 = ClientHello, length)
//   - Legacy version TLS 1.2 (0x0303)
//   - 32 bytes random
//   - Empty session ID
//   - Two cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
//   - One compression method: null (0x00)
//   - Extensions: SNI for "example.com", supported_versions with TLS 1.3
func buildSyntheticClientHello() []byte {
	var hello []byte

	// legacy_version: TLS 1.2
	hello = append(hello, 0x03, 0x03)

	// random: 32 bytes of 0x01
	random := make([]byte, 32)
	for i := range random {
		random[i] = 0x01
	}
	hello = append(hello, random...)

	// session_id: length 0
	hello = append(hello, 0x00)

	// cipher_suites: 2 suites = 4 bytes
	csLen := make([]byte, 2)
	binary.BigEndian.PutUint16(csLen, 4)
	hello = append(hello, csLen...)
	cs1 := make([]byte, 2)
	binary.BigEndian.PutUint16(cs1, 0x1301) // TLS_AES_128_GCM_SHA256
	hello = append(hello, cs1...)
	cs2 := make([]byte, 2)
	binary.BigEndian.PutUint16(cs2, 0x1302) // TLS_AES_256_GCM_SHA384
	hello = append(hello, cs2...)

	// compression_methods: 1 method, null
	hello = append(hello, 0x01, 0x00)

	// Build extensions
	var exts []byte

	// SNI extension (type 0x0000)
	sni := "example.com"
	sniNameBytes := []byte(sni)
	// SNI extension body: list_length (2) + name_type (1) + name_length (2) + name
	var sniBody []byte
	sniListLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sniListLen, uint16(1+2+len(sniNameBytes)))
	sniBody = append(sniBody, sniListLen...)
	sniBody = append(sniBody, 0x00) // name_type = host_name
	sniNameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sniNameLen, uint16(len(sniNameBytes)))
	sniBody = append(sniBody, sniNameLen...)
	sniBody = append(sniBody, sniNameBytes...)

	sniExtType := make([]byte, 2)
	binary.BigEndian.PutUint16(sniExtType, 0x0000)
	sniExtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sniExtLen, uint16(len(sniBody)))
	exts = append(exts, sniExtType...)
	exts = append(exts, sniExtLen...)
	exts = append(exts, sniBody...)

	// Supported versions extension (type 0x002b)
	// Body: list_length (1 byte) + 1 version (2 bytes) = 3 bytes body
	svBody := []byte{0x02, 0x03, 0x04} // list_len=2, TLS 1.3 (0x0304)
	svExtType := make([]byte, 2)
	binary.BigEndian.PutUint16(svExtType, 0x002b)
	svExtLen := make([]byte, 2)
	binary.BigEndian.PutUint16(svExtLen, uint16(len(svBody)))
	exts = append(exts, svExtType...)
	exts = append(exts, svExtLen...)
	exts = append(exts, svBody...)

	// Extensions total length
	extsTotalLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extsTotalLen, uint16(len(exts)))
	hello = append(hello, extsTotalLen...)
	hello = append(hello, exts...)

	// Handshake header: type=0x01, length=len(hello)
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	helloLen := len(hello)
	handshake = append(handshake, byte(helloLen>>16), byte(helloLen>>8), byte(helloLen))
	handshake = append(handshake, hello...)

	// TLS record header: type=0x16, version=0x0301, length=len(handshake)
	var record []byte
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(handshake)))
	record = append(record, recLen...)
	record = append(record, handshake...)

	return record
}

// TestRun_ValidClientHello verifies that run() with a valid synthetic
// ClientHello binary returns exit 0 and a non-empty JA4 fingerprint.
func TestRun_ValidClientHello(t *testing.T) {
	data := buildSyntheticClientHello()

	tmpFile := filepath.Join(t.TempDir(), "valid.bin")
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := run([]string{tmpFile})
	if err != nil {
		t.Fatalf("run() error: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty JA4 fingerprint")
	}
	// JA4 fingerprints start with 't' (TLS) or 'q' (QUIC)
	if result[0] != 't' && result[0] != 'q' {
		t.Errorf("JA4 fingerprint should start with 't' or 'q', got %q", result)
	}
	t.Logf("JA4 fingerprint: %s", result)
}

// TestRun_EmptyFile verifies that run() returns a parse error for a zero-byte file.
func TestRun_EmptyFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(tmpFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := run([]string{tmpFile})
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if _, ok := err.(*parseError); !ok {
		t.Errorf("expected *parseError, got %T: %v", err, err)
	}
}

// TestRun_NoArgs verifies that run() returns an error with no arguments.
func TestRun_NoArgs(t *testing.T) {
	_, err := run(nil)
	if err == nil {
		t.Fatal("expected error for no arguments")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Errorf("expected usage message, got: %v", err)
	}
}

// TestRun_NonexistentFile verifies that run() returns a file read error.
func TestRun_NonexistentFile(t *testing.T) {
	_, err := run([]string{"/nonexistent/file.bin"})
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	// Should NOT be a parseError (it's a file read error)
	if _, ok := err.(*parseError); ok {
		t.Error("file read errors should not be parseError")
	}
}

// TestRun_InvalidData verifies that run() returns a parseError for invalid TLS data.
func TestRun_InvalidData(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(tmpFile, []byte("not a clienthello"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := run([]string{tmpFile})
	if err == nil {
		t.Fatal("expected error for invalid TLS data")
	}
	pe, ok := err.(*parseError)
	if !ok {
		t.Fatalf("expected *parseError, got %T: %v", err, err)
	}
	if !strings.Contains(pe.Error(), "parse error") {
		t.Errorf("error message should contain 'parse error', got: %v", pe)
	}
}

// TestParseError_ErrorMethod verifies the parseError.Error() string format.
func TestParseError_ErrorMethod(t *testing.T) {
	pe := &parseError{err: os.ErrNotExist}
	got := pe.Error()
	if !strings.HasPrefix(got, "parse error: ") {
		t.Errorf("parseError.Error() = %q; want prefix 'parse error: '", got)
	}
}

// TestMainResult_ValidFile verifies mainResult returns code 0 for valid input.
func TestMainResult_ValidFile(t *testing.T) {
	data := buildSyntheticClientHello()
	tmpFile := filepath.Join(t.TempDir(), "valid.bin")
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, code := mainResult([]string{tmpFile})
	if code != 0 {
		t.Errorf("mainResult exit code = %d; want 0 (output: %s)", code, result)
	}
	if result == "" {
		t.Error("mainResult should return non-empty JA4 fingerprint")
	}
}

// TestMainResult_NoArgs verifies mainResult returns code 1 for no arguments.
func TestMainResult_NoArgs(t *testing.T) {
	_, code := mainResult(nil)
	if code != 1 {
		t.Errorf("mainResult exit code = %d; want 1", code)
	}
}

// TestMainResult_InvalidData verifies mainResult returns code 2 for parse errors.
func TestMainResult_InvalidData(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(tmpFile, []byte("not tls"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, code := mainResult([]string{tmpFile})
	if code != 2 {
		t.Errorf("mainResult exit code = %d; want 2", code)
	}
	if !strings.Contains(result, "parse error") {
		t.Errorf("expected parse error message, got: %s", result)
	}
}

// TestMainResult_MissingFile verifies mainResult returns code 1 for missing file.
func TestMainResult_MissingFile(t *testing.T) {
	_, code := mainResult([]string{"/nonexistent/file.bin"})
	if code != 1 {
		t.Errorf("mainResult exit code = %d; want 1", code)
	}
}

// TestMain_OsExitOverride exercises main() by overriding osExit and os.Args.
func TestMain_OsExitOverride(t *testing.T) {
	// Save originals
	origArgs := os.Args
	origExit := osExit
	defer func() {
		os.Args = origArgs
		osExit = origExit
	}()

	var exitCode int
	osExit = func(code int) { exitCode = code }

	// Test: no args (should exit 1)
	os.Args = []string{"ja4check"}
	exitCode = -1
	main()
	if exitCode != 1 {
		t.Errorf("no args: exit code = %d; want 1", exitCode)
	}

	// Test: valid file (should exit 0 — osExit not called)
	data := buildSyntheticClientHello()
	tmpFile := filepath.Join(t.TempDir(), "valid.bin")
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"ja4check", tmpFile}
	exitCode = -1
	main()
	// For success, osExit is not called; exitCode stays -1
	if exitCode != -1 {
		t.Errorf("valid file: osExit called with code %d; want no call", exitCode)
	}

	// Test: invalid data (should exit 2)
	badFile := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(badFile, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"ja4check", badFile}
	exitCode = -1
	main()
	if exitCode != 2 {
		t.Errorf("invalid data: exit code = %d; want 2", exitCode)
	}
}
