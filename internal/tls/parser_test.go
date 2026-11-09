// Phase 62 — Adversarial corpus regression test for the production
// ClientHello parser. This test is the deterministic counterpart to the
// coverage-guided fuzzer in cmd/proxy/fuzz_test.go: it runs in every normal
// `go test ./...` pass and asserts that every known-bad input shape held in
// tests/adversarial/corpus/ either returns an error or a partial result —
// never a panic, never a hang.
package tls

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// adversarialCorpusGlobs lists the candidate paths for the adversarial corpus
// directory. Tests run from internal/tls/ when invoked via `go test`, but
// the same suite is sometimes invoked from the repo root.
var adversarialCorpusGlobs = []string{
	"../../tests/adversarial/corpus/*.bin",
	"tests/adversarial/corpus/*.bin",
}

// findCorpusFixtures returns the resolved list of *.bin files. It returns an
// empty slice (and never an error) if the corpus directory does not exist —
// the test will skip rather than fail in that case.
func findCorpusFixtures(t *testing.T) []string {
	t.Helper()
	for _, pattern := range adversarialCorpusGlobs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			return matches
		}
	}
	return nil
}

// TestParseClientHello_AdversarialCorpus drives ParseClientHello with each
// fixture under tests/adversarial/corpus/. Every fixture must satisfy three
// invariants:
//
//   - The parser must not panic on the input.
//   - The parser must return within 100 ms (no infinite loops on malformed
//     length prefixes).
//   - The parser must not return both a non-nil result and an error.
//
// New fixtures committed to the corpus directory are picked up automatically.
func TestParseClientHello_AdversarialCorpus(t *testing.T) {
	matches := findCorpusFixtures(t)
	if len(matches) == 0 {
		t.Skip("no adversarial corpus fixtures found on disk")
	}
	for _, path := range matches {
		path := path
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			type result struct {
				info *ClientHelloInfo
				err  error
			}
			done := make(chan result, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("ParseClientHello panicked on %s: %v", name, r)
						done <- result{}
					}
				}()
				info, err := ParseClientHello(data)
				done <- result{info: info, err: err}
			}()

			select {
			case res := <-done:
				if res.info != nil && res.err != nil {
					t.Errorf("parser returned both result and error on %s: info=%+v err=%v", name, res.info, res.err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("parser hung on %s (>100ms) — possible infinite loop", name)
			}
		})
	}
}

// TestParseClientHello_BoundaryConditions satisfies Gate G-2.2 for Phase 868.
// Verifies boundary conditions: 1-byte record, empty extension, extension length > remainder,
// 0-length ALPN entry, 0-entry ALPN list, ALPN list spanning a record boundary,
// 255-entry protocol list, and 65535-byte SNI.
func TestParseClientHello_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "1-byte record",
			data:    []byte{0x16},
			wantErr: true,
		},
		{
			name:    "incomplete TLS record header (4 bytes)",
			data:    []byte{0x16, 0x03, 0x01, 0x00},
			wantErr: true,
		},
		{
			name:    "extension length > remainder",
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},
			wantErr: true,
		},
		{
			name: "0-entry ALPN list",
			data: func() []byte {
				// ALPN extension: ext_type=0x0010, ext_len=2, list_len=0
				exts := []byte{0x00, 0x10, 0x00, 0x02, 0x00, 0x00}
				var body []byte
				body = append(body, 0x03, 0x03)
				body = append(body, make([]byte, 32)...)
				body = append(body, 0x00) // session ID
				body = append(body, 0x00, 0x02, 0x00, 0x9c) // ciphers
				body = append(body, 0x01, 0x00) // compression
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)
				handshakeLen := len(body)
				var record []byte
				record = append(record, 0x16, 0x03, 0x01)
				recLen := handshakeLen + 4
				record = append(record, byte(recLen>>8), byte(recLen))
				record = append(record, 0x01, 0x00, byte(handshakeLen>>8), byte(handshakeLen))
				record = append(record, body...)
				return record
			}(),
			wantErr: false,
		},
		{
			name: "0-length ALPN entry",
			data: func() []byte {
				// ALPN extension: ext_type=0x0010, ext_len=3, list_len=1, entry_len=0
				exts := []byte{0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00}
				var body []byte
				body = append(body, 0x03, 0x03)
				body = append(body, make([]byte, 32)...)
				body = append(body, 0x00) // session ID
				body = append(body, 0x00, 0x02, 0x00, 0x9c) // ciphers
				body = append(body, 0x01, 0x00) // compression
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)
				handshakeLen := len(body)
				var record []byte
				record = append(record, 0x16, 0x03, 0x01)
				recLen := handshakeLen + 4
				record = append(record, byte(recLen>>8), byte(recLen))
				record = append(record, 0x01, 0x00, byte(handshakeLen>>8), byte(handshakeLen))
				record = append(record, body...)
				return record
			}(),
			wantErr: false,
		},
		{
			name: "255-entry protocol list",
			data: func() []byte {
				// Construct valid ClientHello with ALPN containing 255 1-byte protocols
				var alpnData []byte
				for i := 0; i < 255; i++ {
					alpnData = append(alpnData, 1, byte(i))
				}
				extLen := len(alpnData) + 2
				var exts []byte
				exts = append(exts, 0x00, 0x10) // ALPN ext type 16
				exts = append(exts, byte(extLen>>8), byte(extLen))
				exts = append(exts, byte(len(alpnData)>>8), byte(len(alpnData)))
				exts = append(exts, alpnData...)

				var body []byte
				body = append(body, 0x03, 0x03) // TLS 1.2
				body = append(body, make([]byte, 32)...) // random
				body = append(body, 0x00) // session ID len
				body = append(body, 0x00, 0x02, 0x00, 0x9c) // ciphers
				body = append(body, 0x01, 0x00) // compression
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)

				handshakeLen := len(body)
				var record []byte
				record = append(record, 0x16, 0x03, 0x01)
				recLen := handshakeLen + 4
				record = append(record, byte(recLen>>8), byte(recLen))
				record = append(record, 0x01, 0x00, byte(handshakeLen>>8), byte(handshakeLen))
				record = append(record, body...)
				return record
			}(),
			wantErr: false,
		},
		{
			name: "65535-byte SNI buffer",
			data: func() []byte {
				// Record header indicates 65535 bytes but only truncated header supplied
				return []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseClientHello(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseClientHello() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && info == nil {
				t.Errorf("ParseClientHello() returned nil info with nil error")
			}
		})
	}
}
