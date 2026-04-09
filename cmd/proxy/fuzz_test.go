// Phase 62 — Go-native fuzz targets for the TLS ClientHello parser and the
// PROXY protocol header reader. These targets replace the retired Python
// atheris fuzzers and give the production Go proxy first-class coverage-guided
// fuzzing against the two hottest untrusted-input boundaries.
//
// Run a single target for 10 s:
//
//	GOROOT=/snap/go/current go test -run=^$ -fuzz=FuzzClientHello -fuzztime=10s ./cmd/proxy/
//
// Any panic discovered by the fuzzer is saved under
// testdata/fuzz/<FuzzName>/<sha>. Crash artefacts must be committed so the
// failing input becomes a regression seed.
package main

import (
	"os"
	"path/filepath"
	"testing"

	proxypkg "github.com/anomalyco/ja4proxy/internal/proxy"
	tlsparse "github.com/anomalyco/ja4proxy/internal/tls"
)

// seedAdversarialCorpus walks tests/adversarial/corpus/*.bin and adds every
// binary fixture to the fuzz seed corpus. Missing files are ignored so the
// target still runs in a checkout that has pruned fixtures.
//
// phase-62 review-fix #2 (N9): if neither root resolves any seeds, log a
// warning. A future refactor that renames or moves tests/adversarial/corpus
// would otherwise silently demote the fuzzer to "synthetic seeds only" with
// no signal in CI logs.
func seedAdversarialCorpus(f *testing.F) {
	f.Helper()
	roots := []string{
		"../../tests/adversarial/corpus",
		"tests/adversarial/corpus",
	}
	for _, root := range roots {
		matches, err := filepath.Glob(filepath.Join(root, "*.bin"))
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, p := range matches {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			f.Add(data)
		}
		return
	}
	f.Logf("seedAdversarialCorpus: no adversarial seed fixtures found under %v "+
		"— fuzzer will run with synthetic seeds only. If this is unexpected, "+
		"check that tests/adversarial/corpus/*.bin still exists.", roots)
}

// FuzzClientHello drives the production TLS parser with arbitrary bytes.
// The parser must never panic on any input. It may return an error or a
// partial *ClientHelloInfo — both are acceptable outcomes. A panic is
// always a bug and fails the fuzz target.
func FuzzClientHello(f *testing.F) {
	seedAdversarialCorpus(f)

	// Known-valid minimal TLS record header — seeds the coverage walker with
	// a non-malformed starting point so mutation can discover new paths.
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	// Degenerate inputs.
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseClientHello panicked on %x: %v", data, r)
			}
		}()
		_, _ = tlsparse.ParseClientHello(data)
	})
}

// FuzzReadProxyProtocol drives the PROXY protocol v1 header reader with
// arbitrary bytes. The reader must never panic and must never block.
//
// The current Go signature is (buf []byte) → (clientIP string, ok bool).
// Phase 200 will split this into ReadProxyProtocolV1/V2 — at that point the
// fuzz target should be updated to call the V1 entry point directly.
func FuzzReadProxyProtocol(f *testing.F) {
	f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n"))
	f.Add([]byte("PROXY TCP6 ::1 ::1 1234 443\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("PROXY"))
	f.Add([]byte("PROXY TCP4 not-an-ip 5.6.7.8 1234 443\r\n"))
	f.Add([]byte("PROXY TCP4     \r\n"))
	// A Chrome-like TLS ClientHello prefix — must not be mistaken for PROXY.
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadProxyProtocol panicked on %x: %v", data, r)
			}
		}()
		_, _ = proxypkg.ReadProxyProtocol(data)
	})
}

// FuzzReadProxyProtocolV2 is gated on the V2 binary reader introduced by
// Phase 200. The current proxy package exposes only the v1 text reader, so
// this target wraps the same entry point with v2-shaped binary seeds. When
// Phase 200 adds ReadProxyProtocolV2 this target should be updated to call
// it directly; until then the fuzzer still exercises the shared entry point
// against the binary wire format and guarantees it cannot panic on any
// v2-looking input.
func FuzzReadProxyProtocolV2(f *testing.F) {
	// Valid v2 signature + minimal v4 header.
	f.Add([]byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x50, 0x01, 0xBB,
	})
	// Valid v2 signature + zero-length body.
	f.Add([]byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x20, 0x00, 0x00, 0x00,
	})
	// Truncated signature.
	f.Add([]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadProxyProtocol (v2-shaped input) panicked on %x: %v", data, r)
			}
		}()
		_, _ = proxypkg.ReadProxyProtocol(data)
	})
}
