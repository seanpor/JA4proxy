package tls

import (
	"os"
	"path/filepath"
	"testing"
)

func seedAdversarialCorpus(f *testing.F) {
	f.Helper()
	roots := []string{
		"testdata/adversarial",
		"internal/tls/testdata/adversarial",
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
}

func FuzzParseClientHello(f *testing.F) {
	// Seed from adversarial corpus fixtures
	seedAdversarialCorpus(f)

	// Seed 1: Minimal valid ClientHello
	f.Add(buildClientHelloBytes(0x0303, []uint16{0x1301}, nil))

	// Seed 2: Chrome-like ClientHello
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	exts := []extensionSpec{
		{extType: 0x0000, data: buildSNIExt("example.com")},
		{extType: 0x0010, data: buildALPNExt([]string{"h2", "http/1.1"})},
		{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304})},
	}
	f.Add(buildClientHelloBytes(0x0303, ciphers, exts))

	// Degenerate seeds
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseClientHello/ComputeJA4 panicked on %x: %v", data, r)
			}
		}()

		info, err := ParseClientHello(data)
		if err == nil && info != nil {
			// If it parses, compute JA4 to fuzz that too
			ComputeJA4(info)
		}
	})
}
