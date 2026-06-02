package tls

import (
	"testing"
)

func FuzzParseClientHello(f *testing.F) {
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

	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := ParseClientHello(data)
		if err == nil && info != nil {
			// If it parses, compute JA4 to fuzz that too
			ComputeJA4(info)
		}
	})
}
