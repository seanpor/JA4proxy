package tls_test

import (
	"testing"

	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func TestParseClientHello_ExtensionErrorPaths(t *testing.T) {
	// Truncated SNI extension data
	specSNITruncated := tlsfixture.Spec{
		Extensions: []tlsfixture.Extension{
			{Type: 0x0000, Data: []byte{0x00, 0x01}}, // missing host_name payload
		},
	}
	info, err := tlsparse.ParseClientHello(tlsfixture.Build(specSNITruncated))
	if err == nil && info.SNI != "" {
		t.Fatalf("expected empty SNI on truncated SNI extension")
	}

	// Truncated ALPN extension data
	specALPNTruncated := tlsfixture.Spec{
		Extensions: []tlsfixture.Extension{
			{Type: 0x0010, Data: []byte{0x00, 0x05, 0x02, 'h'}}, // truncated alpn list
		},
	}
	info, err = tlsparse.ParseClientHello(tlsfixture.Build(specALPNTruncated))
	if err == nil && len(info.ALPNProtocols) != 0 {
		t.Fatalf("expected empty ALPNProtocols on truncated ALPN extension")
	}

	// Truncated Supported Versions extension
	specSuppVersTruncated := tlsfixture.Spec{
		Extensions: []tlsfixture.Extension{
			{Type: 0x002b, Data: []byte{0x03, 0x03}}, // odd length byte (3 bytes total expected, only 2 provided)
		},
	}
	info, err = tlsparse.ParseClientHello(tlsfixture.Build(specSuppVersTruncated))
	if err == nil && info.LegacyVersion == 0 {
		t.Fatalf("expected non-zero LegacyVersion fallback on truncated supported_versions extension")
	}

	// Truncated Supported Groups extension
	specSuppGroupsTruncated := tlsfixture.Spec{
		Extensions: []tlsfixture.Extension{
			{Type: 0x000a, Data: []byte{0x00, 0x05, 0x00}}, // truncated group list
		},
	}
	_, _ = tlsparse.ParseClientHello(tlsfixture.Build(specSuppGroupsTruncated))

	// Truncated Signature Algorithms extension
	specSigAlgsTruncated := tlsfixture.Spec{
		Extensions: []tlsfixture.Extension{
			{Type: 0x000d, Data: []byte{0x00, 0x05, 0x04}}, // truncated sig algs list
		},
	}
	_, _ = tlsparse.ParseClientHello(tlsfixture.Build(specSigAlgsTruncated))
}

func TestComputeJA4_TLSVersionFallbackStrings(t *testing.T) {
	// TLS 1.0 (0x0301), TLS 1.1 (0x0302), SSL 3.0 (0x0300)
	specTLS10 := tlsfixture.Spec{
		LegacyVersion: 0x0301,
	}
	info, err := tlsparse.ParseClientHello(tlsfixture.Build(specTLS10))
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	ja4 := tlsparse.ComputeJA4(info)
	if ja4[:3] != "t10" {
		t.Fatalf("expected ja4 prefix t10 for TLS 1.0, got %s", ja4[:3])
	}

	specTLS11 := tlsfixture.Spec{
		LegacyVersion: 0x0302,
	}
	info, err = tlsparse.ParseClientHello(tlsfixture.Build(specTLS11))
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	ja4 = tlsparse.ComputeJA4(info)
	if ja4[:3] != "t11" {
		t.Fatalf("expected ja4 prefix t11 for TLS 1.1, got %s", ja4[:3])
	}

	// Unknown version e.g. 0x0200
	specUnknown := tlsfixture.Spec{
		LegacyVersion: 0x0200,
	}
	info, err = tlsparse.ParseClientHello(tlsfixture.Build(specUnknown))
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	ja4 = tlsparse.ComputeJA4(info)
	if ja4[:3] != "t00" {
		t.Fatalf("expected ja4 prefix t00 for unknown version 0x0200, got %s", ja4[:3])
	}
}
