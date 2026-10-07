package tlsfixture

import (
	"pgregory.net/rapid"
)

// GenSpec returns a rapid generator for structurally valid ClientHello Spec objects.
func GenSpec() *rapid.Generator[Spec] {
	return rapid.Custom(func(t *rapid.T) Spec {
		sni := rapid.SampledFrom([]string{"example.com", "ja4proxy.io", "test.local", ""}).Draw(t, "sni")
		alpn := rapid.SampledFrom([][]string{{"h2", "http/1.1"}, {"http/1.1"}, nil}).Draw(t, "alpn")
		ciphers := rapid.SliceOfN(rapid.SampledFrom([]uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}), 1, 10).Draw(t, "ciphers")
		supportedVers := rapid.SampledFrom([][]uint16{{0x0304, 0x0303}, {0x0303}, nil}).Draw(t, "supportedVers")

		return Spec{
			LegacyVersion: 0x0303,
			Ciphers:       ciphers,
			SNI:           sni,
			ALPN:          alpn,
			SupportedVers: supportedVers,
		}
	})
}
