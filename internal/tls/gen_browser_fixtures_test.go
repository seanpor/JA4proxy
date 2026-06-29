//go:build generate

package tls

// TestGenBrowserLikeFixtures generates synthetic browser-like ClientHello
// binary fixtures and updates tests/fixtures/clienthello/known_ja4.json.
//
// Run once to produce committed fixture files:
//
//	go test -run TestGenBrowserLikeFixtures -tags generate ./internal/tls/
//
// The produced .bin files and the updated known_ja4.json are checked in.
// Normal test runs (without -tags generate) never execute this test.
//
// Why synthetic rather than live captures?
// Capturing real browser traffic requires an interactive browser session and
// is not reproducible in CI. These synthetic fixtures are constructed from
// published TLS fingerprint documentation and exercise the same JA4 code
// paths that real browsers hit: GREASE filtering, compress_certificate,
// post_handshake_auth, multi-protocol ALPN, and record_size_limit.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const genFixtureDir = "../../tests/fixtures/clienthello"

func TestGenBrowserLikeFixtures(t *testing.T) {
	fixtures := []struct {
		name string
		data []byte
	}{
		{"chrome_tls13_like", buildChromeLike()},
		{"firefox_tls13_like", buildFirefoxLike()},
	}

	// Load existing known_ja4.json.
	jsonPath := filepath.Join(genFixtureDir, "known_ja4.json")
	raw, err := os.ReadFile(jsonPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read known_ja4.json: %v", err)
	}
	expected := map[string]string{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatalf("parse known_ja4.json: %v", err)
		}
	}

	for _, fix := range fixtures {
		// Write .bin file.
		binPath := filepath.Join(genFixtureDir, fix.name+".bin")
		if err := os.WriteFile(binPath, fix.data, 0o644); err != nil {
			t.Fatalf("write %s: %v", binPath, err)
		}
		t.Logf("wrote %s (%d bytes)", binPath, len(fix.data))

		// Compute JA4 and register in known_ja4.json.
		info, err := ParseClientHello(fix.data)
		if err != nil {
			t.Fatalf("%s: parse error: %v", fix.name, err)
		}
		ja4 := ComputeJA4(info)
		expected[fix.name] = ja4
		t.Logf("%s → %s", fix.name, ja4)
	}

	out, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatalf("marshal known_ja4.json: %v", err)
	}
	if err := os.WriteFile(jsonPath, append(out, '\n'), 0o644); err != nil {
		t.Fatalf("write known_ja4.json: %v", err)
	}
	t.Logf("updated %s", jsonPath)
}

// buildChromeLike constructs a Chrome 120+ style TLS 1.3 ClientHello.
//
// Key browser-specific features exercised:
//   - GREASE in both cipher suite and extension lists (filtered by JA4)
//   - compress_certificate extension (0x001b)
//   - post_handshake_auth extension (0x0031)
//   - extended_master_secret (0x0017)
//   - Multi-protocol ALPN: h2 + http/1.1
//
// Cipher suites: 1 GREASE + 15 real → JA4 cipher count "15"
// Extensions: 1 GREASE + 16 real → JA4 ext count "16"
// ALPN first: h2 → JA4 ALPN field "h2"
// SNI present → JA4 SNI field "d"
// TLS 1.3 via supported_versions → JA4 version "t13"
// Expected JA4 prefix: t13d1516h2
func buildChromeLike() []byte {
	ciphers := []uint16{
		0x0a0a,                 // GREASE — filtered by JA4
		0x1301, 0x1302, 0x1303, // TLS 1.3 suites
		0xc02b, 0xc02f, // ECDHE-ECDSA/RSA AES-128-GCM
		0xc02c, 0xc030, // ECDHE-ECDSA/RSA AES-256-GCM
		0xcca9, 0xcca8, // ECDHE-ECDSA/RSA CHACHA20
		0xc013, 0xc014, // ECDHE-RSA AES-128/256-CBC
		0x009c, 0x009d, // RSA AES-128/256-GCM
		0x002f, 0x0035, // RSA AES-128/256-CBC
	} // 15 non-GREASE cipher suites

	exts := []extensionSpec{
		{extType: 0x0a0a, data: []byte{0x00, 0x00}}, // GREASE — filtered by JA4
		{extType: 0x0000, data: buildSNIExt("example.com")},
		{extType: 0x0017, data: []byte{}},                                    // extended_master_secret
		{extType: 0xff01, data: []byte{0x00}},                                // renegotiation_info
		{extType: 0x000a, data: buildSupportedGroupsExt()},                   // supported_groups
		{extType: 0x000b, data: []byte{0x01, 0x00}},                          // ec_point_formats
		{extType: 0x0023, data: []byte{}},                                    // session_ticket
		{extType: 0x0010, data: buildALPNExt([]string{"h2", "http/1.1"})},    // ALPN
		{extType: 0x0005, data: []byte{0x01, 0x00, 0x00, 0x00, 0x00}},        // status_request
		{extType: 0x000d, data: buildSigAlgsExt()},                           // signature_algorithms
		{extType: 0x0012, data: []byte{}},                                    // signed_certificate_timestamp
		{extType: 0x0033, data: buildKeyShareExt()},                          // key_share
		{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304})}, // supported_versions
		{extType: 0x002d, data: []byte{0x01, 0x01}},                          // psk_key_exchange_modes
		{extType: 0x001b, data: []byte{0x02, 0x00, 0x02}},                    // compress_certificate
		{extType: 0x0031, data: []byte{}},                                    // post_handshake_auth
		{extType: 0x0015, data: make([]byte, 133)},                           // padding
	} // 16 non-GREASE extensions (0x0015=padding counted; 0xff01=renegotiation counted)

	return buildClientHelloBytes(0x0303, ciphers, exts)
}

// buildFirefoxLike constructs a Firefox 122+ style TLS 1.3 ClientHello.
//
// Key differences from Chrome:
//   - No GREASE (Firefox does not send GREASE values)
//   - Different cipher ordering (TLS_CHACHA20 before TLS_AES_256)
//   - record_size_limit extension (0x001c) instead of compress_certificate
//   - delegated_credentials extension (0x0022) absent; post_handshake_auth present
//   - No padding extension
//
// Cipher suites: 15 → JA4 cipher count "15"
// Extensions (non-GREASE, non-SNI, non-supported-versions): 13 → JA4 ext count "13"
// ALPN first: h2 → JA4 ALPN field "h2"
// SNI present → JA4 SNI field "d"
// TLS 1.3 via supported_versions → JA4 version "t13"
// Expected JA4 prefix: t13d1513h2
func buildFirefoxLike() []byte {
	ciphers := []uint16{
		0x1301,                         // TLS_AES_128_GCM_SHA256
		0x1303,                         // TLS_CHACHA20_POLY1305_SHA256 (Firefox orders before AES-256)
		0x1302,                         // TLS_AES_256_GCM_SHA384
		0xc02b, 0xc02f, 0xcca9, 0xcca8, // ECDHE ECDSA/RSA GCM + CHACHA20
		0xc02c, 0xc030, // ECDHE ECDSA/RSA AES-256-GCM
		0xc014, 0xc013, // ECDHE-RSA AES-256/128-CBC (reversed vs Chrome)
		0x009c, 0x009d, // RSA AES-128/256-GCM
		0x002f, 0x0035, // RSA AES-128/256-CBC
	} // 15 cipher suites

	exts := []extensionSpec{
		{extType: 0x0000, data: buildSNIExt("example.com")},
		{extType: 0x0017, data: []byte{}},                                    // extended_master_secret
		{extType: 0xff01, data: []byte{0x00}},                                // renegotiation_info
		{extType: 0x000a, data: buildSupportedGroupsExt()},                   // supported_groups
		{extType: 0x000b, data: []byte{0x01, 0x00}},                          // ec_point_formats
		{extType: 0x0023, data: []byte{}},                                    // session_ticket
		{extType: 0x0010, data: buildALPNExt([]string{"h2", "http/1.1"})},    // ALPN
		{extType: 0x0005, data: []byte{0x01, 0x00, 0x00, 0x00, 0x00}},        // status_request
		{extType: 0x000d, data: buildSigAlgsExt()},                           // signature_algorithms
		{extType: 0x0033, data: buildKeyShareExt()},                          // key_share
		{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304})}, // supported_versions
		{extType: 0x002d, data: []byte{0x01, 0x01}},                          // psk_key_exchange_modes
		{extType: 0x001c, data: []byte{0x40, 0x01}},                          // record_size_limit
		{extType: 0x0031, data: []byte{}},                                    // post_handshake_auth
		{extType: 0x0012, data: []byte{}},                                    // signed_certificate_timestamp
	} // 15 extensions (SNI and supported_versions are excluded from JA4 ext count → 13)

	return buildClientHelloBytes(0x0303, ciphers, exts)
}

// buildSupportedGroupsExt returns a minimal supported_groups extension body.
func buildSupportedGroupsExt() []byte {
	groups := []uint16{0x001d, 0x0017, 0x0018, 0x0019} // x25519, secp256r1, secp384r1, secp521r1
	var data []byte
	data = appendUint16(data, uint16(len(groups)*2))
	for _, g := range groups {
		data = appendUint16(data, g)
	}
	// Wrap in outer length.
	var out []byte
	out = appendUint16(out, uint16(len(data)))
	return append(out, data...)
}

// buildSigAlgsExt returns a minimal signature_algorithms extension body.
func buildSigAlgsExt() []byte {
	algs := []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
		0x0501, 0x0806, 0x0601, 0x0201,
	}
	var list []byte
	for _, a := range algs {
		list = appendUint16(list, a)
	}
	var data []byte
	data = appendUint16(data, uint16(len(list)))
	return append(data, list...)
}

// buildKeyShareExt returns a minimal key_share extension body with x25519.
func buildKeyShareExt() []byte {
	// client_shares: one entry — group x25519 (0x001d), 32-byte zero key
	key := make([]byte, 32)
	var entry []byte
	entry = appendUint16(entry, 0x001d)           // group
	entry = appendUint16(entry, uint16(len(key))) // key_exchange length
	entry = append(entry, key...)
	var data []byte
	data = appendUint16(data, uint16(len(entry))) // client_shares length
	return append(data, entry...)
}
