// Copyright 2026 Anomaly Collective
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under the License.
package tls

import (
	"bytes"
	"slices"
	"testing"
)

// BenchmarkClientHelloParse benchmarks TLS ClientHello parsing at scale.
func BenchmarkClientHelloParse(b *testing.B) {
	hello := generateTestClientHello()

	// Fail fast with a clear message if the fixture itself is malformed, rather
	// than reporting a misleading parse cost from a buffer the parser rejects
	// on its first length check.
	if _, err := ParseClientHello(hello); err != nil {
		b.Fatalf("benchmark fixture is not a valid ClientHello: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := ParseClientHello(hello); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJA4Compute benchmarks JA4 fingerprint computation.
func BenchmarkJA4Compute(b *testing.B) {
	info, err := ParseClientHello(generateTestClientHello())
	if err != nil {
		b.Fatalf("benchmark fixture is not a valid ClientHello: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ComputeJA4(info)
	}
}

// BenchmarkClientHelloParseAdversarial benchmarks the parser's *rejection* path
// on malformed and hostile input.
//
// These inputs are expected to be rejected — that is the code path under
// measurement. The benchmark therefore discards the error rather than asserting
// on it. (It previously called b.Fatal on any error except the empty case,
// which asserted that truncated and non-TLS buffers must parse *successfully*;
// that is backwards, and it fired on every run.) A panic or hang still fails
// the benchmark, which is the property actually worth guarding here.
func BenchmarkClientHelloParseAdversarial(b *testing.B) {
	adversarialCases := []struct {
		name string
		data []byte
	}{
		{"truncated", clientHelloWithTruncation(4)},
		{"GREASE-heavy", clientHelloWithManyGreaseValues()},
		{"empty", []byte{}},
		{"non-tls", []byte("HTTP/1.1\r\n")},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, tc := range adversarialCases {
			//nolint:errcheck // rejection is the measured path; see doc comment
			_, _ = ParseClientHello(tc.data)
		}
	}
}

// TestBenchmarkFixturesAreValid guards the fixtures the benchmarks above depend on.
//
// This test exists because `go test` does not run benchmarks without -bench, so
// a rotted benchmark fixture is invisible to `make test`. That is precisely how
// BenchmarkClientHelloParse, BenchmarkJA4Compute and
// BenchmarkClientHelloParseAdversarial came to fail on every run for an extended
// period without anyone noticing — and `make bench-micro` ends in `|| true`, so
// the benchmark run could not report it either.
//
// Keep this a Test, not a Benchmark: it must run in the default suite.
func TestBenchmarkFixturesAreValid(t *testing.T) {
	t.Run("generateTestClientHello parses", func(t *testing.T) {
		info, err := ParseClientHello(generateTestClientHello())
		if err != nil {
			t.Fatalf("benchmark fixture does not parse: %v", err)
		}
		if info.SNI != "example.com" {
			t.Errorf("SNI: got %q, want %q", info.SNI, "example.com")
		}
		if len(info.CipherSuites) != 8 {
			t.Errorf("CipherSuites: got %d, want 8", len(info.CipherSuites))
		}
	})

	t.Run("GREASE-heavy fixture parses and carries every GREASE value", func(t *testing.T) {
		info, err := ParseClientHello(clientHelloWithManyGreaseValues())
		if err != nil {
			t.Fatalf("GREASE fixture does not parse: %v", err)
		}
		// It is a stress case for the extension loop, so it must actually reach
		// that loop rather than being rejected at the record layer.
		want := len(benchGreaseValues())
		var got int
		for _, ext := range info.Extensions {
			if isGREASE(ext) {
				got++
			}
		}
		if got != want {
			t.Errorf("GREASE extensions parsed: got %d, want %d", got, want)
		}
	})

	t.Run("fixtures are deterministic", func(t *testing.T) {
		// Benchmarks must compare like with like between runs.
		if !bytes.Equal(generateTestClientHello(), generateTestClientHello()) {
			t.Error("generateTestClientHello is not deterministic")
		}
		if !bytes.Equal(clientHelloWithManyGreaseValues(), clientHelloWithManyGreaseValues()) {
			t.Error("clientHelloWithManyGreaseValues is not deterministic")
		}
	})

	t.Run("adversarial inputs are rejected without panicking", func(t *testing.T) {
		for _, data := range [][]byte{
			clientHelloWithTruncation(4),
			{},
			[]byte("HTTP/1.1\r\n"),
		} {
			if _, err := ParseClientHello(data); err == nil {
				t.Errorf("expected rejection for %q, got nil error", data)
			}
		}
	})
}

// benchGreaseValues flattens the production greaseValues set (ja4.go) into a
// deterministic slice.
//
// Derived from that map rather than duplicated, so the benchmark fixture can
// never drift from the set the parser actually treats as GREASE. Sorted because
// Go randomises map iteration order and a benchmark fixture must be
// byte-identical between runs.
func benchGreaseValues() []uint16 {
	out := make([]uint16, 0, len(greaseValues))
	for v := range greaseValues {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// generateTestClientHello constructs a valid, browser-like ClientHello for
// benchmarking.
//
// It delegates to buildClientHelloBytes (ja4_test.go) — the same builder the
// package's parser tests use — rather than hand-assembling bytes. The previous
// hand-rolled version was not a well-formed ClientHello: it omitted the 2-byte
// record length and the 4-byte handshake header entirely, so the parser read
// two bytes of the random field as the record length. That yielded "TLS record
// too large" or "truncated ClientHello" depending on the random draw, and
// BenchmarkClientHelloParse and BenchmarkJA4Compute failed on every run.
//
// The fixture is deterministic (buildClientHelloBytes uses a zero random field).
// Benchmarks want reproducibility, and the parser does not branch on the
// contents of the random field.
func generateTestClientHello() []byte {
	ciphers := []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030}
	exts := []extensionSpec{
		{extType: 0x0000, data: buildSNIExt("example.com")},
		{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304, 0x0303})},
		{extType: 0x0010, data: buildALPNExt([]string{"h2", "http/1.1"})},
		{extType: 0x000b, data: []byte{0x01, 0x00}},                         // ec_point_formats: uncompressed
		{extType: 0x000a, data: []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17}}, // supported_groups
	}
	return buildClientHelloBytes(0x0303, ciphers, exts)
}

// clientHelloWithTruncation returns a valid ClientHello cut to n bytes, so the
// parser hits its length checks rather than a structural error.
func clientHelloWithTruncation(n int) []byte {
	base := generateTestClientHello()
	if len(base) < n {
		return base
	}
	return base[:n]
}

// clientHelloWithManyGreaseValues returns a structurally valid ClientHello
// carrying every GREASE code point in both the cipher-suite list and the
// extension list, to stress the parser's extension loop.
//
// The previous version appended raw bytes past the end of a complete record,
// producing a buffer that was neither valid nor a meaningful GREASE stress
// case — the parser rejected it at the record layer without ever reaching the
// extension loop it was written to exercise.
func clientHelloWithManyGreaseValues() []byte {
	grease := benchGreaseValues()

	ciphers := make([]uint16, 0, len(grease)+3)
	ciphers = append(ciphers, grease...)
	ciphers = append(ciphers, 0x1301, 0x1302, 0x1303)

	exts := []extensionSpec{
		{extType: 0x0000, data: buildSNIExt("grease.example.com")},
		{extType: 0x002b, data: buildSupportedVersionsExt([]uint16{0x0304, 0x0303})},
		{extType: 0x0010, data: buildALPNExt([]string{"h2"})},
	}
	for _, g := range grease {
		exts = append(exts, extensionSpec{extType: g, data: []byte{}})
	}

	return buildClientHelloBytes(0x0303, ciphers, exts)
}
