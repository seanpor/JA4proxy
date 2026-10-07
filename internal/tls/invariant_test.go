package tls_test

import (
	"regexp"
	"testing"

	"pgregory.net/rapid"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

var ja4Regex = regexp.MustCompile(`^t[0-9]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestInvariant_TLS_GREASEIndependence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		baselineRaw := tlsfixture.Build(spec)
		infoBaseline, err := tlsparse.ParseClientHello(baselineRaw)
		if err != nil {
			t.Skip()
		}
		baselineJA4 := tlsparse.ComputeJA4(infoBaseline)

		greaseVal := rapid.SampledFrom(tlsfixture.GREASE[:]).Draw(t, "grease")
		greaseSpec := tlsfixture.WithGREASE(spec, greaseVal)
		greaseRaw := tlsfixture.Build(greaseSpec)
		infoGrease, err := tlsparse.ParseClientHello(greaseRaw)
		if err != nil {
			t.Fatalf("Failed to parse ClientHello with injected GREASE 0x%04x: %v", greaseVal, err)
		}
		greaseJA4 := tlsparse.ComputeJA4(infoGrease)

		if greaseJA4 != baselineJA4 {
			t.Fatalf("GREASE 0x%04x mutated JA4: got %s, want %s", greaseVal, greaseJA4, baselineJA4)
		}
	})
}

func TestInvariant_TLS_ExtensionPermutationInvariance(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		seed := rapid.Int64().Draw(t, "seed")
		shuffledSpec := tlsfixture.ShuffleExtensions(spec, seed)

		infoA, errA := tlsparse.ParseClientHello(tlsfixture.Build(spec))
		infoB, errB := tlsparse.ParseClientHello(tlsfixture.Build(shuffledSpec))
		if errA != nil || errB != nil {
			t.Skip()
		}

		ja4A := tlsparse.ComputeJA4(infoA)
		ja4B := tlsparse.ComputeJA4(infoB)
		if ja4A != ja4B {
			t.Fatalf("Extension permutation mutated JA4: got %s vs %s", ja4A, ja4B)
		}
	})
}

func TestInvariant_TLS_GrammarAdherence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		info, err := tlsparse.ParseClientHello(tlsfixture.Build(spec))
		if err != nil {
			t.Skip()
		}
		ja4 := tlsparse.ComputeJA4(info)
		if !ja4Regex.MatchString(ja4) {
			t.Fatalf("JA4 %q violates canonical regex grammar", ja4)
		}
	})
}

func TestInvariant_TLS_ParserTotality(t *testing.T) {
	corpus := tlsfixture.Corpus(t)
	for _, entry := range corpus {
		for i := len(entry.Raw); i >= 0; i-- {
			truncated := entry.Raw[:i]
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Panic on truncated ClientHello %s at len %d: %v", entry.Name, i, r)
					}
				}()
				_, _ = tlsparse.ParseClientHello(truncated)
			}()
		}
	}
}
