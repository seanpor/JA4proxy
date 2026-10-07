package tlsfixture_test

import (
	"bytes"
	"testing"

	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
	"pgregory.net/rapid"
)

func TestBuild_ParsesWithProductionParser(t *testing.T) {
	raw := tlsfixture.Build(tlsfixture.Spec{
		SNI:  "example.com",
		ALPN: []string{"h2", "http/1.1"},
	})

	info, err := tlsparse.ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if info.SNI != "example.com" {
		t.Fatalf("SNI mismatch: got %q, want example.com", info.SNI)
	}
}

func TestCorpus_MatchesKnownJA4(t *testing.T) {
	corpus := tlsfixture.Corpus(t)
	if len(corpus) == 0 {
		t.Fatalf("Corpus loaded 0 entries")
	}

	for _, entry := range corpus {
		info, err := tlsparse.ParseClientHello(entry.Raw)
		if err != nil {
			t.Fatalf("Corpus entry %s failed to parse: %v", entry.Name, err)
		}

		ja4 := tlsparse.ComputeJA4(info)
		if ja4 != entry.WantJA4 {
			t.Fatalf("Corpus entry %s JA4 mismatch: got %s, want %s", entry.Name, ja4, entry.WantJA4)
		}
	}
}

func TestWithGREASE_AllSixteenValuesParse(t *testing.T) {
	baseSpec := tlsfixture.Spec{SNI: "test.local"}
	for _, g := range tlsfixture.GREASE {
		spec := tlsfixture.WithGREASE(baseSpec, g)
		raw := tlsfixture.Build(spec)
		_, err := tlsparse.ParseClientHello(raw)
		if err != nil {
			t.Fatalf("GREASE 0x%04x failed to parse: %v", g, err)
		}
	}
}

func TestGenSpec_ParseRateIsTotal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		raw := tlsfixture.Build(spec)
		_, err := tlsparse.ParseClientHello(raw)
		if err != nil {
			t.Fatalf("Generated Spec failed to parse: %v", err)
		}
	})
}

func TestSplit_ConcatenationIsIdentity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "spec")
		raw := tlsfixture.Build(spec)
		s1 := rapid.IntRange(1, len(raw)).Draw(t, "s1")
		s2 := rapid.IntRange(1, len(raw)).Draw(t, "s2")

		chunks := tlsfixture.Split(raw, s1, s2)
		joined := bytes.Join(chunks, nil)
		if !bytes.Equal(joined, raw) {
			t.Fatalf("Split concatenation mismatch")
		}
	})
}
