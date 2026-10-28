package security

import (
	"net"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// FuzzSNIAnalyzer verifies that SNI parsing and DGA analysis never panic,
// enter infinite loops, or return out-of-range risk scores for any arbitrary input string.
func FuzzSNIAnalyzer(f *testing.F) {
	seeds := []string{
		"",
		"example.com",
		"sub.domain.example.co.uk",
		"192.168.1.1",
		"2001:db8::1",
		"a.b.c.d.e.f.g.h.i.j.k",
		"x" + strings.Repeat(".y", 50),
		"asdfqwerzxcv123456.com",
		"very-long-label-without-any-vowels-at-all-bbbbbbbbbbbb.org",
		"valid-hostname.com.",
		"trailing-dot...com",
		"invalid space hostname.com",
		"\x00\x01\x02\xff\xfe\xfd",
		strings.Repeat("a", 1024),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	analyzer := NewSNIAnalyzer(&SNIAnalyzerConfig{
		MissingSNIEnabled:    true,
		MissingSNIScore:      30,
		IPLiteralSNIEnabled:  true,
		IPLiteralSNIScore:    25,
		DGAEnabled:           true,
		DGAScoreCap:          40,
		UnexpectedSNIEnabled: true,
		UnexpectedSNIScore:   15,
		MaliciousSNIEnabled:  true,
		MaliciousSNIScore:    100,
		ExpectedHostnames:    map[string]bool{"example.com": true},
	}, nil)

	f.Fuzz(func(t *testing.T, sni string) {
		signals := analyzer.Analyze(sni)
		for _, sig := range signals {
			if sig.Score < 0 || sig.Score > 100 {
				t.Fatalf("Analyze(%q) produced out-of-bounds score: %d (signal: %s)", sni, sig.Score, sig.Name)
			}
			if sig.Weight < 0 {
				t.Fatalf("Analyze(%q) produced negative weight: %f (signal: %s)", sni, sig.Weight, sig.Name)
			}
		}

		// Verify dgaConfidence directly
		conf := dgaConfidence(sni)
		if conf < 0.0 || conf > 1.0 {
			t.Fatalf("dgaConfidence(%q) out of [0.0, 1.0]: %f", sni, conf)
		}
	})
}

// FuzzBuildRanger verifies that the feed CIDR/IP line parser is total,
// handles corrupt, binary, and malformed inputs gracefully without panicking.
func FuzzBuildRanger(f *testing.F) {
	seeds := []string{
		"192.0.2.1/32",
		"192.0.2.0/24 ; Spamhaus SBL12345",
		"10.0.0.1",
		"2001:db8::/32",
		"2001:db8::1",
		"add myset 192.0.2.0/24",
		"add myset 2001:db8::/64",
		"# comment line",
		"; spamhaus comment",
		"",
		"invalid-cidr/99",
		"999.999.999.999/24",
		"add",
		"add onlytwotokens",
		"add set 1.2.3.4 extra options",
		strings.Repeat("9", 2000),
	}

	for _, s := range seeds {
		f.Add(s, "cidr")
		f.Add(s, "ipset")
		f.Add(s, "spamhaus")
	}

	f.Fuzz(func(t *testing.T, line, format string) {
		token, ok := parseFeedLine(line, format)
		if ok {
			if token == "" {
				t.Fatalf("parseFeedLine returned ok=true but empty token for %q format=%q", line, format)
			}
		}

		r := strings.NewReader(line)
		ranger, loaded, err := BuildRanger(r, format)
		if err != nil && loaded > 0 {
			t.Fatalf("BuildRanger returned loaded > 0 with error: %v", err)
		}
		if ranger == nil {
			t.Fatal("BuildRanger returned nil ranger")
		}
	})
}

// FuzzEffectiveThresholdAndDecider verifies ActionDecider and EffectiveThreshold
// mathematical stability, boundedness, and lack of panics across the entire int space.
func FuzzEffectiveThresholdAndDecider(f *testing.F) {
	f.Add(70, 0, 50)
	f.Add(70, 50, 85)
	f.Add(70, 100, 70)
	f.Add(0, 0, 0)
	f.Add(100, 100, 100)
	f.Add(-10, -5, -20)
	f.Add(1000, 500, 1000)

	decider := NewActionDeciderDefault()

	f.Fuzz(func(t *testing.T, configured, dial, score int) {
		eff := EffectiveThreshold(configured, dial)
		if dial == 0 && eff != 101 {
			t.Fatalf("EffectiveThreshold(%d, 0) = %d, expected 101", configured, eff)
		}

		action := decider.Decide(score, dial)
		switch action {
		case "allow", "flag", "rate_limit", "tarpit", "block", "ban":
			// valid actions
		default:
			t.Fatalf("Decide(%d, %d) returned unknown action: %q", score, dial, action)
		}

		if dial == 0 && action != "allow" {
			t.Fatalf("Decide(%d, dial=0) = %q, expected 'allow' (monitor mode)", score, action)
		}
	})
}

// FuzzRiskScorer verifies RiskScorer aggregation, clamping, and explanation generation
// under arbitrary signal scores, weights, names, and reasons.
func FuzzRiskScorer(f *testing.F) {
	f.Add(10, 1.0, -20, 1.5, 90, 0.5, "sigA", "sigB", "sigC")
	f.Add(100, 2.0, 100, 2.0, 100, 2.0, "max1", "max2", "max3")
	f.Add(-100, 1.0, -100, 1.0, -100, 1.0, "min1", "min2", "min3")
	f.Add(0, 0.0, 0, 0.0, 0, 0.0, "", "", "")

	scorer := NewRiskScorerDefault()

	f.Fuzz(func(t *testing.T, s1 int, w1 float64, s2 int, w2 float64, s3 int, w3 float64, n1, n2, n3 string) {
		signals := []RiskSignal{
			{Name: n1, Score: s1, Weight: w1, Reason: "reason1"},
			{Name: n2, Score: s2, Weight: w2, Reason: "reason2"},
			{Name: n3, Score: s3, Weight: w3, Reason: "reason3"},
		}

		assessment := scorer.Score(signals)
		if assessment.TotalScore < 0 || assessment.TotalScore > 100 {
			t.Fatalf("Score() TotalScore out of bounds [0, 100]: %d", assessment.TotalScore)
		}

		switch assessment.RecommendedAction {
		case "allow", "flag", "rate_limit", "tarpit", "block", "ban":
		default:
			t.Fatalf("Score() RecommendedAction unknown: %q", assessment.RecommendedAction)
		}
	})
}

// FuzzPipelineBypassesAndHardBlocks verifies that CheckBypasses and CheckHardBlocks
// handle arbitrary strings for IP, JA4, JA4X, ALPN, and Country without panicking.
func FuzzPipelineBypassesAndHardBlocks(f *testing.F) {
	f.Add("192.168.1.1", "t13d1516h2_8daaf6152771_0123456789ab", "d1516_0123456789ab", "h2", "US", true)
	f.Add("", "", "", "", "", false)
	f.Add("not-an-ip", "malformed_ja4", "malformed_ja4x", "invalid_alpn", "INVALID", false)
	f.Add("::1", "t12i0500_unknown", "x", "h1", "CN", true)

	cfg := &PipelineConfig{
		ALPNBrowserBypass:        true,
		JA4WhitelistBypass:       true,
		JA4XWhitelistBypass:      true,
		JA4XEnabled:              true,
		MTLSBypass:               true,
		StaticIPAllowlistEnabled: true,
		StaticIPAllowlist:        map[string]bool{"192.168.1.1": true},
		JA4BlockingEnabled:       true,
		JA4XBlockingEnabled:      true,
		CountryBlockingEnabled:   true,
		CountryBlacklist:         map[string]bool{"CN": true, "RU": true},
		WhitelistSuffs:           []string{"_0123456789ab"},
	}

	pipeline := &Pipeline{
		log: nil,
	}
	snap := &PipelineSnapshot{
		cfg:            cfg,
		whitelist:      map[string]bool{"t13d1516h2_8daaf6152771_0123456789ab": true},
		blacklist:      map[string]bool{"t12i0500_unknown": true},
		ja4xWhitelist:  map[string]bool{"d1516_0123456789ab": true},
		ja4xBlacklist:  map[string]bool{"malformed_ja4x": true},
	}
	pipeline.snapshot.Store(snap)

	f.Fuzz(func(t *testing.T, ip, ja4, ja4x, alpn, country string, validCert bool) {
		conn := &ConnectionContext{
			ClientIP:            ip,
			JA4:                 ja4,
			JA4X:                ja4x,
			ALPN:                alpn,
			Country:             country,
			HasValidClientCert:  validCert,
			ParsedIP:            net.ParseIP(ip),
		}

		bypass, reasonB := pipeline.CheckBypasses(conn)
		if bypass && reasonB == "" {
			t.Fatal("CheckBypasses returned true but empty reason")
		}

		block, reasonH := pipeline.CheckHardBlocks(conn)
		if block && reasonH == "" {
			t.Fatal("CheckHardBlocks returned true but empty reason")
		}
	})
}

// TestProperty_ActionDecider_Monotonicity verifies via Rapid that as score increases,
// the severity of the action never decreases.
func TestProperty_ActionDecider_Monotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dial := rapid.IntRange(0, 100).Draw(t, "dial")
		score1 := rapid.IntRange(0, 100).Draw(t, "score1")
		score2 := rapid.IntRange(0, 100).Draw(t, "score2")

		if score1 > score2 {
			score1, score2 = score2, score1
		}

		decider := NewActionDeciderDefault()
		action1 := decider.Decide(score1, dial)
		action2 := decider.Decide(score2, dial)

		severity := map[string]int{
			"allow":      0,
			"flag":       1,
			"rate_limit": 2,
			"tarpit":     3,
			"block":      4,
			"ban":        5,
		}

		sev1 := severity[action1]
		sev2 := severity[action2]

		if sev1 > sev2 {
			t.Fatalf("ActionDecider monotonicity violation at dial %d: score %d gave %s (sev %d) > score %d gave %s (sev %d)",
				dial, score1, action1, sev1, score2, action2, sev2)
		}
	})
}

// TestProperty_RiskScorer_Clamping verifies via Rapid that TotalScore is strictly
// in [0, 100] regardless of arbitrary inputs.
func TestProperty_RiskScorer_Clamping(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numSignals := rapid.IntRange(0, 20).Draw(t, "numSignals")
		signals := make([]RiskSignal, numSignals)
		for i := 0; i < numSignals; i++ {
			signals[i] = RiskSignal{
				Name:   rapid.StringMatching(`^[a-z_]{1,10}$`).Draw(t, "name"),
				Score:  rapid.IntRange(-500, 500).Draw(t, "score"),
				Weight: rapid.Float64Range(0.0, 5.0).Draw(t, "weight"),
				Reason: "fuzz",
			}
		}

		scorer := NewRiskScorerDefault()
		res := scorer.Score(signals)

		if res.TotalScore < 0 || res.TotalScore > 100 {
			t.Fatalf("RiskScorer TotalScore %d out of bounds [0, 100]", res.TotalScore)
		}
	})
}

// BenchmarkRuleEvaluation benchmarks the throughput and allocation cost
// of scoring and action decision in the security filter path.
func BenchmarkRuleEvaluation(b *testing.B) {
	scorer := NewRiskScorerDefault()
	decider := NewActionDeciderDefault()

	signals := []RiskSignal{
		{Name: "missing_sni", Score: 30, Weight: 1.0, Reason: "no SNI"},
		{Name: "dga", Score: 20, Weight: 1.0, Reason: "DGA like"},
		{Name: "rdap_suspicious", Score: 15, Weight: 0.8, Reason: "young domain"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		assessment := scorer.Score(signals)
		action := decider.Decide(assessment.TotalScore, 50)
		if action == "" {
			b.Fatal("empty action")
		}
	}
}

// BenchmarkSNIAnalyzer benchmarks SNI analysis throughput and allocations.
func BenchmarkSNIAnalyzer(b *testing.B) {
	analyzer := NewSNIAnalyzer(&SNIAnalyzerConfig{
		MissingSNIEnabled:   true,
		MissingSNIScore:     30,
		IPLiteralSNIEnabled: true,
		IPLiteralSNIScore:   25,
		DGAEnabled:          true,
		DGAScoreCap:         40,
		MaliciousSNIEnabled: true,
		MaliciousSNIScore:   100,
	}, nil)

	hostnames := []string{
		"www.google.com",
		"asdfqwerzxcv123456.org",
		"192.168.1.1",
		"",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := hostnames[i%len(hostnames)]
		_ = analyzer.Analyze(h)
	}
}

// BenchmarkPipelineCheckBypasses benchmarks bypass check hot-path.
func BenchmarkPipelineCheckBypasses(b *testing.B) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		WhitelistSuffs:     []string{"_0123456789ab"},
	}
	pipeline := &Pipeline{}
	snap := &PipelineSnapshot{
		cfg:       cfg,
		whitelist: map[string]bool{"t13d1516h2_8daaf6152771_0123456789ab": true},
	}
	pipeline.snapshot.Store(snap)

	conn := &ConnectionContext{
		ClientIP: "192.168.1.100",
		JA4:      "t13d1516h2_8daaf6152771_0123456789ab",
		ALPN:     "h2",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		bypass, _ := pipeline.CheckBypasses(conn)
		if !bypass {
			b.Fatal("expected bypass")
		}
	}
}
