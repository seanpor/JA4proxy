package security

import (
	"math"
	"net"
	"regexp"
	"strings"
	"unicode"

	"github.com/anomalyco/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// SNIAnalyzerConfig configures the SNI analysis module.
type SNIAnalyzerConfig struct {
	MissingSNIEnabled    bool
	MissingSNIScore      int
	IPLiteralSNIEnabled  bool
	IPLiteralSNIScore    int
	DGAEnabled           bool
	DGAScoreCap          int
	UnexpectedSNIEnabled bool
	UnexpectedSNIScore   int
	ExpectedHostnames    map[string]bool
}

// SNIAnalyzer analyzes the SNI hostname from ClientHello for risk indicators.
type SNIAnalyzer struct {
	cfg *SNIAnalyzerConfig
	log *logrus.Logger
}

// NewSNIAnalyzer creates an SNIAnalyzer with the given configuration.
func NewSNIAnalyzer(cfg *SNIAnalyzerConfig, log *logrus.Logger) *SNIAnalyzer {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &SNIAnalyzerConfig{}
	}
	return &SNIAnalyzer{cfg: cfg, log: log}
}

// Analyze returns risk signals for the given SNI value.
// sni is the empty string when no SNI extension was present.
// Never returns an error; fails open (returns empty slice on any panic).
func (a *SNIAnalyzer) Analyze(sni string) (signals []RiskSignal) {
	defer func() {
		if r := recover(); r != nil {
			a.log.WithField("panic", r).Warn("sni_analyzer: recovered from panic")
			signals = nil
		}
	}()

	// Missing SNI
	if sni == "" {
		if a.cfg.MissingSNIEnabled {
			metrics.SNISignalTotal.WithLabelValues("missing_sni").Inc()
			signals = append(signals, RiskSignal{
				Name:   "missing_sni",
				Score:  a.cfg.MissingSNIScore,
				Reason: "no SNI extension present",
				Weight: 1.0,
			})
		}
		return signals
	}

	// IP literal SNI
	if a.cfg.IPLiteralSNIEnabled && net.ParseIP(sni) != nil {
		metrics.SNISignalTotal.WithLabelValues("ip_literal_sni").Inc()
		signals = append(signals, RiskSignal{
			Name:   "ip_literal_sni",
			Score:  a.cfg.IPLiteralSNIScore,
			Reason: "SNI is an IP literal: " + sni,
			Weight: 1.0,
		})
		return signals
	}

	// DGA detection
	if a.cfg.DGAEnabled {
		confidence := dgaConfidence(sni)
		metrics.SNIDGAScore.Observe(confidence)
		score := int(confidence * float64(a.cfg.DGAScoreCap))
		if score > 0 {
			metrics.SNISignalTotal.WithLabelValues("dga").Inc()
			signals = append(signals, RiskSignal{
				Name:   "dga",
				Score:  score,
				Reason: "DGA-like hostname",
				Weight: 1.0,
			})
		}
	}

	// Unexpected SNI
	if a.cfg.UnexpectedSNIEnabled && len(a.cfg.ExpectedHostnames) > 0 {
		if !a.cfg.ExpectedHostnames[sni] {
			metrics.SNISignalTotal.WithLabelValues("unexpected_sni").Inc()
			signals = append(signals, RiskSignal{
				Name:   "unexpected_sni",
				Score:  a.cfg.UnexpectedSNIScore,
				Reason: "SNI not in expected hostnames: " + sni,
				Weight: 1.0,
			})
		}
	}

	return signals
}

// Phase 203d: DGA confidence algorithm ported rule-for-rule from Python's
// src/security/sni_analyzer.py::dga_score. Byte-for-byte equivalence is
// required (parity enforced by tests/fixtures/dga/expected_scores.json).

// minDGALabelLen mirrors Python's _MIN_DGA_LABEL_LEN.
const minDGALabelLen = 6

// skipPrefixes mirrors Python's _SKIP_PREFIXES. Keep in sync with
// src/security/sni_analyzer.py line 47.
var skipPrefixes = map[string]bool{
	"www":    true,
	"mail":   true,
	"m":      true,
	"api":    true,
	"static": true,
	"cdn":    true,
	"img":    true,
	"assets": true,
}

// dgaDigitRun matches 4+ consecutive digits anywhere in the label
// (Python's re.search(r"\d{4,}")).
var dgaDigitRun = regexp.MustCompile(`\d{4,}`)

// dgaVowels mirrors Python's VOWELS = frozenset("aeiou"). ASCII-only.
var dgaVowels = map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true}

// getPrimaryLabel mirrors Python's _get_primary_label: lowercase, strip
// trailing dots, split, return the first non-empty label that is not a
// common non-significant prefix; fall back to parts[0].
func getPrimaryLabel(hostname string) string {
	lowered := strings.ToLower(hostname)
	trimmed := strings.TrimRight(lowered, ".")
	parts := strings.Split(trimmed, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if !skipPrefixes[part] {
			return part
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// shannonEntropy returns the Shannon entropy in bits/char. Mirrors Python's
// _shannon_entropy — iterates the raw character stream (runes in Go, single
// code points in Python str).
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0.0
	}
	freq := make(map[rune]int)
	var n int
	for _, r := range s {
		freq[r]++
		n++
	}
	fn := float64(n)
	ent := 0.0
	for _, count := range freq {
		p := float64(count) / fn
		ent -= p * math.Log2(p)
	}
	return ent
}

// dgaConfidence computes a DGA confidence score (0.0–1.0) for the given
// hostname. Byte-for-byte equivalent to Python's dga_score.
func dgaConfidence(hostname string) float64 {
	label := getPrimaryLabel(hostname)
	if len([]rune(label)) < minDGALabelLen {
		return 0.0
	}

	score := 0.0

	// 1. Shannon entropy — high entropy suggests randomness (weight 0.40).
	ent := shannonEntropy(label)
	if ent >= 3.8 {
		delta := (ent - 3.8) * 2.0
		if delta > 0.40 {
			delta = 0.40
		}
		score += delta
	}

	// 2. Vowel/consonant analysis — collect alphabetic runes (Unicode-aware,
	// matching Python's str.isalpha()).
	alphaCount := 0
	vowelCount := 0
	for _, r := range label {
		if !unicode.IsLetter(r) {
			continue
		}
		alphaCount++
		if dgaVowels[r] {
			vowelCount++
		}
	}
	if alphaCount >= 6 {
		if vowelCount == 0 {
			// Complete absence of vowels: strong DGA signal (weight 0.30).
			score += 0.30
		} else if alphaCount >= 10 && float64(alphaCount)/float64(vowelCount) > 5.0 {
			// Very consonant-heavy AND long: moderate DGA signal (weight 0.20).
			score += 0.20
		}
	}

	// 3. Label length — DGA labels tend to be long (weight 0.20).
	labelRuneLen := len([]rune(label))
	if labelRuneLen >= 20 {
		score += 0.20
	} else if labelRuneLen >= 16 {
		score += 0.10
	}

	// 4. Dense digit sequence — 4+ consecutive digits (weight 0.10).
	if dgaDigitRun.MatchString(label) {
		score += 0.10
	}

	if score > 1.0 {
		return 1.0
	}
	return score
}
