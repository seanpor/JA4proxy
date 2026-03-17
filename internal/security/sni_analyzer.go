package security

import (
	"math"
	"net"
	"strings"

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
		score := int(confidence * float64(a.cfg.DGAScoreCap))
		if score > 0 {
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

// dgaConfidence computes a DGA confidence score (0.0–1.0) for the given hostname.
// Algorithm ported exactly from src/security/sni_analyzer.py.
func dgaConfidence(hostname string) float64 {
	// Use the leftmost label only
	label := hostname
	if idx := strings.IndexByte(hostname, '.'); idx >= 0 {
		label = hostname[:idx]
	}
	if len(label) == 0 {
		return 0.0
	}

	confidence := 0.0

	// 1. Shannon entropy of the label
	freq := make(map[rune]float64)
	for _, ch := range label {
		freq[ch]++
	}
	labelLen := float64(len([]rune(label)))
	entropy := 0.0
	for _, count := range freq {
		p := count / labelLen
		entropy -= p * math.Log2(p)
	}
	if entropy > 3.5 {
		confidence += 0.35
	}
	if entropy > 4.0 {
		confidence += 0.15
	}

	// 2. Vowel ratio
	vowels := map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true}
	vowelCount := 0
	runes := []rune(label)
	for _, ch := range runes {
		if vowels[ch] {
			vowelCount++
		}
	}
	vowelRatio := float64(vowelCount) / labelLen
	if vowelRatio < 0.10 {
		confidence += 0.30
	}

	// 3. Label length
	if len(runes) > 15 {
		confidence += 0.15
	}

	// 4. Consecutive consonant runs (4+ non-vowel chars)
	consecutiveConsonants := 0
	maxConsecutive := 0
	for _, ch := range runes {
		if !vowels[ch] && (ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
			consecutiveConsonants++
			if consecutiveConsonants > maxConsecutive {
				maxConsecutive = consecutiveConsonants
			}
		} else {
			consecutiveConsonants = 0
		}
	}
	if maxConsecutive >= 4 {
		confidence += 0.20
	}

	// 5. Digit ratio
	digitCount := 0
	for _, ch := range runes {
		if ch >= '0' && ch <= '9' {
			digitCount++
		}
	}
	digitRatio := float64(digitCount) / labelLen
	if digitRatio > 0.30 {
		confidence += 0.20
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}
