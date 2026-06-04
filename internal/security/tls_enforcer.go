package security

import (
	"fmt"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

// ja4PrefixToTLSVersion maps JA4 fingerprint prefix (first 3 chars) to the
// TLS version the prefix claims. Keep in sync with src/security/tls_enforcer.py.
var ja4PrefixToTLSVersion = map[string]uint16{
	"t13": 0x0304, // TLS 1.3
	"t12": 0x0303, // TLS 1.2
	"t11": 0x0302, // TLS 1.1
	"t10": 0x0301, // TLS 1.0
	"s30": 0x0300, // SSL 3.0
}

// CheckJA4TLSMismatch returns a ja4_tls_mismatch RiskSignal when the JA4
// prefix disagrees with the negotiated TLS version. Fail open: returns nil
// on malformed or unknown JA4 prefixes, and also when actualTLSVersion ==
// 0x0000. Absence of a recorded negotiated version is NOT evidence of
// mismatch — it means the caller never observed a completed handshake, so
// we cannot say anything about parity. Phase 203b.
func (e *TLSEnforcer) CheckJA4TLSMismatch(ja4 string, actualTLSVersion uint16) *RiskSignal {
	if len(ja4) < 3 {
		return nil
	}
	// Fail open when TLS version is absent/uninitialised (0x0000) — the
	// negotiated version was never captured.
	if actualTLSVersion == 0 {
		return nil
	}
	prefix := ja4[:3]
	claimed, ok := ja4PrefixToTLSVersion[prefix]
	if !ok {
		return nil
	}
	if claimed == actualTLSVersion {
		return nil
	}
	metrics.JA4TLSMismatchTotal.WithLabelValues("flag").Inc()
	return &RiskSignal{
		Name:   "ja4_tls_mismatch",
		Score:  35,
		Weight: 1.0,
		Reason: fmt.Sprintf("JA4 prefix %q claims TLS 0x%04x; negotiated 0x%04x", prefix, claimed, actualTLSVersion),
	}
}

// weakCipherSet contains cipher suites considered weak or broken.
// These are identical to WEAK_CIPHERS in src/security/tls_enforcer.py lines 50-92.
// Sources: NIST SP 800-52r2, RFC 9325, Mozilla "Old" security profile.
// RC4, NULL, EXPORT, ANON, DES, 3DES — all considered broken or insecure.
// Keep in sync with Python; phase-203c parity test enforces exact match.
var weakCipherSet = map[uint16]bool{
	0x0000: true, // TLS_NULL_WITH_NULL_NULL
	0x0001: true, // TLS_RSA_WITH_NULL_MD5
	0x0002: true, // TLS_RSA_WITH_NULL_SHA
	0x0003: true, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x0004: true, // TLS_RSA_WITH_RC4_128_MD5
	0x0005: true, // TLS_RSA_WITH_RC4_128_SHA
	0x0006: true, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	0x0007: true, // TLS_RSA_WITH_IDEA_CBC_SHA
	0x0008: true, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0009: true, // TLS_RSA_WITH_DES_CBC_SHA
	0x000A: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x000B: true, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
	0x000C: true, // TLS_DH_DSS_WITH_DES_CBC_SHA
	0x000D: true, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
	0x000E: true, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x000F: true, // TLS_DH_RSA_WITH_DES_CBC_SHA
	0x0010: true, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
	0x0011: true, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	0x0012: true, // TLS_DHE_DSS_WITH_DES_CBC_SHA
	0x0013: true, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	0x0014: true, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0015: true, // TLS_DHE_RSA_WITH_DES_CBC_SHA
	0x0016: true, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	0x0017: true, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
	0x0018: true, // TLS_DH_anon_WITH_RC4_128_MD5
	0x0019: true, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
	0x001A: true, // TLS_DH_anon_WITH_DES_CBC_SHA
	0x001B: true, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
	0x002F: true, // TLS_RSA_WITH_AES_128_CBC_SHA (no PFS)
	0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA (no PFS)
	0x003B: true, // TLS_RSA_WITH_NULL_SHA256
	0x0041: true, // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (no PFS)
	0x0084: true, // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (no PFS)
	0xC007: true, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	0xC011: true, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
	0xC015: true, // TLS_ECDH_anon_WITH_NULL_SHA
	0xC016: true, // TLS_ECDH_anon_WITH_RC4_128_SHA
	0xC017: true, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
	0xC018: true, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
	0xC019: true, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
}

// TLSEnforcerConfig configures TLS version and cipher enforcement.
type TLSEnforcerConfig struct {
	TLSVersionBypassEnabled bool
	BlockTLS10              bool
	BlockTLS11              bool
	FlagTLS12               bool
	BlockWeakCiphers        bool
}

// TLSEnforcer checks TLS version and cipher list against policy.
type TLSEnforcer struct {
	cfg *TLSEnforcerConfig
	log *logrus.Logger
}

// NewTLSEnforcer creates a TLSEnforcer with the given configuration.
func NewTLSEnforcer(cfg *TLSEnforcerConfig, log *logrus.Logger) *TLSEnforcer {
	if log == nil {
		log = logrus.New()
	}
	if cfg == nil {
		cfg = &TLSEnforcerConfig{}
	}
	return &TLSEnforcer{cfg: cfg, log: log}
}

// Check returns signals and whether to hard-block.
// hardBlock=true means block immediately without scoring.
// On hardBlock=true, signals will be nil.
// Fail open: any unexpected state returns (nil, false).
func (e *TLSEnforcer) Check(tlsVersion uint16, ciphers []uint16) (signals []RiskSignal, hardBlock bool) {
	// SSLv3 (0x0300): always hard block, no config toggle
	if tlsVersion == 0x0300 {
		e.log.Debug("tls_enforcer: SSLv3 detected — hard block")
		return nil, true
	}

	// TLS 1.0 (0x0301)
	if tlsVersion == 0x0301 {
		if e.cfg.TLSVersionBypassEnabled && e.cfg.BlockTLS10 {
			e.log.Debug("tls_enforcer: TLS 1.0 detected — hard block")
			return nil, true
		}
		if !e.cfg.TLSVersionBypassEnabled {
			signals = append(signals, RiskSignal{
				Name:   "tls_version",
				Score:  40,
				Reason: "TLS 1.0 detected",
				Weight: 1.0,
			})
		}
		return signals, false
	}

	// TLS 1.1 (0x0302)
	if tlsVersion == 0x0302 {
		if e.cfg.TLSVersionBypassEnabled && e.cfg.BlockTLS11 {
			e.log.Debug("tls_enforcer: TLS 1.1 detected — hard block")
			return nil, true
		}
		if !e.cfg.TLSVersionBypassEnabled {
			signals = append(signals, RiskSignal{
				Name:   "tls_version",
				Score:  40,
				Reason: "TLS 1.1 detected",
				Weight: 1.0,
			})
		}
		return signals, false
	}

	// TLS 1.2 (0x0303)
	if tlsVersion == 0x0303 && e.cfg.FlagTLS12 {
		signals = append(signals, RiskSignal{
			Name:   "tls_12",
			Score:  10,
			Reason: "TLS 1.2 detected (flagged by policy)",
			Weight: 1.0,
		})
	}

	// Check for weak ciphers
	hasWeak := false
	for _, c := range ciphers {
		if weakCipherSet[c] {
			hasWeak = true
			break
		}
	}

	if hasWeak {
		if e.cfg.BlockWeakCiphers {
			e.log.Debug("tls_enforcer: weak cipher detected — hard block")
			return nil, true
		}
		signals = append(signals, RiskSignal{
			Name:   "weak_cipher",
			Score:  20,
			Reason: "weak cipher suite offered",
			Weight: 1.0,
		})
	}

	return signals, false
}
