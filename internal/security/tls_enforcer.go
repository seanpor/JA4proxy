package security

import "github.com/sirupsen/logrus"

// weakCipherSet contains cipher suites considered weak or broken.
// These are identical to WEAK_CIPHERS in src/security/tls_enforcer.py.
var weakCipherSet = map[uint16]bool{
	0x0001: true, // TLS_RSA_WITH_NULL_MD5
	0x0002: true, // TLS_RSA_WITH_NULL_SHA
	0x0004: true, // TLS_RSA_WITH_RC4_128_MD5
	0x0005: true, // TLS_RSA_WITH_RC4_128_SHA
	0x000A: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x002F: true, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x003C: true, // TLS_RSA_WITH_AES_128_CBC_SHA256
	0x003D: true, // TLS_RSA_WITH_AES_256_CBC_SHA256
	0x0018: true, // TLS_DHE_RSA_WITH_RC4_128_SHA (EXPORT)
	0x0033: true, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	0x0039: true, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
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
