package tls

// ComputeJA4T returns the JA4T fingerprint from a list of TLS alert codes.
// JA4T format: comma-separated decimal alert codes, sorted ascending.
// Returns "" if alertCodes is empty.
// This is a stub for Phase 15 — full alert capture requires hooking the TLS
// state machine at a lower level than is currently implemented.
func ComputeJA4T(alertCodes []uint8) string {
	return ""
}
