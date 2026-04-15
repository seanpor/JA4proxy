package security

// Phase 203c — TDD red: weak cipher parity with Python's WEAK_CIPHERS.
// Source of truth: src/security/tls_enforcer.py lines 50-92 (WEAK_CIPHERS frozenset).
//
// This test expects exactly 40 entries. The current Go weakCipherSet has 12.
// It will FAIL until the 203c implementer expands the set to match Python.

import "testing"

// pythonWeakCiphers is a verbatim copy of src/security/tls_enforcer.py
// WEAK_CIPHERS (lines 50-92). Do not modify without also updating Python.
var pythonWeakCiphers = []struct {
	code uint16
	name string
}{
	{0x0000, "TLS_NULL_WITH_NULL_NULL"},
	{0x0001, "TLS_RSA_WITH_NULL_MD5"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA"},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
	{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
	{0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
	{0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA"},
	{0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"},
	{0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA"},
	{0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"},
	{0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
	{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
	{0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
	{0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
	{0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA"},
	{0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
	{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{0x003B, "TLS_RSA_WITH_NULL_SHA256"},
	{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},
	{0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
	{0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
	{0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
	{0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"},
	{0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
	{0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"},
	{0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},
	{0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
}

func TestWeakCipherSet_PythonList_Has40UniqueEntries(t *testing.T) {
	// Guard: the hardcoded Python list must itself be 40 unique codes.
	// If this ever changes, the Python source changed and the Go set must too.
	seen := map[uint16]string{}
	for _, c := range pythonWeakCiphers {
		if prev, dup := seen[c.code]; dup {
			t.Errorf("duplicate code in Python source list: 0x%04X (%s and %s)", c.code, prev, c.name)
		}
		seen[c.code] = c.name
	}
	if len(seen) != 40 {
		t.Fatalf("Python WEAK_CIPHERS has %d unique codes; expected 40 "+
			"(if Python changed, sync both the test list and Go's weakCipherSet)", len(seen))
	}
}

func TestWeakCipherSet_Size_MatchesPython(t *testing.T) {
	if got := len(weakCipherSet); got != 40 {
		t.Errorf("weakCipherSet has %d entries; expected 40 to match Python WEAK_CIPHERS", got)
	}
}

func TestWeakCipherSet_Parity_EveryPythonEntryPresent(t *testing.T) {
	for _, c := range pythonWeakCiphers {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if !weakCipherSet[c.code] {
				t.Errorf("weakCipherSet is missing Python cipher 0x%04X (%s)", c.code, c.name)
			}
		})
	}
}

func TestWeakCipherSet_NoExtras_NotInPython(t *testing.T) {
	pythonCodes := make(map[uint16]bool, len(pythonWeakCiphers))
	for _, c := range pythonWeakCiphers {
		pythonCodes[c.code] = true
	}
	for code := range weakCipherSet {
		if !pythonCodes[code] {
			t.Errorf("weakCipherSet contains 0x%04X which is NOT in Python WEAK_CIPHERS", code)
		}
	}
}
