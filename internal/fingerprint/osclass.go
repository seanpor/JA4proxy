// Package fingerprint holds vocabulary shared by the passive TAP sensor (the
// writer of OS fingerprints) and the inline proxy consumer (the reader). Keeping
// the OS-class type in one place is the fix for the contract bug the 316b design
// review found: the archived Python writer stored values like "linux_5x_default"
// while the Go consumer compared against the bare class "linux", so the two could
// never match — a silent no-op signal. With a single type used by both sides, the
// writer and reader can never drift again.
package fingerprint

// OSClass is the canonical operating-system class vocabulary for the OS-mismatch
// signal. The zero value OSUnknown is deliberate: it is never written to Redis
// and never compared, so unclassifiable traffic (no SYN observed, an ambiguous
// or middlebox-normalized stack, an unmapped JA4) produces no signal — the
// conservative, fail-open default the core asymmetry demands.
//
// The MVP vocabulary is intentionally small (316b). Android is omitted: it is
// passively indistinguishable from Linux (it is Linux) and has no JA4 mapping,
// so it could only manufacture false mismatches. The full vocabulary, if needed,
// grows in a later phase.
type OSClass uint8

const (
	OSUnknown OSClass = iota
	OSWindows
	OSMacOS
	OSLinux
	OSIOS
)

// String returns the canonical bare class string stored in Redis (e.g. "linux").
// OSUnknown maps to "unknown"; it is never persisted (the store skips it), so a
// consumer never reads it back.
func (c OSClass) String() string {
	switch c {
	case OSWindows:
		return "windows"
	case OSMacOS:
		return "macos"
	case OSLinux:
		return "linux"
	case OSIOS:
		return "ios"
	default:
		return "unknown"
	}
}

// IsKnown reports whether the class is concrete — i.e. writable to Redis and
// comparable in the mismatch check. OSUnknown is the only non-known value.
func (c OSClass) IsKnown() bool { return c != OSUnknown }

// ParseOSClass maps a stored Redis string back to an OSClass. Any unrecognised
// value (including "", "unknown", or a legacy encoded form) yields OSUnknown,
// preserving fail-open behaviour.
func ParseOSClass(s string) OSClass {
	switch s {
	case "windows":
		return OSWindows
	case "macos":
		return OSMacOS
	case "linux":
		return OSLinux
	case "ios":
		return OSIOS
	default:
		return OSUnknown
	}
}

// JA4OSClass returns the OS class implied by a JA4 TLS fingerprint, or OSUnknown
// when the fingerprint does not map to a known OS. The key is the JA4 prefix up
// to the first underscore (e.g. "t13d1516h2"). The starter table is intentionally
// small; gaps are fail-open (OSUnknown → no signal). Mappings derive from
// config/os_fingerprints.yml and the public FoxIO-LLC/ja4 dataset.
func JA4OSClass(ja4 string) OSClass {
	if len(ja4) == 0 {
		return OSUnknown
	}
	underscore := -1
	for i := 0; i < len(ja4); i++ {
		if ja4[i] == '_' {
			underscore = i
			break
		}
	}
	if underscore <= 0 {
		return OSUnknown
	}
	switch ja4[:underscore] {
	case "t13d1516h2":
		// Chrome/Edge on Windows (modern) — 10 extensions, 2 sigalgs.
		return OSWindows
	case "t13d1517h2":
		// Chrome on macOS variant — widely documented in FoxIO JA4 corpus.
		return OSMacOS
	case "t13d1715h2":
		// Firefox on Linux — commonly reported JA4 shape.
		return OSLinux
	case "t13d3112h2":
		// Safari on macOS.
		return OSMacOS
	case "t13d3113h2":
		// Safari on iOS.
		return OSIOS
	case "t13d0310h2":
		// curl / command-line TLS clients (Linux default builds).
		return OSLinux
	case "t13d1314h1":
		// Go http.Client default — Linux-shaped stack when run on Linux.
		return OSLinux
	}
	return OSUnknown
}
