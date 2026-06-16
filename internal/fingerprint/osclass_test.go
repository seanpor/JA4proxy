package fingerprint

import "testing"

func TestOSClass_StringParseRoundTrip(t *testing.T) {
	for _, c := range []OSClass{OSWindows, OSMacOS, OSLinux, OSIOS} {
		if got := ParseOSClass(c.String()); got != c {
			t.Errorf("round-trip %v: String()=%q Parse=%v", c, c.String(), got)
		}
		if !c.IsKnown() {
			t.Errorf("%v should be known", c)
		}
	}
}

func TestOSClass_UnknownIsNotKnown(t *testing.T) {
	if OSUnknown.IsKnown() {
		t.Error("OSUnknown must not be known (never written, never compared)")
	}
	if OSUnknown.String() != "unknown" {
		t.Errorf("OSUnknown.String() = %q; want unknown", OSUnknown.String())
	}
	// The zero value must be OSUnknown so a freshly-declared OSClass is safe.
	var zero OSClass
	if zero != OSUnknown {
		t.Errorf("zero OSClass = %v; want OSUnknown", zero)
	}
}

func TestParseOSClass_UnrecognisedYieldsUnknown(t *testing.T) {
	for _, s := range []string{"", "unknown", "android", "other", "linux_5x_default", "Windows", "LINUX"} {
		if got := ParseOSClass(s); got != OSUnknown {
			t.Errorf("ParseOSClass(%q) = %v; want OSUnknown", s, got)
		}
	}
}

func TestJA4OSClass_StarterTable(t *testing.T) {
	cases := []struct {
		prefix string
		want   OSClass
	}{
		{"t13d1516h2", OSWindows},
		{"t13d1517h2", OSMacOS},
		{"t13d1715h2", OSLinux},
		{"t13d3112h2", OSMacOS},
		{"t13d3113h2", OSIOS},
		{"t13d0310h2", OSLinux},
		{"t13d1314h1", OSLinux},
	}
	for _, c := range cases {
		ja4 := c.prefix + "_aabbccddeeff_aabbccddeeff"
		if got := JA4OSClass(ja4); got != c.want {
			t.Errorf("JA4OSClass(%q) = %v; want %v", ja4, got, c.want)
		}
	}
}

func TestJA4OSClass_FailOpen(t *testing.T) {
	for _, ja4 := range []string{
		"",                  // empty
		"t13d1516h2",        // no underscore → can't isolate prefix
		"_aabb",             // leading underscore
		"t13ffffffh2_aa_bb", // unmapped prefix
	} {
		if got := JA4OSClass(ja4); got != OSUnknown {
			t.Errorf("JA4OSClass(%q) = %v; want OSUnknown", ja4, got)
		}
	}
}
