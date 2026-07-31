package fingerprint

import "testing"

func TestCanonicalIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.5", "203.0.113.5"},
		{"2001:DB8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := CanonicalIP(c.in); got != c.want {
			t.Errorf("CanonicalIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
