package tap

import "testing"

func TestExcludeList_Contains(t *testing.T) {
	e := NewExcludeList("203.0.113.5, 198.51.100.0/24, 2001:db8::1")

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.5", true},
		{"203.0.113.6", false},
		{"198.51.100.42", true},
		{"198.51.101.1", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := e.Contains(c.ip); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestExcludeList_EmptyNeverExcludes(t *testing.T) {
	e := NewExcludeList("")
	if e.Contains("203.0.113.5") {
		t.Error("empty exclude list must never exclude anything")
	}
}

func TestExcludeList_NilReceiverSafe(t *testing.T) {
	var e *ExcludeList
	if e.Contains("203.0.113.5") {
		t.Error("nil ExcludeList must fail open (never exclude)")
	}
}

func TestExcludeList_MalformedEntriesSkipped(t *testing.T) {
	e := NewExcludeList("not-an-ip, 203.0.113.5, also-garbage/64")
	if !e.Contains("203.0.113.5") {
		t.Error("valid entry must still match despite malformed siblings in the list")
	}
	if e.Contains("10.0.0.1") {
		t.Error("unrelated IP must not match")
	}
}
