package tap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func ja4tCounter(result string) float64 {
	return testutil.ToFloat64(JA4TWrittenTotal.WithLabelValues(result))
}

func TestStore_WritesJA4T(t *testing.T) {
	before := ja4tCounter(fpWritten)
	fs := &fakeSetter{}
	NewStore(fs).WriteJA4T(context.Background(), "203.0.113.7", "64240_2-1-3-1-1-4_1460_8")

	if fs.calls != 1 {
		t.Fatalf("expected 1 Set call; got %d", fs.calls)
	}
	if fs.key != "fp:ja4t:ip:203.0.113.7" {
		t.Errorf("key = %q; want fp:ja4t:ip:203.0.113.7", fs.key)
	}
	if fs.value != "64240_2-1-3-1-1-4_1460_8" {
		t.Errorf("value = %q; want the JA4T string", fs.value)
	}
	if fs.ttl != 24*time.Hour {
		t.Errorf("ttl = %v; want 24h", fs.ttl)
	}
	if got := ja4tCounter(fpWritten); got != before+1 {
		t.Errorf("written counter %v -> %v; want +1", before, got)
	}
}

func TestStore_SkipsEmptyJA4T(t *testing.T) {
	before := ja4tCounter(fpSkippedUnknown)
	fs := &fakeSetter{}
	NewStore(fs).WriteJA4T(context.Background(), "203.0.113.7", "")

	if fs.calls != 0 {
		t.Errorf("empty JA4T (no SYN) must not write; got %d Set calls", fs.calls)
	}
	if got := ja4tCounter(fpSkippedUnknown); got != before+1 {
		t.Errorf("skipped_unknown counter %v -> %v; want +1", before, got)
	}
}

func TestStore_NilBackendSkipsJA4T(t *testing.T) {
	before := ja4tCounter(fpSkippedUnknown)
	NewStore(nil).WriteJA4T(context.Background(), "203.0.113.7", "64240_2_1460_0")
	if got := ja4tCounter(fpSkippedUnknown); got != before+1 {
		t.Errorf("nil backend should count skipped; %v -> %v", before, got)
	}
}

func TestStore_RedisErrorFailsOpenJA4T(t *testing.T) {
	before := ja4tCounter(fpError)
	fs := &fakeSetter{err: errors.New("redis down")}
	NewStore(fs).WriteJA4T(context.Background(), "203.0.113.7", "64240_2_1460_0")
	if got := ja4tCounter(fpError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestStore_UnparsableIPCountsErrorJA4T(t *testing.T) {
	before := ja4tCounter(fpError)
	fs := &fakeSetter{}
	NewStore(fs).WriteJA4T(context.Background(), "not-an-ip", "64240_2_1460_0")
	if fs.calls != 0 {
		t.Errorf("unparsable IP must not write; got %d calls", fs.calls)
	}
	if got := ja4tCounter(fpError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestStore_CanonicalisesIPJA4T(t *testing.T) {
	cases := []struct{ in, wantKey string }{
		{"203.0.113.7", "fp:ja4t:ip:203.0.113.7"},
		{"2001:DB8::1", "fp:ja4t:ip:2001:db8::1"},
		{"[2001:db8::1]", "fp:ja4t:ip:2001:db8::1"},
		{"fe80::1%eth0", "fp:ja4t:ip:fe80::1"},
	}
	for _, c := range cases {
		fs := &fakeSetter{}
		NewStore(fs).WriteJA4T(context.Background(), c.in, "64240_2_1460_0")
		if fs.key != c.wantKey {
			t.Errorf("WriteJA4T(%q) key = %q; want %q", c.in, fs.key, c.wantKey)
		}
	}
}
