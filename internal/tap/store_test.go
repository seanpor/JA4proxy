package tap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/seanpor/ja4proxy/internal/fingerprint"
)

type fakeSetter struct {
	key, value string
	ttl        time.Duration
	err        error
	calls      int
}

func (f *fakeSetter) Set(_ context.Context, key, value string, ttl time.Duration) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.key, f.value, f.ttl = key, value, ttl
	return nil
}

func counter(result string) float64 {
	return testutil.ToFloat64(FingerprintsWrittenTotal.WithLabelValues(result))
}

func TestStore_WritesKnownClass(t *testing.T) {
	before := counter(fpWritten)
	fs := &fakeSetter{}
	NewStore(fs).WriteOSClass(context.Background(), "203.0.113.7", fingerprint.OSLinux)

	if fs.calls != 1 {
		t.Fatalf("expected 1 Set call; got %d", fs.calls)
	}
	if fs.key != "fp:os:ip:203.0.113.7" {
		t.Errorf("key = %q; want fp:os:ip:203.0.113.7", fs.key)
	}
	if fs.value != "linux" {
		t.Errorf("value = %q; want linux", fs.value)
	}
	if fs.ttl != 24*time.Hour {
		t.Errorf("ttl = %v; want 24h", fs.ttl)
	}
	if got := counter(fpWritten); got != before+1 {
		t.Errorf("written counter %v -> %v; want +1", before, got)
	}
}

func TestStore_SkipsUnknown(t *testing.T) {
	before := counter(fpSkippedUnknown)
	fs := &fakeSetter{}
	NewStore(fs).WriteOSClass(context.Background(), "203.0.113.7", fingerprint.OSUnknown)

	if fs.calls != 0 {
		t.Errorf("Unknown must not write; got %d Set calls", fs.calls)
	}
	if got := counter(fpSkippedUnknown); got != before+1 {
		t.Errorf("skipped_unknown counter %v -> %v; want +1", before, got)
	}
}

func TestStore_NilBackendSkips(t *testing.T) {
	before := counter(fpSkippedUnknown)
	NewStore(nil).WriteOSClass(context.Background(), "203.0.113.7", fingerprint.OSWindows)
	if got := counter(fpSkippedUnknown); got != before+1 {
		t.Errorf("nil backend should count skipped; %v -> %v", before, got)
	}
}

func TestStore_RedisErrorFailsOpen(t *testing.T) {
	before := counter(fpError)
	fs := &fakeSetter{err: errors.New("redis down")}
	NewStore(fs).WriteOSClass(context.Background(), "203.0.113.7", fingerprint.OSLinux)
	if got := counter(fpError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestStore_UnparsableIPCountsError(t *testing.T) {
	before := counter(fpError)
	fs := &fakeSetter{}
	NewStore(fs).WriteOSClass(context.Background(), "not-an-ip", fingerprint.OSLinux)
	if fs.calls != 0 {
		t.Errorf("unparsable IP must not write; got %d calls", fs.calls)
	}
	if got := counter(fpError); got != before+1 {
		t.Errorf("error counter %v -> %v; want +1", before, got)
	}
}

func TestStore_CanonicalisesIP(t *testing.T) {
	cases := []struct{ in, wantKey string }{
		{"203.0.113.7", "fp:os:ip:203.0.113.7"},
		{"2001:db8::1", "fp:os:ip:2001:db8::1"},
		{"2001:DB8::1", "fp:os:ip:2001:db8::1"},
		{"2001:0db8:0:0::1", "fp:os:ip:2001:db8::1"},
		{"[2001:db8::1]", "fp:os:ip:2001:db8::1"},
		{"fe80::1%eth0", "fp:os:ip:fe80::1"},
	}
	for _, c := range cases {
		fs := &fakeSetter{}
		NewStore(fs).WriteOSClass(context.Background(), c.in, fingerprint.OSWindows)
		if fs.key != c.wantKey {
			t.Errorf("WriteOSClass(%q) key = %q; want %q", c.in, fs.key, c.wantKey)
		}
	}
}
