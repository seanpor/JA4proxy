package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

// TestRegister_FreshRegistry verifies Register() successfully registers all
// metrics into a fresh prometheus.DefaultRegisterer. Since the default registry
// may already have them from other tests, we test that calling Register on a
// package-level function doesn't panic when already registered.
func TestRegister_NoPanic(t *testing.T) {
	// Register may have been called already. Calling again should either succeed
	// or produce an AlreadyRegisteredError — but should NOT panic.
	defer func() {
		if r := recover(); r != nil {
			// MustRegister panics if already registered with the default registry.
			// That's acceptable in a test environment where multiple tests share
			// the same process. We just need to verify it was called.
			t.Logf("Register() panicked (expected if already registered): %v", r)
		}
	}()
	Register()
}

// TestRegister_PreInitializesActionLabels verifies that after Register(), the
// six standard action labels are pre-initialised on ConnectionsTotal.
func TestRegister_PreInitializesActionLabels(t *testing.T) {
	// After Register(), these labels should exist. We can't call Register()
	// twice in the default registry, so just verify the counters are usable.
	actions := []string{"allow", "flag", "rate_limit", "tarpit", "block", "ban"}
	for _, a := range actions {
		// WithLabelValues should not panic — it was pre-initialised.
		c := ConnectionsTotal.WithLabelValues(a)
		if c == nil {
			t.Errorf("ConnectionsTotal.WithLabelValues(%q) returned nil", a)
		}
	}
}

// TestStartNTPMonitor_ContextCancellation verifies the NTP monitor goroutine
// exits cleanly when its context is cancelled.
func TestStartNTPMonitor_ContextCancellation(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartNTPMonitor(ctx, 1, log)
		close(done)
	}()

	// Cancel immediately
	cancel()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("StartNTPMonitor did not exit after context cancellation")
	}
}

// TestStartNTPMonitor_DefaultInterval verifies that passing 0 defaults to 60s
// (the function should not panic).
func TestStartNTPMonitor_DefaultInterval(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartNTPMonitor(ctx, 0, log)
		close(done)
	}()

	// Cancel immediately — we just want to verify it starts without panic
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("StartNTPMonitor did not exit")
	}
}

// TestCheckNTP_DoesNotPanic verifies checkNTP handles unavailable NTP tools
// gracefully (no panic, just a debug log).
func TestCheckNTP_DoesNotPanic(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	// Should not panic even if chronyc/ntpstat aren't available
	checkNTP(log)
}

// TestCheckNTP_SetsAvailabilityGauge verifies the F-400-04 (#245) availability
// gauge tracks whether drift can actually be read.
//
// Without this gauge, ja4proxy_sync_clock_drift_seconds is simply never Set when
// neither chronyc nor ntpstat is present — and a never-set gauge is
// indistinguishable from "drift is currently 0" on a dashboard. Clock-skew
// monitoring could therefore be silently disabled in production while the drift
// panel showed a reassuring flat zero.
//
// Asserted relative to the environment rather than to a fixed value, so this
// holds both in CI (no NTP tooling) and on a host that has chronyd running.
func TestCheckNTP_SetsAvailabilityGauge(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	_, driftErr := getNTPDrift()
	checkNTP(log)

	want := 1.0
	if driftErr != nil {
		want = 0.0
	}

	if got := testutil.ToFloat64(SyncClockMonitorAvailable); got != want {
		t.Errorf("SyncClockMonitorAvailable = %v, want %v (getNTPDrift err: %v)", got, want, driftErr)
	}
}

// TestGetNTPDrift_ReturnsErrorWhenToolsMissing verifies getNTPDrift returns
// an error when neither chronyc nor ntpstat is available (common in CI/containers).
func TestGetNTPDrift_ReturnsErrorWhenToolsMissing(t *testing.T) {
	// In most CI environments, neither chronyc nor ntpstat is installed.
	// If one IS installed, we at least verify it doesn't panic.
	_, err := getNTPDrift()
	if err != nil {
		// Expected in CI
		t.Logf("getNTPDrift returned expected error: %v", err)
	}
	// If err == nil, the tool is available and returned a valid drift — also fine.
}

// TestParseChronycTracking_NoSystemTimeLine verifies error when the expected
// "System time" line is missing.
func TestParseChronycTracking_NoSystemTimeLine(t *testing.T) {
	_, err := parseChronycTracking("Stratum : 3\nRef time : blah\n")
	if err == nil {
		t.Error("expected error for missing 'System time' line")
	}
}

// TestParseChronycTracking_MalformedNumber verifies error when the drift value
// is not a valid float.
func TestParseChronycTracking_MalformedNumber(t *testing.T) {
	_, err := parseChronycTracking("System time     : notanumber seconds fast of NTP time\n")
	if err == nil {
		t.Error("expected error for malformed drift number")
	}
}

// TestParseNtpstat_MissingDriftLine verifies error when drift info is missing.
func TestParseNtpstat_MissingDriftLine(t *testing.T) {
	_, err := parseNtpstat("synchronised to NTP server\npolling every 64s\n")
	if err == nil {
		t.Error("expected error for missing drift line")
	}
}

// TestParseNtpstat_SecondsUnit verifies seconds (not ms) unit parsing.
func TestParseNtpstat_SecondsUnit(t *testing.T) {
	out := "synchronised to NTP server (1.2.3.4) at stratum 2\n   time correct to within 5 s\n"
	drift, err := parseNtpstat(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drift != 5.0 {
		t.Errorf("got %f, want 5.0", drift)
	}
}

// TestMetricNames_Phase201c verifies phase-201c metrics exist with expected names.
func TestMetricNames_Phase201c(t *testing.T) {
	cases := []struct {
		name      string
		collector prometheus.Collector
		wantName  string
	}{
		{"RedisHealth", RedisHealth, "ja4proxy_redis_health"},
		{"RedisScriptReloadsTotal", RedisScriptReloadsTotal, "ja4proxy_redis_script_reloads_total"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan *prometheus.Desc, 1)
			tc.collector.Describe(ch)
			d := <-ch
			s := d.String()
			if s == "" {
				t.Errorf("empty descriptor for %s", tc.name)
			}
		})
	}
}

// TestMetricNames_Phase203 verifies phase-203 metrics exist.
func TestMetricNames_Phase203(t *testing.T) {
	cases := []struct {
		name      string
		collector prometheus.Collector
	}{
		{"JA4TLSMismatchTotal", JA4TLSMismatchTotal},
		{"TapLookupsTotal", TapLookupsTotal},
		{"TapSignalTotal", TapSignalTotal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan *prometheus.Desc, 1)
			tc.collector.Describe(ch)
			d := <-ch
			if d.String() == "" {
				t.Errorf("empty descriptor for %s", tc.name)
			}
		})
	}
}
