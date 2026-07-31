package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/tap"
)

// fakeRedisSetGetter is a minimal Set+Get fake satisfying whatever narrow
// interface tap.NewEnforcer expects (unexported, so this file can't name it —
// Go's structural typing doesn't require that).
type fakeRedisSetGetter struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeRedisSetGetter) Set(_ context.Context, key, _ string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	return nil
}

func (f *fakeRedisSetGetter) Get(_ context.Context, _ string) (string, error) { return "", nil }

func (f *fakeRedisSetGetter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestConfigureLogger_FormatAndLevel guards R-008: --log-format must select
// text or json, and --log-level must map to a real logrus level; unknown
// values are rejected rather than silently defaulting.
func TestConfigureLogger_FormatAndLevel(t *testing.T) {
	t.Run("json format", func(t *testing.T) {
		log := logrus.New()
		if err := configureLogger(log, "json", "info"); err != nil {
			t.Fatalf("configureLogger: %v", err)
		}
		if _, ok := log.Formatter.(*logrus.JSONFormatter); !ok {
			t.Errorf("Formatter = %T, want *logrus.JSONFormatter", log.Formatter)
		}
	})

	t.Run("text format", func(t *testing.T) {
		log := logrus.New()
		if err := configureLogger(log, "text", "warn"); err != nil {
			t.Fatalf("configureLogger: %v", err)
		}
		if _, ok := log.Formatter.(*logrus.TextFormatter); !ok {
			t.Errorf("Formatter = %T, want *logrus.TextFormatter", log.Formatter)
		}
		if log.GetLevel() != logrus.WarnLevel {
			t.Errorf("Level = %v, want WarnLevel", log.GetLevel())
		}
	})

	t.Run("unknown format rejected", func(t *testing.T) {
		if err := configureLogger(logrus.New(), "xml", "info"); err == nil {
			t.Error("expected an error for an unknown --log-format, got nil")
		}
	})

	t.Run("unknown level rejected", func(t *testing.T) {
		if err := configureLogger(logrus.New(), "text", "not-a-level"); err == nil {
			t.Error("expected an error for an unknown --log-level, got nil")
		}
	})
}

// TestHandleOperationalSignals_SIGHUPReloadsBlocklist guards R-007/R-009: a
// blocklist starts empty (enforcement can never fire), SIGHUP re-reads
// JA4T_BLOCKLIST from the environment, and Consider() must start firing for
// a JA4T on the newly-loaded list — without a restart.
func TestHandleOperationalSignals_SIGHUPReloadsBlocklist(t *testing.T) {
	const ja4t = "64240_2-1-3-1-1-4_1460_8"
	t.Setenv("JA4T_BLOCKLIST", ja4t)

	rs := &fakeRedisSetGetter{}
	enf := tap.NewEnforcer(tap.EnforcerConfig{Armed: false}, rs)
	log := logrus.New()
	log.SetOutput(io.Discard)

	// Precondition: blocklist starts empty, so Consider() writes nothing.
	enf.Consider(context.Background(), "203.0.113.9", ja4t)
	if got := rs.callCount(); got != 0 {
		t.Fatalf("precondition failed: expected 0 writes before reload, got %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		handleOperationalSignals(ctx, sigs, enf, &count, log)
		close(done)
	}()

	sigs <- syscall.SIGHUP

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		enf.Consider(context.Background(), "203.0.113.9", ja4t)
		if rs.callCount() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := rs.callCount(); got == 0 {
		t.Fatal("SIGHUP did not reload the blocklist within 2s: Consider() still writes nothing")
	}

	cancel()
	<-done
}

// TestDrive_HeartbeatLogsWithoutQuiet guards R-005: the heartbeat must fire
// on its own ticker (independent of --quiet and of any handshake traffic)
// and must not be suppressed by --quiet.
func TestDrive_HeartbeatLogsWithoutQuiet(t *testing.T) {
	orig := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	defer func() { heartbeatInterval = orig }()

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	log.SetFormatter(&logrus.JSONFormatter{})

	store := tap.NewStore(nil)
	enf := tap.NewEnforcer(tap.EnforcerConfig{}, nil)
	src := &idleSource{} // mimics an idle live interface (ErrPollTimeout) — never EOFs

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var count atomic.Int64
	_ = drive(ctx, 0, src, func() error { return nil }, store, enf, true /* quiet */, 16, &count, log)

	if !strings.Contains(buf.String(), "heartbeat") {
		t.Error("expected at least one heartbeat log line even in quiet mode with no traffic; got none")
	}
}

// idleSource mimics an idle live interface: every read returns
// tap.ErrPollTimeout after a short sleep (never io.EOF), so the sensor's Run
// loop keeps re-checking ctx.Done() instead of exiting immediately — letting
// a test's heartbeat ticker actually get a chance to fire before ctx expires.
type idleSource struct{}

func (s *idleSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	time.Sleep(2 * time.Millisecond)
	return nil, gopacket.CaptureInfo{}, tap.ErrPollTimeout
}
