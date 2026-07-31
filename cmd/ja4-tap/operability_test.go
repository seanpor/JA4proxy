package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	var excludePtr atomic.Pointer[tap.ExcludeList]
	excludePtr.Store(tap.NewExcludeList(""))
	done := make(chan struct{})
	go func() {
		handleOperationalSignals(ctx, sigs, enf, &excludePtr, &count, log)
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
	_ = drive(ctx, 0, src, func() error { return nil }, store, enf, true /* quiet */, 16, nil, &count, log)

	if !strings.Contains(buf.String(), "heartbeat") {
		t.Error("expected at least one heartbeat log line even in quiet mode with no traffic; got none")
	}
}

// --- minimal synthetic single-connection TLS handshake, for the
// --exclude-ips wiring test below. Trimmed to the client direction only
// (SYN + ClientHello + FIN) since maybeEmit force-emits on FIN once a
// ClientHello is captured, without needing a ServerHello. ---

func tlsRecord(payload []byte) []byte {
	r := make([]byte, 5+len(payload))
	r[0] = 22 // handshake content type
	r[1], r[2] = 0x03, 0x01
	r[3] = byte(len(payload) >> 8)
	r[4] = byte(len(payload))
	copy(r[5:], payload)
	return r
}

func clientHelloMessage(bodyLen int) []byte {
	body := bytes.Repeat([]byte{0xAB}, bodyLen)
	m := make([]byte, 4+len(body))
	m[0] = 1 // ClientHello
	m[1] = byte(len(body) >> 16)
	m[2] = byte(len(body) >> 8)
	m[3] = byte(len(body))
	copy(m[4:], body)
	return m
}

// seg serialises one client->server TCP segment for a fixed synthetic flow
// (10.0.0.1:51000 -> 10.0.0.2:443).
func seg(t *testing.T, seq uint32, syn, fin bool, payload []byte) []byte {
	t.Helper()
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")}
	tcp := layers.TCP{SYN: syn, ACK: !syn, FIN: fin, Seq: seq, Window: 65535,
		SrcPort: 51000, DstPort: 443}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, ip, &tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// memSource replays a fixed list of frames as a tap.PacketSource, then EOFs.
type memSource struct {
	frames [][]byte
	i      int
}

func (m *memSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if m.i >= len(m.frames) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	f := m.frames[m.i]
	m.i++
	return f, gopacket.CaptureInfo{Timestamp: time.Unix(1_700_000_000, 0), CaptureLength: len(f), Length: len(f)}, nil
}

// TestDrive_ExcludedIPSkipsAllWrites guards P-003: a client IP on
// --exclude-ips must produce zero Store/Enforcer Redis writes, even though
// its handshake is fully captured and would otherwise be written.
func TestDrive_ExcludedIPSkipsAllWrites(t *testing.T) {
	const cISN = 1000
	ch := clientHelloMessage(48)
	chRec := tlsRecord(ch)
	frames := [][]byte{
		seg(t, cISN, true, false, nil),                      // SYN
		seg(t, cISN+1, false, false, chRec),                 // ClientHello
		seg(t, cISN+1+uint32(len(chRec)), false, true, nil), // FIN forces emit
	}

	run := func(exclude *tap.ExcludeList) *fakeRedisSetGetter {
		rs := &fakeRedisSetGetter{}
		store := tap.NewStore(rs)
		enf := tap.NewEnforcer(tap.EnforcerConfig{}, rs)
		log := logrus.New()
		log.SetOutput(io.Discard)
		var count atomic.Int64
		var excludePtr atomic.Pointer[tap.ExcludeList]
		excludePtr.Store(exclude)
		src := &memSource{frames: frames}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = drive(ctx, layers.LinkTypeEthernet, src, func() error { return nil }, store, enf, true, 16, &excludePtr, &count, log)
		return rs
	}

	t.Run("not excluded writes fp:os:ip", func(t *testing.T) {
		rs := run(tap.NewExcludeList(""))
		if rs.callCount() == 0 {
			t.Fatal("expected at least one Redis write for a non-excluded client; got 0")
		}
	})

	t.Run("excluded IP writes nothing", func(t *testing.T) {
		rs := run(tap.NewExcludeList("10.0.0.1"))
		if got := rs.callCount(); got != 0 {
			t.Errorf("expected 0 Redis writes for an excluded client; got %d", got)
		}
	})
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

// statsIdleSource is an idleSource that also implements tap.StatsSource, so
// the heartbeat's ring-buffer-fill-ratio sampling (R-011) has something to
// type-assert against.
type statsIdleSource struct {
	idleSource
	packets, drops uint64
}

func (s *statsIdleSource) RingBufferStats() (packets, drops uint64, ok bool) {
	return s.packets, s.drops, true
}

// TestDrive_HeartbeatSamplesRingBufferStats guards R-011: when the active
// PacketSource implements StatsSource, the heartbeat must sample it and set
// RingBufferFillRatio to the observed drop ratio.
func TestDrive_HeartbeatSamplesRingBufferStats(t *testing.T) {
	orig := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	defer func() { heartbeatInterval = orig }()

	log := logrus.New()
	log.SetOutput(io.Discard)

	store := tap.NewStore(nil)
	enf := tap.NewEnforcer(tap.EnforcerConfig{}, nil)
	src := &statsIdleSource{packets: 90, drops: 10} // 10% drop ratio

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var count atomic.Int64
	_ = drive(ctx, 0, src, func() error { return nil }, store, enf, true, 16, nil, &count, log)

	if got := testutil.ToFloat64(tap.RingBufferFillRatio); got != 0.1 {
		t.Errorf("RingBufferFillRatio = %v, want 0.1 (10 drops / 100 total)", got)
	}
}
