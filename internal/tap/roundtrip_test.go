package tap_test

// Closed-loop test for the OS-mismatch signal (PHASE_316b D3): the TAP sensor
// writes fp:os:ip via internal/tap, and the inline proxy consumer reads it via
// internal/security. The original 203a code never had this test, which is how the
// vocabulary-mismatch bug ("linux" vs "linux_5x_default") went unnoticed. Here the
// writer and reader share one Redis and one OSClass vocabulary, so a real mismatch
// must light up end to end.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gopacket/gopacket/layers"
	goredis "github.com/redis/go-redis/v9"

	"github.com/seanpor/ja4proxy/internal/fingerprint"
	"github.com/seanpor/ja4proxy/internal/security"
	"github.com/seanpor/ja4proxy/internal/tap"
)

// redisBridge satisfies both the writer's setter and the consumer's getter over
// one go-redis client, mapping the missing-key Nil error to the ("", nil) miss
// the consumer expects.
type redisBridge struct{ c *goredis.Client }

func (r redisBridge) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	return r.c.Set(ctx, k, v, ttl).Err()
}

func (r redisBridge) Get(ctx context.Context, k string) (string, error) {
	v, err := r.c.Get(ctx, k).Result()
	if err == goredis.Nil {
		return "", nil
	}
	return v, err
}

func linuxStack() tap.StackFeatures {
	return tap.StackFeatures{
		HasSYN: true, TTL: 56, SYNWindow: 64240, MSS: 1460, WSOptPresent: true,
		OptionOrder: []layers.TCPOptionKind{
			layers.TCPOptionKindMSS, layers.TCPOptionKindSACKPermitted,
			layers.TCPOptionKindTimestamps, layers.TCPOptionKindNop,
			layers.TCPOptionKindWindowScale,
		},
	}
}

func windowsStack() tap.StackFeatures {
	return tap.StackFeatures{
		HasSYN: true, TTL: 120, SYNWindow: 64240, MSS: 1460, WSOptPresent: true,
		OptionOrder: []layers.TCPOptionKind{
			layers.TCPOptionKindMSS, layers.TCPOptionKindNop,
			layers.TCPOptionKindWindowScale, layers.TCPOptionKindNop,
			layers.TCPOptionKindNop, layers.TCPOptionKindSACKPermitted,
		},
	}
}

func darwinStack() tap.StackFeatures {
	return tap.StackFeatures{
		HasSYN: true, TTL: 60, SYNWindow: 65535, MSS: 1460, WSOptPresent: true,
		OptionOrder: []layers.TCPOptionKind{
			layers.TCPOptionKindMSS, layers.TCPOptionKindNop,
			layers.TCPOptionKindWindowScale, layers.TCPOptionKindNop,
			layers.TCPOptionKindNop, layers.TCPOptionKindTimestamps,
			layers.TCPOptionKindSACKPermitted, layers.TCPOptionKindEndList,
		},
	}
}

func newConsumer(br redisBridge) *security.TapConsumer {
	return security.NewTapConsumer(&security.TapConsumerConfig{
		Enabled:      true,
		SignalScore:  30,
		RedisTimeout: 200 * time.Millisecond,
		CacheTTL:     time.Second,
	}, br, nil)
}

const (
	// JA4 prefixes from the shared starter table.
	ja4Windows = "t13d1516h2_aabbccddeeff_aabbccddeeff" // claims windows
	ja4Linux   = "t13d1715h2_aabbccddeeff_aabbccddeeff" // claims linux
)

func TestRoundTrip_MismatchFires(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	// Sensor observes a Linux stack from 198.51.100.10 and writes it.
	const ip = "198.51.100.10"
	class := tap.Classify(linuxStack())
	if class != fingerprint.OSLinux {
		t.Fatalf("precondition: Classify(linuxStack) = %v; want linux", class)
	}
	tap.NewStore(br).WriteOSClass(ctx, ip, class)
	if got, _ := mr.Get("fp:os:ip:" + ip); got != "linux" {
		t.Fatalf("fp:os:ip not written as bare class; got %q", got)
	}

	// Consumer: a JA4 claiming Windows over an observed-Linux stack → mismatch.
	sig := newConsumer(br).GetSignal(ctx, ip, ja4Windows)
	if sig == nil {
		t.Fatal("expected tap_os_mismatch signal; got nil — the dormant loop is still broken")
	}
	if sig.Name != "tap_os_mismatch" {
		t.Errorf("signal Name = %q; want tap_os_mismatch", sig.Name)
	}
	if sig.Score != 30 {
		t.Errorf("signal Score = %d; want 30", sig.Score)
	}
}

func TestRoundTrip_AgreementNoSignal(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.11"
	tap.NewStore(br).WriteOSClass(ctx, ip, tap.Classify(linuxStack()))

	// JA4 also claims Linux → observed == claimed → no signal.
	if sig := newConsumer(br).GetSignal(ctx, ip, ja4Linux); sig != nil {
		t.Errorf("agreement must produce no signal; got %+v", sig)
	}
}

// TestFPCorpus_NoFalseMismatches stands in for the mandatory Tranco-top-10k FP
// gate (CLAUDE.md): a sensor that drives scoring must never mislabel a real
// browser. We replay legitimate (stack, JA4) pairs where the OS genuinely agrees
// — Windows-Chrome over a Windows stack, Firefox-Linux over a Linux stack, and
// Safari over a Darwin stack (which the classifier conservatively leaves Unknown,
// so it can never produce a mismatch). Across the whole corpus the OS-mismatch
// signal must fire exactly zero times. (A real-pcap corpus replay is wired in the
// live test target; this exercises the classification+consumer loop deterministically.)
func TestFPCorpus_NoFalseMismatches(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()
	consumer := newConsumer(br)

	type legit struct {
		stack tap.StackFeatures
		ja4   string
	}
	profiles := []legit{
		{windowsStack(), ja4Windows},                            // Chrome/Edge on Windows
		{linuxStack(), ja4Linux},                                // Firefox on Linux
		{darwinStack(), "t13d3112h2_aabbccddeeff_aabbccddeeff"}, // Safari on macOS
		{darwinStack(), "t13d3113h2_aabbccddeeff_aabbccddeeff"}, // Safari on iOS
	}

	const perProfile = 250
	var falsePositives int
	for pi, p := range profiles {
		for i := 0; i < perProfile; i++ {
			ip := fmtIP(pi, i)
			tap.NewStore(br).WriteOSClass(ctx, ip, tap.Classify(p.stack))
			if sig := consumer.GetSignal(ctx, ip, p.ja4); sig != nil {
				falsePositives++
				t.Errorf("false mismatch for legit profile %d (%s) at %s: %+v", pi, p.ja4, ip, sig)
			}
		}
	}
	if falsePositives != 0 {
		t.Fatalf("FP corpus: %d false mismatches across %d legitimate connections; want 0",
			falsePositives, len(profiles)*perProfile)
	}
}

func fmtIP(a, b int) string {
	// 10.a.(b/256).(b%256) — unique per (profile,index), all private.
	return "10." + itoa(a) + "." + itoa(b/256) + "." + itoa(b%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestRoundTrip_UnknownWritesNothing(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	br := redisBridge{c: goredis.NewClient(&goredis.Options{Addr: mr.Addr()})}
	ctx := context.Background()

	const ip = "198.51.100.12"
	// Darwin stack → Unknown → nothing written.
	class := tap.Classify(darwinStack())
	if class.IsKnown() {
		t.Fatalf("precondition: darwin stack should classify Unknown; got %v", class)
	}
	tap.NewStore(br).WriteOSClass(ctx, ip, class)
	if mr.Exists("fp:os:ip:" + ip) {
		t.Error("Unknown class must not write a key")
	}
	// No observed value → consumer emits nothing even with a concrete JA4 claim.
	if sig := newConsumer(br).GetSignal(ctx, ip, ja4Windows); sig != nil {
		t.Errorf("no observed OS must produce no signal; got %+v", sig)
	}
}
