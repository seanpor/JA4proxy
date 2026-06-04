package security

import (
	"context"
	"math/rand"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	redisclient "github.com/seanpor/ja4proxy/internal/redis"
)

// mockRedisCounter implements RedisReader for rate limiter tests.
type mockRedisCounter struct {
	mockRedis
	counts map[string]int
}

func (m *mockRedisCounter) SlidingWindowCount(_ context.Context, key string, _ float64, _ int) int {
	return m.counts[key]
}

func defaultRateLimiterCfg() *RateLimiterConfig {
	return &RateLimiterConfig{
		Enabled: true,
		ByIP:    StrategyConfig{Enabled: true, Suspicious: 50, Block: 200, Ban: 500, Window: 1, TTL: 300},
		ByJA4:   StrategyConfig{Enabled: true, Suspicious: 20, Block: 100, Ban: 200, Window: 1, TTL: 300},
		ByIPJA4: StrategyConfig{Enabled: true, Suspicious: 20, Block: 50, Ban: 100, Window: 1, TTL: 300},
	}
}

func TestRateLimiter_Disabled_NoSignal(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	cfg.Enabled = false
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4": 1000,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("disabled rate limiter: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_BelowThreshold_NoSignal(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              10,
		"ratelimit:ja4:t13d1234":            5,
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("below threshold: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_SingleStrategy_Suspicious_NoSignal(t *testing.T) {
	// Only 1 strategy hits suspicious — majority=2 required, so no signal.
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              60, // above Suspicious(50) for ByIP
		"ratelimit:ja4:t13d1234":            5,  // below Suspicious(20) for ByJA4
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,  // below Suspicious(20) for ByIPJA4
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) != 0 {
		t.Errorf("single strategy suspicious: expected no signal (majority=2 required), got %d signals", len(sigs))
	}
}

func TestRateLimiter_MajoritySuspicious_SignalFired(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              60, // ByIP: suspicious (>50)
		"ratelimit:ja4:t13d1234":            25, // ByJA4: suspicious (>20)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,  // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("majority suspicious: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_suspicious" {
		t.Errorf("expected 'rate_limit_suspicious', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_MajorityBlock_SignalFired(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              250, // ByIP: block (>200)
		"ratelimit:ja4:t13d1234":            120, // ByJA4: block (>100)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,   // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("majority block: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_block" {
		t.Errorf("expected 'rate_limit_block', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_AnyBan_SignalFired(t *testing.T) {
	// Single strategy at ban level → signal (no majority required).
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              600, // ByIP: ban (>500)
		"ratelimit:ja4:t13d1234":            5,   // ByJA4: below threshold
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 3,   // ByIPJA4: below threshold
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("any ban: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_ban" {
		t.Errorf("expected 'rate_limit_ban', got %q", sigs[0].Name)
	}
}

func TestRateLimiter_EmptyJA4_SkipsJA4Strategies(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	// Only ByIP key will be checked; JA4 strategies skipped since ja4="".
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4": 10,
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "")
	// Only 1 strategy result available (ByIP) — can't reach majority for any level.
	if len(sigs) != 0 {
		t.Errorf("empty JA4: expected no signals, got %d", len(sigs))
	}
}

func TestRateLimiter_HighestLevelWins(t *testing.T) {
	// Both block and ban conditions are met — ban should win.
	cfg := defaultRateLimiterCfg()
	rl := NewRateLimiter(cfg, &mockRedisCounter{counts: map[string]int{
		"ratelimit:ip:1.2.3.4":              600, // ByIP: ban (>500)
		"ratelimit:ja4:t13d1234":            250, // ByJA4: block (>100)
		"ratelimit:ip_ja4:1.2.3.4:t13d1234": 60,  // ByIPJA4: block (>50)
	}}, nil)
	sigs := rl.Check(context.Background(), "1.2.3.4", "t13d1234")
	if len(sigs) == 0 {
		t.Fatal("highest level wins: expected signal, got none")
	}
	if sigs[0].Name != "rate_limit_ban" {
		t.Errorf("expected 'rate_limit_ban' (ban beats block), got %q", sigs[0].Name)
	}
}

// ----------------------------------------------------------------------------
// Phase 201d — sanitizeKey contract tests.
//
// REQUIRES (Coder must add in internal/security/rate_limiter.go):
//   func sanitizeKey(clientIP, ja4 string) (canonIP, safeJA4 string, ok bool)
//     * ok=false if netip.ParseAddr fails or addr is invalid.
//     * ok=true: canonIP = addr.String() (canonical form), safeJA4 truncated
//       to at most 256 bytes.
//   Check() must call sanitizeKey first; on !ok, log WARN with a sha256 hash
//   prefix (16 hex chars) in field "ip_hash", message containing "fail-open",
//   and return nil WITHOUT writing any Redis key.
//
// If sanitizeKey is missing, this block FAILS TO COMPILE — the correct TDD
// red-phase signal.
// ----------------------------------------------------------------------------

func TestSanitizeKey_IPv4(t *testing.T) {
	ip, ja4, ok := sanitizeKey("1.2.3.4", "t13d1234")
	if !ok {
		t.Fatal("IPv4 should be accepted")
	}
	if ip != "1.2.3.4" {
		t.Errorf("canonIP: got %q, want %q", ip, "1.2.3.4")
	}
	if ja4 != "t13d1234" {
		t.Errorf("safeJA4: got %q, want %q", ja4, "t13d1234")
	}
}

func TestSanitizeKey_IPv6(t *testing.T) {
	ip, _, ok := sanitizeKey("2001:db8::1", "ja4")
	if !ok {
		t.Fatal("IPv6 should be accepted")
	}
	if ip != "2001:db8::1" {
		t.Errorf("canonIP: got %q, want %q", ip, "2001:db8::1")
	}
}

func TestSanitizeKey_IPv6_Verbose_CanonicalisedToCompact(t *testing.T) {
	ip, _, ok := sanitizeKey("2001:0db8:0000:0000:0000:0000:0000:0001", "ja4")
	if !ok {
		t.Fatal("verbose IPv6 should be accepted")
	}
	if ip != "2001:db8::1" {
		t.Errorf("canonIP: got %q, want %q (netip canonical form)", ip, "2001:db8::1")
	}
}

func TestSanitizeKey_IPv6WithZone(t *testing.T) {
	_, _, ok := sanitizeKey("fe80::1%eth0", "ja4")
	if !ok {
		t.Error("IPv6 with zone identifier should parse (netip.ParseAddr accepts it)")
	}
}

func TestSanitizeKey_Empty(t *testing.T) {
	if _, _, ok := sanitizeKey("", "ja4"); ok {
		t.Error("empty IP must be rejected")
	}
}

func TestSanitizeKey_Garbage(t *testing.T) {
	cases := []string{
		"1.2.3.4\nSET evil x",
		"::evil",
		"999.999.999.999",
		"1.2.3",
		string(make([]byte, 4096)),
	}
	for _, s := range cases {
		if _, _, ok := sanitizeKey(s, "ja4"); ok {
			t.Errorf("garbage IP %q should be rejected", s)
		}
	}
}

func TestSanitizeKey_OverlongJA4_Truncated(t *testing.T) {
	longJA4 := strings.Repeat("a", 1024)
	_, safe, ok := sanitizeKey("1.2.3.4", longJA4)
	if !ok {
		t.Fatal("valid IPv4 should be accepted even with long JA4")
	}
	if len(safe) != 256 {
		t.Errorf("safeJA4 length: got %d, want 256", len(safe))
	}
}

func TestSanitizeKey_OracleProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		n := r.Intn(49)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(r.Intn(256))
		}
		s := string(buf)
		_, _, gotOK := sanitizeKey(s, "ja4")
		addr, err := netip.ParseAddr(s)
		wantOK := err == nil && addr.IsValid()
		if gotOK != wantOK {
			t.Errorf("iter %d: input %q: sanitizeKey ok=%v, netip.ParseAddr-valid=%v",
				i, s, gotOK, wantOK)
		}
	}
}

// TestRateLimiter_Check_FailOpenOnBadIP verifies that a bad IP triggers the
// fail-open path: no signals, a WARN log with hashed IP, and NO Redis write.
func TestRateLimiter_Check_FailOpenOnBadIP(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	rc := redisclient.New(redisclient.Config{
		Host:    mr.Host(),
		Port:    mr.Server().Addr().Port,
		Timeout: 2 * time.Second,
	}, log)

	rl := NewRateLimiter(defaultRateLimiterCfg(), rc, log)
	sigs := rl.Check(context.Background(), "not-an-ip\n", "ja4")
	if len(sigs) != 0 {
		t.Errorf("bad IP: expected empty signals, got %d", len(sigs))
	}

	// No ratelimit:* key should have been written.
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "ratelimit:") {
			t.Errorf("no Redis ratelimit key should exist on bad-IP fail-open; found %q", k)
		}
	}

	// WARN log with sha256 hex prefix in ip_hash field, and "fail-open" in message.
	hashRE := regexp.MustCompile(`^[0-9a-f]{16}$`)
	saw := false
	for _, e := range hook.AllEntries() {
		if e.Level != logrus.WarnLevel {
			continue
		}
		ipHash, ok := e.Data["ip_hash"].(string)
		if !ok || !hashRE.MatchString(ipHash) {
			continue
		}
		if !strings.Contains(strings.ToLower(e.Message), "fail-open") {
			continue
		}
		// Critical: raw IP bytes must NOT appear in the log entry.
		if strings.Contains(e.Message, "not-an-ip") {
			t.Errorf("raw IP leaked into log message: %q", e.Message)
		}
		saw = true
		break
	}
	if !saw {
		t.Errorf("expected WARN with ip_hash=/^[0-9a-f]{16}$/ and message containing 'fail-open'; got entries: %+v", hook.AllEntries())
	}
}
