package security

import (
	"context"
	"strings"
	"testing"
)

// mockRedisCounterWithKeys records which keys were actually queried.
type mockRedisCounterWithKeys struct {
	mockRedis
	counts    map[string]int
	queried   []string
}

func (m *mockRedisCounterWithKeys) SlidingWindowCount(_ context.Context, key string, _ float64, _ int) int {
	m.queried = append(m.queried, key)
	return m.counts[key]
}

// TestRateLimiter_IPTooLong verifies that an IP string > 45 chars is
// rejected with a logged warning (201e).
func TestRateLimiter_IPTooLong(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	mock := &mockRedisCounterWithKeys{counts: map[string]int{}}
	rl := NewRateLimiter(cfg, mock, nil)

	// 46-char string (exceeds max IPv6 length of 45 chars with zone ID).
	longIP := strings.Repeat("a", 46)

	_ = rl.Check(context.Background(), longIP, "t13d1234")

	// The rate limiter should reject this — no Redis keys should be queried.
	// NOTE: This test will fail until input validation is implemented.
	if len(mock.queried) != 0 {
		t.Errorf("long IP: expected no Redis queries (rejected input), got %d queries: %v", len(mock.queried), mock.queried)
	}
}

// TestRateLimiter_IPWithEmbeddedColons verifies that an IP with embedded
// colons that would create an unexpected key structure is rejected (201e).
func TestRateLimiter_IPWithEmbeddedColons(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	mock := &mockRedisCounterWithKeys{counts: map[string]int{}}
	rl := NewRateLimiter(cfg, mock, nil)

	// An IP-like string with extra colons that would break the key structure.
	maliciousIP := "1.2.3.4:malicious:suffix"

	_ = rl.Check(context.Background(), maliciousIP, "t13d1234")

	// Should be rejected — no Redis keys should be queried.
	if len(mock.queried) != 0 {
		t.Errorf("embedded colons: expected no Redis queries (rejected input), got %d queries: %v", len(mock.queried), mock.queried)
	}
}

// TestRateLimiter_JA4TooLong verifies that a JA4 string > 256 chars is
// truncated or rejected (201e).
func TestRateLimiter_JA4TooLong(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	mock := &mockRedisCounterWithKeys{counts: map[string]int{}}
	rl := NewRateLimiter(cfg, mock, nil)

	// 257-char JA4 string.
	longJA4 := strings.Repeat("x", 257)

	_ = rl.Check(context.Background(), "1.2.3.4", longJA4)

	// Should either be rejected (no queries) or truncated (JA4 strategies
	// should use the truncated value, not the full 257-char string).
	// We check that no queried key contains a string > 256 chars after
	// "ratelimit:ja4:" or "ratelimit:ip_ja4:".
	for _, key := range mock.queried {
		// Extract the JA4 portion from keys like "ratelimit:ja4:{ja4}"
		// or "ratelimit:ip_ja4:{ip}:{ja4}".
		if strings.HasPrefix(key, "ratelimit:ja4:") {
			ja4Part := key[len("ratelimit:ja4:"):]
			if len(ja4Part) > 256 {
				t.Errorf("JA4 part of key %q is %d chars (exceeds 256 limit)", key, len(ja4Part))
			}
		}
		if strings.HasPrefix(key, "ratelimit:ip_ja4:") {
			// Format: ratelimit:ip_ja4:{ip}:{ja4}
			// The JA4 part is after the second colon following "ip_ja4:"
			parts := strings.SplitN(key[len("ratelimit:ip_ja4:"):], ":", 2)
			if len(parts) == 2 && len(parts[1]) > 256 {
				t.Errorf("JA4 part key %q is %d chars (exceeds 256 limit)", key, len(parts[1]))
			}
		}
	}
}

// TestRateLimiter_ValidIPv4Accepted verifies that valid IPv4 addresses
// are accepted and rate limiting proceeds normally (201e).
func TestRateLimiter_ValidIPv4Accepted(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	cfg.ByIP.Ban = 1
	mock := &mockRedisCounterWithKeys{counts: map[string]int{
		"ratelimit:ip:192.168.1.1": 10,
	}}
	rl := NewRateLimiter(cfg, mock, nil)

	sigs := rl.Check(context.Background(), "192.168.1.1", "t13d1234")

	// The IP key should have been queried.
	found := false
	for _, key := range mock.queried {
		if key == "ratelimit:ip:192.168.1.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("valid IPv4: expected ratelimit:ip:192.168.1.1 to be queried, got: %v", mock.queried)
	}
	_ = sigs // signals depend on thresholds; we're testing key access, not scoring
}

// TestRateLimiter_ValidIPv6Accepted verifies that valid IPv6 addresses
// are accepted and rate limiting proceeds normally (201e).
func TestRateLimiter_ValidIPv6Accepted(t *testing.T) {
	cfg := defaultRateLimiterCfg()
	cfg.ByIP.Ban = 1
	mock := &mockRedisCounterWithKeys{counts: map[string]int{
		"ratelimit:ip:2001:db8::1": 10,
	}}
	rl := NewRateLimiter(cfg, mock, nil)

	sigs := rl.Check(context.Background(), "2001:db8::1", "t13d1234")

	found := false
	for _, key := range mock.queried {
		if key == "ratelimit:ip:2001:db8::1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("valid IPv6: expected ratelimit:ip:2001:db8::1 to be queried, got: %v", mock.queried)
	}
	_ = sigs
}

// TestRateLimiter_InputValidation_Table is a table-driven test covering
// multiple input validation cases (201e).
func TestRateLimiter_InputValidation_Table(t *testing.T) {
	cases := []struct {
		name         string
		ip           string
		ja4          string
		expectReject bool // true = no Redis queries should be made
	}{
		{
			name:         "valid IPv4",
			ip:           "10.0.0.1",
			ja4:          "t13d1234",
			expectReject: false,
		},
		{
			name:         "valid IPv6",
			ip:           "2001:db8::1",
			ja4:          "t13d1234",
			expectReject: false,
		},
		{
			name:         "IP exceeds 45 chars",
			ip:           strings.Repeat("a", 46),
			ja4:          "t13d1234",
			expectReject: true,
		},
		{
			name:         "IP with extra colons",
			ip:           "1.2.3.4:extra:stuff",
			ja4:          "t13d1234",
			expectReject: true,
		},
		{
			name:         "JA4 exceeds 256 chars",
			ip:           "1.2.3.4",
			ja4:          strings.Repeat("x", 257),
			expectReject: false, // truncated, not rejected
		},
		{
			name:         "localhost IPv4",
			ip:           "127.0.0.1",
			ja4:          "t13d1234",
			expectReject: false,
		},
		{
			name:         "localhost IPv6",
			ip:           "::1",
			ja4:          "t13d1234",
			expectReject: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultRateLimiterCfg()
			cfg.ByIP.Ban = 1000000 // very high so no signal fires
			mock := &mockRedisCounterWithKeys{counts: map[string]int{}}
			rl := NewRateLimiter(cfg, mock, nil)

			_ = rl.Check(context.Background(), tc.ip, tc.ja4)

			if tc.expectReject {
				// Rejected input should not produce any Redis queries.
				if len(mock.queried) != 0 {
					t.Errorf("expected rejection (no Redis queries), got %d queries: %v", len(mock.queried), mock.queried)
				}
			} else {
				// Valid input: at least the ByIP key should be queried.
				if len(mock.queried) == 0 {
					t.Errorf("expected at least one Redis query for valid input, got none")
				}
			}
		})
	}
}
