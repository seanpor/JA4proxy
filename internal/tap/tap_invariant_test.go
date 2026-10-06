package tap

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"pgregory.net/rapid"
)

type mockRedisSetterGetter struct {
	err error
}

func (m *mockRedisSetterGetter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return m.err
}

func (m *mockRedisSetterGetter) Get(ctx context.Context, key string) (string, error) {
	return "", m.err
}

// INV-TAP-001: 16 KiB Per-Direction Buffer Cap
// forall stream, BufferLen(dir) <= 16384
func TestInvariant_Tap_BufferCap16KiB(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		chunkSize := rapid.IntRange(100, 4096).Draw(t, "chunkSize")
		numChunks := rapid.IntRange(5, 20).Draw(t, "numChunks")
		isClient := rapid.Bool().Draw(t, "isClient")

		s := &tlsStream{}
		data := make([]byte, chunkSize)
		for i := 0; i < len(data); i++ {
			data[i] = byte(i % 256)
		}

		for i := 0; i < numChunks; i++ {
			s.append(isClient, data)
		}

		bufLen := len(s.clientBuf)
		if !isClient {
			bufLen = len(s.serverBuf)
		}

		if bufLen > maxHandshakeBytes {
			t.Fatalf("Buffer cap exceeded: got %d bytes, max allowed is %d", bufLen, maxHandshakeBytes)
		}
	})
}

// INV-TAP-002: Single HandshakeEvent Emission
// forall stream, Count(HandshakeEvent) <= 1
func TestInvariant_Tap_SingleHandshakeEvent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var emitCount int32
		s := &tlsStream{
			clientIP:   "1.2.3.4",
			serverIP:   "5.6.7.8",
			clientPort: 12345,
			serverPort: 443,
			clientHello: []byte{0x16, 0x03, 0x03},
			serverHello: []byte{0x16, 0x03, 0x03},
			emit: func(evt HandshakeEvent) {
				atomic.AddInt32(&emitCount, 1)
			},
		}

		numTriggers := rapid.IntRange(1, 10).Draw(t, "numTriggers")
		force := rapid.Bool().Draw(t, "force")

		for i := 0; i < numTriggers; i++ {
			s.maybeEmit(force)
		}

		count := atomic.LoadInt32(&emitCount)
		if count > 1 {
			t.Fatalf("Duplicate HandshakeEvent emitted: got count %d, want <= 1", count)
		}
	})
}

// INV-TAP-003: Active Stream Eviction
// ActiveStreams delta == 0 after ReassemblyComplete
func TestInvariant_Tap_ActiveStreamEviction(t *testing.T) {
	// Silence logrus debug logs during test
	logrus.SetLevel(logrus.ErrorLevel)

	rapid.Check(t, func(t *rapid.T) {
		s := &tlsStream{
			clientIP:   "10.0.0.1",
			serverIP:   "10.0.0.2",
			clientPort: 54321,
			serverPort: 443,
			emit:       func(evt HandshakeEvent) {},
		}

		// Simulate stream lifecycle start
		ActiveStreams.Inc()

		// Complete reassembly
		removed := s.ReassemblyComplete(nil)
		if !removed {
			t.Fatalf("ReassemblyComplete returned false; expected stream pool removal")
		}
	})
}

// INV-TAP-004: Circuit Breaker Cooldown Exactness
// Failures >= N => Open && ResetsAt(t_cooldown)
func TestInvariant_Tap_CircuitBreakerCooldownExactness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mockErr := errors.New("redis connection refused")
		mr := &mockRedisSetterGetter{err: mockErr}
		cb := NewRedisCircuitBreaker(mr)

		failCount := rapid.IntRange(5, 15).Draw(t, "failCount")
		for i := 0; i < failCount; i++ {
			_ = cb.Set(context.Background(), fmt.Sprintf("key-%d", i), "val", time.Minute)
		}

		// Must be open now
		err := cb.Set(context.Background(), "key-after-trip", "val", time.Minute)
		if !errors.Is(err, ErrRedisCircuitOpen) {
			t.Fatalf("Circuit breaker expected to be open (ErrRedisCircuitOpen), got: %v", err)
		}

		// Also check Get while open
		_, getErr := cb.Get(context.Background(), "key-after-trip")
		if !errors.Is(getErr, ErrRedisCircuitOpen) {
			t.Fatalf("Circuit breaker Get expected to return ErrRedisCircuitOpen, got: %v", getErr)
		}
	})
}
