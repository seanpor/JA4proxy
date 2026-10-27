package server

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
)

// TestTarpit_StrictConcurrencyBounds verifies JA4PROXY-2026-0013:
// Under heavy concurrent load, active tarpit slots never exceed MaxActiveConnections
// globally, and never exceed MaxPerIP per IP address.
func TestTarpit_StrictConcurrencyBounds(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	const maxGlobal = 10
	const maxPerIP = 3

	cfg := &config.Config{
		Tarpit: config.TarpitConfig{
			MaxActiveConnections: maxGlobal,
			MaxPerIP:             maxPerIP,
			OverflowAction:       "block",
		},
		Proxy: config.ProxyConfig{
			TarpitHost: "127.0.0.1",
			TarpitPort: config.FlexInt(9999),
		},
	}

	srv := &Server{
		Cfg:         cfg,
		Log:         log,
		TarpitPerIP: make(map[string]int),
	}

	var peakGlobal int64
	var totalAttempts int64
	var wg sync.WaitGroup

	const numWorkers = 50
	const iterationsPerWorker = 20

	// Simulated remote IPs
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			clientIP := ips[workerID%len(ips)]

			for i := 0; i < iterationsPerWorker; i++ {
				atomic.AddInt64(&totalAttempts, 1)

				// Create an in-memory pipe connection
				clientSide, serverSide := net.Pipe()

				go func() {
					_ = clientSide.Close()
				}()

				srv.Tarpit(serverSide, []byte("test-handshake"), clientIP)

				srv.TarpitMu.Lock()
				curGlobal := int64(srv.TarpitConcurrent)
				if curGlobal > atomic.LoadInt64(&peakGlobal) {
					atomic.StoreInt64(&peakGlobal, curGlobal)
				}
				if srv.TarpitConcurrent > maxGlobal {
					t.Errorf("TarpitConcurrent %d exceeded maxGlobal %d", srv.TarpitConcurrent, maxGlobal)
				}
				if srv.TarpitPerIP[clientIP] > maxPerIP {
					t.Errorf("TarpitPerIP[%s] %d exceeded maxPerIP %d", clientIP, srv.TarpitPerIP[clientIP], maxPerIP)
				}
				srv.TarpitMu.Unlock()
			}
		}(w)
	}

	wg.Wait()

	srv.TarpitMu.Lock()
	finalGlobal := srv.TarpitConcurrent
	srv.TarpitMu.Unlock()

	if finalGlobal != 0 {
		t.Errorf("Leaked tarpit slots: expected 0, got %d", finalGlobal)
	}
	t.Logf("Tarpit concurrency test completed: %d total attempts, peak concurrent %d <= %d cap",
		totalAttempts, peakGlobal, maxGlobal)
}

// TestAdmitConn_CapacityCeiling verifies that AdmitConn bounds active connections
// to AcceptSem capacity without blocking or leaking.
func TestAdmitConn_CapacityCeiling(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	const capacity = 16
	srv := &Server{
		Log:       log,
		AcceptSem: make(chan struct{}, capacity),
	}

	// Fill the capacity
	var conns []net.Conn
	for i := 0; i < capacity; i++ {
		c1, c2 := net.Pipe()
		conns = append(conns, c1)
		if !srv.AdmitConn(c2) {
			t.Fatalf("AdmitConn failed to admit connection within capacity (slot %d)", i)
		}
	}

	// An overflow connection must be rejected immediately without blocking
	_, overflowConn := net.Pipe()
	admitted := srv.AdmitConn(overflowConn)
	if admitted {
		t.Errorf("AdmitConn admitted connection beyond capacity %d", capacity)
	}

	// Release one slot
	<-srv.AcceptSem
	_, retryConn := net.Pipe()
	if !srv.AdmitConn(retryConn) {
		t.Errorf("AdmitConn failed to admit connection after slot was freed")
	}

	// Clean up
	for _, c := range conns {
		_ = c.Close()
	}
}

// BenchmarkServer_AdmitConn measures admission throughput under high contention.
func BenchmarkServer_AdmitConn(b *testing.B) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	srv := &Server{
		Log:       log,
		AcceptSem: make(chan struct{}, 1000),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c1, c2 := net.Pipe()
			if srv.AdmitConn(c2) {
				<-srv.AcceptSem
			}
			_ = c1.Close()
		}
	})
}
