package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
)

// TestProxy_AdversarialCorpusViaNetPipe verifies that all binary corpus fixtures
// (from internal/tls/testdata/adversarial) fed directly into the proxy pipeline
// via net.Pipe are handled cleanly without crashes, panics, or goroutine leaks.
func TestProxy_AdversarialCorpusViaNetPipe(t *testing.T) {
	prx, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer prx.redis.Close()

	// Spin up a mock backend listener
	backendHost, backendPort, cleanupBackend := startEchoFinisher(t)
	defer cleanupBackend()
	cfg.Proxy.BackendHost = backendHost
	cfg.Proxy.BackendPort = config.FlexInt(backendPort)
	cfg.Proxy.ReadTimeout = 1
	cfg.Proxy.WriteTimeout = 1

	corpusDir := "testdata/adversarial"
	matches, err := filepath.Glob(filepath.Join(corpusDir, "*.bin"))
	if err != nil || len(matches) == 0 {
		corpusDir = "../../internal/tls/testdata/adversarial"
		matches, err = filepath.Glob(filepath.Join(corpusDir, "*.bin"))
		if err != nil || len(matches) == 0 {
			corpusDir = "internal/tls/testdata/adversarial"
			matches, err = filepath.Glob(filepath.Join(corpusDir, "*.bin"))
			if err != nil || len(matches) == 0 {
				t.Fatalf("no adversarial corpus files found")
			}
		}
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	for _, fixturePath := range matches {
		fixtureName := filepath.Base(fixturePath)
		t.Run(fixtureName, func(t *testing.T) {
			data, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", fixturePath, err)
			}

			clientConn, proxyConn := net.Pipe()
			defer clientConn.Close()

			_ = clientConn.SetDeadline(time.Now().Add(1 * time.Second))
			_ = proxyConn.SetDeadline(time.Now().Add(1 * time.Second))

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("handleConn panicked on %s: %v", fixtureName, r)
					}
				}()
				prx.handleConn(context.Background(), proxyConn)
			}()

			// Send the adversarial payload (or close if 0-length)
			go func() {
				if len(data) > 0 {
					_, _ = clientConn.Write(data)
				}
				// Close client end after sending so reading goroutines see EOF
				time.Sleep(20 * time.Millisecond)
				_ = clientConn.Close()
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("handleConn hung on fixture %s (>2s)", fixtureName)
			}
		})
	}

	// Verify no goroutine explosion after processing all fixtures
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	leaked := runtime.NumGoroutine() - baseGoroutines
	if leaked > 10 {
		t.Fatalf("goroutine leak detected after feeding adversarial corpus: %d goroutines leaked (base %d, now %d)",
			leaked, baseGoroutines, runtime.NumGoroutine())
	}
}

// TestProxy_AdversarialTrafficScenarios tests fragmented, malformed, and rapid-burst adversarial
// traffic scenarios against the proxy connection pipeline to ensure zero panics and proper containment.
func TestProxy_AdversarialTrafficScenarios(t *testing.T) {
	prx, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer prx.redis.Close()

	backendHost, backendPort, cleanupBackend := startEchoFinisher(t)
	defer cleanupBackend()
	cfg.Proxy.BackendHost = backendHost
	cfg.Proxy.BackendPort = config.FlexInt(backendPort)
	cfg.Proxy.ReadTimeout = 1

	scenarios := []struct {
		name string
		data []byte
	}{
		{"SingleByteGarbage", []byte{0xFF}},
		{"NullBytes100", make([]byte, 100)},
		{"MalformedRecordHeader", []byte{0x16, 0x03, 0x01, 0xFF, 0xFF}},
		{"TruncatedHandshakeHeader", []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01}},
		{"NonTLSPrefixSSH", []byte("SSH-2.0-OpenSSH_8.9p1\r\n")},
		{"NonTLSPrefixHTTP", []byte("GET /malicious HTTP/1.1\r\nHost: evil.com\r\n\r\n")},
		{"LargeGarbage4KB", []byte(strings.Repeat("X", 4096))},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			clientConn, proxyConn := net.Pipe()
			defer clientConn.Close()

			_ = clientConn.SetDeadline(time.Now().Add(1 * time.Second))
			_ = proxyConn.SetDeadline(time.Now().Add(1 * time.Second))

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("handleConn panicked on %s: %v", sc.name, r)
					}
				}()
				prx.handleConn(context.Background(), proxyConn)
			}()

			go func() {
				_, _ = clientConn.Write(sc.data)
				time.Sleep(20 * time.Millisecond)
				_ = clientConn.Close()
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("handleConn hung on scenario %s", sc.name)
			}
		})
	}
}

// TestProxy_ConcurrentAdversarialBursts verifies the proxy remains stable and leak-free
// under concurrent streams of adversarial connections.
func TestProxy_ConcurrentAdversarialBursts(t *testing.T) {
	prx, mr, cfg := newTestProxy(t)
	defer mr.Close()
	defer prx.redis.Close()

	backendHost, backendPort, cleanupBackend := startEchoFinisher(t)
	defer cleanupBackend()
	cfg.Proxy.BackendHost = backendHost
	cfg.Proxy.BackendPort = config.FlexInt(backendPort)
	cfg.Proxy.ReadTimeout = 1

	payloads := [][]byte{
		{},
		{0x00},
		{0x16, 0x03, 0x01, 0x00, 0x00},
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		[]byte("SSH-2.0-Test\r\n"),
		{0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1C},
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		pIdx := i % len(payloads)
		payload := payloads[pIdx]
		go func(data []byte) {
			defer wg.Done()
			clientConn, proxyConn := net.Pipe()
			defer clientConn.Close()

			_ = clientConn.SetDeadline(time.Now().Add(1 * time.Second))
			_ = proxyConn.SetDeadline(time.Now().Add(1 * time.Second))

			done := make(chan struct{})
			go func() {
				defer close(done)
				prx.handleConn(context.Background(), proxyConn)
			}()

			if len(data) > 0 {
				_, _ = clientConn.Write(data)
			}
			time.Sleep(10 * time.Millisecond)
			_ = clientConn.Close()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Errorf("concurrent handleConn timed out")
			}
		}(payload)
	}

	wg.Wait()

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	leaked := runtime.NumGoroutine() - baseGoroutines
	if leaked > 10 {
		t.Fatalf("goroutines leaked after burst: %d", leaked)
	}
}
