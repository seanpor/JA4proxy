package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Result struct {
	TotalConns    int
	SuccessConns  int
	FailedConns   int
	TotalLatency  time.Duration
	StartTime     time.Time
	EndTime       time.Time
	mu            sync.Mutex
}

func (r *Result) RecordSuccess(latency time.Duration) {
	r.mu.Lock()
	r.SuccessConns++
	r.TotalLatency += latency
	r.mu.Unlock()
}

func (r *Result) RecordFailure() {
	r.mu.Lock()
	r.FailedConns++
	r.mu.Unlock()
}

func (r *Result) CPS() float64 {
	duration := r.EndTime.Sub(r.StartTime).Seconds()
	if duration == 0 {
		return 0
	}
	return float64(r.SuccessConns) / duration
}

func (r *Result) AvgLatency() time.Duration {
	if r.SuccessConns == 0 {
		return 0
	}
	return r.TotalLatency / time.Duration(r.SuccessConns)
}

func (r *Result) Print() {
	fmt.Printf("=== Benchmark Results ===\n")
	fmt.Printf("Total Connections:    %d\n", r.TotalConns)
	fmt.Printf("Successful:           %d\n", r.SuccessConns)
	fmt.Printf("Failed:               %d\n", r.FailedConns)
	fmt.Printf("CPS:                  %.2f\n", r.CPS())
	fmt.Printf("Avg Latency:          %v\n", r.AvgLatency())
	fmt.Printf("Duration:             %v\n", r.EndTime.Sub(r.StartTime))
}

func main() {
	var (
		host        string
		connections int
		rate        int
		dialMode    string
		workers     int
	)
	flag.StringVar(&host, "host", "127.0.0.1:8443", "Target host:port")
	flag.IntVar(&connections, "conns", 1000, "Total connections")
	flag.IntVar(&rate, "rate", 100, "Target connections per second")
	flag.StringVar(&dialMode, "dial", "monitor", "dial|monitor|block")
	flag.IntVar(&workers, "workers", 1, "Number of workers")
	flag.IntVar(&workers, "w", "1", "Number of workers")
	flag.Parse()

	result := &Result{
		TotalConns: connections,
		StartTime:  time.Now(),
	}

	ctx, cancel := errgroup.WithContext(context.Background())

	// Load fixtures
	fixtures := loadFixtures()

	// Calculate connections per worker
	connsPerWorker := connections / workers
	if connsPerWorker == 0 {
		connsPerWorker = 1
	}

	// Rate limiter per worker
	ratePerWorker := rate / workers
	if ratePerWorker == 0 {
		ratePerWorker = 1
	}
	ticker := time.NewTicker(time.Second / time.Duration(ratePerWorker))
	defer ticker.Stop()

	// Launch workers
	for i := 0; i < workers; i++ {
		i := i
		ctx.Go(func() error {
			return runWorker(ctx, host, connsPerWorker, dialMode, fixtures, ticker.C, result)
		})
	}

	// Wait for completion
	if err := ctx.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "worker error: %v\n", err)
	}

	result.EndTime = time.Now()
	result.Print()
}

func loadFixtures() [][]byte {
	// For now, return a simple TLS 1.3 ClientHello
	// In production, load from cmd/ja4bench/fixtures/*.bin
	return [][]byte{
		// Minimal TLS 1.3 ClientHello
		{0x16, 0x03, 0x01, 0x00, 0x5c, 0x01, 0x00, 0x00, 0x58, 0x03, 0x03,
			0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
			0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
			0xde, 0xf0, 0x12, 0x34, 0x00, 0x20, 0xcc, 0xa8, 0x13, 0x01, 0x13,
			0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xc0, 0x2c,
			0xc0, 0x30, 0x00, 0x9d, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x6b, 0x00,
			0x6a, 0x00, 0x39, 0x00, 0x38, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9c,
			0xc0, 0x09, 0xc0, 0x13, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01,
			0x00, 0x00, 0x4a, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x0d,
			0x00, 0x1a, 0x00, 0x18, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
			0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x08, 0x09, 0x08, 0x0a,
			0x08, 0x0b, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04,
			0x03, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x03, 0x00, 0x17, 0x00,
			0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00,
			0x0a, 0x03, 0x04, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x23, 0x00,
			0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08,
			0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00,
			0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x18, 0x00,
			0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
			0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08,
			0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02,
			0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x03},
	}
}

func getTLSConfig() *tls.Config {
	rootCAs := x509.NewCertPool()
	return &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

func runWorker(ctx context.Context, host string, conns int, mode string, fixtures [][]byte, ticker <-chan time.Time, result *Result) error {
	conn := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker:
			if conn >= conns {
				return nil
			}

			conn++
			fixture := fixtures[conn%len(fixtures)]

			start := time.Now()
			err := connectAndSend(host, fixture, mode)
			latency := time.Since(start)

			if err != nil {
				result.RecordFailure()
				if conn <= 5 || conn%100 == 0 {
					log.Printf("worker conn %d failed: %v", conn, err)
				}
			} else {
				result.RecordSuccess(latency)
			}
		}
	}
}

func connectAndSend(host string, fixture []byte, mode string) error {
	conn, err := tls.Dial("tcp", host, getTLSConfig())
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	// Send ClientHello
	_, err = conn.Write(fixture)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	// Read response (at least ServerHello)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	if n < 5 {
		return fmt.Errorf("response too short: %d bytes", n)
	}

	// Basic validation: check for TLS record type 0x16 (Handshake)
	if buf[0] != 0x16 {
		return fmt.Errorf("unexpected record type: 0x%02x", buf[0])
	}

	return nil
}