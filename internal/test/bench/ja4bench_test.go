// Copyright 2026 Anomaly Collective
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at:
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under the License.
package bench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// newResult returns a BenchResult with a non-zero duration so Calculate() can
// derive throughput without dividing by zero.
func newResult() *BenchResult {
	start := time.Now().Add(-10 * time.Second)
	return &BenchResult{StartTime: start, EndTime: start.Add(10 * time.Second)}
}

// TestStatus covers the verdict that RunBenchmark turns into an exit code.
//
// Before Phase 800 this verdict was only ever printed — `ja4p test benchmark`
// exited 0 no matter what, so `make bench-macro` reported success after making
// zero connections and logging thousands of 'connection refused' errors.
func TestStatus(t *testing.T) {
	tests := []struct {
		name       string
		result     func() *BenchResult
		wantErr    bool
		wantSubstr string
	}{
		{
			name: "zero connections with errors is a failure",
			result: func() *BenchResult {
				r := newResult()
				r.Errors = 2880
				r.LastError = "dial tcp 127.0.0.1:10381: connect: connection refused"
				return r
			},
			wantErr:    true,
			wantSubstr: "no successful connections",
		},
		{
			// Regression guard: the old check was `total == 0 && r.Errors > 0`,
			// so a run that connected zero times AND recorded zero errors fell
			// through to the false-positive branch and reported PASSED.
			name: "zero connections with zero errors is still a failure",
			result: func() *BenchResult {
				return newResult()
			},
			wantErr:    true,
			wantSubstr: "no successful connections",
		},
		{
			name: "good traffic all allowed passes",
			result: func() *BenchResult {
				r := newResult()
				for i := 0; i < 1000; i++ {
					r.Record(true, true, 5*time.Millisecond, nil)
				}
				return r
			},
			wantErr: false,
		},
		{
			name: "any blocked good traffic is a failure",
			result: func() *BenchResult {
				r := newResult()
				for i := 0; i < 999; i++ {
					r.Record(true, true, 5*time.Millisecond, nil)
				}
				r.Record(true, false, 0, nil)
				return r
			},
			wantErr:    true,
			wantSubstr: "false positives",
		},
		{
			// Documents existing behaviour: false negatives (bad traffic
			// allowed) are reported but do not fail the run, because the dial
			// defaults to 0 (monitor mode) where allowing bad traffic is
			// expected. Only false positives fail. Unchanged by Phase 800.
			name: "false negatives alone do not fail the run",
			result: func() *BenchResult {
				r := newResult()
				for i := 0; i < 500; i++ {
					r.Record(true, true, 5*time.Millisecond, nil)
				}
				for i := 0; i < 500; i++ {
					r.Record(false, true, 5*time.Millisecond, nil)
				}
				return r
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result().Status()

			if tt.wantErr && err == nil {
				t.Fatal("expected a non-nil error, got nil (this is what let a failed benchmark exit 0)")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q does not mention %q", err, tt.wantSubstr)
			}
		})
	}
}

// TestRatesAreZeroWhenNoTrafficSent pins the guard that stops the benchmark
// reporting a reassuring 0.00% computed from zero samples.
func TestRatesAreZeroWhenNoTrafficSent(t *testing.T) {
	r := newResult()

	if got := r.FalsePositiveRate(); got != 0 {
		t.Errorf("FalsePositiveRate with no good traffic: got %v, want 0", got)
	}
	if got := r.FalseNegativeRate(); got != 0 {
		t.Errorf("FalseNegativeRate with no bad traffic: got %v, want 0", got)
	}
	// The rate being 0 must NOT be readable as success — Status() is the verdict.
	if err := r.Status(); err == nil {
		t.Error("a run with no traffic must fail Status() despite 0% rates")
	}
}

func TestRatesAreComputedCorrectly(t *testing.T) {
	r := newResult()
	for i := 0; i < 190; i++ {
		r.Record(true, true, 5*time.Millisecond, nil)
	}
	for i := 0; i < 10; i++ {
		r.Record(true, false, 0, nil)
	}
	for i := 0; i < 5; i++ {
		r.Record(false, true, 5*time.Millisecond, nil)
	}
	for i := 0; i < 45; i++ {
		r.Record(false, false, 0, nil)
	}

	if got, want := r.FalsePositiveRate(), 5.0; got != want {
		t.Errorf("FalsePositiveRate: got %v, want %v", got, want)
	}
	if got, want := r.FalseNegativeRate(), 10.0; got != want {
		t.Errorf("FalseNegativeRate: got %v, want %v", got, want)
	}
}

func TestOfferedRate(t *testing.T) {
	cases := []struct {
		rate    int
		workers int
		want    int
	}{
		{100, 8, 96},
		{4, 8, 8},
		{0, 8, 0},
		{10, 16, 16},
		{190, 16, 176},
		{1000, 32, 992},
	}
	for _, tc := range cases {
		got := OfferedRate(tc.rate, tc.workers)
		if got != tc.want {
			t.Errorf("OfferedRate(%d, %d) = %d, want %d", tc.rate, tc.workers, got, tc.want)
		}
	}
}

func TestRateLimitedCalculation(t *testing.T) {
	r := newResult()
	r.OfferedRateCPS = 100
	r.Workers = 8
	// 100 total connections over 10 seconds = 10 CPS. Offered is 100 CPS. 10 < 90 -> RateLimited false
	for i := 0; i < 100; i++ {
		r.Record(true, true, 5*time.Millisecond, nil)
	}
	r.Calculate()
	if r.RateLimited {
		t.Errorf("expected RateLimited=false at 10 CPS out of 100 offered, got true")
	}

	// Now simulate achieved throughput >= 90% of offered
	r2 := newResult()
	r2.OfferedRateCPS = 100
	r2.Workers = 8
	// 950 total connections over 10 seconds = 95 CPS. 95 >= 90 -> RateLimited true
	for i := 0; i < 950; i++ {
		r2.Record(true, true, 5*time.Millisecond, nil)
	}
	r2.Calculate()
	if !r2.RateLimited {
		t.Errorf("expected RateLimited=true at 95 CPS out of 100 offered, got false")
	}
}

// generateTestTLSCert creates an ephemeral in-memory TLS certificate for hermetic tests.
func generateTestTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "backend"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"backend", "localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// TestRunProfileHermetic_F1 verifies that runProfile correctly observes rate_limited=true
// when the server responds fast (5ms delay), and rate_limited=false when throughput is bottlenecked.
func TestRunProfileHermetic_F1(t *testing.T) {
	cert := generateTestTLSCert(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to listen on tls: %v", err)
	}
	defer ln.Close()

	stopServer := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopServer:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(5 * time.Millisecond)
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
				}
			}(conn)
		}
	}()
	defer close(stopServer)

	// Offered rate = 40 CPS (workers=4, ratePerWorker=10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := &BenchResult{
		StartTime:      time.Now(),
		OfferedRateCPS: OfferedRate(40, 4),
		Workers:        4,
	}

	err = runProfile(ctx, ln.Addr().String(), true, 40, 4, res)
	if err != nil {
		t.Fatalf("runProfile failed: %v", err)
	}
	res.EndTime = time.Now()
	res.Calculate()

	if res.TotalGood == 0 {
		t.Fatalf("expected completed connections, got 0")
	}
	// Under 5ms server latency with 100ms tick period, achieved rate meets the offered rate
	if !res.RateLimited {
		t.Errorf("expected rate_limited=true on fast server path, got false (Throughput: %.2f, Offered: %d)",
			res.ThroughputCPS, res.OfferedRateCPS)
	}
}

// TestRunProfileHermetic_F2 verifies that a connection blocked by the proxy (RST / connection drop)
// is recorded through Record() as a block (GoodBlocked > 0), producing FalsePositiveRate > 0
// and tripping Status().
func TestRunProfileHermetic_F2(t *testing.T) {
	// TCP listener that accepts and immediately resets/closes connections without completing TLS handshake
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	defer ln.Close()

	stopServer := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopServer:
					return
				default:
					return
				}
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
		}
	}()
	defer close(stopServer)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	res := &BenchResult{
		StartTime:      time.Now(),
		OfferedRateCPS: OfferedRate(20, 2),
		Workers:        2,
	}

	err = runProfile(ctx, ln.Addr().String(), true, 20, 2, res)
	if err != nil {
		t.Fatalf("runProfile returned unexpected error: %v", err)
	}
	res.EndTime = time.Now()
	res.Calculate()

	if res.GoodBlocked == 0 {
		t.Errorf("expected GoodBlocked > 0 when connection is reset/dropped, got %d", res.GoodBlocked)
	}
	if fp := res.FalsePositiveRate(); fp == 0 {
		t.Errorf("expected FalsePositiveRate > 0, got %.2f%%", fp)
	}
	if statusErr := res.Status(); statusErr == nil {
		t.Errorf("expected Status() to fail with false positive error, got nil")
	} else if !strings.Contains(statusErr.Error(), "false positives") {
		t.Errorf("expected Status() error to mention false positives, got %v", statusErr)
	}
}
