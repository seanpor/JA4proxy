// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package bench

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

type BenchResult struct {
	TotalGood      int           `json:"total_good"`
	GoodAllowed    int           `json:"good_allowed"`
	GoodBlocked    int           `json:"good_blocked"`
	TotalBad       int           `json:"total_bad"`
	BadAllowed     int           `json:"bad_allowed"`
	BadBlocked     int           `json:"bad_blocked"`
	TotalLatency   time.Duration `json:"-"`
	Latencies      []time.Duration `json:"-"`
	Errors         int           `json:"errors"`
	LastError      string        `json:"last_error,omitempty"`
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	Duration       time.Duration `json:"duration_total"`
	ThroughputCPS  float64       `json:"throughput_cps"`
	AvgLatencyMS   float64       `json:"avg_latency_ms"`
	P50LatencyMS   float64       `json:"p50_latency_ms"`
	P95LatencyMS   float64       `json:"p95_latency_ms"`
	P99LatencyMS   float64       `json:"p99_latency_ms"`
	mu             sync.Mutex
}

func (r *BenchResult) Record(isGood, allowed bool, latency time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.Errors++
		r.LastError = err.Error()
		return
	}
	r.TotalLatency += latency
	r.Latencies = append(r.Latencies, latency)
	if isGood {
		r.TotalGood++
		if allowed {
			r.GoodAllowed++
		} else {
			r.GoodBlocked++
		}
	} else {
		r.TotalBad++
		if allowed {
			r.BadAllowed++
		} else {
			r.BadBlocked++
		}
	}
}

func (r *BenchResult) Calculate() {
	r.Duration = r.EndTime.Sub(r.StartTime)
	total := r.TotalGood + r.TotalBad
	if r.Duration.Seconds() > 0 {
		r.ThroughputCPS = float64(total) / r.Duration.Seconds()
	}

	if total > 0 {
		r.AvgLatencyMS = float64(r.TotalLatency.Milliseconds()) / float64(total)
	}

	if len(r.Latencies) > 0 {
		sort.Slice(r.Latencies, func(i, j int) bool {
			return r.Latencies[i] < r.Latencies[j]
		})
		r.P50LatencyMS = float64(r.Latencies[len(r.Latencies)*50/100].Microseconds()) / 1000.0
		r.P95LatencyMS = float64(r.Latencies[len(r.Latencies)*95/100].Microseconds()) / 1000.0
		r.P99LatencyMS = float64(r.Latencies[len(r.Latencies)*99/100].Microseconds()) / 1000.0
	}
}

func (r *BenchResult) Print() {
	r.Calculate()
	total := r.TotalGood + r.TotalBad
	
	fmt.Printf("\n=== JA4proxy High-Speed Benchmark Results ===\n")
	fmt.Printf("Duration:          %v\n", r.Duration)
	fmt.Printf("Total Connections: %d (%.2f CPS)\n", total, r.ThroughputCPS)
	fmt.Printf("Avg Latency:       %.2fms\n", r.AvgLatencyMS)
	fmt.Printf("p50 Latency:       %.2fms\n", r.P50LatencyMS)
	fmt.Printf("p95 Latency:       %.2fms\n", r.P95LatencyMS)
	fmt.Printf("p99 Latency:       %.2fms\n", r.P99LatencyMS)
	fmt.Printf("Errors:            %d\n", r.Errors)
	if r.Errors > 0 && r.LastError != "" {
		fmt.Printf("Last Error:        %s\n", r.LastError)
	}
	fmt.Printf("--------------------------------------------\n")
	fmt.Printf("Good Traffic:      %d sent, %d allowed, %d blocked\n", r.TotalGood, r.GoodAllowed, r.GoodBlocked)
	fmt.Printf("Bad Traffic:       %d sent, %d allowed, %d blocked\n", r.TotalBad, r.BadAllowed, r.BadBlocked)
	fmt.Printf("--------------------------------------------\n")
	
	fp := 0.0
	if r.TotalGood > 0 {
		fp = float64(r.GoodBlocked) / float64(r.TotalGood) * 100
	}
	fn := 0.0
	if r.TotalBad > 0 {
		fn = float64(r.BadAllowed) / float64(r.TotalBad) * 100
	}
	
	fmt.Printf("False Positive:    %.2f%%\n", fp)
	fmt.Printf("False Negative:    %.2f%%\n", fn)
	
	if total == 0 && r.Errors > 0 {
		fmt.Printf("Status:            FAILED \u274c (No successful connections made)\n")
	} else if fp == 0 {
		fmt.Printf("Status:            PASSED \u2705\n")
	} else {
		fmt.Printf("Status:            FAILED \u274c (False positives detected)\n")
	}
	fmt.Printf("============================================\n")
}

func RunBenchmark(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	var (
		host       string
		goodRate   int
		badRate    int
		duration   int
		workers    int
		outputFormat string
	)
	fs.StringVar(&host, "host", "127.0.0.1:8081", "Target host:port")
	fs.IntVar(&goodRate, "good-rate", 100, "Good connections per second")
	fs.IntVar(&badRate, "bad-rate", 0, "Bad connections per second")
	fs.IntVar(&duration, "duration", 10, "Test duration in seconds")
	fs.IntVar(&workers, "workers", 8, "Number of concurrent workers")
	fs.StringVar(&outputFormat, "output", "text", "Output format (text|json)")
	fs.Parse(args)

	if outputFormat != "json" {
		fmt.Printf("\u25b6 Starting benchmark against %s (%ds duration)...\n", host, duration)
	}

	res := &BenchResult{StartTime: time.Now()}
	
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, testCtx := errgroup.WithContext(ctx)
	
	if duration > 0 {
		var cancel context.CancelFunc
		testCtx, cancel = context.WithTimeout(testCtx, time.Duration(duration)*time.Second)
		defer cancel()
	}

	if goodRate > 0 {
		g.Go(func() error {
			return runProfile(testCtx, host, true, goodRate, workers, res)
		})
	}

	if badRate > 0 {
		g.Go(func() error {
			return runProfile(testCtx, host, false, badRate, workers, res)
		})
	}

	if outputFormat != "json" {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-testCtx.Done():
					return
				case <-ticker.C:
					res.mu.Lock()
					total := res.TotalGood + res.TotalBad
					elapsed := time.Since(res.StartTime).Seconds()
					cps := float64(total) / elapsed
					fmt.Printf("[%ds] TPS: %.2f | Connections: %d | Errors: %d\n", int(elapsed), cps, total, res.Errors)
					res.mu.Unlock()
				}
			}
		}()
	}

	err := g.Wait()
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "Benchmark error: %v\n", err)
	}

	if ctx.Err() == context.Canceled {
		fmt.Println("\n(Interrupt received, finalizing...)")
	}

	res.EndTime = time.Now()

	if outputFormat == "json" {
		res.Calculate()
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	} else {
		res.Print()
	}
}

func runProfile(ctx context.Context, host string, isGood bool, rate, workers int, res *BenchResult) error {
	ratePerWorker := rate / workers
	if ratePerWorker == 0 { ratePerWorker = 1 }

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second / time.Duration(ratePerWorker))
			defer ticker.Stop()

			conf := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "backend",
			}
			if isGood {
				conf.NextProtos = []string{"h2", "http/1.1"}
			}

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					startDial := time.Now()
					conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2*time.Second}, "tcp", host, conf)
					dialDuration := time.Since(startDial)
					start := time.Now()
					if err != nil {
						res.Record(isGood, false, 0, err)
						continue
					}
					fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n")
					io.Copy(io.Discard, conn)
					conn.Close()
					res.Record(isGood, true, time.Since(start) + dialDuration, nil)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}
