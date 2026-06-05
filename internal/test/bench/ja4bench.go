// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package bench

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type BenchResult struct {
	TotalGood      int
	GoodAllowed    int
	GoodBlocked    int
	TotalBad       int
	BadAllowed     int
	BadBlocked     int
	TotalLatency   time.Duration
	Errors         int
	LastError      error
	StartTime      time.Time
	EndTime        time.Time
	mu             sync.Mutex
}

func (r *BenchResult) Record(isGood, allowed bool, latency time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.Errors++
		r.LastError = err
		return
	}
	r.TotalLatency += latency
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

func (r *BenchResult) Print() {
	duration := r.EndTime.Sub(r.StartTime)
	total := r.TotalGood + r.TotalBad
	
	cps := 0.0
	if duration.Seconds() > 0 {
		cps = float64(total) / duration.Seconds()
	}

	avgLatency := time.Duration(0)
	if total > 0 {
		avgLatency = r.TotalLatency / time.Duration(total)
	}
	
	fmt.Printf("\n=== JA4proxy High-Speed Benchmark Results ===\n")
	fmt.Printf("Duration:          %v\n", duration)
	fmt.Printf("Total Connections: %d (%.2f CPS)\n", total, cps)
	fmt.Printf("Avg Latency:       %v\n", avgLatency)
	fmt.Printf("Errors:            %d\n", r.Errors)
	if r.Errors > 0 && r.LastError != nil {
		fmt.Printf("Last Error:        %v\n", r.LastError)
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
		fmt.Printf("Status:            FAILED ❌ (No successful connections made)\n")
	} else if fp == 0 {
		fmt.Printf("Status:            PASSED ✅\n")
	} else {
		fmt.Printf("Status:            FAILED ❌ (False positives detected)\n")
	}
	fmt.Printf("============================================\n")
}

func RunBenchmark(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	var (
		host     string
		goodRate int
		badRate  int
		duration int
		workers  int
	)
	fs.StringVar(&host, "host", "127.0.0.1:8081", "Target host:port")
	fs.IntVar(&goodRate, "good-rate", 100, "Good connections per second")
	fs.IntVar(&badRate, "bad-rate", 0, "Bad connections per second")
	fs.IntVar(&duration, "duration", 10, "Test duration in seconds")
	fs.IntVar(&workers, "workers", 8, "Number of concurrent workers")
	fs.Parse(args)

	fmt.Printf("▶ Starting benchmark against %s (%ds duration)...\n", host, duration)

	res := &BenchResult{StartTime: time.Now()}
	g, ctx := errgroup.WithContext(context.Background())
	testCtx, cancel := context.WithTimeout(ctx, time.Duration(duration)*time.Second)
	defer cancel()

	// Browser Profile (Good)
	if goodRate > 0 {
		g.Go(func() error {
			return runProfile(testCtx, host, true, goodRate, workers, res)
		})
	}

	// Bot Profile (Bad)
	if badRate > 0 {
		g.Go(func() error {
			return runProfile(testCtx, host, false, badRate, workers, res)
		})
	}

	g.Wait()
	res.EndTime = time.Now()
	res.Print()
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
					start := time.Now()
					conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2*time.Second}, "tcp", host, conf)
					if err != nil {
						res.Record(isGood, false, 0, err)
						continue
					}
					// Send a dummy request
					fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n")
					io.Copy(io.Discard, conn)
					conn.Close()
					res.Record(isGood, true, time.Since(start), nil)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}
