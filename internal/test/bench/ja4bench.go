// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package bench

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Result struct {
	TotalConns   int
	SuccessConns int
	FailedConns  int
	TotalLatency time.Duration
	StartTime    time.Time
	EndTime      time.Time
	mu           sync.Mutex
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

func RunBenchmark(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	var (
		host        string
		connections int
		rate        int
		dialMode    string
		workers     int
	)
	fs.StringVar(&host, "host", "127.0.0.1:8443", "Target host:port")
	fs.IntVar(&connections, "conns", 1000, "Total connections")
	fs.IntVar(&rate, "rate", 100, "Target connections per second")
	fs.StringVar(&dialMode, "dial", "monitor", "dial|monitor|block")
	fs.IntVar(&workers, "workers", 4, "Number of workers")
	fs.Parse(args)

	result := &Result{
		TotalConns: connections,
		StartTime:  time.Now(),
	}

	g, ctx := errgroup.WithContext(context.Background())

	connsPerWorker := connections / workers
	if connsPerWorker == 0 {
		connsPerWorker = 1
	}

	ratePerWorker := rate / workers
	if ratePerWorker == 0 {
		ratePerWorker = 1
	}

	for i := 0; i < workers; i++ {
		g.Go(func() error {
			return runWorker(ctx, host, connsPerWorker, ratePerWorker, result)
		})
	}

	if err := g.Wait(); err != nil {
		fmt.Printf("Benchmark failed: %v\n", err)
	}

	result.EndTime = time.Now()
	result.Print()
}

func runWorker(ctx context.Context, host string, count, rate int, res *Result) error {
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			start := time.Now()
			conn, err := tls.Dial("tcp", host, conf)
			if err != nil {
				res.RecordFailure()
				continue
			}
			conn.Close()
			res.RecordSuccess(time.Since(start))
		}
	}
	return nil
}
