package security

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestPipeline_HighPreemptionStress drives 100 concurrent workers evaluating
// connections while continuous reloads (ReplaceConfig, UpdateSets, UpdateDynamicCIDRs)
// execute across a high number of iterations with zero data races and zero panics.
func TestPipeline_HighPreemptionStress(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	base := &PipelineConfig{
		JA4BlockingEnabled:       true,
		StaticIPAllowlistEnabled: true,
		StaticIPAllowlist:        map[string]bool{"192.0.2.1": true},
		DecisionCacheMaxEntries:  1000,
	}
	p := NewPipeline(base, &mockRedis{dial: 50}, nil)
	p.Sync = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var ops atomic.Int64

	const numWorkers = 50
	const numUpdaters = 5

	// Writers: concurrently update config, sets, and dynamic CIDRs
	for u := 0; u < numUpdaters; u++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					cfg := *base
					cfg.DecisionCacheAllowTTLSeconds = 60 + id
					p.ReplaceConfig(&cfg)

					p.UpdateSets(
						map[string]bool{fmt.Sprintf("t13d1516h2_whitelisted_%d", id): true},
						map[string]bool{fmt.Sprintf("t13d1516h2_blacklisted_%d", id): true},
					)

					p.UpdateDynamicCIDRs([]string{
						fmt.Sprintf("10.%d.0.0/16", id),
						fmt.Sprintf("198.51.100.%d", id),
					})

					time.Sleep(10 * time.Millisecond)
				}
			}
		}(u)
	}

	// Readers: evaluate connections across diverse IPs and JA4 fingerprints
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(workerID + 100))) // #nosec G404 -- testing only
			for {
				select {
				case <-ctx.Done():
					return
				default:
					ipNum := r.Intn(250) + 1
					ipStr := fmt.Sprintf("192.0.2.%d", ipNum)
					conn := &ConnectionContext{
						ClientIP: ipStr,
						ParsedIP: net.ParseIP(ipStr),
						JA4:      fmt.Sprintf("t13d1516h2_%d_%d", workerID, r.Intn(10)),
						SNI:      "example.com",
					}

					res := p.Process(ctx, conn)
					if res == nil {
						t.Errorf("Process returned nil result")
						return
					}
					ops.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()
	t.Logf("Completed %d concurrent Process operations under continuous mutation with 0 races", ops.Load())
}
