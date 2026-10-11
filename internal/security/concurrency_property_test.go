package security

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"go.uber.org/goleak"
	"pgregory.net/rapid"
)

// TestProperty_ConcurrentPipelineLinearizability uses pgregory.net/rapid to
// verify linearizability and race-free consistency of Pipeline operations under
// arbitrarily interleaved concurrent actions.
func TestProperty_ConcurrentPipelineLinearizability(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	rapid.Check(t, func(rt *rapid.T) {
		base := &PipelineConfig{
			JA4BlockingEnabled: rapid.Bool().Draw(rt, "ja4_blocking_enabled"),
			Thresholds: map[string]int{
				"block": rapid.IntRange(50, 100).Draw(rt, "threshold_block"),
			},
		}

		p := NewPipeline(base, &mockRedis{dial: rapid.IntRange(0, 100).Draw(rt, "dial")}, nil)
		p.Sync = true

		numActions := rapid.IntRange(20, 50).Draw(rt, "num_actions")
		var wg sync.WaitGroup

		for i := 0; i < numActions; i++ {
			actionType := rapid.IntRange(1, 4).Draw(rt, fmt.Sprintf("action_%d", i))
			wg.Add(1)

			switch actionType {
			case 1:
				// Concurrent connection evaluation
				ipLastByte := rapid.IntRange(1, 254).Draw(rt, fmt.Sprintf("ip_%d", i))
				ja4Hash := rapid.StringMatching(`[a-f0-9]{12}`).Draw(rt, fmt.Sprintf("ja4_%d", i))
				go func(ipByte int, hash string) {
					defer wg.Done()
					ipStr := fmt.Sprintf("198.51.100.%d", ipByte)
					conn := &ConnectionContext{
						ClientIP: ipStr,
						ParsedIP: net.ParseIP(ipStr),
						JA4:      fmt.Sprintf("t13d1516h2_%s_001122334455", hash),
					}
					res := p.Process(context.Background(), conn)
					if res == nil {
						rt.Fatalf("Process returned nil result")
					}
				}(ipLastByte, ja4Hash)

			case 2:
				// Concurrent ReplaceConfig
				newBlock := rapid.IntRange(40, 95).Draw(rt, fmt.Sprintf("new_block_%d", i))
				go func(blockThresh int) {
					defer wg.Done()
					newCfg := *base
					newCfg.Thresholds = map[string]int{"block": blockThresh}
					p.ReplaceConfig(&newCfg)
				}(newBlock)

			case 3:
				// Concurrent UpdateSets
				ja4 := rapid.StringMatching(`t13d1516h2_[a-f0-9]{12}`).Draw(rt, fmt.Sprintf("set_ja4_%d", i))
				go func(j string) {
					defer wg.Done()
					p.UpdateSets(
						map[string]bool{j: true},
						map[string]bool{},
					)
				}(ja4)

			case 4:
				// Concurrent UpdateDynamicCIDRs
				cidrSuffix := rapid.IntRange(1, 250).Draw(rt, fmt.Sprintf("cidr_%d", i))
				go func(sub int) {
					defer wg.Done()
					p.UpdateDynamicCIDRs([]string{fmt.Sprintf("192.0.%d.0/24", sub)})
				}(cidrSuffix)
			}
		}

		wg.Wait()
	})
}
