package security

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/seanpor/ja4proxy/internal/config"
)

// TestPipeline_ReplaceConfigRaceFree_JA4PROXY_2026_0088 drives ReplaceConfig
// (the SIGHUP / pub/sub hot-reload path) concurrently with the scoring path and
// the beaconing worker. Before the fix, processInternal and beaconingWorker read
// p.cfg and the swappable signal modules without holding p.mu while ReplaceConfig
// reassigned them under the lock — a memory-unsafe data race. Run under `go test
// -race`: this test fails if the per-call snapshot (or the locked read in
// beaconingWorker) is removed.
func TestPipeline_ReplaceConfigRaceFree_JA4PROXY_2026_0088(t *testing.T) {
	base := &PipelineConfig{
		JA4BlockingEnabled: true,
		// A non-"score" datacenter policy forces processInternal to read
		// cfg.DatacenterPolicy and asnClassifier — one of the racy reads.
		DatacenterPolicy: config.DatacenterPolicyConfig{Action: "block", LogActions: false},
	}
	p := NewPipeline(base, &mockRedis{dial: 100}, nil)
	p.Sync = true

	var wg sync.WaitGroup

	// Writer: continuously hot-reload the config, swapping every module pointer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			cfg := *base
			p.ReplaceConfig(&cfg)
		}
	}()

	// Readers: score connections (drives the module snapshot + beaconing worker).
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p.Process(context.Background(), &ConnectionContext{
					ClientIP: "192.0.2.7", ParsedIP: net.ParseIP("192.0.2.7"),
					JA4: "t13d1516h2_aabbccddeeff_001122334455", SNI: "example.com",
				})
			}
		}()
	}

	wg.Wait()
}
