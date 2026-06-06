// Phase 62 — Pipeline-level throughput benchmarks for the Go proxy.
//
// These benchmarks are intentionally minimal: they wire up a real
// security.Pipeline against a no-op Redis stub and measure two paths:
//
//   - BenchmarkPipeline_Allow: a request that hits the h2 ALPN bypass and
//     short-circuits before any signal collection. This is the fastest path
//     through the pipeline and represents the cost floor for legitimate
//     browser traffic.
//
//   - BenchmarkPipeline_Score: a request that misses every bypass and walks
//     the full signal-collection / scoring / decision path. This represents
//     the cost of an unknown / suspicious request.
//
// No assertion is made on the absolute ns/op number — bench numbers are
// noisy on shared CI runners. The goal is that both benches compile and
// run; phase 86 will lock in published baselines from these.
//
// Run:
//
//	GOROOT=/snap/go/current go test -bench=BenchmarkPipeline -run=^$ -benchmem ./cmd/proxy/
package main

import (
	"context"
	"net"
	"testing"

	"github.com/seanpor/ja4proxy/internal/security"
)

// benchRedis is a no-op RedisReader that returns dial=100 (full blocking).
// It exists in cmd/proxy_test rather than internal/security because the
// benches live in cmd/proxy by spec; the type is local to this package.
type benchRedis struct{}

func (benchRedis) GetDial(_ context.Context) int                             { return 100 }
func (benchRedis) SIsMember(_ context.Context, _ string, _ interface{}) bool { return false }
func (benchRedis) SlidingWindowCount(_ context.Context, _ string, _ float64, _ int) int {
	return 0
}
func (benchRedis) HGetAll(_ context.Context, _ string) map[string]string          { return nil }
func (benchRedis) GetString(_ context.Context, _ string) string                   { return "" }
func (benchRedis) SetString(_ context.Context, _ string, _ string, _ int)         {}
func (benchRedis) Exists(_ context.Context, _ string) bool                        { return false }
func (benchRedis) Ping(_ context.Context) error                                   { return nil }
func (benchRedis) ZAdd(_ context.Context, _ string, _ float64, _ string)          {}
func (benchRedis) ZRemRangeByScore(_ context.Context, _ string, _, _ float64)     {}
func (benchRedis) ZRange(_ context.Context, _ string, _, _ int64) []string        { return nil }
func (benchRedis) ZCard(_ context.Context, _ string) int64                        { return 0 }
func (benchRedis) ZRangeScores(_ context.Context, _ string, _, _ int64) []float64 { return nil }

func newBenchPipeline(_ testing.TB) *security.Pipeline {
	cfg := &security.PipelineConfig{
		ALPNBrowserBypass:  true,
		JA4WhitelistBypass: true,
		JA4BlockingEnabled: true,
		MTLSBypass:         true,
		Whitelist:          map[string]bool{},
		Blacklist:          map[string]bool{},
	}
	return security.NewPipeline(cfg, benchRedis{}, nil)
}

func benchH2Connection() *security.ConnectionContext {
	return &security.ConnectionContext{
		ParsedIP: net.ParseIP("198.51.100.10"),
		ClientIP: "198.51.100.10",
		JA4:      "t13d1516h2_8daaf6152771_02713d6af862",
		ALPN:     "h2",
	}
}

func benchSuspiciousConnection() *security.ConnectionContext {
	return &security.ConnectionContext{
		ParsedIP: net.ParseIP("192.0.2.55"),
		ClientIP: "192.0.2.55",
		JA4:      "t13d000000_aaaaaaaaaaaa_bbbbbbbbbbbb",
	}
}

// BenchmarkPipeline_Allow measures the fast h2 ALPN bypass path. This is
// the hot loop for legitimate browser traffic and should report the lowest
// ns/op of the two benches.
func BenchmarkPipeline_Allow(b *testing.B) {
	p := newBenchPipeline(b)
	conn := benchH2Connection()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Process(ctx, conn)
	}
}

// BenchmarkPipeline_Score measures the full signal-collection and scoring
// path for a connection that misses every bypass. This is the cost ceiling
// for unknown traffic.
func BenchmarkPipeline_Score(b *testing.B) {
	p := newBenchPipeline(b)
	conn := benchSuspiciousConnection()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Process(ctx, conn)
	}
}

func (benchRedis) MultiCheck(_ context.Context, _ string) (int, bool, bool) { return 0, false, false }
