// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// faultyDependencyRedis simulates Redis outages, corrupt payloads, and timeouts.
type faultyDependencyRedis struct {
	mockRedis
	corruptPayload bool
	timeout        bool
}

func (f *faultyDependencyRedis) GetString(ctx context.Context, key string) string {
	if f.timeout {
		return ""
	}
	if f.corruptPayload {
		if key == "ban:198.51.100.77" {
			return "" // No operator ban
		}
		return "{not-valid-json:@@@"
	}
	return ""
}

func (f *faultyDependencyRedis) HGetAll(ctx context.Context, key string) map[string]string {
	if f.corruptPayload {
		return map[string]string{"total": "not-an-int", "resumed": "corrupted"}
	}
	return nil
}

// TestFailOpen_ExternalDependencyDegradation verifies that when external dependencies
// (DNS enrichment, AbuseIPDB, RDAP, Redis) return errors, timeout, or return corrupt payloads,
// the pipeline ALWAYS fails open to ALLOW and never causes an accidental BLOCK or panic.
func TestFailOpen_ExternalDependencyDegradation(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()

	scenarios := []struct {
		name           string
		corruptPayload bool
		timeout        bool
	}{
		{"redis_timeout_and_empty", false, true},
		{"corrupt_redis_json_payloads", true, false},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			redisDouble := &faultyDependencyRedis{
				corruptPayload: sc.corruptPayload,
				timeout:        sc.timeout,
			}

			cfg := &PipelineConfig{
				ALPNBrowserBypass:            false, // Test with bypass disabled to execute full scoring
				JA4BlockingEnabled:           true,
				BeaconingEnabled:             true,
				DNSEnrichmentEnabled:         true,
				AbuseIPDBEnabled:             true,
				RDAPEnabled:                  true,
				TCPAnalyzerEnabled:           true,
				TCPAnalyzerSessionResumptionEnabled: true,
				TCPAnalyzerConcurrencyEnabled: true,
				TCPAnalyzerReturnVisitorEnabled: true,
			}

			p := NewPipeline(cfg, redisDouble, log)
			p.Sync = true // Synchronous execution to evaluate full pipeline stack

			conn := &ConnectionContext{
				ClientIP: "198.51.100.77",
				ParsedIP: net.ParseIP("198.51.100.77"),
				JA4:      "t13d1516h2_8daaf6152771_b0da82dd1658",
				ALPN:     "h2",
				SNI:      "example.com",
			}

			res := p.Process(ctx, conn)
			if res == nil {
				t.Fatal("Process returned nil result")
			}

			// Invariant: Subsystem degradation must never fail-closed into BLOCK
			if res.Action == "block" || res.Action == "ban" {
				t.Fatalf("dependency degradation failed closed into %q! Score=%d", res.Action, res.Score)
			}
			if res.Action != "allow" {
				t.Fatalf("expected fail-open action 'allow', got %q", res.Action)
			}
		})
	}
}

// TestFailOpen_TelemetrySidecarBackpressureInvariant verifies that slow or stalled
// telemetry sinks (LogTide / UDS / stdout / OnScored callback panics or delays)
// never block or fail-closed the security evaluation path.
func TestFailOpen_TelemetrySidecarBackpressureInvariant(t *testing.T) {
	cfg := &PipelineConfig{
		JA4BlockingEnabled: true,
	}
	p := NewPipeline(cfg, &mockRedis{}, logrus.New())

	// Stalled / slow telemetry receiver (e.g. LogTide sidecar backpressure)
	telemetryInvoked := false
	p.OnScored = func(conn *ConnectionContext, result *PipelineResult) {
		telemetryInvoked = true
		// Simulate heavy backpressure stall or slow consumer
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	p.StartBackgroundWorkers(ctx)

	start := time.Now()
	// Process connection on async path
	conn := &ConnectionContext{
		ClientIP: "198.51.100.88",
		ParsedIP: net.ParseIP("198.51.100.88"),
		JA4:      "t13d1516h2_test_1234",
	}

	res := p.Process(ctx, conn)
	elapsed := time.Since(start)

	// Process must return IMMEDIATELY (sub-millisecond) without waiting on the telemetry callback
	if elapsed > 5*time.Millisecond {
		t.Fatalf("Process blocked on telemetry callback: took %v", elapsed)
	}
	if res.Action != "allow" {
		t.Fatalf("expected immediate allow on async path, got %q", res.Action)
	}

	// Give worker a moment to execute
	time.Sleep(50 * time.Millisecond)
	if !telemetryInvoked {
		t.Fatal("telemetry callback was never invoked")
	}
}
