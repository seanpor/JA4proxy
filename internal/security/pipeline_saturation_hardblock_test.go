package security

// Regression test for JA4PROXY-2026-0094 (MEDIUM) — hard blocks bypassed
// under scoring-queue saturation.
//
// Process() ran the manual-ban and blocklist hard-block checks only inside
// processInternal — the async path, reached via the workChan select. When
// workChan is full, the select falls through to `default` and Process
// returned "allow" without processInternal (and these two checks) ever
// running, so a banned or Spamhaus-listed IP was forwarded to the backend
// while the scoring queue was saturated.
//
// The fix moved both checks into Process(), synchronously, before the async
// enqueue. This test fills workChan to force the saturation path and asserts
// both hard blocks still fire; a third case asserts ordinary (non-hard-block)
// traffic still gets "allow" under the same saturation — the fail-open
// behaviour for *scoring* must be unchanged.

import (
	"context"
	"net"
	"testing"
)

// fillWorkChan pushes cap(p.workChan) placeholder connections onto the
// unexported channel so the next Process() call hits the saturated `default`
// branch. The test lives in package security, so the unexported field is
// reachable directly.
func fillWorkChan(p *Pipeline) {
	for i := 0; i < cap(p.workChan); i++ {
		p.workChan <- &ConnectionContext{}
	}
}

func TestPipeline_ManualBanEnforcedUnderSaturation(t *testing.T) {
	p := newTestPipeline(0) // monitor dial
	p.Sync = false          // newTestPipeline defaults to Sync=true; force the async path
	p.redis = &banRedis{banned: map[string]string{"ban:9.9.9.9": "operator ban: abuse"}}
	fillWorkChan(p)

	res := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "9.9.9.9", ParsedIP: net.ParseIP("9.9.9.9"),
	})
	if res.Action != "block" {
		t.Fatalf("manual ban under saturation: action = %q, want block", res.Action)
	}
	if res.BypassReason != "manual_ban" {
		t.Fatalf("manual ban under saturation: reason = %q, want manual_ban", res.BypassReason)
	}
}

func TestPipeline_BlocklistEnforcedUnderSaturation(t *testing.T) {
	feedPath := writeTempBlocklist(t, "1.2.3.0/24\n")
	cfg := &PipelineConfig{
		BlocklistFeeds: []BlocklistFeedConfig{{
			Name:     "spamhaus_test",
			Enabled:  true,
			Path:     feedPath,
			IsBypass: true,
			Action:   "block",
		}},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil) // Sync left false — async mode
	fillWorkChan(p)

	res := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "1.2.3.4", ParsedIP: net.ParseIP("1.2.3.4"),
	})
	if res.Action != "block" {
		t.Fatalf("blocklist under saturation: action = %q, want block", res.Action)
	}
	if res.BypassReason != "blocklist" {
		t.Fatalf("blocklist under saturation: reason = %q, want blocklist", res.BypassReason)
	}
}

// Non-hard-block traffic must still return "allow" when the queue is
// saturated — the fail-open behaviour for scoring is intentional and must
// not regress while fixing 0094.
func TestPipeline_NonHardBlockStillAllowsUnderSaturation(t *testing.T) {
	p := newTestPipeline(0)
	p.Sync = false // force the async path
	fillWorkChan(p)

	res := p.Process(context.Background(), &ConnectionContext{
		ClientIP: "5.6.7.8", ParsedIP: net.ParseIP("5.6.7.8"),
	})
	if res.Action != "allow" {
		t.Fatalf("non-hard-block traffic under saturation: action = %q, want allow (fail-open for scoring)", res.Action)
	}
}
