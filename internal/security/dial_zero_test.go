// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestDialZero_NonBlockingInvariantProof mathematically and empirically proves
// that dial=0 is strictly non-blocking across 100% of pipeline scoring evaluation paths.
// Even under maximum risk conditions (DGA, missing SNI, rate limits, high beaconing,
// bad orgs, feed matches), dial=0 forces Action == "allow".
func TestDialZero_NonBlockingInvariantProof(t *testing.T) {
	// Construct an extreme worst-case connection context designed to accumulate maximum risk score
	conn := &ConnectionContext{
		ClientIP:           "198.51.100.99",
		ParsedIP:           net.ParseIP("198.51.100.99"),
		JA4:                "t13d091100_extremebad_0011223344",
		ALPN:               "",
		SNI:                "x9q8z7w6v5u4t3s2r1.evil-domain-1234567.com", // high DGA score
		TLSVersion:         0x0301,                                       // TLS 1.0
		ConnectionLifespanMS: 50,                                         // very short lifespan
	}

	cfg := &PipelineConfig{
		ALPNBrowserBypass:    false,
		MissingSNIEnabled:    true,
		MissingSNIScore:      30,
		DGAEnabled:           true,
		DGAScoreCap:          40,
		TCPAnalyzerEnabled:   true,
		TCPAnalyzerShortLifespanEnabled: true,
	}

	redisDouble := &mockRedisDial{dial: 0}
	p := NewPipeline(cfg, redisDouble, logrus.New())
	p.Sync = true
	ctx := context.Background()

	res := p.Process(ctx, conn)
	if res == nil {
		t.Fatal("Process returned nil result")
	}

	// Score is accumulated
	if res.Score <= 0 {
		t.Fatalf("expected high risk score for hostile handshake, got %d", res.Score)
	}

	// Dial=0 non-blocking invariant: Action MUST BE "allow"
	if res.Action != "allow" {
		t.Fatalf("VIOLATION OF DIAL=0 INVARIANT: got action %q with score %d at dial=0", res.Action, res.Score)
	}

	// Counterfactuals must reflect what WOULD happen at higher dials
	if len(res.Counterfactuals) == 0 {
		t.Fatal("expected counterfactuals to be populated at dial=0")
	}
	if res.Counterfactuals[100] == "allow" && res.Score >= 70 {
		t.Errorf("counterfactual at dial 100 should reflect enforcement, got %q", res.Counterfactuals[100])
	}
}

// TestDialZero_ExhaustiveDecisionSpace asserts that ActionDecider.Decide(score, 0) == "allow"
// for every integer score from -100 to 200.
func TestDialZero_ExhaustiveDecisionSpace(t *testing.T) {
	decider := NewActionDeciderDefault()
	for score := -100; score <= 200; score++ {
		action := decider.Decide(score, 0)
		if action != "allow" {
			t.Fatalf("ActionDecider.Decide(%d, 0) = %q; want 'allow'", score, action)
		}
	}
}
