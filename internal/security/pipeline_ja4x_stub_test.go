// SPDX-License-Identifier: MIT

//go:build no_ja4plus

package security

import (
	"context"
	"net"
	"testing"
)

func TestPipeline_JA4XExtraction_Stub(t *testing.T) {
	cfg := &PipelineConfig{
		ALPNBrowserBypass:  false,
		JA4WhitelistBypass: false,
		JA4XEnabled:        true,
		Whitelist:          map[string]bool{},
	}
	p := NewPipeline(cfg, &mockRedis{dial: 0}, nil)
	p.Sync = true

	conn := &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4",
		ALPN:              "http/1.1",
		JA4X:              "",
		ClientCertificate: []byte{0x30, 0x82, 0x01},
	}

	p.Process(context.Background(), conn)

	expected := "000000000000_000000000000_000000000000"
	if conn.JA4X != expected {
		t.Fatalf("JA4X from cert in no_ja4plus build: got %q, want %q", conn.JA4X, expected)
	}
}
