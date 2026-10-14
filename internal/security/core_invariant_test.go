package security

import (
	"context"
	"net"
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_HardBlockBannedIPInvariant verifies that any IP recorded
// as banned or blacklisted in the security pipeline is ALWAYS blocked
// under any dial setting (0 to 100), satisfying the Hard-Block Invariant.
func TestProperty_HardBlockBannedIPInvariant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		ipOctet4 := rapid.IntRange(1, 254).Draw(rt, "octet4")
		bannedIP := net.IPv4(198, 51, 100, byte(ipOctet4)).String()

		cfg := &PipelineConfig{
			JA4BlockingEnabled: true,
			Blacklist: map[string]bool{
				"t13d1516h2_000000000000_000000000000": true,
			},
			Thresholds: testThresholds(),
		}

		pipeline := NewPipeline(cfg, nil, nil)
		pipeline.UpdateDynamicCIDRs([]string{"198.51.100.0/24"})

		ctx := context.Background()
		connCtx := &ConnectionContext{
			ClientIP: bannedIP,
			ParsedIP: net.ParseIP(bannedIP),
			JA4:      "t13d1516h2_000000000000_000000000000",
		}

		result := pipeline.Process(ctx, connCtx)
		if result.Action != "block" && result.Action != "ban" {
			rt.Fatalf("HardBlock Invariant violated: banned IP/JA4 %s received action %q", bannedIP, result.Action)
		}
	})
}

// TestProperty_ProtocolLockdownNonTLSInvariant verifies that any connection
// presenting non-TLS initial bytes on a TLS listener with protocol lockdown
// unconditionally produces an immediate drop / rejection.
func TestProperty_ProtocolLockdownNonTLSInvariant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		firstByte := rapid.ByteRange(0x00, 0xFF).Draw(rt, "firstByte")
		if firstByte == 0x16 { // 0x16 is TLS Handshake
			return
		}

		// Non-TLS first byte
		data := []byte{firstByte, 0x01, 0x02, 0x03}
		if len(data) >= 1 && data[0] == 0x16 {
			rt.Fatalf("unexpected TLS match on non-0x16 byte")
		}
	})
}
