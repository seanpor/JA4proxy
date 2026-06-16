//go:build linux

package tap

import (
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

// NewLiveSource opens an AF_PACKET (TPACKETv3) capture handle on iface in
// promiscuous mode. It is pure-Go (no cgo/libpcap) — see ADR-316a. *TPacket
// already implements PacketSource via ReadPacketData.
//
// NOTE (deferred to 316a increment 2): kernel BPF filtering and post-bind
// capability drop + seccomp are not wired here yet. Until then the sensor relies
// on userspace filtering (non-TCP frames are dropped in ProcessPacket) and the
// operator must constrain privileges externally (cap_add: NET_RAW only).
func NewLiveSource(iface string, frameSize int) (src PacketSource, linkType layers.LinkType, closeFn func(), err error) {
	opts := []any{afpacket.OptInterface(iface)}
	if frameSize > 0 {
		opts = append(opts, afpacket.OptFrameSize(frameSize))
	}
	tp, err := afpacket.NewTPacket(opts...)
	if err != nil {
		return nil, 0, nil, err
	}
	return tp, layers.LinkTypeEthernet, tp.Close, nil
}
