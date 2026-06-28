//go:build linux

package tap

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// NewLiveSource opens an AF_PACKET (TPACKETv3) capture handle on iface in
// promiscuous mode, optionally applying a kernel BPF filter (compiled from
// bpfFilter) to discard non-TLS traffic before every userspace read.
//
// When bpfFilter is empty the sensor relies on userspace filtering in
// ProcessPacket instead.  Privilege dropping and seccomp are handled by the
// caller (DropCapabilities / LoadSeccomp).
func NewLiveSource(iface string, frameSize int, bpfFilter []bpf.RawInstruction) (src PacketSource, linkType layers.LinkType, closeFn func(), err error) {
	opts := []any{afpacket.OptInterface(iface), afpacket.OptPollTimeout(100 * time.Millisecond)}
	if frameSize > 0 {
		opts = append(opts, afpacket.OptFrameSize(frameSize))
	}
	tp, err := afpacket.NewTPacket(opts...)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(bpfFilter) > 0 {
		if err := tp.SetBPF(bpfFilter); err != nil {
			tp.Close()
			return nil, 0, nil, fmt.Errorf("set BPF filter: %w", err)
		}
	}
	return tp, layers.LinkTypeEthernet, tp.Close, nil
}
