//go:build !linux

package tap

import (
	"errors"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// NewLiveSource is unavailable off Linux — AF_PACKET is a Linux facility, and
// the sensor ships Linux-only. Offline pcap replay (OpenPcapFile) still works
// everywhere for development and tests. The bpfFilter parameter is accepted
// but (on non-Linux) never applied.
func NewLiveSource(iface string, frameSize int, bpfFilter []bpf.RawInstruction) (PacketSource, layers.LinkType, func(), error) {
	return nil, 0, nil, errors.New("tap: live AF_PACKET capture is only supported on Linux")
}
