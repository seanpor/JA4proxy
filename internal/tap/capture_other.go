//go:build !linux

package tap

import (
	"errors"

	"github.com/gopacket/gopacket/layers"
)

// NewLiveSource is unavailable off Linux — AF_PACKET is a Linux facility, and
// the sensor ships Linux-only. Offline pcap replay (OpenPcapFile) still works
// everywhere for development and tests.
func NewLiveSource(iface string, frameSize int) (PacketSource, layers.LinkType, func(), error) {
	return nil, 0, nil, errors.New("tap: live AF_PACKET capture is only supported on Linux")
}
