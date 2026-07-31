//go:build linux

package tap

import (
	"errors"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// tpacketSource wraps *afpacket.TPacket to translate its poll-timeout
// sentinel (afpacket.ErrTimeout) into the platform-independent
// tap.ErrPollTimeout. sensor.go's Run loop must stay buildable on every
// platform (capture_other.go has no afpacket import at all), so it cannot
// check for afpacket.ErrTimeout directly -- this is the one place that
// translation happens (F-014).
type tpacketSource struct {
	tp *afpacket.TPacket
}

func (t *tpacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := t.tp.ReadPacketData()
	if errors.Is(err, afpacket.ErrTimeout) {
		return data, ci, ErrPollTimeout
	}
	return data, ci, err
}

// RingBufferStats implements the optional statsSource interface (R-011):
// packets/drops as reported by the kernel's AF_PACKET socket statistics.
// The TPACKETv3 counters are used when available (SocketStatsV3), falling
// back to the TPACKETv2 counters otherwise. ok=false only on a genuine
// syscall error reading the stats, not on zero traffic.
func (t *tpacketSource) RingBufferStats() (packets, drops uint64, ok bool) {
	ss, ssv3, err := t.tp.SocketStats()
	if err != nil {
		return 0, 0, false
	}
	if p := ssv3.Packets(); p > 0 {
		return uint64(p), uint64(ssv3.Drops()), true
	}
	return uint64(ss.Packets()), uint64(ss.Drops()), true
}

// NewLiveSource opens an AF_PACKET (TPACKETv3) capture handle on iface in
// promiscuous mode, optionally applying a kernel BPF filter (compiled from
// bpfFilter) to discard non-TLS traffic before every userspace read.
//
// When bpfFilter is empty the sensor relies on userspace filtering in
// ProcessPacket instead.  Privilege dropping and seccomp are handled by the
// caller (DropCapabilities / LoadSeccomp).
func NewLiveSource(iface string, frameSize int, bpfFilter []bpf.RawInstruction) (src PacketSource, linkType layers.LinkType, closeFn func(), err error) {
	if err := checkInterfaceUp(iface); err != nil {
		return nil, 0, nil, err
	}
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
	return &tpacketSource{tp: tp}, layers.LinkTypeEthernet, tp.Close, nil
}
