package tap

import (
	"fmt"
	"net"
	"os"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// checkInterfaceUp verifies iface exists and is administratively up before
// capture starts (F-015). NewTPacket's own error handling covers the
// nonexistent/no-CAP_NET_RAW cases, but an interface that exists yet is
// administratively down (e.g. a misconfigured span port) fails silently
// otherwise -- capture opens fine, no error is ever returned, and no
// packets ever arrive.
func checkInterfaceUp(iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %q exists but is administratively down", iface)
	}
	return nil
}

// OpenPcapFile opens a classic .pcap file for offline replay (PHASE_316a §3
// --pcap-file mode). It is pure-Go (pcapgo) — no libpcap, no cgo, no raw-socket
// privileges — so it powers both CI fixtures and local development. The returned
// source, link type, and close function feed straight into NewSensor/Run.
func OpenPcapFile(path string) (src PacketSource, linkType layers.LinkType, closeFn func() error, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, 0, nil, err
	}
	return r, r.LinkType(), f.Close, nil
}
