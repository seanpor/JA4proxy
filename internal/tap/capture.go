package tap

import (
	"os"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

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
