package tap

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Proto identifies the transport protocol decoded from the frame.
type Proto int

const (
	ProtoTCP Proto = iota
	ProtoUDP
	ProtoUnsupported
)

// decodeResult holds the output of decode. The caller inspects .Proto to
// decide whether to use .TCP or .UDP. Only one transport layer is valid per call.
type decodeResult struct {
	NetFlow gopacket.Flow
	TCP     *layers.TCP
	UDP     *layers.UDP
	TTL     uint8
	Proto   Proto
}

// decoder turns a raw captured frame into a network flow and TCP/UDP layer using a
// pre-allocated gopacket.DecodingLayerParser. The layer structs are reused
// across calls, so steady-state decoding is allocation-free on the hot path
// (PHASE_316a §3 zero-copy decode). A decoder is NOT safe for concurrent use;
// each sensor owns one and decodes packets on a single goroutine.
type decoder struct {
	parser   *gopacket.DecodingLayerParser
	linkType layers.LinkType
	eth      layers.Ethernet
	ip4      layers.IPv4
	ip6      layers.IPv6
	tcp      layers.TCP
	udp      layers.UDP // NEW
	payload  gopacket.Payload
	decoded  []gopacket.LayerType
}

func newDecoder(linkType layers.LinkType) *decoder {
	d := &decoder{linkType: linkType, decoded: make([]gopacket.LayerType, 0, 6)}
	d.parser = gopacket.NewDecodingLayerParser(
		firstLayerType(linkType),
		&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.payload,
	)
	// Mirror feeds carry plenty of protocols we don't model (ARP, ICMP,
	// tunnelling). Skip them quietly instead of erroring per packet.
	d.parser.IgnoreUnsupported = true
	return d
}

// decode reports the network flow, transport layer, and IP TTL. The returned
// *layers.TCP or *layers.UDP aliases reused storage and is only valid until
// the next decode call.
func (d *decoder) decode(data []byte) decodeResult {
	_ = d.parser.DecodeLayers(data, &d.decoded)

	var res decodeResult
	res.Proto = ProtoUnsupported
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			res.NetFlow = d.ip4.NetworkFlow()
			res.TTL = d.ip4.TTL
		case layers.LayerTypeIPv6:
			res.NetFlow = d.ip6.NetworkFlow()
			res.TTL = d.ip6.HopLimit
		case layers.LayerTypeTCP:
			res.TCP = &d.tcp
			res.Proto = ProtoTCP
		case layers.LayerTypeUDP:
			res.UDP = &d.udp
			res.Proto = ProtoUDP
		}
	}
	return res
}

// firstLayerType maps a capture link type to the gopacket layer the parser
// should start from. Ethernet covers SPAN/mirror feeds; the others support
// common pcap link types so offline replay "just works".
func firstLayerType(lt layers.LinkType) gopacket.LayerType {
	switch lt {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		return layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		return layers.LayerTypeIPv6
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		return layers.LayerTypeLoopback
	default:
		return layers.LayerTypeEthernet
	}
}
