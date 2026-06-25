package tap

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// decoder turns a raw captured frame into a network flow and TCP layer using a
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
	payload  gopacket.Payload
	decoded  []gopacket.LayerType
}

func newDecoder(linkType layers.LinkType) *decoder {
	d := &decoder{linkType: linkType, decoded: make([]gopacket.LayerType, 0, 6)}
	d.parser = gopacket.NewDecodingLayerParser(
		firstLayerType(linkType),
		&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.payload,
	)
	// Mirror feeds carry plenty of protocols we don't model (ARP, ICMP, UDP,
	// tunnelling). Skip them quietly instead of erroring per packet.
	d.parser.IgnoreUnsupported = true
	return d
}

// decode reports the network flow (client→server orientation for the first
// packet of a connection), the decoded TCP layer, and the IP TTL (IPv4) or
// hop-limit (IPv6) of the frame. ok is false when the frame is not IPv4/IPv6 +
// TCP. The returned *layers.TCP aliases reused storage and is only valid until
// the next decode call. The TTL is plumbed through to OS classification (316b),
// which needs it from the SYN; the reassembly callbacks never see the IP layer.
func (d *decoder) decode(data []byte) (netFlow gopacket.Flow, tcp *layers.TCP, ttl uint8, ok bool) {
	// DecodeLayers returns an error for the trailing unsupported/truncated
	// layer; that's expected, so we inspect d.decoded rather than the error.
	_ = d.parser.DecodeLayers(data, &d.decoded)

	var haveIP, haveTCP bool
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			netFlow = d.ip4.NetworkFlow()
			ttl = d.ip4.TTL
			haveIP = true
		case layers.LayerTypeIPv6:
			netFlow = d.ip6.NetworkFlow()
			ttl = d.ip6.HopLimit
			haveIP = true
		case layers.LayerTypeTCP:
			haveTCP = true
		}
	}
	if !haveIP || !haveTCP {
		return netFlow, nil, 0, false
	}
	return netFlow, &d.tcp, ttl, true
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
