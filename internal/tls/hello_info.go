package tls

import (
	"encoding/binary"
)

// ClientHelloField holds a single extension field from ClientHello.
type ClientHelloField struct {
	Extension uint16      // Extension type (e.g., 0x0017 = SNI)
	DataLen   uint16      // Length of data in bytes
	Data      []byte      // Raw data for this extension
}

// ClientHelloInfo contains parsed ClientHello metadata before JA4 computation.
type ClientHelloInfo struct {
	Plaintext     []byte      // Raw TCP payload (first clienthello message only)
	CipherSuite   uint16      // TLS cipher suite from hello.message.cipher_suites
	JA4Ver        byte        // MSB of version from handshake
	JA4Cipher     byte        // LSB of cipher
	RandLen       uint16      // Length of RAND (32-64 bytes typical)
	 JA4Extensions ClientHelloField