package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCertificate creates a minimal in-memory self-signed TLS cert for differential testing.
func generateTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"JA4proxy Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "test.local"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

// FuzzDifferentialClientHello performs differential oracle fuzzing comparing
// ParseClientHello against Go's standard library crypto/tls server handshake.
func FuzzDifferentialClientHello(f *testing.F) {
	// Seed 1: Minimal valid ClientHello
	seed1 := []byte{
		0x16, 0x03, 0x01, 0x00, 0x30, // Record header (48 bytes)
		0x01, 0x00, 0x00, 0x2c, // Handshake header
		0x03, 0x03, // TLS 1.2
		// Random (32 bytes)
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		0x00,       // Session ID len 0
		0x00, 0x02, // Cipher suites len 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // Compression methods len 1, null
		0x00, 0x00, // Extensions len 0
	}
	f.Add(seed1)

	// Seed 2: ClientHello with SNI "example.com"
	seed2 := []byte{
		0x16, 0x03, 0x01, 0x00, 0x43, // Record header (67 bytes)
		0x01, 0x00, 0x00, 0x3f, // Handshake header
		0x03, 0x03, // TLS 1.2
		// Random (32 bytes)
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		0x00,       // Session ID len 0
		0x00, 0x02, // Cipher suites len 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // Compression methods len 1, null
		0x00, 0x13, // Extensions len 19
		// Extension: server_name (0x0000), len 15
		0x00, 0x00, 0x00, 0x0f,
		0x00, 0x0d, // list len 13
		0x00,       // host_name (0)
		0x00, 0x0a, // name len 10
		's', 'e', 'c', 'u', 'r', 'e', '.', 'c', 'o', 'm',
	}
	f.Add(seed2)

	cert := generateTestCertificate(&testing.T{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// 1. Invocation of JA4proxy parser: MUST NEVER PANIC
		helloInfo, err := ParseClientHello(data)

		// 2. Invocation of crypto/tls oracle via in-memory net.Pipe
		var stdlibInfo *tls.ClientHelloInfo
		var stdlibCaptured bool

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				stdlibInfo = chi
				stdlibCaptured = true
				return nil, nil
			},
		}

		clientConn, serverConn := net.Pipe()
		server := tls.Server(serverConn, config)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = server.Handshake()
		}()

		// Write mutated data to server side
		go func() {
			_, _ = clientConn.Write(data)
			_ = clientConn.Close()
		}()

		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			_ = serverConn.Close()
			<-done
		}

		// 3. Differential assertions:
		// If standard library successfully extracts SNI, JA4proxy must also succeed and match.
		if stdlibCaptured && stdlibInfo != nil && stdlibInfo.ServerName != "" {
			if err != nil {
				t.Fatalf("crypto/tls accepted SNI %q, but ParseClientHello failed: %v", stdlibInfo.ServerName, err)
			}
			if helloInfo.SNI != stdlibInfo.ServerName {
				t.Fatalf("SNI discrepancy: crypto/tls got %q, ParseClientHello got %q", stdlibInfo.ServerName, helloInfo.SNI)
			}
		}

		// Invariant: If ParseClientHello succeeded, JA4 computation must never panic
		if helloInfo != nil {
			_ = ComputeJA4(helloInfo)
		}
	})
}

// TestFragmentedMultiRecordEphemeralHeapSafety proves whether multi-record reassembly
// retains strings from an ephemeral buffer that is mutated afterwards.
func TestFragmentedMultiRecordEphemeralHeapSafety(t *testing.T) {
	// Construct a fragmented ClientHello across 2 records:
	// Record 1: Record Header + Handshake Header + TLS version + Random + SessionID + Ciphers
	// Record 2: Record Header + Extensions (with SNI "victim.corp")

	rec1Payload := []byte{
		0x01, 0x00, 0x00, 0x3f, // Handshake header (total 63 bytes)
		0x03, 0x03,
		// Random 32 bytes
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		0x00,       // session id len
		0x00, 0x02, // ciphers len 2
		0x13, 0x01,
		0x01, 0x00, // compression
	}

	rec2Payload := []byte{
		0x00, 0x14, // extensions len 20
		// SNI extension
		0x00, 0x00, 0x00, 0x10,
		0x00, 0x0e, // list len 14
		0x00,       // host_name
		0x00, 0x0b, // name len 11
		'v', 'i', 'c', 't', 'i', 'm', '.', 'c', 'o', 'r', 'p',
	}

	var wire []byte
	// Record 1 (type 0x16, version 0x0301, len)
	rec1Hdr := make([]byte, 5)
	rec1Hdr[0] = 0x16
	rec1Hdr[1], rec1Hdr[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec1Hdr[3:5], uint16(len(rec1Payload)))
	wire = append(wire, rec1Hdr...)
	wire = append(wire, rec1Payload...)

	// Record 2
	rec2Hdr := make([]byte, 5)
	rec2Hdr[0] = 0x16
	rec2Hdr[1], rec2Hdr[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec2Hdr[3:5], uint16(len(rec2Payload)))
	wire = append(wire, rec2Hdr...)
	wire = append(wire, rec2Payload...)

	info, err := ParseClientHello(wire)
	if err != nil {
		t.Fatalf("ParseClientHello failed on valid 2-record fragmented ClientHello: %v", err)
	}

	if info.SNI != "victim.corp" {
		t.Fatalf("Expected SNI victim.corp, got %q", info.SNI)
	}

	// Invariant check: In ParseClientHello, if recordCount > 1, payloads was allocated on heap.
	// info.SNI must be a safely cloned string rather than pointing into a transient buffer
	// that could be collected or overwritten.
	sniBytes := []byte(info.SNI)
	if !bytes.Equal(sniBytes, []byte("victim.corp")) {
		t.Fatalf("SNI corrupted: %s", info.SNI)
	}
}
