package tls_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
)

func TestExtractJA4XFromPEM_InvalidOrMissingBlock(t *testing.T) {
	// Empty or non-PEM input
	fp := tlsparse.ExtractJA4XFromPEM([]byte("invalid pem data"))
	if len(fp) != 38 {
		t.Fatalf("expected 38-char JA4X string, got %q (len=%d)", fp, len(fp))
	}

	// Wrong block type (e.g. RSA PRIVATE KEY)
	wrongPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})
	fpWrong := tlsparse.ExtractJA4XFromPEM(wrongPEM)
	if len(fpWrong) != 38 {
		t.Fatalf("expected 38-char JA4X string for wrong block type, got %q (len=%d)", fpWrong, len(fpWrong))
	}
}

func TestExtractJA4XFromPEM_ValidCertificate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	u, _ := url.Parse("https://example.com/san")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Subject",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.com"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		URIs:                  []*url.URL{u},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create self-signed cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	ja4xPEM := tlsparse.ExtractJA4XFromPEM(certPEM)
	ja4xDER := tlsparse.ExtractJA4X(certDER)

	if ja4xPEM != ja4xDER {
		t.Fatalf("JA4X from PEM (%s) does not match JA4X from DER (%s)", ja4xPEM, ja4xDER)
	}
}
