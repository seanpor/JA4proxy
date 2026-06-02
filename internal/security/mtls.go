package security

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// MTLSVerifier verifies TLS client certificates against a trusted CA pool.
type MTLSVerifier struct {
	pool *x509.CertPool
}

// NewMTLSVerifier loads trusted CAs from pemPath.
// If pemPath is empty or the file cannot be read, returns a verifier that
// always returns false (fail open — no certs trusted).
func NewMTLSVerifier(pemPath string) *MTLSVerifier {
	if pemPath == "" {
		return &MTLSVerifier{}
	}
	data, err := os.ReadFile(pemPath) // #nosec G304
	if err != nil {
		return &MTLSVerifier{}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data)
	return &MTLSVerifier{pool: pool}
}

// Verify returns true if certDER is a valid certificate signed by a trusted CA.
// Returns false on any error (fail open).
func (v *MTLSVerifier) Verify(certDER []byte) bool {
	if v.pool == nil || len(certDER) == 0 {
		return false
	}
	// Try DER first
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		// Try PEM
		block, _ := pem.Decode(certDER)
		if block == nil {
			return false
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
	}
	opts := x509.VerifyOptions{Roots: v.pool}
	_, err = cert.Verify(opts)
	return err == nil
}
