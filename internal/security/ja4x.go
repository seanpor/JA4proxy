package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

const sentinelHash = "000000000000"

func ExtractJA4X(certDER []byte) string {
	if len(certDER) == 0 {
		return formatJA4X("", "", "")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return formatJA4X("", "", "")
	}

	issuer := formatName(cert.Issuer)
	subject := formatName(cert.Subject)
	san := extractSAN(cert)

	return formatJA4X(issuer, subject, san)
}

func ExtractJA4XFromPEM(pemData []byte) string {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return formatJA4X("", "", "")
	}
	return ExtractJA4X(block.Bytes)
}

func extractSAN(cert *x509.Certificate) string {
	result := ""
	for i, dnsName := range cert.DNSNames {
		if i > 0 {
			result += ","
		}
		result += dnsName
	}
	return result
}

func formatName(name interface{ String() string }) string {
	return name.String()
}

func formatJA4X(issuer, subject, san string) string {
	return fmt.Sprintf("%s_%s_%s",
		hash12(issuer),
		hash12(subject),
		hash12(san),
	)
}

func hash12(data string) string {
	if data == "" {
		return sentinelHash
	}
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])[:12]
}
