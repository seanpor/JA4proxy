package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

const sentinelHash = "000000000000"

// ExtractJA4X computes the JA4X fingerprint from a DER-encoded X.509 certificate.
// Returns three underscore-separated 12-char SHA-256 hex segments: issuer_subject_san.
// Returns all-sentinel on parse failure or empty input.
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

// ExtractJA4XFromPEM computes the JA4X fingerprint from a PEM-encoded certificate.
func ExtractJA4XFromPEM(pemData []byte) string {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return formatJA4X("", "", "")
	}
	return ExtractJA4X(block.Bytes)
}

func extractSAN(cert *x509.Certificate) string {
	if len(cert.DNSNames) == 0 && len(cert.EmailAddresses) == 0 &&
		len(cert.IPAddresses) == 0 && len(cert.URIs) == 0 {
		return ""
	}

	var sanList []string
	for _, dns := range cert.DNSNames {
		sanList = append(sanList, fmt.Sprintf("<DNSName(value='%s')>", dns))
	}
	for _, email := range cert.EmailAddresses {
		sanList = append(sanList, fmt.Sprintf("<RFC822Name(value='%s')>", email))
	}
	for _, ip := range cert.IPAddresses {
		sanList = append(sanList, fmt.Sprintf("<IPAddress(value='%s')>", ip.String()))
	}
	for _, uri := range cert.URIs {
		sanList = append(sanList, fmt.Sprintf("<URI(value='%s')>", uri.String()))
	}

	sort.Strings(sanList)
	return strings.Join(sanList, ",")
}

func formatName(name pkix.Name) string {
	var attrs []string
	for _, attr := range name.Names {
		attrs = append(attrs, fmt.Sprintf("%s=%s", attr.Type.String(), attr.Value))
	}
	sort.Strings(attrs)
	return strings.Join(attrs, ",")
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
