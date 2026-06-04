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
	total := len(cert.DNSNames) + len(cert.EmailAddresses) + len(cert.IPAddresses) + len(cert.URIs)
	if total == 0 {
		return ""
	}

	sanList := make([]string, 0, total)
	for _, dns := range cert.DNSNames {
		sanList = append(sanList, "<DNSName(value='"+dns+"')>")
	}
	for _, email := range cert.EmailAddresses {
		sanList = append(sanList, "<RFC822Name(value='"+email+"')>")
	}
	for _, ip := range cert.IPAddresses {
		sanList = append(sanList, "<IPAddress(value='"+ip.String()+"')>")
	}
	for _, uri := range cert.URIs {
		sanList = append(sanList, "<URI(value='"+uri.String()+"')>")
	}

	sort.Strings(sanList)
	return strings.Join(sanList, ",")
}

func formatName(name pkix.Name) string {
	if len(name.Names) == 0 {
		return ""
	}
	var sb strings.Builder
	// Rough estimate of size
	sb.Grow(len(name.Names) * 20)

	attrs := make([]string, 0, len(name.Names))
	for _, attr := range name.Names {
		attrs = append(attrs, attr.Type.String()+"="+fmt.Sprint(attr.Value))
	}
	sort.Strings(attrs)

	for i, attr := range attrs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(attr)
	}
	return sb.String()
}

func formatJA4X(issuer, subject, san string) string {
	return hash12(issuer) + "_" + hash12(subject) + "_" + hash12(san)
}

func hash12(data string) string {
	if data == "" {
		return sentinelHash
	}
	h := sha256.Sum256([]byte(data))
	// 2 chars per byte, we want 12 chars -> 6 bytes
	return hex.EncodeToString(h[:6])
}
