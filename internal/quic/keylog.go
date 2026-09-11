package quic

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// QUIC_SECRET_LOG format (NSS/Chrome convention):
//   QUIC_SECRET <label> <hex_secret> <hex_clientiv> <hex_serveriv>
//
// Labels:
//   QUIC_SECRET_HANDSHAKE_TRAFFIC_SECRET <secret>
//   QUIC_SECRET_CLIENT_HANDSHAKE_TRAFFIC_SECRET <secret>
//   QUIC_SECRET_SERVER_HANDSHAKE_TRAFFIC_SECRET <secret>
//   QUIC_SECRET_CLIENT_TRAFFIC_SECRET_0 <secret>
//   QUIC_SECRET_SERVER_TRAFFIC_SECRET_0 <secret>
//
// For Initial packet decryption we only need the HANDSHAKE_TRAFFIC_SECRET
// (or the derived handshake key) to decrypt the Initial packet.

// KeyLog parses a QUIC_SECRET_LOG file and provides traffic keys for decryption.
type KeyLog struct {
	mu     sync.RWMutex
	entries map[string]*keyLogEntry // label -> entry
}

type keyLogEntry struct {
	Secret  []byte
	ClientIV []byte
	ServerIV []byte
}

// NewKeyLog creates a KeyLog and loads keys from the given reader.
func NewKeyLog(r io.Reader) (*KeyLog, error) {
	kl := &KeyLog{
		entries: make(map[string]*keyLogEntry),
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := kl.parseLine(line); err != nil {
			continue // skip malformed lines
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("keylog scan: %w", err)
	}
	return kl, nil
}

// LoadFromEnv loads keys from the QUIC_SECRET_LOG environment variable.
func LoadFromEnv() (*KeyLog, error) {
	path := os.Getenv("QUIC_SECRET_LOG")
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open QUIC_SECRET_LOG %q: %w", path, err)
	}
	defer f.Close()
	return NewKeyLog(f)
}

// parseLine parses a single QUIC_SECRET_LOG line:
//   QUIC_SECRET <label> <hex_clientsecret> <hex_serversecret>
func (kl *KeyLog) parseLine(line string) error {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return fmt.Errorf("expected at least 3 fields, got %d", len(fields))
	}
	// fields[0] is "QUIC_SECRET"
	label := fields[1]
	clientSecret, err := hex.DecodeString(fields[2])
	if err != nil {
		return fmt.Errorf("invalid client secret hex: %w", err)
	}

	entry := &keyLogEntry{
		Secret: clientSecret,
	}

	if len(fields) >= 4 {
		iv, err := hex.DecodeString(fields[3])
		if err == nil {
			entry.ClientIV = iv
		}
	}
	if len(fields) >= 5 {
		iv, err := hex.DecodeString(fields[4])
		if err == nil {
			entry.ServerIV = iv
		}
	}

	kl.mu.Lock()
	kl.entries[label] = entry
	kl.mu.Unlock()
	return nil
}

// GetSecret returns the client secret for the given label, or nil if not found.
func (kl *KeyLog) GetSecret(label string) []byte {
	if kl == nil {
		return nil
	}
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	entry, ok := kl.entries[label]
	if !ok {
		return nil
	}
	return entry.Secret
}

// HasKeys reports whether any handshake keys are available.
func (kl *KeyLog) HasKeys() bool {
	if kl == nil {
		return false
	}
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return len(kl.entries) > 0
}

// DeriveInitialKey derives the AEAD key and IV for a QUIC Initial packet
// from the client DCID and the handshake secret. This implements the
// QUIC Initial Key Derivation (RFC 9001 §5.1).
//
// The Initial key is derived as:
//   key = HKDF-Expand-Label(HKDF-Expand-Label(secret, "quic key", "", 16), "quic iv", dcid, 12)
//
// For simplicity we use the TLS 1.3 HKDF derivation with SHA-256.
func DeriveInitialKey(dcid, handshakeSecret []byte) (key, iv []byte, err error) {
	if len(handshakeSecret) == 0 {
		return nil, nil, fmt.Errorf("empty handshake secret")
	}

	// TLS 1.3 HKDF-Expand-Label per RFC 8446 §7.1
	// We derive "quic key" and "quic iv" labels.

	// Derive key: HKDF-Expand-Label(secret, "quic key", "", 16)
	salt := hkdfExpandLabel(handshakeSecret, []byte("tls13 quic key"), nil, 16)

	// Derive IV: HKDF-Expand-Label(secret, "quic iv", dcid, 12)
	iv = hkdfExpandLabel(handshakeSecret, []byte("tls13 quic iv"), dcid, 12)

	return salt, iv, nil
}

func hkdfExpandLabel(secret, label, context []byte, length uint16) []byte {
	// HkdfLabel = uint16(length) + LabelLen + Label + ContextLen + Context
	// struct {
	//   uint16 length = Hash.length;  // truncated to 'length'
	//   opaque label<7..255> = "HKDF-Expand-Label: " + Label;
	//   opaque context<0..255>;
	// } HkdfLabel;

	prefix := []byte("HKDF-Expand-Label:")
	labelFull := append(prefix, label...)
	if len(labelFull) > 255 || len(context) > 255 {
		return nil
	}

	hkdfLabel := make([]byte, 2+1+len(labelFull)+1+len(context))
	binary.BigEndian.PutUint16(hkdfLabel[0:2], length)
	hkdfLabel[2] = byte(len(labelFull) & 0xff)
	copy(hkdfLabel[3:], labelFull)
	off := 3 + len(labelFull)
	hkdfLabel[off] = byte(len(context) & 0xff)
	copy(hkdfLabel[off+1:], context)

	// HKDF-Expand(PRK, info, L) using HMAC-SHA256
	return hkdfExpand(secret, hkdfLabel, int(length))
}

// hkdfExpand implements HKDF-Expand (RFC 5869 §2.2) with HMAC-SHA256.
func hkdfExpand(secret, info []byte, length int) []byte {
	hash := sha256.New
	h := hash()
	n := (h.Size() + length - 1) / h.Size()

	var result []byte
	var prev []byte
	for i := 1; i <= n; i++ {
		mac := hash()
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		result = append(result, prev...)
	}
	return result[:length]
}

// DecryptInitial decrypts a QUIC Initial packet using the derived key and IV.
// Returns the decrypted payload (CRYPTO frames) or an error.
func DecryptInitial(ciphertext, key, iv, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM: %w", err)
	}

	if len(ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: %d < %d overhead", len(ciphertext), aead.Overhead())
	}

	nonce := iv
	if len(nonce) != aead.NonceSize() {
		// If IV is too long, truncate; if too short, zero-pad
		nonce = make([]byte, aead.NonceSize())
		copy(nonce, iv)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("AEAD open: %w", err)
	}
	return plaintext, nil
}
