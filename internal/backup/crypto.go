// Package backup implements the Go production runtime's encrypted Redis
// backup engine (Phase 315a). The proxy is stateless; all durable security
// state lives in Redis, so "backing up the proxy" means snapshotting the
// right Redis keys into a safe, encrypted, restorable artifact and emitting
// the ja4proxy_backup_* metrics the alert rules watch for.
//
// Restore is the sister phase (315b) and is deliberately kept separate — it
// is the dangerous half (it can re-block real users and resurrect
// GDPR-erased data) and deserves its own focused review.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Binary artifact layout (the header is plaintext; the payload is encrypted):
//
//	┌─────────────┬──────────────┬───────────┬─────────────────────┬──────────────┬────────────────────┐
//	│ Magic "JA4P"│ FormatVer 1B │ Salt 16B  │ PBKDF2 iterations 4B│ GCM nonce 12B│ ciphertext (var)   │
//	└─────────────┴──────────────┴───────────┴─────────────────────┴──────────────┴────────────────────┘
//
// Salt and nonce live in the plaintext header by design: neither needs to be
// secret, only unique per artifact. The GCM tag (appended to the ciphertext by
// Seal) authenticates both the payload and — via additional data — the header,
// so any tampering or truncation fails closed on decrypt.
const (
	magic         = "JA4P"
	formatVersion = 1
	saltLen       = 16
	nonceLen      = 12 // AES-GCM standard nonce size
	keyLen        = 32 // AES-256
	// pbkdf2Iterations is the work factor for password-based key derivation.
	// 100k SHA-256 iterations is a conservative 2020s-era floor; it is recorded
	// in the header so a future bump stays backward-compatible on decrypt.
	pbkdf2Iterations = 100_000

	headerLen = len(magic) + 1 + saltLen + 4 + nonceLen
)

// ErrShortArtifact is returned when a blob is too small to contain a valid header.
var ErrShortArtifact = errors.New("backup: artifact too short / truncated")

// ErrBadMagic is returned when the artifact does not start with the JA4P magic.
var ErrBadMagic = errors.New("backup: bad magic — not a JA4proxy backup artifact")

// ErrUnsupportedVersion is returned for an unrecognised format version.
var ErrUnsupportedVersion = errors.New("backup: unsupported artifact format version")

// deriveKey derives a 32-byte AES-256 key from the passphrase and salt using
// PBKDF2-HMAC-SHA256. An empty passphrase is rejected — an unencrypted backup
// of audit logs, bans and MFA material would be a data breach waiting to happen.
func deriveKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("backup: empty encryption passphrase")
	}
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
}

// EncryptPayload encrypts plaintext with AES-256-GCM under a key derived from
// passphrase, and returns the full artifact bytes (plaintext header followed by
// ciphertext+tag). A fresh random salt and nonce are generated per call.
func EncryptPayload(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("backup: generating salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("backup: generating nonce: %w", err)
	}

	key, err := deriveKey(passphrase, salt, pbkdf2Iterations)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 0, headerLen)
	header = append(header, magic...)
	header = append(header, formatVersion)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, uint32(pbkdf2Iterations))
	header = append(header, nonce...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: gcm: %w", err)
	}
	// The header is authenticated as additional data so a tampered salt/nonce
	// (or a swapped version byte) is detected on decrypt.
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)

	return append(header, ciphertext...), nil
}

// DecryptPayload parses an artifact produced by EncryptPayload, verifies its
// integrity (GCM tag over header+ciphertext) and returns the plaintext. A wrong
// passphrase, a truncated artifact or any tampering fails closed.
func DecryptPayload(artifact []byte, passphrase string) ([]byte, error) {
	if len(artifact) < headerLen {
		return nil, ErrShortArtifact
	}
	off := 0
	if string(artifact[:len(magic)]) != magic {
		return nil, ErrBadMagic
	}
	off += len(magic)
	if artifact[off] != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, artifact[off])
	}
	off++
	salt := artifact[off : off+saltLen]
	off += saltLen
	iterations := int(binary.BigEndian.Uint32(artifact[off : off+4]))
	off += 4
	nonce := artifact[off : off+nonceLen]
	off += nonceLen
	header := artifact[:off]
	ciphertext := artifact[off:]

	key, err := deriveKey(passphrase, salt, iterations)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		// Wrong key or tampered/truncated artifact — fail closed, do not leak which.
		return nil, errors.New("backup: decryption failed (wrong key or corrupt artifact)")
	}
	return plaintext, nil
}
