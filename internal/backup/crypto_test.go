package backup

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("the durable security state — bans, dial, audit logs")
	art, err := EncryptPayload(plain, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if bytes.Contains(art, plain) {
		t.Fatal("artifact contains plaintext — not encrypted")
	}
	got, err := DecryptPayload(art, "correct horse battery staple")
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestWrongPassphraseFailsClosed(t *testing.T) {
	art, err := EncryptPayload([]byte("secret"), "right-key")
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if _, err := DecryptPayload(art, "wrong-key"); err == nil {
		t.Fatal("decrypt with wrong key should fail, got nil error")
	}
}

func TestTamperedArtifactFailsClosed(t *testing.T) {
	art, err := EncryptPayload([]byte("secret payload bytes"), "k")
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	// Flip a byte in the ciphertext region (after the header).
	art[len(art)-1] ^= 0xFF
	if _, err := DecryptPayload(art, "k"); err == nil {
		t.Fatal("decrypt of tampered artifact should fail (GCM tag), got nil error")
	}
}

func TestTamperedHeaderFailsClosed(t *testing.T) {
	art, err := EncryptPayload([]byte("payload"), "k")
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	// Flip a salt byte (in the authenticated header).
	art[len(magic)+1] ^= 0x01
	if _, err := DecryptPayload(art, "k"); err == nil {
		t.Fatal("decrypt with tampered header should fail, got nil error")
	}
}

func TestShortAndBadMagic(t *testing.T) {
	if _, err := DecryptPayload([]byte("x"), "k"); err != ErrShortArtifact {
		t.Fatalf("short artifact: got %v want ErrShortArtifact", err)
	}
	bad := make([]byte, headerLen+4)
	copy(bad, "XXXX")
	if _, err := DecryptPayload(bad, "k"); err != ErrBadMagic {
		t.Fatalf("bad magic: got %v want ErrBadMagic", err)
	}
}

func TestEmptyPassphraseRejected(t *testing.T) {
	if _, err := EncryptPayload([]byte("x"), ""); err == nil {
		t.Fatal("empty passphrase should be rejected on encrypt")
	}
}

func TestUniqueSaltAndNonce(t *testing.T) {
	a, _ := EncryptPayload([]byte("same"), "k")
	b, _ := EncryptPayload([]byte("same"), "k")
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext produced identical artifacts (salt/nonce reuse)")
	}
}
