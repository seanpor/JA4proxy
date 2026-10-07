package backup_test

import (
	"bytes"
	"testing"

	"github.com/seanpor/ja4proxy/internal/backup"
	"pgregory.net/rapid"
)

// INV-BACKUP-001: Roundtrip Encrypted Backup Integrity
// DecryptPayload(EncryptPayload(payload, pass), pass) == payload for all valid payloads and passphrases.
func TestInvariant_Backup_RoundtripEncryption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		payload := rapid.SliceOf(rapid.Byte()).Draw(t, "payload")
		passphrase := rapid.StringMatching(`[a-zA-Z0-9!@#$%^&*()_+-=]{1,64}`).Draw(t, "passphrase")

		artifact, err := backup.EncryptPayload(payload, passphrase)
		if err != nil {
			t.Fatalf("EncryptPayload failed: %v", err)
		}

		decrypted, err := backup.DecryptPayload(artifact, passphrase)
		if err != nil {
			t.Fatalf("DecryptPayload failed: %v", err)
		}

		if !bytes.Equal(decrypted, payload) {
			t.Fatalf("Decrypted payload mismatch: got %v, want %v", decrypted, payload)
		}
	})
}

// INV-BACKUP-002: Tampered/Truncated Artifact Fail-Closed
// Any mutation (truncation, byte flip, wrong passphrase) causes DecryptPayload to fail closed with an error.
func TestInvariant_Backup_TamperedArtifactFailClosed(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		payload := rapid.SliceOf(rapid.Byte()).Draw(t, "payload")
		passphrase := rapid.StringMatching(`[a-zA-Z0-9]{1,32}`).Draw(t, "passphrase")

		artifact, err := backup.EncryptPayload(payload, passphrase)
		if err != nil {
			t.Fatalf("EncryptPayload failed: %v", err)
		}

		mode := rapid.IntRange(0, 2).Draw(t, "mutationMode")
		switch mode {
		case 0: // Truncation
			if len(artifact) == 0 {
				return
			}
			cut := rapid.IntRange(0, len(artifact)-1).Draw(t, "cutLen")
			_, err := backup.DecryptPayload(artifact[:cut], passphrase)
			if err == nil {
				t.Fatalf("DecryptPayload succeeded on truncated artifact of length %d (full len %d)", cut, len(artifact))
			}
		case 1: // Single byte corruption
			if len(artifact) == 0 {
				return
			}
			corruptIdx := rapid.IntRange(0, len(artifact)-1).Draw(t, "corruptIdx")
			corrupted := append([]byte(nil), artifact...)
			corrupted[corruptIdx] ^= 0xFF // flip all bits of the byte

			_, err := backup.DecryptPayload(corrupted, passphrase)
			if err == nil {
				t.Fatalf("DecryptPayload succeeded on corrupted artifact at index %d", corruptIdx)
			}
		case 2: // Wrong passphrase
			wrongPassphrase := passphrase + "_wrong"
			_, err := backup.DecryptPayload(artifact, wrongPassphrase)
			if err == nil {
				t.Fatalf("DecryptPayload succeeded with wrong passphrase %q", wrongPassphrase)
			}
		}
	})
}
