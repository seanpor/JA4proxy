# Backup & Compliance Invariants

## Goal
Implement property-based invariant test suites for state backup restoration and compliance classification (`internal/backup`, `internal/compliance`). Establish formal guarantees using `pgregory.net/rapid` that roundtrip AES-256-GCM encryption/decryption preserves arbitrary binary payloads, that tampered or truncated backup artifacts strictly fail closed, that signal classification deterministically respects default category mappings, and that custom overrides take precedence while adhering to weight/alphabetical tie-breaking rules.

---

## Read These First
- `internal/backup/crypto.go` (AES-256-GCM PBKDF2 payload encryption/decryption)
- `internal/backup/restore.go` (Redis state restoration)
- `internal/compliance/classifier.go` (RiskSignal mapping and classification engine)

---

## Verified API Surface
- `backup.EncryptPayload(plaintext []byte, passphrase string) ([]byte, error)` — `internal/backup/crypto.go:70`
- `backup.DecryptPayload(artifact []byte, passphrase string) ([]byte, error)` — `internal/backup/crypto.go:110`
- `compliance.NewSignalClassifier()` — `internal/compliance/classifier.go:44`
- `compliance.NewSignalClassifierWithOverrides(overrides map[string]CategoryEntry)` — `internal/compliance/classifier.go:55`
- `(*SignalClassifier).Classify(signals []string)` — `internal/compliance/classifier.go:79`

---

## Invariants

| ID | Plain-English Statement | Formal Statement | SecOps Rationale |
|---|---|---|---|
| `INV-BACKUP-001` | Roundtrip Encrypted Backup Integrity | $\forall p \in \text{Bytes}, pass \neq "" \implies \text{Decrypt}(\text{Encrypt}(p, pass), pass) \equiv p$ | Guarantees that any proxy state backed up can be accurately restored without data corruption. |
| `INV-BACKUP-002` | Tampered/Truncated Artifact Fail-Closed | $\forall \text{mutated artifact } A', \quad \text{Decrypt}(A', pass) \text{ returns error}$ | Prevents malicious tampering, header spoofing, or corrupted backup restoration. |
| `INV-COMPLIANCE-001` | Signal Classifier Default Determinism | $\forall s \in \text{DefaultSignals}, \quad \text{Classify}(\{s\}) \equiv \text{Category}(s)$ | Ensures critical security signals map predictably to compliance audit categories. |
| `INV-COMPLIANCE-002` | Signal Classifier Override Precedence | $\forall o \in \text{Overrides}, \quad \text{Classify}(\text{signals}) \text{ obeys overrides + weight/alpha rules}$ | Guarantees customized threat intelligence rules cleanly override defaults without breaking category resolution hierarchy. |

---

## Step-by-Step Implementation Guide

### Step 1: Create `internal/backup/backup_invariant_test.go`
Create Rapid property-based invariant test suite for backup encryption & tampering.

### Step 2: Create `internal/compliance/compliance_invariant_test.go`
Create Rapid property-based invariant test suite for compliance classification and overrides.

---

## Test Commands

- **Run Backup Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/backup -run '^TestInvariant_'`
- **Run Compliance Invariants:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/compliance -run '^TestInvariant_'`

---

## Coverage Target

- **Package `internal/backup` Baseline:** $\ge 85.0\%$
- **Package `internal/compliance` Baseline:** $\ge 90.0\%$

---

## Acceptance Criteria

- [ ] `internal/backup/backup_invariant_test.go` created and passing.
- [ ] `internal/compliance/compliance_invariant_test.go` created and passing.
- [ ] Invariants registered in `docs/testing/invariants.yaml`.
- [ ] News fragment created in `docs/fragments/phase-606k-backup-compliance-invariants.md`.
- [ ] `make preflight` passes 100% green.

---

## Out of Scope
- Direct Redis network connection restoration (tested via integration tests).
