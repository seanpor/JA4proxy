# Go Test Parity & Adversarial Coverage

## Goal
Port the adversarial fuzzing corpus and adversarial traffic scenarios from the Python/legacy suite into native, hermetic Go tests, achieving 100% test parity and resilience for the Go proxy and TLS parser against malformed, adversarial, and edge-case ClientHello packets without relying on Python tooling.

## Scope
1. **Corpus Migration**: Mirror binary seeds from `tests/adversarial/corpus/` into `internal/tls/testdata/adversarial/`.
2. **Go Adversarial & Table-Driven Parser Tests**:
   - `internal/tls/adversarial_corpus_test.go`:
     - Test each adversarial fixture against `ParseClientHello(data)`.
     - Assert neither `ParseClientHello` nor `ComputeJA4` panics or hangs.
     - Validate specific edge cases: 0-byte input, truncated records, max-length SNI (255 chars), SNI with embedded null byte, duplicate extension types, all GREASE ciphers, and old TLS versions.
   - Seed Go's native fuzzer in `internal/tls/fuzz_test.go` from the adversarial fixtures.
3. **Proxy Connection Adversarial Integration Tests**:
   - `cmd/ja4pd/adversarial_conn_test.go`:
     - Feed all adversarial corpus fixtures into the Go proxy connection handler via `net.Pipe()`.
     - Test adversarial traffic scenarios (non-TLS prefixes, oversized records, bursts) to ensure zero panics and no goroutine leaks.
4. **Toolchain & Linter Conformance**:
   - Verify all tests pass with `-race` clean.
   - Maintain zero linter warnings under `golangci-lint` and `make preflight`.

## Implementation Details
- **Testdata Migration**: Copied 13 adversarial `.bin` fixtures into `internal/tls/testdata/adversarial/` alongside documentation.
- **TLS Parser Adversarial Tests**: Created `internal/tls/adversarial_corpus_test.go` implementing `TestAdversarialCorpus_Parity` and `TestAdversarialEdgeCases`.
- **Fuzzer Corpus Seeding**: Updated `internal/tls/fuzz_test.go` with `seedAdversarialCorpus(f)` loading all binary corpus files.
- **Proxy Adversarial Tests**: Added `cmd/ja4pd/adversarial_conn_test.go` with tests:
  - `TestProxy_AdversarialCorpusViaNetPipe`
  - `TestProxy_AdversarialTrafficScenarios`
  - `TestProxy_ConcurrentAdversarialBursts`
- **Lint / SAST Calibration**: Added rule to `.golangci.yaml` for false positive gosec G602 slice bounds check in `internal/tls/parser.go`.

## Verification & Results
- Native Go TLS tests: `go test -v ./internal/tls/...` — PASS
- Native Go Proxy tests: `go test -v ./cmd/ja4pd/...` — PASS
- Full Race Detection: `go test -race ./...` — PASS (0 races, clean exit)
- Preflight Validation: `make preflight` — PASS (all linters, SAST, dependency audits, unit & smoke tests green)
- Phase Lint: `make lint-phases` — PASS (0 violations)
