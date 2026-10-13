# Fuzzing — Go-native targets

> **Production runtime is Go.** All adversarial fuzzing of the proxy hot path
> lives in Go and runs via `go test -fuzz=...`. The former Python harness
> (`tests/fuzz/test_properties.py`) was removed in phase-309 along with the rest
> of the deprecated Python prototype; the property-style invariants it asserted
> are now covered by `internal/security/property_test.go`.

## Where the targets live

| Target | File | What it fuzzes |
|---|---|---|
| `FuzzClientHello` | `cmd/ja4pd/fuzz_test.go` | The TLS ClientHello parser in proxy server. Must never panic, hang, or read out of bounds. |
| `FuzzReadProxyProtocol` | `cmd/ja4pd/fuzz_test.go` | The PROXY-protocol v1 reader. Must never panic on malformed v1 headers. |
| `FuzzReadProxyProtocolV2` | `cmd/ja4pd/fuzz_test.go` | The PROXY-protocol v2 binary reader. Validates header framing and address extraction. |
| `FuzzFragmentation` | `cmd/ja4pd/fuzz_test.go` | TCP packet fragmentation simulation across record boundaries. |
| `FuzzProtocolSmuggling` | `cmd/ja4pd/fuzz_test.go` | Multi-packet PROXY protocol smuggling secondary read validation. |
| `FuzzParseClientHello` | `internal/tls/fuzz_test.go` | Low-level TLS record parser and JA4 computation engine. |
| `FuzzDifferentialClientHello` | `internal/tls/differential_fuzz_test.go` | Differential fuzzing between JA4proxy parser and standard Go crypto/tls parser. |

Seed inputs are pulled from `tests/adversarial/corpus/*.bin` if present.
Add new regression seeds under `cmd/ja4pd/testdata/fuzz/<TargetName>/` or `internal/tls/testdata/fuzz/<TargetName>/`.

## Running Fuzz Smoke Tests (on demand)

Run fuzz targets for ~10 seconds each to verify no panics or regressions on known seeds:

```bash
GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzClientHello$' -fuzztime=10s ./cmd/ja4pd/
GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzReadProxyProtocol$' -fuzztime=10s ./cmd/ja4pd/
GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzReadProxyProtocolV2$' -fuzztime=10s ./cmd/ja4pd/
GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzParseClientHello$' -fuzztime=10s ./internal/tls/
```

Each target produces hundreds of thousands of executions in ten seconds. The
goal of the smoke run is **regression detection on already-known input shapes**,
not new bug discovery. CI runs these targets.

## Quarterly long-form fuzzing (operator procedure)

Once per quarter (or before any release that touches the parser, the
ClientHello path, or the PROXY-protocol reader), run extended fuzzing
overnight against each target:

```bash
GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzClientHello$' \
    -fuzztime=24h ./cmd/ja4pd/

GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzReadProxyProtocol$' \
    -fuzztime=24h ./cmd/ja4pd/

GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzReadProxyProtocolV2$' \
    -fuzztime=24h ./cmd/ja4pd/

GOROOT=/snap/go/current go test -run='^$' -fuzz='^FuzzParseClientHello$' \
    -fuzztime=24h ./internal/tls/
```

Run them serially (not in parallel) on a dedicated host so CPU contention
doesn't artificially slow down execution counts. Expected throughput on
modern hardware is ~50–100k execs/sec for the ClientHello target.

### What to do if a target finds a crash

1. Go's fuzz harness writes the failing input to `cmd/ja4pd/testdata/fuzz/<TargetName>/` or `internal/tls/testdata/fuzz/<TargetName>/`.
2. **Commit that file immediately** — it becomes a permanent regression seed.
3. File a bug with severity HIGH (parser-level memory safety regression).
4. Reproduce locally with:
   ```bash
   go test -run=<TargetName>/<HashOfFailingInput> ./cmd/ja4pd/
   ```
5. Fix the parser, re-run the smoke target, then re-run a 1h fuzz to confirm
   no new failure mode is unmasked by the fix.

## Why we do not run 24h fuzz in CI

A 24h `-fuzztime` per target means 72h serial wall-clock. CI minutes are
finite and fuzzers asymptote — most new-coverage discoveries happen in the
first 30 minutes. The 10s smoke run catches regressions on the existing
seed corpus. Quarterly long-form fuzzing on dedicated hardware is the
right place to discover **new** failure modes.

## Cross-language fuzz coverage

The Python prototype in `proxy.py` was previously fuzzed via `atheris`.
Those harnesses are deprecated as of Phase 62 alongside the Python prototype
itself. New adversarial parsing work goes into the Go targets above.
