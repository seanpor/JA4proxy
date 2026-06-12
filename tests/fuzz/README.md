# Fuzzing — Go-native targets

> **Production runtime is Go.** All adversarial fuzzing of the proxy hot path
> lives in Go and runs via `go test -fuzz=...`. The former Python harness
> (`tests/fuzz/test_properties.py`) was removed in phase-309 along with the rest
> of the deprecated Python prototype; the property-style invariants it asserted
> are now covered by `internal/security/property_test.go`.

## Where the targets live

| Target | File | What it fuzzes |
|---|---|---|
| `FuzzClientHello` | `cmd/proxy/fuzz_test.go` | The TLS ClientHello parser. Must never panic, hang, or read out of bounds for any input. |
| `FuzzReadProxyProtocol` | `cmd/proxy/fuzz_test.go` | The PROXY-protocol v1 reader. Must never panic on malformed v1 headers. |
| `FuzzReadProxyProtocolV2` | `cmd/proxy/fuzz_test.go` | Currently fuzzes the same v1 reader with v2-shaped seeds (the v1 reader rejects them after the first byte). The dedicated v2 binary reader does not yet exist on the Go side; it lands in **Phase 200**. The fuzz target is wired now so the harness exists when the v2 reader does. |

Seed inputs are pulled from `tests/adversarial/corpus/*.bin` if present.
Add new regression seeds under `cmd/proxy/testdata/fuzz/<TargetName>/`.

## Fast smoke run (every PR, locally on demand)

```bash
make test-go-fuzz-smoke   # runs each fuzz target for ~10 s, panic-free required
```

Each target produces hundreds of thousands of executions in ten seconds. The
goal of the smoke run is **regression detection on already-known input shapes**,
not new bug discovery. CI runs this on every PR.

## Quarterly long-form fuzzing (operator procedure)

Once per quarter (or before any release that touches the parser, the
ClientHello path, or the PROXY-protocol reader), run extended fuzzing
overnight against each target:

```bash
GOROOT=/snap/go/current go test -run='^$' -fuzz=FuzzClientHello \
    -fuzztime=24h ./cmd/proxy/

GOROOT=/snap/go/current go test -run='^$' -fuzz=FuzzReadProxyProtocol \
    -fuzztime=24h ./cmd/proxy/

GOROOT=/snap/go/current go test -run='^$' -fuzz=FuzzReadProxyProtocolV2 \
    -fuzztime=24h ./cmd/proxy/
```

Run them serially (not in parallel) on a dedicated host so CPU contention
doesn't artificially slow down execution counts. Expected throughput on
modern hardware is ~50–100k execs/sec for the ClientHello target.

### What to do if a target finds a crash

1. Go's fuzz harness writes the failing input to `cmd/proxy/testdata/fuzz/<TargetName>/`.
2. **Commit that file immediately** — it becomes a permanent regression seed.
3. File a bug with severity HIGH (parser-level memory safety regression).
4. Reproduce locally with:
   ```bash
   go test -run=<TargetName>/<HashOfFailingInput> ./cmd/proxy/
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
