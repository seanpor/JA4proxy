<!--
title: Runbook: Go PGO Profile Regeneration
audience: operator
last_reviewed: 2026-11-06
phase: 863
-->

# Runbook: Go PGO Profile Regeneration

## Overview
Profile-Guided Optimization (PGO) allows the Go compiler (`go build`) to inline hot execution paths, optimize branch predictions, and improve CPU instruction cache hit rates based on real workloads.
JA4proxy proxy daemon (`cmd/ja4pd`) maintains a representative raw pprof CPU profile at `cmd/ja4pd/default.pgo`.

Because Go 1.21+ automatically consumes `default.pgo` in the main package's directory (`-pgo=auto` is default), keeping this profile current ensures maximum throughput.

## When to Regenerate
Regenerate `cmd/ja4pd/default.pgo` when:
1. Significant changes are made to the proxy pipeline hot path (`internal/proxy`, `internal/tls`, `cmd/ja4pd`).
2. Major Go toolchain minor/major version upgrades occur (e.g. Go 1.27 -> 1.28).
3. New TLS fingerprinting routines or rules engine stages are introduced.

## Regeneration Procedure

Run the automated regeneration script:
```bash
./scripts/gen_pgo_profile.sh
```

The script executes representative pipeline benchmarks (`BenchmarkPipeline_Allow` and `BenchmarkPipeline_Score`) under CPU profiling and saves the resulting pprof output to `cmd/ja4pd/default.pgo`.

> [!NOTE]
> `cmd/ja4pd/default.pgo` must be a RAW pprof profile file. Do NOT run `go tool preprofile` manually. The Go compiler invokes `preprofile` automatically during compilation.

## Verification

1. Verify that `cmd/ja4pd/default.pgo` is consumed by the Go build:
```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27.3-alpine sh -c \
  "go build -x -o /dev/null ./cmd/ja4pd 2>&1 | grep preprofile"
```
Expected output:
```text
/usr/local/go/pkg/tool/linux_amd64/preprofile -o ... -i .../cmd/ja4pd/default.pgo
```

2. Run unit tests to confirm stability:
```bash
make test
```
