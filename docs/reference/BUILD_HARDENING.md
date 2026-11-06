<!--
title: Go Proxy Build Hardening & Runtime Security
audience: reference
last_reviewed: 2026-11-06
phase: 863
-->

# Go Proxy Build Hardening & Runtime Security

## Overview
This document specifies the compiler flags, linker parameters, runtime architecture, and hardening guarantees for the JA4proxy Go proxy (`cmd/ja4pd`).

## Compiler & Linker Flags (F2 Configuration)

All production binaries are compiled via `scripts/go_build_hardened.sh` with the following parameters:

```bash
CGO_ENABLED=1 GOOS=linux go build \
    -buildmode=pie \
    -trimpath \
    -tags netgo,osusergo \
    -ldflags="-s -w -buildid= -linkmode external -extldflags \"-static -z relro -z now\" \
      -X github.com/seanpor/ja4proxy/internal/config.Version=${VERSION} \
      -X github.com/seanpor/ja4proxy/internal/config.GitCommit=${GIT_COMMIT} \
      -X github.com/seanpor/ja4proxy/internal/config.BuildDate=${BUILD_DATE}" \
    -o "${OUTPUT}" \
    "${PKG}"
```

### Explanations & Security Guarantees

| Flag / Setting | Purpose & Security Guarantee |
|---|---|
| `CGO_ENABLED=1` + `-buildmode=pie` | Produces a Position Independent Executable (PIE), ensuring full Address Space Layout Randomization (ASLR). |
| `-linkmode external` | Uses Alpine's `gcc` and `musl-dev` external linker so linker security flags can be enforced. |
| `-extldflags "-static -z relro -z now"` | Enforces Full RELRO (`GNU_RELRO` segment) and Immediate Binding (`BIND_NOW`). Makes the Global Offset Table (GOT) completely read-only before control reaches program execution. Links `libc` statically (`musl`), avoiding any external shared library dependency. |
| `-tags netgo,osusergo` | Forces Go to use the pure-Go DNS resolver and user lookup routines rather than libc resolvers, preventing thread exhaustion or glibc/musl resolver edge cases. |
| `-trimpath` | Strips host filesystem paths from stack traces and binary symbols. |
| `-buildid=` | Empties the Go internal build ID inside `-ldflags`, ensuring reproducible builds. |
| `-s -w` | Strips ELF symbol table and DWARF debug info, minimizing attack surface and binary size. |

## Runtime Stage (Distroless Static)

The runtime container image uses `gcr.io/distroless/static:debug`:
- Zero package managers (`apk`, `apt`), zero shell utilities in standard distroless (debug variant retains incident response busybox).
- Health checks are self-contained: `ja4pd --health-check` runs natively without requiring `curl` or `wget`.
- Production secret injection supports native `${VAR}_FILE` expansion (e.g. `REDIS_PASSWORD_FILE`), removing shell wrapper execution.
- Least-privilege numeric UID/GID `1000:1000` enforced for Kubernetes PSA `restricted` compliance.
- Runtime memory constrained via `GOMEMLIMIT=400MiB` and `GOGC=100`.

## Profile-Guided Optimization (PGO)

The proxy leverages Go PGO via `cmd/ja4pd/default.pgo`. Go 1.21+ automatically detects and applies optimizations during compilation (`-pgo=auto`).
To regenerate the profile after modifying hot paths, refer to [pgo_regeneration.md](../runbooks/pgo_regeneration.md).
