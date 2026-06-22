---
phase: 500
title: "Full Codebase Bug Hunt — Multi-Strand Security Audit"
size: XLARGE
created: 2026-06-22
audience: [security, developer, operations]
---

# Full Codebase Bug Hunt

## What is this?

A systematic bug hunt across the entire JA4proxy codebase, organised by vulnerability
class (CWE family). The goal is to **find bugs, fix them, write regression tests, and
check for the same bug elsewhere**.

This is **not** a code review — it is an execution phase. Every finding gets a
regression test and a propagation sweep.

## How to use these documents

Pick a guide based on what you are auditing:

| Guide | File | Covers |
|-------|------|--------|
| **Go Proxy** | [PHASE_500a.md](PHASE_500a.md) | `cmd/ja4pd/`, `internal/` — TLS parsing, concurrency, auth, crypto, DoS, logging |
| **Python / API** | [PHASE_510a.md](PHASE_510a.md) | `management/api/`, `src/analytics/` — injection, auth, session, data exposure |
| **Infrastructure** | [PHASE_510b.md](PHASE_510b.md) | `scripts/`, `deploy/`, `config/` — Docker, Ansible, shell scripts, misconfiguration |

Each guide has:
- **Grep commands** you can copy-paste to find patterns
- **Exact files** to read with line numbers
- **Checklists** to work through
- **Example bugs** from prior findings so you know what to look for
- **Regression test templates** for each bug class

## Execution order (recommended)

Start with the Go proxy (internet-facing), then Python, then infrastructure:

1. 500a — Protocol parsing (raw network input)
2. 500e — Resource exhaustion (DoS)
3. 500b — Concurrency (race conditions)
4. 500c — Access control (auth bypass)
5. 500d — Cryptography
6. 500f — Information exposure
7. 510a — Injection / web security
8. 510b — Auth / session management
9. 510c — Data exposure / logging
10. 510d — Misconfiguration
11. 510e — Crypto integrity
12. 510f — Supply chain / scripts

All sub-phases are **independent** — you can work on multiple in parallel.

## When you find a bug

1. **Register it** in `docs/security/findings.yaml` (see template in each guide)
2. **Fix it** with a regression test
3. **Search for the same pattern** elsewhere in the codebase (propagation sweep)
4. **Register any sibling findings** with `similar_to:` pointing to the original

## Scope

**In:** Go proxy, Python Management API, analytics worker, scripts, Docker/infra, config
**Out:** Third-party images, dependency CVEs, perf benchmarking, Terraform/K8s (separate repos), docs accuracy

## Acceptance criteria

- [ ] Every finding in `findings.yaml` with CWE, severity, regression test, and status
- [ ] Every confirmed bug has a regression test
- [ ] Every propagation sweep completed
- [ ] `make lint` exits 0
- [ ] `make scan` exits 0 (or only accepted findings)
- [ ] `make test` passes with zero regressions
- [ ] `go test -race ./...` passes (after Go sub-phases)
