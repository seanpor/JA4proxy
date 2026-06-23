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

This **supersedes Phase 400** (Comprehensive Security Review, now DEFERRED), which
produced 12 initial findings (F-400-01 through F-400-12) and 7 stale findings.yaml
entries. Those findings are **seed input** for this phase — they will be verified and
re-registered under the appropriate sub-phase during execution.

This is **not** a code review — it is an execution phase. Every finding gets a
regression test and a propagation sweep.

## How to use these documents

Pick a guide based on what you are auditing. Each guide covers multiple sub-phases
for its technology area:

| Guide | File | Sub-phases | Covers |
|-------|------|-----------|--------|
| **Go Proxy** | `PHASE_500a.md` | 500a–500f | `cmd/ja4pd/`, `internal/` — TLS parsing, concurrency, auth, crypto, DoS, logging |
| **Python / API** | `PHASE_510a.md` | 510a–510c | `management/api/`, `src/analytics/` — injection, auth, session, data exposure |
| **Infrastructure** | `PHASE_510b.md` | 510d–510f | `scripts/`, `deploy/`, `config/` — Docker, Ansible, shell scripts, misconfiguration |

**Why 3 files instead of 12?** Each guide groups related CWE families for one
technology area. An engineer working on the Go proxy only needs to read the Go guide.
The sub-phase numbering (500a, 500b, etc.) identifies the CWE family within each guide.

Each guide has:
- **Grep commands** you can copy-paste to find patterns
- **Exact files** to read with line numbers
- **Checklists** to work through
- **Example bugs** from prior findings so you know what to look for
- **Regression test templates** for each bug class

## Execution order (recommended)

Start with the Go proxy (internet-facing), then Python, then infrastructure:

1. **500a** Protocol parsing (raw network input)
2. **500e** Resource exhaustion (DoS)
3. **500b** Concurrency (race conditions)
4. **500c** Access control (auth bypass)
5. **500d** Cryptography
6. **500f** Information exposure
7. **510a** Injection / web security
8. **510b** Auth / session management
9. **510c** Data exposure / logging
10. **510d** Misconfiguration
11. **510e** Crypto integrity
12. **510f** Supply chain / scripts

All sub-phases are **independent** — you can work on multiple in parallel.
However, agents touching shared Go hot-path files (`cmd/ja4pd/main.go`,
`internal/`) must run **sequentially** per CLAUDE.md. The Python and
infrastructure guides can run in parallel with each other.

## Deduplication

Before starting any sub-phase, check `docs/security/findings.yaml` for
existing findings in the same CWE family. Cross-reference recent security
commits (#213 tls-health leak fix, Phase 336 TAP hardening, Phase 334 code
review) to avoid re-discovering fixed issues. The 62 findings seeded from
Phases 108–121, 334, and 400 serve as exclusion baseline.

## When you find a bug

1. **Register it** in `docs/security/findings.yaml` (see template in each guide)
2. **Fix it** with a regression test
3. **Search for the same pattern** elsewhere in the codebase (propagation sweep)
4. **Register any sibling findings** with `similar_to:` pointing to the original

## Scope

**In:** Go proxy, Python Management API, analytics worker, scripts, Docker/infra, config
**Out:** Third-party images, dependency CVEs, perf benchmarking, Terraform/K8s (separate repos), docs accuracy

## Cross-cutting

Phase 500 touches code owned by three epics:
- **Security Hardening** — core vulnerability classes (all sub-phases)
- **Analytics & Intelligence** — `src/analytics/` covered by 510a–510c
- **Operational Excellence** — `scripts/`, `deploy/`, `config/` covered by 510d–510f

## Acceptance criteria

- [x] Every finding in `findings.yaml` with CWE, severity, regression test, and status
- [x] Every confirmed bug has a regression test
- [x] Every propagation sweep completed
- [x] Phase 400 findings (F-400-01 through F-400-12) verified and re-registered
- [x] `make lint` exits 0
- [x] `make scan` exits 0 (or only accepted findings)
- [x] `make test` passes with zero regressions
- [x] `go test -race ./...` passes (after Go sub-phases)

## Execution results (PR #216, merged to main)

| Sub-phase | Findings | Fixes |
|-----------|----------|-------|
| 500a Protocol Parsing | JA4PROXY-2026-0063 (HIGH) | Multi-record TLS reassembly + parser concatenation |
| 500b Concurrency | 0 | All patterns verified clean |
| 500c Access Control | JA4PROXY-2026-0064 (LOW), 0065 (MEDIUM) | `hmac.Equal` + log hardening |
| 500d Crypto | 0 | PBKDF2, AES-GCM, crypto/rand verified |
| 500e Resource Exhaustion | 0 | All bounds verified |
| 500f Info Exposure | 0 | No secrets in logs |
| 510a Injection/Web | JA4PROXY-2026-0066 (LOW) | Webhook TOCTOU documented |
| 510b Auth/Session | 0 | JWT, CSRF, OIDC, SAML verified |
| 510c Data Exposure | 0 | No sensitive data in logs |
| 510d–510f Infrastructure | 0 | Docker, Ansible, supply chain verified |

**4 findings registered, 3 fixed with regression tests, 1 documented (defense-in-depth).**
