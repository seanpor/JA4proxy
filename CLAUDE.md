# JA4proxy — Agent Master Plan

> **Read this file first, every session.** Then read the specific phase file in
> `docs/phases/` for the phase you are working on. Do not skip ahead.

> ### ⚠ The proxy is Go-only
>
> The **Go proxy** (`cmd/ja4pd`, `internal/`) was promoted to production in
> Phase 15 and is now the **only** proxy implementation. It is what ships in
> releases, Docker images, Helm charts, and enterprise documentation.
>
> The former **Python proxy** (`proxy.py`) was deprecated and **deleted** — there
> is no Python proxy runtime and no Go/Python parity to maintain. Any proxy work
> (signal modules, hot path, config, logging) happens in Go.
>
> Python remains only for services that **are not the proxy** — the Management
> API (FastAPI, `management/`), the analytics node, and supporting tooling under
> `src/`. Those are production code; treat them as Python.

---

## Multi-Agent Coordination — Read Before Anything Else

Multiple Claude Code agents work on this repo in parallel. Conflicts happen when
agents ignore file ownership or push to the wrong branch. Follow these rules exactly.

### Git Rules

- Never commit directly to `main`. Always work on `phase-XX-description`.
- Commit often after each meaningful chunk. Stage only files you own.
- Push your branch when finished, then **land it via a pull request** —
  `gh pr create --base main` then `gh pr merge --auto --squash --delete-branch`.
- **`main` is branch-protected and the protection is enforced for everyone,
  admins included.** A direct `git push origin main` is rejected; a PR can only
  merge once its four required checks pass — **Meta-Validation, Full Lint, Full
  Test, Security Scan**. There is no direct-merge shortcut. (Emergency override
  and full details: the branch-protection callout in `AGENTS.md`.)

### File Ownership

Each phase agent owns ONLY the files in `src/`, `tests/`, and `docs/phases/`
that are relevant to its phase. Shared files have specific rules:

| File | Rule |
|---|---|
| `Makefile` | Add a new named target (`test-phase-XX`) at the bottom. Do NOT edit existing targets. |
| `README.md` | Add your section under `## Phase XX`. Do not edit other sections. |
| `CHANGELOG.md` | Do NOT edit directly. Drop a news fragment in `docs/fragments/phase-XX-*.md` (see that dir's README); it's folded in at release by `make changelog-assemble`. |
| `requirements.txt` | Add new deps at the bottom with `# phase-XX` comment. |
| `config/proxy.yml` | Only edit keys your phase introduces. Comment them `# phase-XX`. |
| `docs/phases/TODO.md`, `docs/reference/PROJECT_STATUS.md` | NOT COMMITTED — gitignored build artifacts generated from `manifest.yaml` by `make sync` (Phase 332). Never `git add` them; there is nothing to conflict on. Edit `manifest.yaml` instead. |
| `docs/phases/manifest.yaml` | Edit ONLY to mark your phase COMPLETE. |
| `docker-compose*.yml` | Only edit if your phase requires a new service. Add at the bottom. |

If you must touch a file another agent owns, spawn a coordination subagent to
merge both changesets preserving all work. Note it in `PHASE_XX_notes.md`.

### Parallel vs Sequential Work

- **Parallel-safe:** different `src/` directories, tests + docs for the same phase,
  read-only exploration.
- **Must run sequentially:** any two agents touching shared Go hot-path files
  (`cmd/ja4pd/main.go`, `internal/`), Makefile aggregate targets, README
  top-level, branch merges.

When merging branches, always preserve ALL content from both sides. Never
discard work. For complex merges, spawn a subagent to produce a single file
that preserves everything.

### Checklist Before Pushing

- [ ] Working on a named branch, not `main`
- [ ] Only edited files within this phase's ownership
- [ ] Tests pass: `make test-unit` at minimum
- [ ] Meaningful commit messages
- [ ] `PHASE_XX_notes.md` written summarising work and decisions

---

## What This Project Is

JA4proxy is a TLS-aware passthrough security proxy that sits in front of web
server infrastructure. It makes allow/block/tarpit decisions based entirely on
**plaintext metadata visible before and during the TLS handshake**. It never
decrypts traffic, never holds TLS keys, and forwards allowed connections
byte-for-byte unchanged. It is **completely standalone** — it requires nothing
from the backend webserver and never inspects HTTP content.

### Architecture

```
Internet ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                      :443                  :8080               :443
                                              │  ▲
                           write events       │  │  write findings
                           (Redis Stream)     ▼  │  (Redis keys)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  FastAPI + React
                                         │     UI       │  :8090
                                         └──────────────┘
```

### Pipeline

```
TCP accept
    │
    ├── Trusted upstream CIDR? → extract real client IP from PROXY protocol
    ├── IPv4/IPv6 normalisation
    │
    ├── [BYPASS CHECKS — never reach scorer]
    │     ├── h2 / h1 ALPN?           → ALLOW immediately
    │     ├── JA4 in whitelist?       → ALLOW immediately
    │     ├── mTLS client cert valid? → ALLOW immediately
    │     ├── JA4 in blacklist?       → BLOCK immediately (RST)
    │     ├── Country in blacklist?   → BLOCK immediately
    │     └── Spamhaus DROP match?    → BLOCK immediately
    │
    ├── [SIGNAL COLLECTION — all run, all produce RiskSignals]
    │     TLS, SNI, TCP/conn, ASN, FCrDNS, beaconing, AbuseIPDB, RDAP, analytics
    │
    ├── [COMPOSITE SCORER] aggregates RiskSignals → score 0–100
    ├── [ACTION DECIDER] applies dial → action
    │     dial=0:   ALLOW (monitor mode)
    │     dial=100: configured thresholds apply
    │
    └── Execute: allow | flag | rate_limit | tarpit | block | ban
```

---

## The Core Asymmetry — This Governs Every Decision

| Error type | Example | Cost |
|-----------|---------|------|
| False negative | Bad bot slips through during cache sync window | Low |
| False positive | Real browser is blocked | **High** |

**When in doubt, fail open.** A missed bad request is recoverable. A blocked
legitimate user is not. This must be reflected in every cache TTL, every
threshold default, every fallback behaviour, every new feature.

Practical rules:
- ALLOW decisions cached with long TTLs. BLOCK decisions with short TTLs.
- When Redis says "block" but local cache says "allow": **local cache wins**.
- When an external service is unreachable: **fail open**, log the failure.
- `h2`/`h1` ALPN browser traffic bypasses everything — it can never be blocked.
- Default dial is 0 (monitor only). The proxy never blocks on first deploy.

---

## Phase Index

The full phase index — including titles, deliverables, and doc links — is no
longer maintained here. **Single source of truth: `docs/phases/manifest.yaml`.**
For human-readable views, see:

- `docs/phases/TODO.md` — open work, regenerated by `make sync`
- `docs/reference/PROJECT_STATUS.md` — high-level status, regenerated by `make sync`
- `docs/phases/PHASE_XX.md` — per-phase plan documents

**Do phases in order. Complete all acceptance criteria before starting the next phase.**

---

## Supporting Documents

Read these before starting any phase:

| Document | Purpose |
|----------|---------|
| `docs/developer/STYLE_GUIDE.md` | Config syntax, log format, test format, doc language |
| `docs/developer/TESTING_STRATEGY.md` | Test layout, conftest, fixtures, parametrize |
| `docs/reference/OBSERVABILITY_STANDARDS.md` | Prometheus registry, JSON log schema, dashboards, alerts, SLIs |
| `docs/developer/TESTING_STRATEGY.md` | Full testing methodology and phase completion gate |
| `docs/developer/DOCUMENTATION_STANDARDS.md` | CHANGELOG, REDIS_SCHEMA, runbook, ADR formats |
| `docs/reference/REDIS_SCHEMA.md` | All Redis key patterns (update every phase) |
| `DMZ_READINESS.md` | Read before Phase 14 (replaces archived DMZ_READINESS.md) |
| `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` | Read before Phase 14 |

---

## Cross-Cutting Requirements

These apply to every phase without exception.

### Bypass Rules (Configurable)

Every bypass condition is independently configurable under `security_policy` in
`config/proxy.yml`. All have safe defaults. The full list of toggles, their
defaults, and their effects lives in `config/proxy.yml` itself — read it
before changing bypass behaviour.

Key invariants:
- **ALLOW bypasses are unaffected by the dial.** If you want to score a
  bypassed category, disable the bypass — don't lower the dial.
- **Disabling a BLOCK bypass routes those connections through the scorer**
  instead of dropping them; they can still be blocked by score.
- The proxy emits a startup `WARN` for every high-risk bypass that is disabled,
  and increments a Prometheus gauge.
- Every change to `security_policy` is appended to `management:policy_audit`
  (LIST, last 1000 entries, no TTL), attributed to the session IP for UI
  changes or `"config_reload"` for file reloads.

### IPv6 (Cross-Cutting From Phase 0)

Every feature that touches an IP address must handle both IPv4 and IPv6:

- **Rate limiting / beaconing / ban keys:** use full IP as-is. Never truncate IPv6.
- **HyperLogLog per subnet:** IPv4 `/24`, IPv6 `/48` (same approximate user
  population density). IPv6 key: `hll:cidr48:{cidr}`.
- **CIDR matching:** `pytricia` (Python) or `net/netip` (Go) — both native.
- **GeoIP / RDAP:** MaxMind and IANA bootstrap both cover v6.
- **Block expansion:** never auto-expand IPv6 beyond `/48`.
- **Logging:** always log the full canonical IP. Never abbreviate IPv6.

When in doubt: store IPs as `ipaddress.ip_address(ip).compressed` (Python) or
`netip.Addr.String()` (Go).

### Async / Non-Blocking

- No blocking I/O on the hot path. Ever.
- All external service calls (AbuseIPDB, RDAP, DNS) use `asyncio.create_task()` —
  fire-and-forget.
- No `time.sleep()` anywhere. Use `asyncio.sleep()`.

### Fail Open

Every external service call must have an explicit failure handler that:
1. Logs the failure with context
2. Increments a Prometheus error counter
3. Returns a zero/neutral result (not an error that propagates)

### Config-Driven & Hot-Reloadable

- Every new feature toggleable in `config/proxy.yml` with conservative defaults.
- New keys require inline YAML comments explaining purpose and valid values.
- Config reload via `SIGHUP` and Redis pub/sub from the Management UI — must
  not require a proxy restart.
- Sections that **cannot** hot-reload (require restart): listen port, Redis URL,
  TLS certificate paths. Document these limitations.

### Testing Standards

See `docs/developer/TESTING_STRATEGY.md` for the full methodology. Summary:
- Maintain ~1.3× test-to-code ratio.
- Required categories: unit, integration, chaos/resilience, adversarial/fuzz,
  FP corpus, performance, E2E.
- All external services use mocks in `tests/mocks/` — never call real APIs.
- Every documented failure mode needs a chaos test.
- New signals: FP rate test against Tranco top 10k.
- Phase completion gate must fully pass before next phase.

**Web service phases — two extra mandatory test files** (learned from 13/51/52):

`test_pages.py` — for every HTML route: GET with auth → 200 + HTML + landmark
string; GET without auth → `< 500` (a 500 means the route crashed before auth ran).

`test_container_config.py` — parse `docker-compose.poc.yml` and assert env
sections pass credentials correctly. In-memory fakes don't need passwords;
real containers do — this gap is invisible to unit tests.

### Documentation Standards

See `docs/developer/DOCUMENTATION_STANDARDS.md`. Summary:
- `CHANGELOG.md`: one news fragment per phase under `docs/fragments/` (never edit `CHANGELOG.md` directly); assembled at release by `make changelog-assemble`.
- `docs/reference/REDIS_SCHEMA.md`: every Redis key documented in the same phase it's introduced.
- Runbooks updated whenever a new service, failure mode, or command lands.
- ADRs in `docs/decisions/ADR-NNN.md` for non-obvious decisions.
- Per-phase documentation gate must pass.

### Code Style

- **Python:** type hints on all public functions and class attributes; docstrings
  on public classes and non-trivial functions; follow patterns in the existing
  `management/` and `src/` code.
- **Go:** `gofmt`-formatted; godoc comments on exports; errors returned not
  panicked (except unrecoverable startup); context propagation for shutdown.

### Prometheus Naming

```
ja4proxy_{subsystem}_{metric_name}_{unit}
ja4proxy_abuseipdb_lookups_total{result="hit|miss|error"}
ja4proxy_risk_score_distribution        # histogram
ja4proxy_dial_setting                   # gauge
```

### Redis Data Structure Quick Reference

| Use case | Structure | Why |
|----------|-----------|-----|
| JA4 black/whitelist | SET + in-process set | O(1) SISMEMBER; small and static |
| IP bans | String + TTL | Per-key TTL required |
| Sliding window rate limit | Sorted Set + Lua | True sliding window; no boundary errors |
| Beaconing timestamps | Sorted Set (score=ts) | ZRANGEBYSCORE for time windows |
| Session resumption | Hash | Atomic HINCRBY |
| Concurrent conn count | INCR/DECR String | Simple atomic counter |
| Return visitor tracking | Hash | Multi-field HINCRBY |
| Unique IP per CIDR | HyperLogLog | O(1), 12KB/key, ~0.81% error |
| Enrichment dedup | Bloom filter | False positives acceptable; O(1) |
| CIDR matching | In-process pytricia / Go trie | No CIDR primitive in Redis |
| GeoIP / ASN lookup | In-process mmap (MaxMind) | Designed for mmap |
| Cross-instance events | Redis Stream | Persistent, replayable |

**Never use Redis for CIDR matching. Always in-process trie.**
**Bloom fallback:** if RedisBloom unavailable, use SET + 24h TTL.

---

## Decision Log (Highlights)

The full decision history lives in `docs/decisions/`. The load-bearing
invariants that affect every phase:

| Decision | Rationale |
|----------|-----------|
| Default dial=0 | Never block on first deploy; must consciously raise |
| Score always, act on dial | Retrospective analysis needs scores even at dial=0 |
| ALLOW bypasses unaffected by dial | Disable the bypass to score a category |
| ALLOW cached 30min, BLOCK cached 30s | False positive cost dwarfs false negative cost |
| Redis blocks but local cache allows → local wins | Real browsers keep working if Redis is down |
| Pub/Sub only for removals/releases | New blocks can propagate slowly; removals need immediate effect |
| AbuseIPDB: never hard-block < score 50 | Shared NAT/VPN IPs make hard-blocking unsafe |
| RDAP block expansion: off by default, never > /24 (v4) or /48 (v6) | A /16 could affect entire ISP customers |
| Analytics: Redis Streams not Pub/Sub | Streams persistent and replayable after downtime |
| Analytics: fire-and-forget XADD | Stream writes must never add hot-path latency |
| Go rewrite (Phase 15) → Go is now the sole proxy | Proved the design in Python first; the Python proxy has since been removed |
| Hot reload: SIGHUP + pub/sub | Config changes must not require restart or traffic gap |

---

## How to Run a Phase

> **Before anything else:** If `docs/phases/PHASE_XX.md` does not exist, you
> MUST create it and have it reviewed by the user **before writing any code**.
> See the **Mandatory Planning & Concurrency Protocol** in `AGENTS.md`. This
> rule overrides the steps below.

### Starting
1. Read this file (`CLAUDE.md`) in full.
2. Read `docs/phases/PHASE_XX.md` (create it first if missing — see note above).
3. Read existing code before writing — `cmd/ja4pd/` and `internal/` for the Go
   proxy; `management/` and `src/` for the Python services.
4. Read `config/proxy.yml` to understand the config structure.
5. Branch: `git checkout main && git pull && git checkout -b phase-XX-description`

### Implementing
6. Implement, following the acceptance criteria in the phase file.
7. Commit often: `git commit -m "phase-XX: description"`
8. Run `make test` — all tests must pass with zero warnings.

### Closing (mandatory — do not skip)
9. Add a CHANGELOG news fragment at `docs/fragments/phase-XX-*.md` (do NOT edit
   `CHANGELOG.md` directly — see `docs/fragments/README.md`).
10. Update `docs/phases/manifest.yaml`: set `status: COMPLETE`, remove resolved gaps.
11. Run `make sync` — regenerates `docs/phases/TODO.md` and `docs/reference/PROJECT_STATUS.md`
    locally so you can preview them. These are **gitignored build artifacts**
    (Phase 332); do not stage them.
12. Commit code, the changelog fragment, and `manifest.yaml` as one atomic commit.
13. Push: `git push origin phase-XX-description`
14. Do not start the next phase until all acceptance criteria pass.
